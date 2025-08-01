#Requires -Version 5.1
#Requires -Modules Az
<#
.SYNOPSIS
    PowerPlatform VNet Injection Cleanup Script
    
.DESCRIPTION
    This script removes all resources created by the PowerPlatform VNet injection deployment.
    It will remove VNet injection, enterprise policy, VNets, NAT gateways, and optionally the resource group.
    
.PARAMETER ConfigFile
    Path to the same configuration file used for deployment
    
.PARAMETER KeepResourceGroup
    If specified, the resource group will not be deleted
    
.EXAMPLE
    .\Cleanup-PowerPlatform-VNetInjection.ps1 -ConfigFile ".\vnet-config.json"
    
.EXAMPLE  
    .\Cleanup-PowerPlatform-VNetInjection.ps1 -ConfigFile ".\vnet-config.json" -KeepResourceGroup
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = ".\vnet-config.json",
    [Parameter(Mandatory=$false)]
    [switch]$KeepResourceGroup
)

# Import the main script functions
. "$PSScriptRoot\Deploy-PowerPlatform-VNetInjection.ps1" -ConfigFile "" 2>$null

function Write-CleanupStatus {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }  
        "Error" { "Red" }
        "Info" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Remove-VNetInjection {
    param($Config)
    
    Write-CleanupStatus "Removing VNet injection from environment: $($Config.EnvironmentId)" "Info"
    
    try {
        # Use BAP API to remove VNet injection
        $accessToken = Get-AzAccessToken -ResourceUrl "https://api.bap.microsoft.com/"
        $headers = @{
            'Authorization' = "Bearer $($accessToken.Token)"
            'Content-Type' = 'application/json'
        }
        
        $removeUri = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/$($Config.EnvironmentId)/networkinjection?api-version=2020-10-01"
        
        # First check if injection exists
        try {
            $existingInjection = Invoke-RestMethod -Uri $removeUri -Method GET -Headers $headers
            if ($existingInjection -and $existingInjection.properties.networkInjectionId) {
                Write-CleanupStatus "Found existing VNet injection, removing..." "Info"
                Invoke-RestMethod -Uri $removeUri -Method DELETE -Headers $headers | Out-Null
                Write-CleanupStatus "VNet injection removed successfully" "Success"
            } else {
                Write-CleanupStatus "No VNet injection found to remove" "Info"
            }
        } catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                Write-CleanupStatus "No VNet injection found to remove" "Info"
            } else {
                Write-CleanupStatus "Failed to remove VNet injection: $($_.Exception.Message)" "Warning"
            }
        }
        
    } catch {
        Write-CleanupStatus "Error accessing VNet injection API: $($_.Exception.Message)" "Warning"
        Write-CleanupStatus "You may need to manually remove VNet injection using PowerShell script:" "Warning"
        Write-CleanupStatus ".\SubnetInjection\RevertSubnetInjection.ps1 -environmentId 'ENVIRONMENT_ID' -policyArmId 'POLICY_ARM_ID'" "Warning"
    }
}

function Remove-EnterprisePolicy {
    param($Config)
    
    Write-CleanupStatus "Removing enterprise policy: $($Config.EnterprisePolicyName)" "Info"
    
    try {
        $policyResourceId = "/subscriptions/$($Config.SubscriptionId)/resourceGroups/$($Config.ResourceGroupName)/providers/Microsoft.PowerPlatform/enterprisePolicies/$($Config.EnterprisePolicyName)"
        
        $policy = Get-AzResource -ResourceId $policyResourceId -ErrorAction SilentlyContinue
        if ($policy) {
            Remove-AzResource -ResourceId $policyResourceId -Force | Out-Null
            Write-CleanupStatus "Enterprise policy removed successfully" "Success"
        } else {
            Write-CleanupStatus "Enterprise policy not found" "Info"
        }
        
    } catch {
        Write-CleanupStatus "Failed to remove enterprise policy: $($_.Exception.Message)" "Warning"
    }
}

function Remove-VirtualNetworks {
    param($Config)
    
    Write-CleanupStatus "Removing virtual network infrastructure..." "Info"
    
    $regions = @($Config.PrimaryRegion, $Config.SecondaryRegion)
    
    foreach ($region in $regions) {
        try {
            # Remove NAT Gateway first
            $natGatewayName = "natgw-powerplatform-$region"
            $natGateway = Get-AzNatGateway -ResourceGroupName $Config.ResourceGroupName -Name $natGatewayName -ErrorAction SilentlyContinue
            if ($natGateway) {
                Write-CleanupStatus "Removing NAT Gateway: $natGatewayName" "Info"
                Remove-AzNatGateway -ResourceGroupName $Config.ResourceGroupName -Name $natGatewayName -Force | Out-Null
                Write-CleanupStatus "NAT Gateway removed: $natGatewayName" "Success"
            }
            
            # Remove Public IP
            $publicIpName = "pip-natgw-powerplatform-$region"
            $publicIp = Get-AzPublicIpAddress -ResourceGroupName $Config.ResourceGroupName -Name $publicIpName -ErrorAction SilentlyContinue
            if ($publicIp) {
                Write-CleanupStatus "Removing Public IP: $publicIpName" "Info"
                Remove-AzPublicIpAddress -ResourceGroupName $Config.ResourceGroupName -Name $publicIpName -Force | Out-Null
                Write-CleanupStatus "Public IP removed: $publicIpName" "Success"
            }
            
            # Remove VNet
            $vnetName = "vnet-powerplatform-$region"
            $vnet = Get-AzVirtualNetwork -ResourceGroupName $Config.ResourceGroupName -Name $vnetName -ErrorAction SilentlyContinue
            if ($vnet) {
                Write-CleanupStatus "Removing VNet: $vnetName" "Info"
                Remove-AzVirtualNetwork -ResourceGroupName $Config.ResourceGroupName -Name $vnetName -Force | Out-Null
                Write-CleanupStatus "VNet removed: $vnetName" "Success"
            }
            
        } catch {
            Write-CleanupStatus "Error removing resources in $region: $($_.Exception.Message)" "Warning"
        }
    }
}

function Remove-ResourceGroupIfRequested {
    param($Config, $KeepResourceGroup)
    
    if ($KeepResourceGroup) {
        Write-CleanupStatus "Keeping resource group as requested: $($Config.ResourceGroupName)" "Info"
        return
    }
    
    Write-CleanupStatus "Removing resource group: $($Config.ResourceGroupName)" "Info"
    
    try {
        $rg = Get-AzResourceGroup -Name $Config.ResourceGroupName -ErrorAction SilentlyContinue
        if ($rg) {
            $confirmation = Read-Host "Are you sure you want to delete resource group '$($Config.ResourceGroupName)' and ALL its contents? (yes/no)"
            if ($confirmation -eq "yes") {
                Remove-AzResourceGroup -Name $Config.ResourceGroupName -Force | Out-Null
                Write-CleanupStatus "Resource group removed successfully" "Success"
            } else {
                Write-CleanupStatus "Resource group deletion cancelled by user" "Info"
            }
        } else {
            Write-CleanupStatus "Resource group not found" "Info"
        }
        
    } catch {
        Write-CleanupStatus "Failed to remove resource group: $($_.Exception.Message)" "Warning"
    }
}

# ========================================
# MAIN CLEANUP EXECUTION
# ========================================

try {
    Write-Banner "PowerPlatform VNet Injection Cleanup" "Yellow"
    
    # Load configuration
    if (-not (Test-Path $ConfigFile)) {
        throw "Configuration file not found: $ConfigFile"
    }
    
    $Config = Get-Content $ConfigFile | ConvertFrom-Json
    
    Write-CleanupStatus "Starting cleanup with configuration:" "Info"
    Write-Host "  Subscription: $($Config.SubscriptionId)" -ForegroundColor Gray
    Write-Host "  Environment: $($Config.EnvironmentId)" -ForegroundColor Gray
    Write-Host "  Resource Group: $($Config.ResourceGroupName)" -ForegroundColor Gray
    
    # Connect to Azure
    Write-CleanupStatus "Connecting to Azure..." "Info"
    Connect-AzAccount -SubscriptionId $Config.SubscriptionId | Out-Null
    Set-AzContext -SubscriptionId $Config.SubscriptionId | Out-Null
    
    # Connect to PowerPlatform
    Write-CleanupStatus "Connecting to PowerPlatform..." "Info"
    Add-PowerAppsAccount | Out-Null
    
    # Execute cleanup steps
    Write-CleanupStatus "Step 1: Removing VNet injection" "Info"
    Remove-VNetInjection -Config $Config
    
    Write-CleanupStatus "Step 2: Removing enterprise policy" "Info"
    Remove-EnterprisePolicy -Config $Config
    
    Write-CleanupStatus "Step 3: Removing virtual networks" "Info"
    Remove-VirtualNetworks -Config $Config
    
    Write-CleanupStatus "Step 4: Resource group cleanup" "Info"
    Remove-ResourceGroupIfRequested -Config $Config -KeepResourceGroup $KeepResourceGroup
    
    Write-Banner "CLEANUP COMPLETED SUCCESSFULLY" "Green"
    Write-CleanupStatus "All specified resources have been cleaned up" "Success"
    
} catch {
    Write-Banner "CLEANUP FAILED" "Red"
    Write-CleanupStatus "Error: $($_.Exception.Message)" "Error"
    Write-CleanupStatus "Some resources may need to be manually cleaned up" "Warning"
    exit 1
}
