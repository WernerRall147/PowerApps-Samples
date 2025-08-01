#Requires -Version 5.1
#Requires -Modules Az
<#
.SYNOPSIS
    Complete PowerPlatform VNet Injection Cleanup Script
    
.DESCRIPTION
    This script removes all VNet injection infrastructure and configuration.
    It safely disconnects the PowerPlatform environment and deletes all Azure resources.
    
.PARAMETER ConfigFile
    Path to configuration file (optional). If not provided, will prompt for required values.
    
.PARAMETER Force
    Skip confirmation prompts and force deletion of all resources.
    
.PARAMETER KeepNetworking
    Keep VNets and networking infrastructure, only remove enterprise policy and injection.
    
.EXAMPLE
    .\Remove-PowerPlatform-VNetInjection.ps1
    
.EXAMPLE
    .\Remove-PowerPlatform-VNetInjection.ps1 -ConfigFile ".\vnet-config.json" -Force
    
.EXAMPLE
    .\Remove-PowerPlatform-VNetInjection.ps1 -KeepNetworking
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$KeepNetworking = $false
)

# Global Configuration
$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# Default configuration
$DefaultConfig = @{
    SubscriptionId = ""
    EnvironmentId = ""
    ResourceGroupName = "PowerPlatformVNETInjection"
    EnterprisePolicyName = "PowerPlatformVNetPolicy"
    PrimaryRegion = "westeurope"
    SecondaryRegion = "northeurope"
    DeleteResourceGroup = $true
}

function Write-Banner {
    param([string]$Title, [string]$Color = "Red")
    $border = "=" * 60
    Write-Host $border -ForegroundColor $Color
    Write-Host " $Title" -ForegroundColor $Color
    Write-Host $border -ForegroundColor $Color
}

function Write-Status {
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

function Get-CleanupConfiguration {
    param([string]$ConfigFile)
    
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        Write-Status "Loading configuration from: $ConfigFile" "Info"
        $config = Get-Content $ConfigFile | ConvertFrom-Json
        
        # Merge with defaults
        $mergedConfig = $DefaultConfig.Clone()
        $config.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne "ValidateOnly") {  # Exclude deployment-specific properties
                $mergedConfig[$_.Name] = $_.Value
            }
        }
        return $mergedConfig
    }
    
    Write-Status "No configuration file provided. Interactive setup required." "Warning"
    
    # Interactive configuration
    $config = $DefaultConfig.Clone()
    
    Write-Host "`nPowerPlatform VNet Injection Cleanup Configuration" -ForegroundColor Yellow
    Write-Host "Please provide the following information:" -ForegroundColor Cyan
    
    $config.SubscriptionId = Read-Host "Azure Subscription ID (required)"
    if ([string]::IsNullOrEmpty($config.SubscriptionId)) {
        throw "Subscription ID is required"
    }
    
    $envInput = Read-Host "PowerPlatform Environment ID (leave empty to skip environment cleanup)"
    if (![string]::IsNullOrEmpty($envInput)) {
        $config.EnvironmentId = $envInput
    }
    
    $rgInput = Read-Host "Resource Group Name (default: $($config.ResourceGroupName))"
    if (![string]::IsNullOrEmpty($rgInput)) { $config.ResourceGroupName = $rgInput }
    
    $policyInput = Read-Host "Enterprise Policy Name (default: $($config.EnterprisePolicyName))"
    if (![string]::IsNullOrEmpty($policyInput)) { $config.EnterprisePolicyName = $policyInput }
    
    if (!$KeepNetworking) {
        $deleteRg = Read-Host "Delete entire resource group? This will remove ALL resources (y/N)"
        $config.DeleteResourceGroup = ($deleteRg -eq "y" -or $deleteRg -eq "Y")
    } else {
        $config.DeleteResourceGroup = $false
    }
    
    return $config
}

function Test-CleanupPrerequisites {
    param($Config)
    
    Write-Status "Checking cleanup prerequisites..." "Info"
    
    # Test Azure connectivity
    try {
        $context = Get-AzContext
        if (-not $context -or $context.Subscription.Id -ne $Config.SubscriptionId) {
            Write-Status "Connecting to Azure..." "Info"
            Connect-AzAccount -SubscriptionId $Config.SubscriptionId | Out-Null
            Set-AzContext -SubscriptionId $Config.SubscriptionId | Out-Null
        }
        Write-Status "Azure connection verified" "Success"
    } catch {
        throw "Failed to connect to Azure: $($_.Exception.Message)"
    }
    
    # Test PowerPlatform connectivity if environment ID provided
    if (![string]::IsNullOrEmpty($Config.EnvironmentId)) {
        try {
            Write-Status "Connecting to PowerPlatform..." "Info"
            Add-PowerAppsAccount | Out-Null
            
            # Test environment access
            $env = Get-PowerAppEnvironment -EnvironmentName $Config.EnvironmentId -ErrorAction SilentlyContinue
            if (-not $env) {
                Write-Status "Cannot access PowerPlatform environment: $($Config.EnvironmentId)" "Warning"
                Write-Status "Will skip environment cleanup" "Warning"
                $Config.EnvironmentId = ""
            } else {
                Write-Status "PowerPlatform environment access verified" "Success"
            }
        } catch {
            Write-Status "PowerPlatform connection failed - will skip environment cleanup" "Warning"
            $Config.EnvironmentId = ""
        }
    }
}

function Get-DeploymentInventory {
    param($Config)
    
    Write-Status "Discovering deployed resources..." "Info"
    
    $inventory = @{
        ResourceGroup = $null
        VirtualNetworks = @()
        Subnets = @()
        NATGateways = @()
        PublicIPs = @()
        EnterprisePolicy = $null
        VNetInjection = $null
    }
    
    # Check resource group
    try {
        $inventory.ResourceGroup = Get-AzResourceGroup -Name $Config.ResourceGroupName -ErrorAction SilentlyContinue
    } catch {
        Write-Status "Resource group not found: $($Config.ResourceGroupName)" "Warning"
    }
    
    if ($inventory.ResourceGroup) {
        # Get all resources in the resource group
        $resources = Get-AzResource -ResourceGroupName $Config.ResourceGroupName
        
        foreach ($resource in $resources) {
            switch ($resource.ResourceType) {
                "Microsoft.Network/virtualNetworks" {
                    $inventory.VirtualNetworks += $resource
                }
                "Microsoft.Network/natGateways" {
                    $inventory.NATGateways += $resource
                }
                "Microsoft.Network/publicIPAddresses" {
                    $inventory.PublicIPs += $resource
                }
                "Microsoft.PowerPlatform/enterprisePolicies" {
                    $inventory.EnterprisePolicy = $resource
                }
            }
        }
        
        # Get subnet information
        foreach ($vnet in $inventory.VirtualNetworks) {
            $vnetObj = Get-AzVirtualNetwork -ResourceGroupName $Config.ResourceGroupName -Name $vnet.Name
            $subnets = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnetObj
            $inventory.Subnets += $subnets
        }
    }
    
    # Check VNet injection on environment
    if (![string]::IsNullOrEmpty($Config.EnvironmentId)) {
        try {
            $inventory.VNetInjection = Get-AdminPowerAppEnvironmentNetworkInjection -EnvironmentName $Config.EnvironmentId -ErrorAction SilentlyContinue
        } catch {
            Write-Status "Could not check VNet injection status" "Warning"
        }
    }
    
    return $inventory
}

function Show-CleanupPlan {
    param($Config, $Inventory)
    
    Write-Banner "CLEANUP PLAN" "Yellow"
    
    Write-Host "The following resources will be removed:" -ForegroundColor Yellow
    
    if ($Inventory.VNetInjection) {
        Write-Host "  ✓ VNet injection from environment: $($Config.EnvironmentId)" -ForegroundColor Red
    }
    
    if ($Inventory.EnterprisePolicy) {
        Write-Host "  ✓ Enterprise Policy: $($Inventory.EnterprisePolicy.Name)" -ForegroundColor Red
    }
    
    if (!$KeepNetworking) {
        if ($Inventory.VirtualNetworks.Count -gt 0) {
            Write-Host "  ✓ Virtual Networks: $($Inventory.VirtualNetworks.Count) networks" -ForegroundColor Red
            foreach ($vnet in $Inventory.VirtualNetworks) {
                Write-Host "    • $($vnet.Name)" -ForegroundColor Gray
            }
        }
        
        if ($Inventory.NATGateways.Count -gt 0) {
            Write-Host "  ✓ NAT Gateways: $($Inventory.NATGateways.Count) gateways" -ForegroundColor Red
        }
        
        if ($Inventory.PublicIPs.Count -gt 0) {
            Write-Host "  ✓ Public IP Addresses: $($Inventory.PublicIPs.Count) addresses" -ForegroundColor Red
        }
        
        if ($Config.DeleteResourceGroup -and $Inventory.ResourceGroup) {
            Write-Host "  ✓ Resource Group: $($Config.ResourceGroupName) (including ALL resources)" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⚠ Networking resources will be kept (--KeepNetworking specified)" -ForegroundColor Yellow
    }
    
    if (!$Force) {
        Write-Host ""
        Write-Host "⚠ WARNING: This action cannot be undone!" -ForegroundColor Red
        $confirmation = Read-Host "Type 'DELETE' to confirm resource removal"
        if ($confirmation -ne "DELETE") {
            Write-Status "Cleanup cancelled by user" "Info"
            exit 0
        }
    }
}

function Remove-VNetInjection {
    param($Config, $Inventory)
    
    if (!$Inventory.VNetInjection -or [string]::IsNullOrEmpty($Config.EnvironmentId)) {
        Write-Status "No VNet injection found on environment - skipping" "Info"
        return
    }
    
    Write-Status "Removing VNet injection from environment..." "Info"
    
    try {
        # Remove VNet injection using PowerPlatform admin cmdlet
        Remove-AdminPowerAppEnvironmentNetworkInjection -EnvironmentName $Config.EnvironmentId
        
        Write-Status "VNet injection removed from environment" "Success"
        Write-Status "Note: It may take 10-15 minutes for the removal to complete" "Warning"
        
        # Wait a moment for the operation to start
        Start-Sleep -Seconds 5
        
    } catch {
        Write-Status "Failed to remove VNet injection: $($_.Exception.Message)" "Error"
        Write-Status "You may need to remove it manually in PowerPlatform Admin Center" "Warning"
    }
}

function Remove-EnterprisePolicy {
    param($Config, $Inventory)
    
    if (!$Inventory.EnterprisePolicy) {
        Write-Status "No enterprise policy found - skipping" "Info"
        return
    }
    
    Write-Status "Removing enterprise policy: $($Inventory.EnterprisePolicy.Name)" "Info"
    
    try {
        Remove-AzResource -ResourceId $Inventory.EnterprisePolicy.ResourceId -Force
        Write-Status "Enterprise policy removed" "Success"
    } catch {
        Write-Status "Failed to remove enterprise policy: $($_.Exception.Message)" "Error"
    }
}

function Remove-NetworkingResources {
    param($Config, $Inventory)
    
    if ($KeepNetworking) {
        Write-Status "Keeping networking resources as requested" "Info"
        return
    }
    
    if ($Config.DeleteResourceGroup -and $Inventory.ResourceGroup) {
        Write-Status "Removing entire resource group: $($Config.ResourceGroupName)" "Warning"
        try {
            Remove-AzResourceGroup -Name $Config.ResourceGroupName -Force
            Write-Status "Resource group removed completely" "Success"
            return
        } catch {
            Write-Status "Failed to remove resource group: $($_.Exception.Message)" "Error"
            Write-Status "Will attempt to remove individual resources" "Info"
        }
    }
    
    # Remove individual networking resources
    if ($Inventory.NATGateways.Count -gt 0) {
        Write-Status "Removing NAT Gateways..." "Info"
        foreach ($natgw in $Inventory.NATGateways) {
            try {
                Remove-AzNatGateway -ResourceGroupName $Config.ResourceGroupName -Name $natgw.Name -Force
                Write-Status "Removed NAT Gateway: $($natgw.Name)" "Success"
            } catch {
                Write-Status "Failed to remove NAT Gateway $($natgw.Name): $($_.Exception.Message)" "Error"
            }
        }
    }
    
    if ($Inventory.VirtualNetworks.Count -gt 0) {
        Write-Status "Removing Virtual Networks..." "Info"
        foreach ($vnet in $Inventory.VirtualNetworks) {
            try {
                Remove-AzVirtualNetwork -ResourceGroupName $Config.ResourceGroupName -Name $vnet.Name -Force
                Write-Status "Removed Virtual Network: $($vnet.Name)" "Success"
            } catch {
                Write-Status "Failed to remove Virtual Network $($vnet.Name): $($_.Exception.Message)" "Error"
            }
        }
    }
    
    if ($Inventory.PublicIPs.Count -gt 0) {
        Write-Status "Removing Public IP Addresses..." "Info"
        foreach ($pip in $Inventory.PublicIPs) {
            try {
                Remove-AzPublicIpAddress -ResourceGroupName $Config.ResourceGroupName -Name $pip.Name -Force
                Write-Status "Removed Public IP: $($pip.Name)" "Success"
            } catch {
                Write-Status "Failed to remove Public IP $($pip.Name): $($_.Exception.Message)" "Error"
            }
        }
    }
}

function Test-CleanupResults {
    param($Config)
    
    Write-Status "Validating cleanup results..." "Info"
    
    $remainingResources = @()
    
    # Check if resource group still exists
    $rg = Get-AzResourceGroup -Name $Config.ResourceGroupName -ErrorAction SilentlyContinue
    if ($rg) {
        $resources = Get-AzResource -ResourceGroupName $Config.ResourceGroupName
        if ($resources.Count -gt 0) {
            $remainingResources += "Resource Group contains $($resources.Count) resources"
            foreach ($resource in $resources) {
                $remainingResources += "  • $($resource.Name) ($($resource.ResourceType))"
            }
        }
    }
    
    # Check VNet injection
    if (![string]::IsNullOrEmpty($Config.EnvironmentId)) {
        try {
            $injection = Get-AdminPowerAppEnvironmentNetworkInjection -EnvironmentName $Config.EnvironmentId -ErrorAction SilentlyContinue
            if ($injection) {
                $remainingResources += "VNet injection still active on environment"
            }
        } catch {
            # Expected if injection was removed
        }
    }
    
    if ($remainingResources.Count -eq 0) {
        Write-Status "Cleanup completed successfully - all resources removed" "Success"
        return $true
    } else {
        Write-Status "Cleanup completed with remaining resources:" "Warning"
        foreach ($resource in $remainingResources) {
            Write-Host "  $resource" -ForegroundColor Yellow
        }
        return $false
    }
}

# ========================================
# MAIN EXECUTION
# ========================================

try {
    Write-Banner "PowerPlatform VNet Injection Cleanup"
    
    # Load configuration
    $Config = Get-CleanupConfiguration -ConfigFile $ConfigFile
    
    Write-Status "Starting cleanup with configuration:" "Info"
    Write-Host "  Subscription: $($Config.SubscriptionId)" -ForegroundColor Gray
    Write-Host "  Environment: $(if($Config.EnvironmentId){'$($Config.EnvironmentId)'}else{'<not specified>'})" -ForegroundColor Gray
    Write-Host "  Resource Group: $($Config.ResourceGroupName)" -ForegroundColor Gray
    Write-Host "  Keep Networking: $KeepNetworking" -ForegroundColor Gray
    Write-Host "  Force Mode: $Force" -ForegroundColor Gray
    
    # Execute cleanup steps
    Write-Status "Step 1: Prerequisites validation" "Info"
    Test-CleanupPrerequisites -Config $Config
    
    Write-Status "Step 2: Resource discovery" "Info"
    $Inventory = Get-DeploymentInventory -Config $Config
    
    Write-Status "Step 3: Cleanup planning" "Info"
    Show-CleanupPlan -Config $Config -Inventory $Inventory
    
    Write-Status "Step 4: VNet injection removal" "Info"
    Remove-VNetInjection -Config $Config -Inventory $Inventory
    
    Write-Status "Step 5: Enterprise policy removal" "Info"
    Remove-EnterprisePolicy -Config $Config -Inventory $Inventory
    
    Write-Status "Step 6: Network infrastructure removal" "Info"
    Remove-NetworkingResources -Config $Config -Inventory $Inventory
    
    Write-Status "Step 7: Cleanup validation" "Info"
    $cleanupSuccess = Test-CleanupResults -Config $Config
    
    if ($cleanupSuccess) {
        Write-Banner "CLEANUP COMPLETED SUCCESSFULLY" "Green"
        Write-Status "All PowerPlatform VNet injection resources have been removed" "Success"
    } else {
        Write-Banner "CLEANUP COMPLETED WITH WARNINGS" "Yellow"
        Write-Status "Some resources may require manual removal" "Warning"
    }
    
} catch {
    Write-Banner "CLEANUP FAILED" "Red"
    Write-Status "Error: $($_.Exception.Message)" "Error"
    Write-Status "Stack trace: $($_.ScriptStackTrace)" "Error"
    exit 1
}
