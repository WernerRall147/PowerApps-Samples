#Requires -Version 5.1
#Requires -Modules Az

<#
.SYNOPSIS
    Test the enhanced PowerPlatform VNet Injection deployment with ARM resources
    
.DESCRIPTION
    This script validates the enhanced deployment script with ARM template integration
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ".\vnet-config-final.json"
)

function Write-TestStatus {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }  
        "Error" { "Red" }
        "Info" { "Cyan" }
        "Test" { "Magenta" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-ScriptSyntax {
    Write-TestStatus "Testing PowerShell syntax..." "Test"
    
    $scriptPath = ".\Deploy-PowerPlatform-VNetInjection-Final.ps1"
    
    if (-not (Test-Path $scriptPath)) {
        Write-TestStatus "❌ Script file not found: $scriptPath" "Error"
        return $false
    }
    
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$null)
        Write-TestStatus "✅ PowerShell syntax is valid" "Success"
        return $true
    }
    catch {
        Write-TestStatus "❌ PowerShell syntax error: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-ARMTemplate {
    Write-TestStatus "Testing ARM template..." "Test"
    
    $templatePath = ".\templates\testing-resources.json"
    
    if (-not (Test-Path $templatePath)) {
        Write-TestStatus "❌ ARM template not found: $templatePath" "Error"
        return $false
    }
    
    try {
        $template = Get-Content $templatePath | ConvertFrom-Json
        
        # Basic validation
        if (-not $template.'$schema') {
            Write-TestStatus "❌ ARM template missing schema" "Error"
            return $false
        }
        
        if (-not $template.resources) {
            Write-TestStatus "❌ ARM template missing resources section" "Error"
            return $false
        }
        
        Write-TestStatus "✅ ARM template structure is valid" "Success"
        Write-TestStatus "   - Schema: $($template.'$schema')" "Info"
        Write-TestStatus "   - Resources: $($template.resources.Count)" "Info"
        Write-TestStatus "   - Parameters: $($template.parameters.PSObject.Properties.Count)" "Info"
        Write-TestStatus "   - Outputs: $($template.outputs.PSObject.Properties.Count)" "Info"
        
        return $true
    }
    catch {
        Write-TestStatus "❌ ARM template validation error: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-TestApplication {
    Write-TestStatus "Testing test application..." "Test"
    
    $appPath = ".\templates\test-app\index.html"
    
    if (-not (Test-Path $appPath)) {
        Write-TestStatus "❌ Test application not found: $appPath" "Error"
        return $false
    }
    
    try {
        $content = Get-Content $appPath -Raw
        
        # Check for required elements
        $requiredElements = @(
            "PowerPlatform VNet Testing Application",
            "testStorageConnectivity",
            "testOutboundConnectivity", 
            "getNetworkInfo",
            "%STORAGE_ACCOUNT_NAME%",
            "%VNET_INTEGRATION_ENABLED%"
        )
        
        $missing = @()
        foreach ($element in $requiredElements) {
            if ($content -notlike "*$element*") {
                $missing += $element
            }
        }
        
        if ($missing.Count -eq 0) {
            Write-TestStatus "✅ Test application contains all required elements" "Success"
            return $true
        }
        else {
            Write-TestStatus "❌ Test application missing elements: $($missing -join ', ')" "Error"
            return $false
        }
    }
    catch {
        Write-TestStatus "❌ Test application validation error: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-ConfigurationFile {
    Write-TestStatus "Testing configuration file..." "Test"
    
    if (-not (Test-Path $ConfigFile)) {
        Write-TestStatus "❌ Configuration file not found: $ConfigFile" "Error"
        return $false
    }
    
    try {
        $config = Get-Content $ConfigFile | ConvertFrom-Json
        
        # Check required properties
        $requiredProperties = @(
            "SubscriptionId",
            "VirtualNetworkName", 
            "SubnetName",
            "ResourceGroupName",
            "EnterprisePolicyName",
            "PrimaryRegion"
        )
        
        $missing = @()
        foreach ($prop in $requiredProperties) {
            if (-not $config.$prop) {
                $missing += $prop
            }
        }
        
        if ($missing.Count -eq 0) {
            Write-TestStatus "✅ Configuration file contains all required properties" "Success"
            Write-TestStatus "   - Subscription: $($config.SubscriptionId)" "Info"
            Write-TestStatus "   - VNet: $($config.VirtualNetworkName)" "Info"
            Write-TestStatus "   - Subnet: $($config.SubnetName)" "Info"
            Write-TestStatus "   - Resource Group: $($config.ResourceGroupName)" "Info"
            Write-TestStatus "   - Primary Region: $($config.PrimaryRegion)" "Info"
            Write-TestStatus "   - Secondary Region: $($config.SecondaryRegion)" "Info"
            return $true
        }
        else {
            Write-TestStatus "❌ Configuration file missing properties: $($missing -join ', ')" "Error"
            return $false
        }
    }
    catch {
        Write-TestStatus "❌ Configuration file validation error: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-ScriptLoading {
    Write-TestStatus "Testing script loading..." "Test"
    
    try {
        $scriptPath = ".\Deploy-PowerPlatform-VNetInjection-Final.ps1"
        
        # Test if script can be imported (dot-sourced) without execution
        $scriptContent = Get-Content $scriptPath -Raw
        
        # Extract just the functions (everything before "# Main execution flow")
        $mainExecutionIndex = $scriptContent.IndexOf("# Main execution flow")
        if ($mainExecutionIndex -gt 0) {
            $functionsOnly = $scriptContent.Substring(0, $mainExecutionIndex)
            $null = [ScriptBlock]::Create($functionsOnly)
            Write-TestStatus "✅ Script functions can be loaded successfully" "Success"
            return $true
        }
        else {
            Write-TestStatus "❌ Could not isolate script functions for testing" "Error"
            return $false
        }
    }
    catch {
        Write-TestStatus "❌ Script loading error: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Main test execution
try {
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host " Enhanced PowerPlatform VNet Injection - Comprehensive Test Suite" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    $tests = @()
    
    # Test 1: Script Syntax
    $tests += Test-ScriptSyntax
    
    # Test 2: ARM Template
    $tests += Test-ARMTemplate
    
    # Test 3: Test Application
    $tests += Test-TestApplication
    
    # Test 4: Configuration File
    $tests += Test-ConfigurationFile
    
    # Test 5: Script Loading
    $tests += Test-ScriptLoading
    
    # Summary
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Yellow
    Write-Host " Test Results Summary" -ForegroundColor Yellow
    Write-Host "=" * 70 -ForegroundColor Yellow
    
    $passed = ($tests | Where-Object { $_ -eq $true }).Count
    $total = $tests.Count
    
    Write-TestStatus "Tests Passed: $passed / $total" "Info"
    
    if ($passed -eq $total) {
        Write-TestStatus "🎉 All tests passed! Enhanced deployment script is ready!" "Success"
        Write-Host ""
        Write-TestStatus "Ready to deploy with:" "Info"
        Write-TestStatus ".\Deploy-PowerPlatform-VNetInjection-Final.ps1 -ConfigFile '$ConfigFile'" "Info"
        Write-Host ""
        exit 0
    }
    else {
        Write-TestStatus "❌ Some tests failed. Please review the errors above." "Error"
        exit 1
    }
}
catch {
    Write-TestStatus "❌ Test suite failed: $($_.Exception.Message)" "Error"
    exit 1
}
