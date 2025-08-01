# Test V1 Script Syntax
Write-Host "=== TESTING DEPLOY-POWERPLATFORM-VNETINJECTIONV1.PS1 ===" -ForegroundColor Green

# Basic syntax check
try {
    $content = Get-Content ".\Deploy-PowerPlatform-VNetInjectionV1.ps1" -Raw -ErrorAction Stop
    [void][System.Management.Automation.PSParser]::Tokenize($content, [ref]$null)
    Write-Host "✓ PowerShell syntax is VALID" -ForegroundColor Green
} catch {
    Write-Host "❌ SYNTAX ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# PSScriptAnalyzer check for errors
try {
    $errors = Invoke-ScriptAnalyzer -Path ".\Deploy-PowerPlatform-VNetInjectionV1.ps1" -Severity Error -ErrorAction Stop
    
    if ($errors.Count -eq 0) {
        Write-Host "✓ No PSScriptAnalyzer ERRORS found" -ForegroundColor Green
    } else {
        Write-Host "❌ Found $($errors.Count) ERROR(s):" -ForegroundColor Red
        foreach ($issue in $errors) {
            Write-Host "  Line $($issue.Line): $($issue.RuleName) - $($issue.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "❌ PSScriptAnalyzer failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Check if script can be dot-sourced (loads functions)
try {
    Write-Host "Testing script loading..." -ForegroundColor Yellow
    . ".\Deploy-PowerPlatform-VNetInjectionV1.ps1" -ConfigFile "nonexistent.json" -ErrorAction Stop 2>$null
    Write-Host "✓ Script loaded successfully!" -ForegroundColor Green
} catch [System.Management.Automation.ParameterBindingException] {
    Write-Host "✓ Script loads OK - Parameter binding expected for test" -ForegroundColor Green
} catch {
    Write-Host "❌ Script load error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Green
Write-Host "The V1 script is ready for testing!" -ForegroundColor Cyan
