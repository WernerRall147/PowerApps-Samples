# Script Analyzer Test
param([string]$ScriptPath = ".\Deploy-PowerPlatform-VNetInjection.ps1")

Write-Host "=== POWERSHELL SYNTAX CHECK ===" -ForegroundColor Green

# Basic syntax check
try {
    $content = Get-Content $ScriptPath -Raw -ErrorAction Stop
    [void][System.Management.Automation.PSParser]::Tokenize($content, [ref]$null)
    Write-Host "✓ Basic PowerShell syntax is VALID" -ForegroundColor Green
}
catch {
    Write-Host "❌ SYNTAX ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== PSSCRIPTANALYZER CHECK ===" -ForegroundColor Green

# PSScriptAnalyzer check for errors only
try {
    $errors = Invoke-ScriptAnalyzer -Path $ScriptPath -Severity Error -ErrorAction Stop
    
    if ($errors.Count -eq 0) {
        Write-Host "✓ No PSScriptAnalyzer ERRORS found" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Found $($errors.Count) ERROR(s):" -ForegroundColor Red
        foreach ($issue in $errors) {
            Write-Host "  Line $($issue.Line): $($issue.RuleName) - $($issue.Message)" -ForegroundColor Red
        }
    }
    
    # Check warnings
    $warnings = Invoke-ScriptAnalyzer -Path $ScriptPath -Severity Warning -ErrorAction Stop
    
    if ($warnings.Count -eq 0) {
        Write-Host "✓ No PSScriptAnalyzer WARNINGS found" -ForegroundColor Green
    }
    else {
        Write-Host "⚠ Found $($warnings.Count) WARNING(s):" -ForegroundColor Yellow
        # Show only first 10 warnings to avoid clutter
        $warnings | Select-Object -First 10 | ForEach-Object {
            Write-Host "  Line $($_.Line): $($_.RuleName) - $($_.Message)" -ForegroundColor Yellow
        }
        if ($warnings.Count -gt 10) {
            Write-Host "  ... and $($warnings.Count - 10) more warnings" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "❌ PSScriptAnalyzer failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Green
Write-Host "Script analysis complete for: $ScriptPath" -ForegroundColor Cyan
