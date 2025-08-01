# Test PowerShell syntax validation
try {
    $content = Get-Content 'c:\Users\weral\Git\PowerApps-Samples\Deploy-PowerPlatform-VNetInjection.ps1' -Raw -ErrorAction Stop
    $null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$null)
    Write-Host "PowerShell syntax is VALID" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "PowerShell syntax ERROR:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
