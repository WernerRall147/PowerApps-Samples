# Test script loading
try {
    Write-Host "Testing script load..." -ForegroundColor Green
    
    # Try to dot-source the script (this loads functions without executing main code)
    . ".\Deploy-PowerPlatform-VNetInjection.ps1" -ErrorAction Stop
    
    Write-Host "✓ Script loaded successfully!" -ForegroundColor Green
    
    # Check if key functions are available
    $functions = @('Write-Status', 'Get-Configuration', 'Test-PowerPlatformPermission', 'New-EnterprisePolicy')
    foreach ($func in $functions) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "✓ Function '$func' is available" -ForegroundColor Green
        } else {
            Write-Host "❌ Function '$func' is not available" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "❌ Script load failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Full error: $($_.Exception.ToString())" -ForegroundColor Red
}
