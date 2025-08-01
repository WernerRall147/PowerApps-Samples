function Write-Status {
    param($Message, $Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" } 
        "Error" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

Write-Status "Test function loaded successfully" "Success"
