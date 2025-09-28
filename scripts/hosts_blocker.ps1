if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}
$hosts = Join-Path $env:WinDir 'System32\drivers\etc\hosts'
Copy-Item -Path $hosts -Destination (Join-Path (Get-Location) 'out\hosts.backup') -Force
$entries = Get-Content (Join-Path (Get-Location) 'config\hosts_blocklist.txt') | Where-Object { $_ -and -not ($_ -match '^#') }
foreach ($e in $entries) {
    $line = "0.0.0.0 `t$e"
    if ((Select-String -Path $hosts -Pattern $e -SimpleMatch -Quiet) -eq $false) {
        Add-Content -Path $hosts -Value $line
    }
}
Write-Host "Hosts entries applied."
