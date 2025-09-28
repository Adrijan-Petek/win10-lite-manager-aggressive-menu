$timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$out = Join-Path (Join-Path (Get-Location) 'out') -ChildPath "audit-$timestamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
Get-AppxPackage | Select Name, PackageFullName | Sort-Object Name | Out-File (Join-Path $out 'appx-packages.txt')
Get-AppxProvisionedPackage -Online | Select DisplayName, PackageName | Out-File (Join-Path $out 'provisioned-packages.txt')
Get-Service | Select Name, Status, StartType | Out-File (Join-Path $out 'services.txt')
$hosts = Join-Path $env:WinDir 'System32\drivers\etc\hosts'
if (Test-Path $hosts) { Copy-Item -Path $hosts -Destination (Join-Path $out 'hosts.backup') -Force }
Write-Host "Audit saved to $out"
