if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}
$latest = Get-ChildItem -Path (Join-Path (Get-Location) 'out') | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "Attempting best-effort restore using folder: $($latest.FullName)"
# Restore hosts
$backup = Get-ChildItem -Path $latest.FullName -Filter 'hosts.backup' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($backup) { Copy-Item -Path $backup.FullName -Destination (Join-Path $env:WinDir 'System32\drivers\etc\hosts') -Force }
# Restore services CSV
$svcCsv = Get-ChildItem -Path $latest.FullName -Filter 'services-original.csv' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($svcCsv) {
    $orig = Import-Csv $svcCsv.FullName
    foreach ($row in $orig) {
        try {
            Set-Service -Name $row.Name -StartupType $row.StartType -ErrorAction SilentlyContinue
            if ($row.Status -eq 'Running') { Start-Service -Name $row.Name -ErrorAction SilentlyContinue }
        } catch {}
    }
}
Write-Host "Restore completed (best-effort). Consider system image restore for full revert."
