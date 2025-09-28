if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}
$config = Get-Content (Join-Path (Get-Location) 'config\services_aggressive.json') | ConvertFrom-Json
$timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$out = Join-Path (Join-Path (Get-Location) 'out') -ChildPath "services-$timestamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$states = @()
foreach ($svc in $config.services) {
    try {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($null -ne $s) {
            $states += [PSCustomObject]@{Name=$svc;Status=$s.Status;StartType=$s.StartType}
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}
$states | Export-Csv -Path (Join-Path $out 'services-original.csv') -NoTypeInformation
Write-Host "Services disabled. Backup at $out"
