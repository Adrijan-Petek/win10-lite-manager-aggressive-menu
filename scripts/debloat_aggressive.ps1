if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}
$config = Get-Content (Join-Path (Get-Location) 'config\apps_aggressive.json') | ConvertFrom-Json
foreach ($app in $config.remove) {
    $pkgs = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
    foreach ($p in $pkgs) {
        try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue } catch {}
    }
}
# remove provisioned packages (affects new users)
$prov = Get-AppxProvisionedPackage -Online
foreach ($app in $config.remove) {
    $matched = $prov | Where-Object { $_.DisplayName -like "*$app*" -or $_.PackageName -like "*$app*" }
    foreach ($m in $matched) {
        try { Remove-AppxProvisionedPackage -Online -PackageName $m.PackageName -ErrorAction SilentlyContinue } catch {}
    }
}
Write-Host "Debloat aggressive completed. Check out/ for logs."
