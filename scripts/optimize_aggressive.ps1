if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}
# Power plan: set to high performance (aggressive)
try { powercfg -setactive SCHEME_MIN } catch {}
# Turn off animations
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 2 -Force -ErrorAction SilentlyContinue
Write-Host "Optimization applied."
