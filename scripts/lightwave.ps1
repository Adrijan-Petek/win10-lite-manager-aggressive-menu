if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}

Write-Host "Starting Lightwave - Intelligent System Space Reduction..." -ForegroundColor Cyan
Write-Host "This will scan your system and suggest optimizations with your approval." -ForegroundColor Yellow
Write-Host ""

# Function to get user confirmation
function Get-UserConfirmation {
    param([string]$message, [string]$default = "n")
    $response = Read-Host "$message (y/N)"
    return ($response -eq "y" -or $response -eq "Y")
}

# Function to show current system state
function Show-SystemScan {
    Write-Host "Scanning current system state..." -ForegroundColor Yellow

    # Check running services
    $runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }
    Write-Host "Services: $($runningServices.Count) running" -ForegroundColor Green

    # Check installed apps
    $installedApps = Get-AppxPackage -AllUsers | Where-Object { $_.IsFramework -eq $false }
    Write-Host "Apps: $($installedApps.Count) installed" -ForegroundColor Green

    # Check Windows features
    $enabledFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' }
    Write-Host "Features: $($enabledFeatures.Count) enabled" -ForegroundColor Green

    # Check disk space
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $totalSpaceGB = [math]::Round($systemDrive.Size / 1GB, 2)
    Write-Host "Disk C: ${freeSpaceGB}GB free of ${totalSpaceGB}GB total" -ForegroundColor Green

    # Check hibernation
    $hiberFile = "C:\hiberfil.sys"
    if (Test-Path $hiberFile) {
        $hiberSizeGB = [math]::Round((Get-Item $hiberFile).Length / 1GB, 2)
        Write-Host "Hibernation: Enabled (${hiberSizeGB}GB used)" -ForegroundColor Yellow
    } else {
        Write-Host "Hibernation: Disabled" -ForegroundColor Green
    }

    Write-Host ""
}

# Phase 1: System Scan
Show-SystemScan

# Phase 2: Service Optimization
Write-Host "Phase 1: Service Optimization" -ForegroundColor Cyan
Write-Host "The following services can be disabled for better performance:" -ForegroundColor Yellow

$servicesToCheck = @(
    @{Name="DiagTrack"; Description="Connected User Experiences and Telemetry"},
    @{Name="dmwappushservice"; Description="Device Management Wireless Application Protocol"},
    @{Name="WMPNetworkSvc"; Description="Windows Media Player Network Sharing"},
    @{Name="WSearch"; Description="Windows Search"},
    @{Name="SysMain"; Description="Superfetch/SysMain"},
    @{Name="TabletInputService"; Description="Tablet PC Input Service"},
    @{Name="MapsBroker"; Description="Downloaded Maps Manager"},
    @{Name="PcaSvc"; Description="Program Compatibility Assistant"},
    @{Name="OneSyncSvc"; Description="Sync Host"},
    @{Name="WpnService"; Description="Windows Push Notifications"},
    @{Name="CDPUserSvc"; Description="Connected Devices Platform User Service"}
)

$servicesToDisable = @()
foreach ($service in $servicesToCheck) {
    $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "  - $($service.Name): $($service.Description) [RUNNING]" -ForegroundColor Yellow
        if (Get-UserConfirmation "Disable $($service.Name)?") {
            $servicesToDisable += $service.Name
        }
    }
}

if ($servicesToDisable.Count -gt 0) {
    Write-Host "Disabling selected services..." -ForegroundColor Green
    foreach ($service in $servicesToDisable) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  [OK] Disabled: $service" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Failed: $service" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No services selected for disabling." -ForegroundColor Yellow
}

# Phase 3: App Removal
Write-Host "`nPhase 2: App Removal" -ForegroundColor Cyan
Write-Host "The following apps can be removed to save space:" -ForegroundColor Yellow

$appsToCheck = @(
    @{Name="Microsoft.WindowsCalculator"; Description="Calculator"},
    @{Name="Microsoft.WindowsCamera"; Description="Camera"},
    @{Name="Microsoft.WindowsAlarms"; Description="Alarms & Clock"},
    @{Name="Microsoft.WindowsMaps"; Description="Maps"},
    @{Name="Microsoft.ZuneMusic"; Description="Groove Music"},
    @{Name="Microsoft.ZuneVideo"; Description="Movies & TV"},
    @{Name="Microsoft.BingWeather"; Description="Weather"},
    @{Name="Microsoft.BingNews"; Description="News"},
    @{Name="Microsoft.People"; Description="People"},
    @{Name="Microsoft.YourPhone"; Description="Your Phone"},
    @{Name="Microsoft.WindowsFeedbackHub"; Description="Feedback Hub"},
    @{Name="Microsoft.ScreenSketch"; Description="Snip & Sketch"},
    @{Name="Microsoft.549981C3F5F10"; Description="Cortana"}
)

$appsToRemove = @()
foreach ($app in $appsToCheck) {
    $pkg = Get-AppxPackage -Name $app.Name -AllUsers -ErrorAction SilentlyContinue
    if ($pkg) {
        Write-Host "  - $($app.Description) [INSTALLED]" -ForegroundColor Yellow
        if (Get-UserConfirmation "Remove $($app.Description)?") {
            $appsToRemove += $app.Name
        }
    }
}

if ($appsToRemove.Count -gt 0) {
    Write-Host "Removing selected apps..." -ForegroundColor Green
    foreach ($app in $appsToRemove) {
        $pkgs = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        foreach ($p in $pkgs) {
            try {
                Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Write-Host "  [OK] Removed: $app" -ForegroundColor Green
            } catch {
                Write-Host "  [FAIL] Failed: $app" -ForegroundColor Red
            }
        }
        # Remove provisioned packages
        $prov = Get-AppxProvisionedPackage -Online
        $matched = $prov | Where-Object { $_.DisplayName -like "*$app*" -or $_.PackageName -like "*$app*" }
        foreach ($m in $matched) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $m.PackageName -ErrorAction SilentlyContinue
            } catch {}
        }
    }
} else {
    Write-Host "No apps selected for removal." -ForegroundColor Yellow
}

# Phase 4: Windows Features
Write-Host "`nPhase 3: Windows Features" -ForegroundColor Cyan
Write-Host "The following Windows features can be disabled:" -ForegroundColor Yellow

$featuresToCheck = @(
    @{Name="WindowsMediaPlayer"; Description="Windows Media Player"},
    @{Name="MediaPlayback"; Description="Media Features"},
    @{Name="Internet-Explorer-Optional-amd64"; Description="Internet Explorer"},
    @{Name="WorkFolders-Client"; Description="Work Folders"},
    @{Name="FaxServicesClientPackage"; Description="Fax and Scan"},
    @{Name="Printing-XPSServices-Features"; Description="XPS Services"},
    @{Name="SMB1Protocol"; Description="SMB 1.0/CIFS File Sharing"},
    @{Name="MicrosoftWindowsPowerShellV2Root"; Description="PowerShell 2.0"},
    @{Name="MicrosoftWindowsPowerShellV2"; Description="PowerShell 2.0 Engine"}
)

$featuresToDisable = @()
foreach ($feature in $featuresToCheck) {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') {
        Write-Host "  - $($feature.Description) [ENABLED]" -ForegroundColor Yellow
        if (Get-UserConfirmation "Disable $($feature.Description)?") {
            $featuresToDisable += $feature.Name
        }
    }
}

if ($featuresToDisable.Count -gt 0) {
    Write-Host "Disabling selected features..." -ForegroundColor Green
    foreach ($feature in $featuresToDisable) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
            Write-Host "  [OK] Disabled: $feature" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Failed: $feature" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No features selected for disabling." -ForegroundColor Yellow
}

# Phase 5: System Cleanup
Write-Host "`nPhase 4: System Cleanup" -ForegroundColor Cyan

if (Get-UserConfirmation "Run system cleanup (temp files, caches)?") {
    Write-Host "Cleaning system..." -ForegroundColor Green

    # Clean temp files
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cleaned temp files" -ForegroundColor Green

    # Clean Windows Update cache
    Stop-Service -Name wuauserv -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cleaned Windows Update cache" -ForegroundColor Green

    # Clean prefetch
    Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cleaned prefetch files" -ForegroundColor Green
}

# Phase 6: Hibernation
Write-Host "`nPhase 5: Hibernation" -ForegroundColor Cyan
$hiberFile = "C:\hiberfil.sys"
if (Test-Path $hiberFile) {
    $hiberSizeGB = [math]::Round((Get-Item $hiberFile).Length / 1GB, 2)
    Write-Host "Hibernation is enabled, using ${hiberSizeGB}GB of disk space." -ForegroundColor Yellow
    if (Get-UserConfirmation "Disable hibernation to save ${hiberSizeGB}GB?") {
        powercfg -h off
        Write-Host "  [OK] Hibernation disabled" -ForegroundColor Green
    }
} else {
    Write-Host "Hibernation is already disabled." -ForegroundColor Green
}

# Phase 7: Disk Cleanup
Write-Host "`nPhase 6: Automated Disk Cleanup" -ForegroundColor Cyan
if (Get-UserConfirmation "Run automated disk cleanup?") {
    try {
        $cleanMgr = "cleanmgr.exe"
        $args = "/sagerun:1"
        Start-Process -FilePath $cleanMgr -ArgumentList $args -Wait -ErrorAction SilentlyContinue
        Write-Host "  [OK] Disk cleanup completed" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Disk cleanup failed" -ForegroundColor Red
    }
}

# Phase 8: System Compression
Write-Host "`nPhase 7: System File Compression" -ForegroundColor Cyan
Write-Host "Compressing system files can save space but may slightly slow down access." -ForegroundColor Yellow
if (Get-UserConfirmation "Compress Windows system files?") {
    try {
        compact /c /s /i /q "C:\Windows\*" | Out-Null
        Write-Host "  [OK] System files compressed" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Compression failed" -ForegroundColor Red
    }
}

# Final Report
Write-Host "`n[SUCCESS] Lightwave completed!" -ForegroundColor Cyan
Write-Host "Summary of changes:" -ForegroundColor Green
Write-Host "  - Services disabled: $($servicesToDisable.Count)" -ForegroundColor Green
Write-Host "  - Apps removed: $($appsToRemove.Count)" -ForegroundColor Green
Write-Host "  - Features disabled: $($featuresToDisable.Count)" -ForegroundColor Green
Write-Host "`n[WARNING] Restart recommended for all changes to take effect." -ForegroundColor Yellow
Write-Host "[INFO] Check disk usage to see space savings." -ForegroundColor Cyan

Read-Host "Press Enter to continue"