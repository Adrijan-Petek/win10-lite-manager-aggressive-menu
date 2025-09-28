if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}

Write-Host "CPU Resource Optimizer - Disable CPU-Intensive Services" -ForegroundColor Cyan
Write-Host "This will help identify and disable services that consume excessive CPU." -ForegroundColor Yellow
Write-Host ""

# Function to get user confirmation
function Get-UserConfirmation {
    param([string]$message)
    $response = Read-Host "$message (y/N)"
    return ($response -eq "y" -or $response -eq "Y")
}

# Function to get CPU usage for services
function Get-ServiceCPUUsage {
    Write-Host "Analyzing current CPU usage by services..." -ForegroundColor Yellow
    try {
        $cpuProcesses = Get-Process | Where-Object { $_.CPU -gt 0 } | Sort-Object CPU -Descending | Select-Object -First 10
        Write-Host "Top CPU-consuming processes:" -ForegroundColor Green
        $cpuProcesses | Format-Table Name, @{Name="CPU%"; Expression={$_.CPU.ToString("F2")}}, Id -AutoSize
        Write-Host ""
    } catch {
        Write-Host "Could not analyze CPU usage. Continuing..." -ForegroundColor Yellow
    }
}

# Services that commonly consume CPU and can be safely disabled
$cpuIntensiveServices = @(
    @{Name="WSearch"; Description="Windows Search - High CPU during indexing, safe to disable if you don't use search"; Risk="Low"},
    @{Name="SysMain"; Description="Superfetch/SysMain - Preloads apps into RAM constantly, safe to disable on SSDs"; Risk="Low"},
    @{Name="BITS"; Description="Background Intelligent Transfer - Transfers data in background, can spike CPU"; Risk="Medium"},
    @{Name="WinDefend"; Description="Windows Defender - Real-time scanning uses significant CPU"; Risk="High"},
    @{Name="DiagTrack"; Description="Connected User Experiences and Telemetry - Constant background telemetry"; Risk="Low"},
    @{Name="dmwappushservice"; Description="Device Management Wireless Application Protocol - Push messages"; Risk="Low"},
    @{Name="WaaSMedicSvc"; Description="Windows Update Medic - Background update service"; Risk="Medium"},
    @{Name="WpnService"; Description="Windows Push Notifications - Push notification service"; Risk="Low"},
    @{Name="CDPUserSvc"; Description="Connected Devices Platform - Device connectivity service"; Risk="Low"},
    @{Name="OneSyncSvc"; Description="Sync Host - Account sync service"; Risk="Low"},
    @{Name="PcaSvc"; Description="Program Compatibility Assistant - Compatibility checking"; Risk="Low"},
    @{Name="MapsBroker"; Description="Downloaded Maps Manager - Maps service"; Risk="Low"},
    @{Name="TabletInputService"; Description="Tablet PC Input Service - Tablet input handling"; Risk="Low"},
    @{Name="WerSvc"; Description="Windows Error Reporting - Sends error reports to Microsoft"; Risk="Low"},
    @{Name="wlidsvc"; Description="Microsoft Account Sign-in Assistant - Microsoft account authentication"; Risk="Low"},
    @{Name="RetailDemo"; Description="Retail Demo Service - Demo mode for retail PCs"; Risk="Low"},
    @{Name="AJRouter"; Description="AllJoyn Router Service - IoT device connectivity"; Risk="Low"},
    @{Name="lfsvc"; Description="Geolocation Service - Location tracking and services"; Risk="Low"},
    @{Name="NgcSvc"; Description="Microsoft Passport - Windows Hello authentication"; Risk="Low"},
    @{Name="NgcCtnrSvc"; Description="Microsoft Passport Container - Windows Hello container"; Risk="Low"},
    @{Name="PhoneSvc"; Description="Phone Service - Phone integration features"; Risk="Low"},
    @{Name="PimIndexMaintenanceSvc"; Description="Contact Data Indexing - Contact data maintenance"; Risk="Low"},
    @{Name="UnistoreSvc"; Description="User Data Storage - User data synchronization"; Risk="Low"},
    @{Name="UserDataSvc"; Description="User Data Access - User data access service"; Risk="Low"},
    @{Name="WpcMonSvc"; Description="Parental Controls - Parental control monitoring"; Risk="Low"},
    @{Name="XboxLiveAuthManager"; Description="Xbox Live Auth Manager - Xbox authentication"; Risk="Low"},
    @{Name="XboxLiveGameSave"; Description="Xbox Live Game Save - Xbox game save service"; Risk="Low"},
    @{Name="XboxLiveNetAuthSvc"; Description="Xbox Live Networking - Xbox networking authentication"; Risk="Low"},
    @{Name="AdobeARMservice"; Description="Adobe Acrobat Update Service - Adobe software updates"; Risk="Low"},
    @{Name="gupdate"; Description="Google Update Service - Google software updates"; Risk="Low"},
    @{Name="gupdatem"; Description="Google Update Service (Machine) - Google software updates"; Risk="Low"},
    @{Name="sppsvc"; Description="Software Protection - Windows activation service"; Risk="Medium"}
)

# Show current CPU analysis
Get-ServiceCPUUsage

$servicesToDisable = @()
Write-Host "Services that can be disabled to reduce CPU usage:" -ForegroundColor Cyan
Write-Host "Risk levels: Low=Safe, Medium=May affect some features, High=Security impact" -ForegroundColor Yellow
Write-Host ""

foreach ($serviceInfo in $cpuIntensiveServices) {
    $service = Get-Service -Name $serviceInfo.Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Host "Service: $($serviceInfo.Name)" -ForegroundColor White
        Write-Host "  Description: $($serviceInfo.Description)" -ForegroundColor Gray
        Write-Host "  Risk Level: $($serviceInfo.Risk)" -ForegroundColor $(if ($serviceInfo.Risk -eq "High") { "Red" } elseif ($serviceInfo.Risk -eq "Medium") { "Yellow" } else { "Green" })
        Write-Host "  Status: RUNNING" -ForegroundColor Yellow

        if (Get-UserConfirmation "Disable $($serviceInfo.Name)?") {
            $servicesToDisable += $serviceInfo.Name
        }
        Write-Host ""
    }
}

# Additional optimizations
Write-Host "Additional CPU optimizations:" -ForegroundColor Cyan

if (Get-UserConfirmation "Disable Windows Search indexing completely?") {
    Write-Host "Disabling Windows Search indexing..." -ForegroundColor Green
    try {
        Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
        Set-Service -Name WSearch -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] Windows Search disabled" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not disable Windows Search" -ForegroundColor Red
    }
}

if (Get-UserConfirmation "Disable Superfetch/SysMain (safe on SSDs)?") {
    Write-Host "Disabling SysMain..." -ForegroundColor Green
    try {
        Stop-Service -Name SysMain -Force -ErrorAction SilentlyContinue
        Set-Service -Name SysMain -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] SysMain disabled" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not disable SysMain" -ForegroundColor Red
    }
}

if (Get-UserConfirmation "Disable background apps to reduce CPU usage?") {
    Write-Host "Disabling background apps..." -ForegroundColor Green
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -ErrorAction SilentlyContinue
        Write-Host "  [OK] Background apps disabled" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not disable background apps" -ForegroundColor Red
    }
}

# Apply service disabling
if ($servicesToDisable.Count -gt 0) {
    Write-Host "`nDisabling selected services..." -ForegroundColor Green
    foreach ($serviceName in $servicesToDisable) {
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  [OK] Disabled: $serviceName" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Failed to disable: $serviceName" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No services selected for disabling." -ForegroundColor Yellow
}

# Final recommendations
Write-Host "`n[SUCCESS] CPU Resource Optimizer completed!" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Green
Write-Host "  - Services disabled: $($servicesToDisable.Count)" -ForegroundColor Green
Write-Host "`n[INFO] Monitor Task Manager to see CPU usage improvements." -ForegroundColor Cyan
Write-Host "[WARNING] If you experience issues, some services can be re-enabled in services.msc" -ForegroundColor Yellow
Write-Host "[RECOMMENDATION] Restart recommended for full effect." -ForegroundColor Green

Read-Host "Press Enter to continue"