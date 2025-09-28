
# Win10 Lite Manager - Aggressive Mode Menu
# Run as Administrator

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

function Show-Menu {
    Clear-Host
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "   ⚡ Win10 Lite Manager - Menu ⚡   " -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " [1] Debloat Aggressive (Apps)" -ForegroundColor Green
    Write-Host " [2] Disable/Stop Services" -ForegroundColor Green
    Write-Host " [3] Privacy Tweaks (Telemetry, Cortana)" -ForegroundColor Green
    Write-Host " [4] Hosts Blocker (Telemetry Domains)" -ForegroundColor Green
    Write-Host " [5] Optimize Performance (UI, Power Plan)" -ForegroundColor Green
    Write-Host " [6] Audit Current State" -ForegroundColor Green
    Write-Host " [7] Restore (Rollback)" -ForegroundColor Green
    Write-Host " [8] Run All (Full Aggressive Mode)" -ForegroundColor Magenta
    Write-Host " [9] Check Debloat Status" -ForegroundColor Cyan
    Write-Host " [10] Lightwave (Intelligent Space Reduction)" -ForegroundColor Red
    Write-Host " [11] CPU Resource Optimizer (Disable CPU Hogs)" -ForegroundColor Magenta
    Write-Host " [12] Update Remover (Remove Unwanted Updates)" -ForegroundColor Yellow
    Write-Host " [13] Custom Security Setup (Post-EOL Protection)" -ForegroundColor Red
    Write-Host ""
    Write-Host " [0] Exit" -ForegroundColor Red
    Write-Host ""
}

function Run-Script {
    param([string]$scriptPath, [string]$description)
    if (Test-Path $scriptPath) {
        try {
            Write-Host "Running $description..." -ForegroundColor Yellow
            & $scriptPath
            Write-Host "$description completed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error running $description`: $_.Exception.Message" -ForegroundColor Red
        }
    } else {
        Write-Host "Script not found: $scriptPath" -ForegroundColor Red
    }
}

function Check-DebloatStatus {
    Write-Host "Checking debloat status..." -ForegroundColor Yellow
    
    # Check apps
    $appConfig = Get-Content (Join-Path (Get-Location) 'config\apps_aggressive.json') | ConvertFrom-Json
    $removedApps = 0
    $totalApps = $appConfig.remove.Count
    foreach ($app in $appConfig.remove) {
        $pkgs = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        if (-not $pkgs) { $removedApps++ }
    }
    Write-Host "Apps: $removedApps/$totalApps removed" -ForegroundColor $(if ($removedApps -eq $totalApps) { "Green" } else { "Yellow" })
    
    # Check services
    $serviceConfig = Get-Content (Join-Path (Get-Location) 'config\services_aggressive.json') | ConvertFrom-Json
    $disabledServices = 0
    $totalServices = $serviceConfig.services.Count
    foreach ($service in $serviceConfig.services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartType -eq 'Disabled') { $disabledServices++ }
    }
    Write-Host "Services: $disabledServices/$totalServices disabled" -ForegroundColor $(if ($disabledServices -eq $totalServices) { "Green" } else { "Yellow" })
    
    # Check hosts file
    $hostsPath = "$env:WinDir\System32\drivers\etc\hosts"
    $blockedDomains = 0
    if (Test-Path $hostsPath) {
        $hostsContent = Get-Content $hostsPath
        $blockedDomains = ($hostsContent | Where-Object { $_ -match '^0\.0\.0\.0' -or $_ -match '^127\.0\.0\.1' }).Count
    }
    Write-Host "Hosts blocks: $blockedDomains domains blocked" -ForegroundColor $(if ($blockedDomains -gt 0) { "Green" } else { "Yellow" })
    
    # Check power plan (simplified)
    $powerPlan = powercfg /getactivescheme
    $isOptimized = $powerPlan -match "High performance"
    Write-Host "Power Plan: $(if ($isOptimized) { "High Performance" } else { "Not optimized" })" -ForegroundColor $(if ($isOptimized) { "Green" } else { "Yellow" })
    
    # Check hibernation
    $hiberFile = "C:\hiberfil.sys"
    $hibernationDisabled = -not (Test-Path $hiberFile)
    Write-Host "Hibernation: $(if ($hibernationDisabled) { "Disabled" } else { "Enabled" })" -ForegroundColor $(if ($hibernationDisabled) { "Green" } else { "Yellow" })
    
    # Check system compression
    $compactInfo = compact /q "C:\Windows\system32\ntoskrnl.exe" | Select-String "compressed"
    $isCompressed = $compactInfo -ne $null
    Write-Host "System Compression: $(if ($isCompressed) { "Enabled" } else { "Disabled" })" -ForegroundColor $(if ($isCompressed) { "Green" } else { "Yellow" })
    
    Write-Host "`nDebloat check completed." -ForegroundColor Cyan
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (0-13)"

    switch ($choice) {
        1 { Run-Script "./scripts/debloat_aggressive.ps1" "Debloat Aggressive"; Pause }
        2 { Run-Script "./scripts/services_aggressive.ps1" "Services Management"; Pause }
        3 { Run-Script "./scripts/privacy_aggressive.ps1" "Privacy Tweaks"; Pause }
        4 { Run-Script "./scripts/hosts_blocker.ps1" "Hosts Blocker"; Pause }
        5 { Run-Script "./scripts/optimize_aggressive.ps1" "Performance Optimization"; Pause }
        6 { Run-Script "./scripts/audit.ps1" "Audit"; Pause }
        7 { Run-Script "./scripts/restore.ps1" "Restore"; Pause }
        8 { 
            $confirm = Read-Host "This will run ALL aggressive scripts. Are you sure? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Run-Script "./scripts/debloat_aggressive.ps1" "Debloat Aggressive"
                Run-Script "./scripts/services_aggressive.ps1" "Services Management"
                Run-Script "./scripts/privacy_aggressive.ps1" "Privacy Tweaks"
                Run-Script "./scripts/hosts_blocker.ps1" "Hosts Blocker"
                Run-Script "./scripts/optimize_aggressive.ps1" "Performance Optimization"
                Write-Host "`n✅ Full Aggressive Mode Completed!" -ForegroundColor Cyan
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Pause
        }
        9 { Check-DebloatStatus; Pause }
        10 { 
            $confirm = Read-Host "LIGHTWAVE will scan your system and ask for approval before changes. Continue? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Run-Script "./scripts/lightwave.ps1" "Lightwave Intelligent Space Reduction"
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Pause
        }
        11 { 
            $confirm = Read-Host "CPU Resource Optimizer will analyze and disable high-CPU services. Continue? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Run-Script "./scripts/cpu_optimizer.ps1" "CPU Resource Optimizer"
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Pause
        }
        12 { 
            $confirm = Read-Host "Update Remover will help remove unwanted Windows updates. Continue? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Run-Script "./scripts/update_remover.ps1" "Update Remover"
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Pause
        }
        13 { 
            $confirm = Read-Host "Custom Security Setup will configure security for post-Windows 10 EOL. Continue? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Run-Script "./scripts/custom_security.ps1" "Custom Security Setup"
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Pause
        }
        0 { Write-Host "Exiting..." -ForegroundColor Red }
        Default { Write-Host "Invalid selection. Try again." -ForegroundColor Yellow; Pause }
    }
} while ($choice -ne 0)
