if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}

Write-Host "Windows Update Remover - Selective Update Removal Tool" -ForegroundColor Cyan
Write-Host "Remove unwanted Windows updates safely" -ForegroundColor Yellow
Write-Host ""

# Function to get user confirmation
function Get-UserConfirmation {
    param([string]$message)
    $response = Read-Host "$message (y/N)"
    return ($response -eq "y" -or $response -eq "Y")
}

# Function to list installed updates
function Get-InstalledUpdates {
    Write-Host "Retrieving installed updates..." -ForegroundColor Yellow
    try {
        $updates = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 50
        Write-Host "Recent installed updates:" -ForegroundColor Green
        $updates | Format-Table HotFixID, Description, InstalledOn -AutoSize
        Write-Host ""
        return $updates
    } catch {
        Write-Host "Could not retrieve updates. Make sure you're running as Administrator." -ForegroundColor Red
        return $null
    }
}

# Function to remove specific update
function Remove-WindowsUpdate {
    param([string]$kbNumber)

    Write-Host "Attempting to remove update $kbNumber..." -ForegroundColor Yellow

    try {
        # Use wusa.exe to uninstall the update
        $process = Start-Process -FilePath "wusa.exe" -ArgumentList "/uninstall /kb:$kbNumber /quiet /norestart" -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Host "  [SUCCESS] Update $kbNumber removed successfully" -ForegroundColor Green
            return $true
        } elseif ($process.ExitCode -eq 3010) {
            Write-Host "  [SUCCESS] Update $kbNumber removed - restart required" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  [FAIL] Failed to remove update $kbNumber (Exit code: $($process.ExitCode))" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "  [ERROR] Exception occurred: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Common updates that can be safely removed (telemetry, unwanted features)
$removableUpdates = @(
    @{KB="4512941"; Description="Windows 10 Telemetry Update - Safe to remove"; Risk="Low"},
    @{KB="4517211"; Description="Windows 10 Compatibility Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4517389"; Description="Windows 10 Customer Experience Improvement - Safe to remove"; Risk="Low"},
    @{KB="4524147"; Description="Windows 10 Telemetry Collection - Safe to remove"; Risk="Low"},
    @{KB="4532693"; Description="Windows 10 Advertising ID - Safe to remove"; Risk="Low"},
    @{KB="4535996"; Description="Windows 10 Location Services - Safe to remove"; Risk="Low"},
    @{KB="4541335"; Description="Windows 10 Cortana Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4559004"; Description="Windows 10 OneDrive Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4561600"; Description="Windows 10 Microsoft Store Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4577586"; Description="Windows 10 Game Bar Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4580325"; Description="Windows 10 Xbox Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4593175"; Description="Windows 10 Edge Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4601319"; Description="Windows 10 Skype Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4611102"; Description="Windows 10 Office Telemetry - Safe to remove"; Risk="Low"},
    @{KB="4625202"; Description="Windows 10 Teams Telemetry - Safe to remove"; Risk="Low"}
)

# Show current updates
$installedUpdates = Get-InstalledUpdates
if (-not $installedUpdates) {
    Write-Host "Cannot continue without update information." -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

# Show removable updates that are actually installed
$availableToRemove = @()
Write-Host "Checking for removable updates that are installed on your system..." -ForegroundColor Cyan
Write-Host ""

foreach ($update in $removableUpdates) {
    $installed = $installedUpdates | Where-Object { $_.HotFixID -eq "KB$($update.KB)" }
    if ($installed) {
        Write-Host "Found removable update: KB$($update.KB)" -ForegroundColor White
        Write-Host "  Description: $($update.Description)" -ForegroundColor Gray
        Write-Host "  Risk Level: $($update.Risk)" -ForegroundColor Green
        Write-Host "  Installed: $($installed.InstalledOn)" -ForegroundColor Yellow

        if (Get-UserConfirmation "Remove KB$($update.KB)?") {
            $availableToRemove += $update
        }
        Write-Host ""
    }
}

# Manual removal option
Write-Host "Manual Update Removal:" -ForegroundColor Cyan
$manualKB = Read-Host "Enter KB number to remove manually (or press Enter to skip)"
if ($manualKB -and $manualKB -match "^\d+$") {
    $manualUpdate = @{KB=$manualKB; Description="Manual removal request"; Risk="Unknown"}
    if (Get-UserConfirmation "Remove KB$manualKB manually? (Risk: Unknown)") {
        $availableToRemove += $manualUpdate
    }
}

# Apply removals
$removedCount = 0
if ($availableToRemove.Count -gt 0) {
    Write-Host "`nRemoving selected updates..." -ForegroundColor Green
    foreach ($update in $availableToRemove) {
        if (Remove-WindowsUpdate -kbNumber $update.KB) {
            $removedCount++
        }
        Start-Sleep -Seconds 2  # Brief pause between removals
    }
} else {
    Write-Host "No updates selected for removal." -ForegroundColor Yellow
}

# Final summary
Write-Host "`n[SUCCESS] Update removal process completed!" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Green
Write-Host "  - Updates removed: $removedCount" -ForegroundColor Green
Write-Host "`n[WARNING] Some updates may require a system restart to complete removal." -ForegroundColor Yellow
Write-Host "[INFO] Removed updates cannot be easily restored - backup important data first." -ForegroundColor Cyan
Write-Host "[RECOMMENDATION] Restart your computer after update removal." -ForegroundColor Green

Read-Host "Press Enter to continue"