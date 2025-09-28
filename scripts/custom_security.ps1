if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}

Write-Host "Custom Security Setup - Post-Windows 10 EOL Security" -ForegroundColor Cyan
Write-Host "Configure security measures since Windows 10 no longer receives updates" -ForegroundColor Yellow
Write-Host ""

# Function to get user confirmation
function Get-UserConfirmation {
    param([string]$message)
    $response = Read-Host "$message (y/N)"
    return ($response -eq "y" -or $response -eq "Y")
}

# Function to apply firewall hardening
function Set-FirewallHardening {
    Write-Host "Applying firewall hardening..." -ForegroundColor Yellow

    try {
        # Enable Windows Firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Block all inbound connections by default
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

        # Allow outbound connections (safer default)
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

        # Block common attack ports
        $blockedPorts = @(135, 137, 138, 139, 445, 3389)  # RPC, NetBIOS, SMB, RDP
        foreach ($port in $blockedPorts) {
            New-NetFirewallRule -DisplayName "Block Port $port" -Direction Inbound -LocalPort $port -Protocol TCP -Action Block -ErrorAction SilentlyContinue
        }

        Write-Host "  [OK] Firewall hardened" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  [FAIL] Could not apply firewall hardening" -ForegroundColor Red
        return $false
    }
}

# Function to disable insecure protocols
function Disable-InsecureProtocols {
    Write-Host "Disabling insecure protocols and services..." -ForegroundColor Yellow

    $changes = 0

    # Disable SMBv1 (major security vulnerability)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Host "  [OK] SMBv1 disabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not disable SMBv1" -ForegroundColor Yellow
    }

    # Disable insecure TLS versions
    try {
        # Create the registry keys if they don't exist
        $tls10ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
        $tls10ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        
        if (-not (Test-Path $tls10ClientPath)) {
            New-Item -Path $tls10ClientPath -Force | Out-Null
        }
        if (-not (Test-Path $tls10ServerPath)) {
            New-Item -Path $tls10ServerPath -Force | Out-Null
        }
        
        New-ItemProperty -Path $tls10ClientPath -Name "Enabled" -Value 0 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $tls10ServerPath -Name "Enabled" -Value 0 -PropertyType DWORD -Force | Out-Null
        Write-Host "  [OK] TLS 1.0 disabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not disable TLS 1.0" -ForegroundColor Yellow
    }

    # Disable RDP if not needed
    if (Get-UserConfirmation "Disable Remote Desktop Protocol (RDP)? Recommended for security") {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Write-Host "  [OK] RDP disabled" -ForegroundColor Green
            $changes++
        } catch {
            Write-Host "  [FAIL] Could not disable RDP" -ForegroundColor Red
        }
    }

    return $changes
}

# Function to configure Windows Defender
function Set-WindowsDefenderConfig {
    Write-Host "Configuring Windows Defender..." -ForegroundColor Yellow

    $changes = 0

    try {
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Host "  [OK] Real-time protection enabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not enable real-time protection" -ForegroundColor Yellow
    }

    # Enable cloud protection
    try {
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent Always
        Write-Host "  [OK] Cloud protection enabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not enable cloud protection" -ForegroundColor Yellow
    }

    # Enable controlled folder access
    if (Get-UserConfirmation "Enable Controlled Folder Access (protects against ransomware)?") {
        try {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            Write-Host "  [OK] Controlled folder access enabled" -ForegroundColor Green
            $changes++
        } catch {
            Write-Host "  [FAIL] Could not enable controlled folder access" -ForegroundColor Red
        }
    }

    return $changes
}

# Function to apply privacy protections
function Set-PrivacyProtections {
    Write-Host "Applying privacy protections..." -ForegroundColor Yellow

    $changes = 0

    # Disable telemetry
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWORD -Force
        Write-Host "  [OK] Telemetry disabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not disable telemetry" -ForegroundColor Yellow
    }

    # Disable advertising ID
    try {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWORD -Force
        Write-Host "  [OK] Advertising ID disabled" -ForegroundColor Green
        $changes++
    } catch {
        Write-Host "  [WARNING] Could not disable advertising ID" -ForegroundColor Yellow
    }

    # Disable location tracking
    if (Get-UserConfirmation "Disable location services?") {
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -Force
            Write-Host "  [OK] Location services disabled" -ForegroundColor Green
            $changes++
        } catch {
            Write-Host "  [FAIL] Could not disable location services" -ForegroundColor Red
        }
    }

    return $changes
}

# Function to show security recommendations
function Show-SecurityRecommendations {
    Write-Host "`n=== POST-WINDOWS 10 EOL SECURITY RECOMMENDATIONS ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Since Windows 10 no longer receives security updates, consider:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. THIRD-PARTY ANTIVIRUS:" -ForegroundColor Green
    Write-Host "   - Install reputable antivirus (Malwarebytes, Bitdefender, etc.)" -ForegroundColor White
    Write-Host "   - Keep Windows Defender as secondary protection" -ForegroundColor White
    Write-Host ""
    Write-Host "2. BROWSER SECURITY:" -ForegroundColor Green
    Write-Host "   - Use Firefox or Chrome with security extensions" -ForegroundColor White
    Write-Host "   - Enable HTTPS Everywhere, uBlock Origin, NoScript" -ForegroundColor White
    Write-Host ""
    Write-Host "3. VPN PROTECTION:" -ForegroundColor Green
    Write-Host "   - Use a reputable VPN service for public WiFi" -ForegroundColor White
    Write-Host "   - Consider Mullvad, ProtonVPN, or IVPN" -ForegroundColor White
    Write-Host ""
    Write-Host "4. REGULAR BACKUPS:" -ForegroundColor Green
    Write-Host "   - Backup important data regularly" -ForegroundColor White
    Write-Host "   - Use external drives or cloud storage" -ForegroundColor White
    Write-Host ""
    Write-Host "5. SYSTEM HARDENING:" -ForegroundColor Green
    Write-Host "   - Keep applications updated manually" -ForegroundColor White
    Write-Host "   - Avoid suspicious downloads and emails" -ForegroundColor White
    Write-Host "   - Use strong, unique passwords" -ForegroundColor White
    Write-Host ""
    Write-Host "6. ALTERNATIVE OS CONSIDERATION:" -ForegroundColor Red
    Write-Host "   - Consider upgrading to Windows 11" -ForegroundColor White
    Write-Host "   - Or switch to Linux (Ubuntu, Fedora) for better security" -ForegroundColor White
    Write-Host ""
}

# Main execution
$firewallChanges = 0
$protocolChanges = 0
$defenderChanges = 0
$privacyChanges = 0

Write-Host "Starting custom security setup..." -ForegroundColor Cyan
Write-Host ""

# Firewall hardening
if (Get-UserConfirmation "Apply firewall hardening (block inbound, allow outbound)?") {
    $firewallChanges = if (Set-FirewallHardening) { 1 } else { 0 }
}

# Disable insecure protocols
$protocolChanges = Disable-InsecureProtocols

# Windows Defender configuration
$defenderChanges = Set-WindowsDefenderConfig

# Privacy protections
$privacyChanges = Set-PrivacyProtections

# Show recommendations
Show-SecurityRecommendations

# Final summary
$totalChanges = $firewallChanges + $protocolChanges + $defenderChanges + $privacyChanges

Write-Host "`n[SUCCESS] Custom security setup completed!" -ForegroundColor Cyan
Write-Host "Summary of changes:" -ForegroundColor Green
Write-Host "  - Firewall hardening: $(if ($firewallChanges -gt 0) { 'Applied' } else { 'Skipped' })" -ForegroundColor $(if ($firewallChanges -gt 0) { 'Green' } else { 'Yellow' })
Write-Host "  - Protocol security: $protocolChanges changes" -ForegroundColor Green
Write-Host "  - Windows Defender: $defenderChanges changes" -ForegroundColor Green
Write-Host "  - Privacy protections: $privacyChanges changes" -ForegroundColor Green
Write-Host "  - Total security improvements: $totalChanges" -ForegroundColor Cyan
Write-Host ""
Write-Host "[WARNING] Test your applications after these changes." -ForegroundColor Yellow
Write-Host "[RECOMMENDATION] Restart your computer for all changes to take effect." -ForegroundColor Green
Write-Host "[INFO] Review the security recommendations above for additional protection." -ForegroundColor Cyan

Read-Host "Press Enter to continue"