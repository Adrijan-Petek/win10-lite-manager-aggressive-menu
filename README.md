# Win10 Lite Manager — Aggressive Mode

**WARNING (READ CAREFULLY)**  
This repository contains **aggressive** system tweaks for Windows 10 that can significantly alter system behavior, remove built-in apps, disable security features, and change privacy-related settings. **Use at your own risk.** Test in a VM and create a full system image backup before running. Some changes may not be reversible.

## Description

Win10 Lite Manager is a collection of PowerShell scripts designed to optimize Windows 10 for performance and privacy by aggressively removing bloatware, disabling unnecessary services, applying privacy tweaks, blocking telemetry domains, and optimizing system settings. This is intended for advanced users who want a lightweight Windows experience.

## Features

- **Debloat Aggressive**: Removes pre-installed apps and provisioned packages.
- **Services Management**: Disables or stops non-essential services.
- **Privacy Tweaks**: Disables telemetry, Cortana, and other privacy-invasive features.
- **Hosts Blocker**: Blocks telemetry domains via hosts file.
- **Performance Optimization**: Tweaks UI settings and power plans.
- **Audit**: Collects current system state for reference.
- **Restore**: Attempts to rollback changes (limited effectiveness).
- **Check Debloat Status**: Verifies if debloat operations have been applied.
- **Lightwave**: Intelligent system scanning and selective space reduction with user approval.
- **CPU Resource Optimizer**: Interactive tool to disable CPU-intensive services, tracking services, and reduce background CPU usage with user confirmation.
- **Update Remover**: Selectively remove unwanted Windows updates, especially telemetry and tracking updates.
- **Custom Security Setup**: Configure security measures for post-Windows 10 EOL, including firewall hardening and privacy protections.

## Requirements

- Windows 10 (tested on 1903+)
- PowerShell 5.1 or higher
- Administrator privileges
- System backup recommended

## Installation

1. Download or clone this repository.
2. Extract to a folder (e.g., `C:\Win10Lite`).
3. Review and customize `config/` files if needed.

## Usage

### Using the Menu (Recommended)

1. Open PowerShell as Administrator.
2. Navigate to the script directory: `cd C:\Path\To\Win10Lite`
3. Run the menu: `.\menu.ps1`
4. Alternatively, double-click `run_menu.bat` (it handles execution policy automatically)
5. Select options from the interactive menu.

### Manual Script Execution

Run scripts individually as Administrator:

```powershell
.\scripts\audit.ps1                    # Collect current state
.\scripts\debloat_aggressive.ps1       # Remove apps
.\scripts\services_aggressive.ps1      # Manage services
.\scripts\privacy_aggressive.ps1       # Privacy tweaks
.\scripts\hosts_blocker.ps1            # Block domains
.\scripts\optimize_aggressive.ps1      # Performance tweaks
.\scripts\lightwave.ps1                # Extreme space reduction
.\scripts\restore.ps1                  # Attempt rollback
```

### Check Debloat Status

From the menu, select option 9 to check if the debloat operations have been successfully applied. This will show:
- Number of bloatware apps removed
- Number of services disabled
- Number of domains blocked in hosts file
- Current power plan status

### Lightwave - Intelligent System Space Reduction

**🌀 INTELLIGENT & SAFE**: Unlike the automated aggressive mode, Lightwave scans your system first and asks for your approval before making any changes.

**What Lightwave Does:**
- **System Scan**: Shows current services, apps, features, and disk usage
- **Service Optimization**: Identifies running services that can be safely disabled
- **App Removal**: Lists installed bloatware with descriptions for selective removal
- **Feature Management**: Shows enabled Windows features that can be disabled
- **System Cleanup**: Offers to clean temp files, caches, and logs
- **Hibernation Control**: Shows hibernation file size and offers to disable
- **Disk Cleanup**: Runs automated Windows disk cleanup
- **File Compression**: Optionally compresses system files for space savings

**Interactive Process:**
1. Scans and displays current system state
2. Shows each category with what's currently enabled/running
3. Asks for confirmation before each type of change
4. Provides clear descriptions of what each item does
5. Shows progress and final summary

**Expected Results:**
- **Selective control**: You decide what gets removed/disabled
- **Space savings**: 2-15GB depending on selections
- **Safety**: No blind removal - everything requires approval
- **Transparency**: Clear feedback on what's being changed

### CPU Resource Optimizer

**⚡ CPU OPTIMIZATION**: Targets services that consume excessive CPU resources, including tracking and telemetry services.

**What the CPU Optimizer Does:**
- **CPU Analysis**: Shows top CPU-consuming processes before optimization
- **Service Review**: Lists 25+ services that can be safely disabled, including:
  - Tracking services (DiagTrack, telemetry)
  - Xbox services (if not using Xbox)
  - Adobe/Google update services
  - Location and sync services
  - Error reporting and compatibility services
- **Risk Assessment**: Each service shows risk level (Low/Medium/High)
- **User Confirmation**: Asks before disabling each service
- **Additional Optimizations**: 
  - Disable Windows Search indexing
  - Disable Superfetch/SysMain (safe on SSDs)
  - Disable background apps

**Interactive Process:**
1. Analyzes current CPU usage by processes
2. Shows each service with description and risk level
3. Asks for confirmation before disabling each service
4. Applies additional CPU optimizations with confirmation
5. Shows summary of disabled services

**Expected Results:**
- **CPU Reduction**: Significant reduction in background CPU usage
- **Privacy**: Disables tracking and telemetry services
- **Performance**: Faster system response, especially on lower-end hardware
- **Safety**: Risk-based approach with user control

### Update Remover

**🗑️ SELECTIVE UPDATE REMOVAL**: Remove unwanted Windows updates that add telemetry, tracking, or unwanted features.

**What the Update Remover Does:**
- **Update Inventory**: Lists recently installed Windows updates
- **Targeted Removal**: Pre-configured list of removable telemetry updates (15+ updates)
- **Safe Removal**: Uses official Windows uninstaller (wusa.exe)
- **Manual Removal**: Option to remove any specific KB update manually
- **Risk Assessment**: Each update shows risk level and description

**Removable Update Categories:**
- Telemetry and data collection updates
- Advertising and tracking updates
- Location services updates
- Cortana and assistant updates
- Xbox and gaming telemetry
- Microsoft Store and app telemetry
- OneDrive and cloud service telemetry

**Interactive Process:**
1. Scans and displays recent installed updates
2. Shows available removable updates with descriptions
3. Asks for confirmation before removing each update
4. Uses Windows uninstaller for safe removal
5. Shows progress and final summary

**Expected Results:**
- **Reduced Tracking**: Removes Microsoft telemetry collection
- **Privacy Protection**: Eliminates unwanted data sharing
- **Performance**: Removes resource-consuming update components
- **Customization**: Choose exactly which updates to remove

**⚠️ Important Notes:**
- Removed updates cannot be easily restored
- Some updates may require system restart
- Backup important data before removal
- Test system stability after removal

### Custom Security Setup

**🔒 POST-WINDOWS 10 EOL SECURITY**: Configure comprehensive security measures since Windows 10 no longer receives security updates.

**What the Security Setup Does:**
- **Firewall Hardening**: Blocks inbound connections, allows outbound
- **Protocol Security**: Disables insecure protocols (SMBv1, TLS 1.0)
- **Windows Defender**: Enables real-time protection and cloud features
- **Privacy Protections**: Disables telemetry, advertising ID, location tracking
- **Service Security**: Optionally disables RDP and other attack vectors

**Security Features:**
- **Firewall Configuration**: Block common attack ports (135, 137, 138, 139, 445, 3389)
- **Protocol Hardening**: Disable vulnerable SMB and TLS versions
- **Defender Optimization**: Enable controlled folder access and cloud protection
- **Privacy Controls**: Block telemetry, advertising, and location services

**Interactive Process:**
1. Asks for confirmation for each security category
2. Applies firewall hardening with user approval
3. Configures Windows Defender settings
4. Applies privacy and tracking protections
5. Shows comprehensive security recommendations

**Expected Results:**
- **Enhanced Security**: Hardened firewall and protocol security
- **Privacy Protection**: Blocks telemetry and tracking
- **Malware Defense**: Optimized Windows Defender configuration
- **Attack Prevention**: Reduced attack surface

**Post-EOL Security Recommendations:**
- Install third-party antivirus (Malwarebytes, Bitdefender)
- Use secure browsers with extensions (uBlock Origin, HTTPS Everywhere)
- Implement VPN for public WiFi protection
- Regular data backups to external storage
- Consider upgrading to Windows 11 or switching to Linux
- Keep all applications manually updated

### Full Aggressive Mode

From the menu, select option 8 to run all scripts in sequence.

## Configuration

Edit JSON files in `config/` to customize:

- `apps_aggressive.json`: List of apps to remove.
- `services_aggressive.json`: Services to disable.
- `hosts_blocklist.txt`: Domains to block.

## Troubleshooting

- If scripts fail, check PowerShell execution policy: `Set-ExecutionPolicy RemoteSigned`
- For unsigned script errors, use `run_menu.bat` or run: `powershell.exe -ExecutionPolicy Bypass -File .\menu.ps1`
- Some changes require restart to take effect.
- Restore script may not undo all changes.

## Contributing

This is a developer template. Fork and modify as needed.

## License

See LICENSE file.

