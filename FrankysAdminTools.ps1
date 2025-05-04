<#
.SYNOPSIS
Franky's Admin Tool v2.5 - Comprehensive menu for system maintenance and diagnostics.

.DESCRIPTION
This script provides a text-based menu for executing numerous
administration, maintenance, repair, and diagnostic tasks.
It must be run with administrator privileges and includes warnings
for potentially disruptive actions. Contains additional convenience features.
This version includes a fix for the date/time display in the header.

.NOTES
Version: 2.5 (Fixed Header)
Date: 2025-04-10 23:30:59 (Current time for reference)

.LINK
None

.EXAMPLE
.\FrankysAdminTool_V2.5_Fixed_EN.ps1
(Must be run in a PowerShell console started as administrator)
#>

#region Script Configuration & Global Variables
# Colors for output
$ColorTitle       = 'Cyan'
$ColorMenu        = 'Yellow'
$ColorSubMenu     = 'Green'
$ColorWarning     = 'Red'
$ColorSuccess     = 'Green'
$ColorInfo        = 'White'
$ColorInputPrompt = 'Gray'
$ColorError       = 'Red'
$ColorDateTime    = 'DarkGray'

# Global variable for admin check
$Global:IsAdmin = $false
#endregion Script Configuration & Global Variables

#region Helper Functions
# --- Function to display the header (CORRECTED VERSION) ---
function Show-MenuHeader {
    param(
        [string]$Title = "Franky's Admin Tool v2.5"
    )
    Clear-Host
    $frameWidth = 60
    $frameLine = "=" * $frameWidth
    $dateTimeString = Get-Date -Format "dd.MM.yyyy HH:mm:ss" # German date format (kept for consistency)

    Write-Host $frameLine -ForegroundColor $ColorTitle

    # Center title
    $padding = " " * (($frameWidth - $Title.Length) / 2)
    $formattedTitle = "{0}{1}" -f $padding, $Title
    Write-Host ("{0,-$frameWidth}" -f $formattedTitle) -ForegroundColor $ColorTitle

    # Date/Time right-aligned with PadLeft
    $paddedDateTime = $dateTimeString.PadLeft($frameWidth)
    Write-Host $paddedDateTime -ForegroundColor $ColorDateTime

    Write-Host $frameLine -ForegroundColor $ColorTitle
    Write-Host ""
}

# --- Function for pauses ---
function Pause-Script {
    param(
        [string]$Message = "Press Enter to continue..."
    )
    Write-Host ""
    Read-Host -Prompt $Message
}

# --- Function for Yes/No confirmations ---
function Get-Confirmation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PromptMessage,
        [string]$WarningColor = $ColorWarning
    )
    while ($true) {
        Write-Host $PromptMessage -ForegroundColor $WarningColor
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Confirm with 'Yes' or 'No'"
        if ($choice -eq 'Yes') { return $true } # Case-sensitive
        if ($choice -eq 'No') { return $false }
        Write-Warning "Invalid input. Please enter 'Yes' or 'No'."
    }
}

# --- Function to query a drive letter ---
function Get-DriveLetter {
    param(
        [string]$PromptMessage = "Enter the drive letter (e.g., C)"
    )
    while ($true) {
        # Input prompt in appropriate color
        $driveLetter = Read-Host -Prompt $PromptMessage
        if ($driveLetter -match '^[a-zA-Z]$') {
            if (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue) {
                return $driveLetter.ToUpper()
            } else {
                Write-Warning "Drive '$($driveLetter.ToUpper()):' was not found."
            }
        } else {
            Write-Warning "Invalid input '$driveLetter'. Please enter only a single letter."
        }
    }
}

# --- Function to query a hostname/IP ---
function Get-Hostname {
     param(
        [string]$PromptMessage = "Enter the hostname or IP address (e.g., google.com or 8.8.8.8)"
    )
     while ($true) {
        # Input prompt in appropriate color
        $hostname = Read-Host -Prompt $PromptMessage
        if ($hostname -match '\S') { # Checks if not empty
            return $hostname
        } else {
            Write-Warning "Input cannot be empty."
        }
    }
}
#endregion Helper Functions

#region Main Logic and Menus

# --- Check Admin Privileges ---
function Check-AdminStatus {
    Write-Host "Checking for administrator privileges..." -ForegroundColor $ColorMenu
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script requires administrator privileges!"
        Write-Warning "Please start PowerShell as Administrator and run the script again."
        Pause-Script "Press Enter to exit..."
        Exit
    }
    Write-Host "Administrator privileges confirmed." -ForegroundColor $ColorSuccess
    $Global:IsAdmin = $true
    Start-Sleep -Seconds 1
}

# --- Menu: System Information ---
function Show-SystemInfoMenu {
    while ($true) {
        Show-MenuHeader -Title "Menu: System Information"
        Write-Host "  1. Show basic system info" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Show network configuration" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Show drive overview" -ForegroundColor $ColorSubMenu
        Write-Host "  4. Show running processes (Top 50 CPU)" -ForegroundColor $ColorSubMenu
        Write-Host "  5. Show installed programs (Registry)" -ForegroundColor $ColorSubMenu
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Select an option"

        switch ($choice) {
            '1' {
                Show-MenuHeader -Title "Basic System Info"
                try {
                    $compInfo = Get-ComputerInfo
                    $userInfo = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    Write-Host "Operating System : $($compInfo.OsName)" -ForegroundColor $ColorInfo
                    Write-Host "Version          : $($compInfo.OsVersion)" -ForegroundColor $ColorInfo
                    Write-Host "Architecture     : $($compInfo.OsArchitecture)" -ForegroundColor $ColorInfo
                    Write-Host "Computer Name    : $($compInfo.CsName)" -ForegroundColor $ColorInfo
                    Write-Host "Current User     : $($userInfo.Name)" -ForegroundColor $ColorInfo
                    Write-Host "Processor        : $($compInfo.CsProcessors.Name | Out-String -Stream | Select-Object -First 1)" -ForegroundColor $ColorInfo
                    Write-Host "RAM (GB)         : $([math]::Round($compInfo.CsTotalPhysicalMemory / 1GB, 2))" -ForegroundColor $ColorInfo
                } catch { Write-Error "Error retrieving system info: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '2' {
                 Show-MenuHeader -Title "Network Configuration (Active Adapters)"
                 try {
                     Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up' -and ($_.IPv4Address -ne $null -or $_.IPv6Address -ne $null)} |
                         Select-Object InterfaceAlias, @{N='Status';E={$_.NetAdapter.Status}}, @{N='MAC';E={$_.NetAdapter.MacAddress}}, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSClientServerAddress | Format-Table -AutoSize
                 } catch { Write-Error "Error retrieving network configuration: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
            '3' {
                 Show-MenuHeader -Title "Drive Overview"
                 try {
                     Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, @{N='Size (GB)';E={[math]::Round($_.Size / 1GB, 2)}}, @{N='Free (GB)';E={[math]::Round($_.SizeRemaining / 1GB, 2)}}, @{N='Free (%)';E={ [math]::Round(($_.SizeRemaining / $_.Size * 100), 1) }} | Format-Table -AutoSize
                 } catch { Write-Error "Error retrieving drive overview: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
             '4' {
                 Show-MenuHeader -Title "Running Processes (Top 50 CPU)"
                 try {
                     Write-Host "Loading process list..." -ForegroundColor $ColorInfo
                     Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize Name, Id, @{N='CPU(s)';E={$_.CPU}}, @{N='RAM(MB)';E={[math]::Round($_.WorkingSet64 / 1MB, 1)}}
                 } catch { Write-Error "Error retrieving processes: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
             '5' {
                 Show-MenuHeader -Title "Installed Programs (from Registry)"
                 Write-Warning "This list might be incomplete (checks HKLM 32/64bit). Loading can take time."
                 try {
                     Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                         Where-Object {$_.DisplayName -ne $null -and $_.DisplayName -notmatch "Update|Hotfix|Security Intelligence"} |
                         Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize
                 } catch { Write-Error "Error retrieving programs: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
            '0' { return } # Back to Main Menu
            default { Write-Warning "Invalid option '$choice'." ; Start-Sleep -Seconds 2 }
        }
    }
}

# --- Menu: Maintenance & Repair ---
function Show-MaintenanceMenu {
     while ($true) {
        Show-MenuHeader -Title "Menu: Maintenance & Repair"
        Write-Host "  1. Defragment drive" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Start Disk Cleanup (GUI)" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Check system files (SFC Scan)" -ForegroundColor $ColorSubMenu
        Write-Host "  4. DISM: Image CheckHealth (Quick)" -ForegroundColor $ColorSubMenu
        Write-Host "  5. DISM: Image ScanHealth (Intensive)" -ForegroundColor $ColorSubMenu
        Write-Host "  6. DISM: Image RestoreHealth (Repair)" -ForegroundColor $ColorSubMenu
        Write-Host "  7. DISM: All Steps (Check, Scan, Restore)" -ForegroundColor $ColorSubMenu
        Write-Host "  8. Check drive (Scan without repair)" -ForegroundColor $ColorSubMenu
        Write-Host "  9. Check & repair drive (CHKDSK /f) " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Restart may be required!]" -ForegroundColor $ColorWarning
        Write-Host " 10. Delete temporary files " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Caution!]" -ForegroundColor $ColorWarning
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Select an option"

        switch ($choice) {
            '1' { # Defrag
                Show-MenuHeader -Title "Defragmentation"
                try {
                    $drive = Get-DriveLetter
                    Write-Host "Starting defragmentation for drive $drive`: ..." -ForegroundColor $ColorInfo
                    Optimize-Volume -DriveLetter $drive -Defrag -Verbose
                    Write-Host "Defragmentation for drive $drive`: completed." -ForegroundColor $ColorSuccess
                } catch { Write-Error "Error during defragmentation: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '2' { # Cleanup GUI
                Show-MenuHeader -Title "Disk Cleanup"
                Write-Host "Starting Windows Disk Cleanup (GUI)..." -ForegroundColor $ColorInfo
                try { Start-Process cleanmgr.exe -Wait } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '3' { # SFC
                Show-MenuHeader -Title "System File Check (SFC)"
                Write-Host "Starting 'sfc /scannow'. This may take some time..." -ForegroundColor $ColorInfo
                try { sfc.exe /scannow } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Write-Host "SFC Scan completed. Check the output above." -ForegroundColor $ColorSuccess
                Pause-Script
            }
             '4' { # DISM Check
                Show-MenuHeader -Title "DISM CheckHealth"
                Write-Host "Checking the component store (quick)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /CheckHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
             '5' { # DISM Scan
                Show-MenuHeader -Title "DISM ScanHealth"
                Write-Host "Scanning the component store for corruption (takes longer)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /ScanHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
             '6' { # DISM Restore
                Show-MenuHeader -Title "DISM RestoreHealth"
                Write-Host "Attempting to repair the component store (takes a long time, may require internet)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /RestoreHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
             '7' { # DISM All Steps
                Show-MenuHeader -Title "DISM All Steps"
                Write-Host "Executing DISM CheckHealth, ScanHealth, and RestoreHealth sequentially." -ForegroundColor $ColorInfo
                Write-Warning "This can take a very long time and may require internet for RestoreHealth."
                if (Get-Confirmation -PromptMessage "Do you really want to start all DISM steps?") {
                    try {
                        Write-Host "`n--- Step 1: CheckHealth ---" -ForegroundColor $ColorMenu
                        Dism.exe /Online /Cleanup-Image /CheckHealth
                        Write-Host "`n--- Step 2: ScanHealth ---" -ForegroundColor $ColorMenu
                        Dism.exe /Online /Cleanup-Image /ScanHealth
                        Write-Host "`n--- Step 3: RestoreHealth ---" -ForegroundColor $ColorMenu
                        Dism.exe /Online /Cleanup-Image /RestoreHealth
                        Write-Host "`nAll DISM steps completed." -ForegroundColor $ColorSuccess
                    } catch { Write-Error "Error during DISM sequence: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                } else { Write-Host "DISM sequence aborted." -ForegroundColor $ColorInfo }
                Pause-Script
             }
             '8' { # Repair-Volume Scan
                Show-MenuHeader -Title "Check Drive (Scan)"
                Write-Host "This checks the file system for errors without making changes (no restart needed)." -ForegroundColor $ColorInfo
                try {
                    $drive = Get-DriveLetter
                    Write-Host "Starting scan for drive $drive`: ..." -ForegroundColor $ColorInfo
                    Repair-Volume -DriveLetter $drive -Scan
                    # Repair-Volume outputs nothing on success, but does on errors.
                    if ($?) { # Checks if the last command was successful
                         Write-Host "Scan for drive $drive`: completed. No errors reported (or errors were displayed)." -ForegroundColor $ColorSuccess
                    }
                } catch { Write-Error "Error during drive scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
             }
            '9' { # CHKDSK /f
                Show-MenuHeader -Title "Check & Repair Drive (CHKDSK)"
                Write-Warning "CHKDSK with /f attempts to fix errors."
                Write-Warning "If the drive is in use (e.g., C:), the PC MUST BE RESTARTED!"
                $drive = Get-DriveLetter
                if (Get-Confirmation -PromptMessage "Do you really want to run CHKDSK /f on drive $drive`:?") {
                    Write-Host "Starting 'chkdsk $drive`: /f'..." -ForegroundColor $ColorInfo
                    try { chkdsk.exe $drive`: /f } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                    Write-Host "CHKDSK has been started. Follow the instructions (you might need to confirm a restart)." -ForegroundColor $ColorInfo
                } else { Write-Host "CHKDSK aborted." -ForegroundColor $ColorInfo }
                Pause-Script
            }
            '10' { # Temp Delete
                Show-MenuHeader -Title "Delete Temporary Files"
                Write-Warning "This deletes content from '$env:TEMP' and 'C:\Windows\Temp'."
                Write-Warning "Close all programs beforehand if possible!"
                if (Get-Confirmation -PromptMessage "Do you really want to delete the temporary files?") {
                    Write-Host "Deleting user temp files ($env:TEMP)..." -ForegroundColor $ColorInfo
                    try { Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch { Write-Error "Error (User Temp): $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                    Write-Host "Deleting Windows temp files (C:\Windows\Temp)..." -ForegroundColor $ColorInfo
                    try { Get-ChildItem -Path 'C:\Windows\Temp' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch { Write-Error "Error (Windows Temp): $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                    Write-Host "Temporary files have been deleted (errors ignored if files were in use)." -ForegroundColor $ColorSuccess
                } else { Write-Host "Deletion process aborted." -ForegroundColor $ColorInfo }
                Pause-Script
            }
            '0' { return } # Back to Main Menu
            default { Write-Warning "Invalid option '$choice'." ; Start-Sleep -Seconds 2 }
        }
    }
}

# --- Menu: Network Tools ---
function Show-NetworkMenu {
     while ($true) {
        Show-MenuHeader -Title "Menu: Network Tools"
        Write-Host "  1. Clear DNS Cache" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Send Ping" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Run Traceroute" -ForegroundColor $ColorSubMenu
        Write-Host "  4. Show Public IP Address" -ForegroundColor $ColorSubMenu
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Select an option"

         switch ($choice) {
            '1' { # DNS Flush
                Show-MenuHeader -Title "Clear DNS Cache"
                Write-Host "Clearing the DNS Client Cache..." -ForegroundColor $ColorInfo
                try { Clear-DnsClientCache; Write-Host "DNS Cache cleared." -ForegroundColor $ColorSuccess } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                Pause-Script
            }
            '2' { # Ping
                Show-MenuHeader -Title "Ping"
                $hostToPing = Get-Hostname
                Write-Host "Sending 4 pings to '$hostToPing'..." -ForegroundColor $ColorInfo
                try { Test-Connection -TargetName $hostToPing -Count 4 } catch { Write-Error "Error during ping: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                Pause-Script
            }
            '3' { # Traceroute
                 Show-MenuHeader -Title "Traceroute"
                 $hostToTrace = Get-Hostname
                 Write-Host "Running traceroute to '$hostToTrace' (can take time)..." -ForegroundColor $ColorInfo
                 try { Test-NetConnection -ComputerName $hostToTrace -TraceRoute } catch { Write-Error "Error during traceroute: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                 Pause-Script
            }
            '4' { # Public IP
                 Show-MenuHeader -Title "Public IP Address"
                 Write-Host "Attempting to retrieve the public IP from ipinfo.io..." -ForegroundColor $ColorInfo
                 try {
                     # -UseBasicParsing is often more robust if IE is not configured
                     $publicIpInfo = Invoke-RestMethod -Uri "http://ipinfo.io/json" -UseBasicParsing -TimeoutSec 10 # Timeout added
                     Write-Host "Public IP    : $($publicIpInfo.ip)" -ForegroundColor $ColorSuccess
                     Write-Host "Hostname     : $($publicIpInfo.hostname)" -ForegroundColor $ColorInfo
                     Write-Host "Location     : $($publicIpInfo.city), $($publicIpInfo.region), $($publicIpInfo.country)" -ForegroundColor $ColorInfo
                     Write-Host "Organization : $($publicIpInfo.org)" -ForegroundColor $ColorInfo
                 } catch {
                     Write-Error "Error retrieving public IP: $($_.Exception.Message)"
                     Write-Warning "Ensure there is an internet connection and the request is not blocked."
                     Start-Sleep -Milliseconds 500
                 }
                 Pause-Script
            }
            '0' { return } # Back to Main Menu
            default { Write-Warning "Invalid option '$choice'." ; Start-Sleep -Seconds 2 }
        }
    }
}

# --- Menu: System Control ---
function Show-ControlMenu {
     while ($true) {
        Show-MenuHeader -Title "Menu: System Control"
        Write-Host "  1. Create System Restore Point" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Start Windows Defender Quick Scan" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Start Windows Defender Full Scan" -ForegroundColor $ColorSubMenu -NoNewline; Write-Host " [Takes a long time!]" -ForegroundColor $ColorWarning
        Write-Host "  4. RESTART System " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Caution!]" -ForegroundColor $ColorWarning
        Write-Host "  5. SHUT DOWN System " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Caution!]" -ForegroundColor $ColorWarning
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Select an option"

         switch ($choice) {
            '1' { # Restore Point
                Show-MenuHeader -Title "Create System Restore Point"
                $desc = "Manual Point (Franky's Tool V2.5) - $(Get-Date)"
                Write-Host "Creating restore point: '$desc'" -ForegroundColor $ColorInfo
                Write-Host "This may take a moment..."
                try { Checkpoint-Computer -Description $desc ; Write-Host "Restore point created." -ForegroundColor $ColorSuccess } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '2' { # Defender Quick Scan
                Show-MenuHeader -Title "Defender Quick Scan"
                Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor $ColorInfo
                try { Start-MpScan -ScanType QuickScan; Write-Host "Quick scan started (runs in the background)." -ForegroundColor $ColorSuccess } catch { Write-Error "Error starting scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                Pause-Script
            }
            '3' { # Defender Full Scan
                Show-MenuHeader -Title "Defender Full Scan"
                Write-Warning "A full scan can take a VERY long time!"
                if (Get-Confirmation -PromptMessage "Do you really want to start a full scan?") {
                    Write-Host "Starting Windows Defender Full Scan..." -ForegroundColor $ColorInfo
                    try { Start-MpScan -ScanType FullScan; Write-Host "Full scan started (runs in the background)." -ForegroundColor $ColorSuccess } catch { Write-Error "Error starting scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                } else { Write-Host "Full scan aborted." -ForegroundColor $ColorInfo }
                Pause-Script
            }
            '4' { # Restart
                 Show-MenuHeader -Title "RESTART System"
                 if (Get-Confirmation -PromptMessage "Are you sure you want to RESTART the computer NOW? All unsaved work will be lost!") {
                     Write-Host "Computer will restart in 5 seconds..." -ForegroundColor $ColorWarning
                     Start-Sleep 5
                     Restart-Computer -Force
                 } else { Write-Host "Restart aborted." -ForegroundColor $ColorInfo ; Pause-Script }
            }
             '5' { # Shutdown
                 Show-MenuHeader -Title "SHUT DOWN System"
                 if (Get-Confirmation -PromptMessage "Are you sure you want to SHUT DOWN the computer NOW? All unsaved work will be lost!") {
                     Write-Host "Computer will shut down in 5 seconds..." -ForegroundColor $ColorWarning
                     Start-Sleep 5
                     Stop-Computer -Force
                 } else { Write-Host "Shutdown aborted." -ForegroundColor $ColorInfo ; Pause-Script }
            }
            '0' { return } # Back to Main Menu
            default { Write-Warning "Invalid option '$choice'." ; Start-Sleep -Seconds 2 }
        }
    }
}

# --- Main Menu ---
function Show-MainMenu {
    # Check admin status once
    if (-not $Global:IsAdmin) { Check-AdminStatus }

    while ($true) {
        Show-MenuHeader
        Write-Host "Main Menu:" -ForegroundColor $ColorMenu
        Write-Host "  1. System Information" -ForegroundColor $ColorMenu
        Write-Host "  2. Maintenance & Repair" -ForegroundColor $ColorMenu
        Write-Host "  3. Network Tools" -ForegroundColor $ColorMenu
        Write-Host "  4. System Control" -ForegroundColor $ColorMenu
        Write-Host "  0. Exit" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt in appropriate color
        $choice = Read-Host -Prompt "Select a category"

        switch ($choice) {
            '1' { Show-SystemInfoMenu }
            '2' { Show-MaintenanceMenu }
            '3' { Show-NetworkMenu }
            '4' { Show-ControlMenu }
            '0' {
                Write-Host "Exiting Franky's Admin Tool. Goodbye!" -ForegroundColor $ColorTitle
                Start-Sleep -Seconds 2
                return # Exits the main loop and the script
            }
            default { Write-Warning "Invalid category '$choice'." ; Start-Sleep -Seconds 2 }
        }
    }
}

# --- Script Start ---
Show-MainMenu

#endregion Main Logic and Menus
