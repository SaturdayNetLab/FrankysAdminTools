<#
.SYNOPSIS
Franky's Admin Tool v2.6 (Enhanced UI) - Comprehensive menu for system maintenance and diagnostics.

.DESCRIPTION
This script provides an enhanced text-based menu for executing numerous
administration, maintenance, repair, and diagnostic tasks.
It must be run with administrator privileges and includes warnings
for potentially disruptive actions. Contains additional convenience features.
This version features a visually updated interface.

.NOTES
Version: 2.6 (Enhanced UI)
Date: 2025-05-04 22:30:00 (Current time for reference)

.LINK
None

.EXAMPLE
.\FrankysAdminTool_V2.6_EnhancedUI_EN.ps1
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
$ColorInputPrompt = 'Gray' # Color for the input prompt itself
$ColorError       = 'Red'
$ColorDateTime    = 'DarkGray'
$ColorSeparator   = 'DarkGray' # Color for separator lines

# Global variable for admin check
$Global:IsAdmin = $false

# Global width for frames and lines
$Global:FrameWidth = 65
#endregion Script Configuration & Global Variables

#region Helper Functions
# --- Function to display the header (ENHANCED VERSION) ---
function Show-MenuHeader {
    param(
        [string]$Title = "Franky's Admin Tool v2.6"
    )
    Clear-Host
    $frameWidth = $Global:FrameWidth
    $topBorder = "╔" + ("═" * ($frameWidth - 2)) + "╗"
    $bottomBorder = "╚" + ("═" * ($frameWidth - 2)) + "╝"
    $emptyLine = "║" + (" " * ($frameWidth - 2)) + "║"
    # Using a culture-neutral or common international format might be better,
    # but keeping dd.MM.yyyy as per original script's intent.
    $dateTimeString = Get-Date -Format "dd.MM.yyyy HH:mm:ss" # German date format (kept for consistency)

    Write-Host $topBorder -ForegroundColor $ColorTitle

    # Center title
    $titlePaddingLength = $frameWidth - 4 - $Title.Length # 2 for borders, 2 for spaces
    $leftPadding = " " * ([Math]::Floor($titlePaddingLength / 2))
    $rightPadding = " " * ([Math]::Ceiling($titlePaddingLength / 2))
    $formattedTitle = "║ $leftPadding$Title$rightPadding ║"
    Write-Host $formattedTitle -ForegroundColor $ColorTitle

    # Empty line for spacing
    Write-Host $emptyLine -ForegroundColor $ColorTitle

    # Date/Time right-aligned
    $dateTimePaddingLength = $frameWidth - 4 - $dateTimeString.Length
    $dateTimePadding = " " * $dateTimePaddingLength
    $formattedDateTime = "║ $dateTimePadding$dateTimeString ║"
    Write-Host $formattedDateTime -ForegroundColor $ColorDateTime

    Write-Host $bottomBorder -ForegroundColor $ColorTitle
    Write-Host "" # Newline after header
}

# --- Function for pauses ---
function Pause-Script {
    param(
        [string]$Message = " Press [Enter] to continue... " # Adjusted message
    )
    Write-Host ""
    Write-Host $Message -BackgroundColor Black -ForegroundColor $ColorInputPrompt -NoNewline
    $null = Read-Host
}

# --- Function for Yes/No confirmations ---
function Get-Confirmation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PromptMessage,
        [string]$WarningColor = $ColorWarning
    )
    while ($true) {
        Show-Separator # Use separator function
        Write-Host $PromptMessage -ForegroundColor $WarningColor
        # Input prompt in appropriate color
        Write-Host "Confirm with 'Yes' or 'No': " -ForegroundColor $ColorInputPrompt -NoNewline
        $choice = Read-Host
        Show-Separator # Use separator function
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
        Write-Host "$PromptMessage`: " -ForegroundColor $ColorInputPrompt -NoNewline
        $driveLetter = Read-Host
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
        [string]$PromptMessage = "Enter the hostname or IP address"
    )
     while ($true) {
        # Input prompt in appropriate color
        Write-Host "$PromptMessage (e.g., google.com or 8.8.8.8): " -ForegroundColor $ColorInputPrompt -NoNewline
        $hostname = Read-Host
        if ($hostname -match '\S') { # Checks if not empty
            return $hostname
        } else {
            Write-Warning "Input cannot be empty."
        }
    }
}

# --- Function to show a separator line ---
function Show-Separator {
    Write-Host ("-" * $Global:FrameWidth) -ForegroundColor $ColorSeparator
}

# --- Function to show an action start message ---
function Show-ActionStart {
    param ([string]$ActionName)
    Show-Separator
    Write-Host "--- Starting: $ActionName ---" -ForegroundColor $ColorInfo
    Show-Separator
}

# --- Function to show an action end message ---
function Show-ActionEnd {
    param ([string]$ActionName)
    Show-Separator
    Write-Host "--- Finished: $ActionName ---" -ForegroundColor $ColorSuccess # Changed "Beendet" to "Finished"
    Show-Separator
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
        Write-Host " Select an action:" -ForegroundColor $ColorMenu # Changed "Wähle eine Aktion"
        Show-Separator
        Write-Host "  1. Show basic system info" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Show network configuration" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Show drive overview" -ForegroundColor $ColorSubMenu
        Write-Host "  4. Show running processes (Top 50 CPU)" -ForegroundColor $ColorSubMenu
        Write-Host "  5. Show installed programs (Registry)" -ForegroundColor $ColorSubMenu
        Show-Separator
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt
        Write-Host "Your choice: " -ForegroundColor $ColorInputPrompt -NoNewline # Changed "Deine Wahl"
        $choice = Read-Host

        switch ($choice) {
            '1' {
                Show-MenuHeader -Title "Basic System Info"
                Show-ActionStart "Retrieving Basic System Info" # Changed action description
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
                    Show-ActionEnd "Retrieving Basic System Info"
                } catch { Write-Error "Error retrieving system info: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '2' {
                Show-MenuHeader -Title "Network Configuration (Active Adapters)"
                Show-ActionStart "Retrieving Network Configuration" # Changed action description
                try {
                    Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up' -and ($_.IPv4Address -ne $null -or $_.IPv6Address -ne $null)} |
                         Select-Object InterfaceAlias, @{N='Status';E={$_.NetAdapter.Status}}, @{N='MAC';E={$_.NetAdapter.MacAddress}}, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSClientServerAddress | Format-Table -AutoSize
                    Show-ActionEnd "Retrieving Network Configuration"
                } catch { Write-Error "Error retrieving network configuration: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '3' {
                 Show-MenuHeader -Title "Drive Overview"
                 Show-ActionStart "Retrieving Drive Overview" # Changed action description
                 try {
                     Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, @{N='Size (GB)';E={[math]::Round($_.Size / 1GB, 2)}}, @{N='Free (GB)';E={[math]::Round($_.SizeRemaining / 1GB, 2)}}, @{N='Free (%)';E={ [math]::Round(($_.SizeRemaining / $_.Size * 100), 1) }} | Format-Table -AutoSize
                     Show-ActionEnd "Retrieving Drive Overview"
                 } catch { Write-Error "Error retrieving drive overview: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
             '4' {
                 Show-MenuHeader -Title "Running Processes (Top 50 CPU)"
                 Show-ActionStart "Loading Process List" # Changed action description
                 try {
                     Write-Host "Loading process list (Top 50 CPU)..." -ForegroundColor $ColorInfo
                     Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize Name, Id, @{N='CPU(s)';E={$_.CPU}}, @{N='RAM(MB)';E={[math]::Round($_.WorkingSet64 / 1MB, 1)}}
                     Show-ActionEnd "Loading Process List"
                 } catch { Write-Error "Error retrieving processes: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 Pause-Script
            }
             '5' {
                 Show-MenuHeader -Title "Installed Programs (from Registry)"
                 Write-Warning "This list might be incomplete. Loading can take time." # Changed warning
                 Show-ActionStart "Retrieving Installed Programs" # Changed action description
                 try {
                     Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                         Where-Object {$_.DisplayName -ne $null -and $_.DisplayName -notmatch "Update|Hotfix|Security Intelligence"} |
                         Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize
                     Show-ActionEnd "Retrieving Installed Programs"
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
        Write-Host " Select an action:" -ForegroundColor $ColorMenu
        Show-Separator
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
        Show-Separator
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt
        Write-Host "Your choice: " -ForegroundColor $ColorInputPrompt -NoNewline
        $choice = Read-Host

        switch ($choice) {
            '1' { # Defrag
                Show-MenuHeader -Title "Defragmentation"
                try {
                    $drive = Get-DriveLetter "For which drive?" # Changed prompt
                    Show-ActionStart "Defragmentation for drive $drive`:"
                    Optimize-Volume -DriveLetter $drive -Defrag -Verbose
                    Show-ActionEnd "Defragmentation for drive $drive`:"
                } catch { Write-Error "Error during defragmentation: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
            }
            '2' { # Cleanup GUI
                Show-MenuHeader -Title "Disk Cleanup"
                Show-ActionStart "Starting Disk Cleanup (GUI)" # Changed action description
                Write-Host "Starting Windows Disk Cleanup (GUI)..." -ForegroundColor $ColorInfo
                try { Start-Process cleanmgr.exe -Wait } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Show-ActionEnd "Starting Disk Cleanup (GUI)"
                Pause-Script
            }
            '3' { # SFC
                Show-MenuHeader -Title "System File Check (SFC)"
                Show-ActionStart "Executing 'sfc /scannow'" # Changed action description
                Write-Host "Starting 'sfc /scannow'. This may take some time..." -ForegroundColor $ColorInfo
                try { sfc.exe /scannow } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Write-Host "SFC Scan completed. Check the output above." -ForegroundColor $ColorInfo
                Show-ActionEnd "Executing 'sfc /scannow'"
                Pause-Script
            }
             '4' { # DISM Check
                Show-MenuHeader -Title "DISM CheckHealth"
                Show-ActionStart "DISM CheckHealth"
                Write-Host "Checking the component store (quick)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /CheckHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Show-ActionEnd "DISM CheckHealth"
                Pause-Script
            }
             '5' { # DISM Scan
                Show-MenuHeader -Title "DISM ScanHealth"
                Show-ActionStart "DISM ScanHealth"
                Write-Host "Scanning the component store for corruption (takes longer)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /ScanHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Show-ActionEnd "DISM ScanHealth"
                Pause-Script
            }
             '6' { # DISM Restore
                Show-MenuHeader -Title "DISM RestoreHealth"
                Show-ActionStart "DISM RestoreHealth"
                Write-Host "Attempting to repair the component store (takes a long time, may require internet)..." -ForegroundColor $ColorInfo
                try { Dism.exe /Online /Cleanup-Image /RestoreHealth } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Show-ActionEnd "DISM RestoreHealth"
                Pause-Script
            }
             '7' { # DISM All Steps
                 Show-MenuHeader -Title "DISM All Steps"
                 Write-Warning "This can take a very long time and may require internet for RestoreHealth." # Changed warning
                 if (Get-Confirmation -PromptMessage "Do you really want to start all DISM steps?") {
                    Show-ActionStart "DISM All Steps (Check, Scan, Restore)" # Changed action description
                     try {
                         Write-Host "`n--- Step 1/3: CheckHealth ---" -ForegroundColor $ColorMenu
                         Dism.exe /Online /Cleanup-Image /CheckHealth
                         Write-Host "`n--- Step 2/3: ScanHealth ---" -ForegroundColor $ColorMenu
                         Dism.exe /Online /Cleanup-Image /ScanHealth
                         Write-Host "`n--- Step 3/3: RestoreHealth ---" -ForegroundColor $ColorMenu
                         Dism.exe /Online /Cleanup-Image /RestoreHealth
                         Show-ActionEnd "DISM All Steps"
                     } catch { Write-Error "Error during DISM sequence: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                 } else { Write-Host "DISM sequence aborted." -ForegroundColor $ColorInfo }
                 Pause-Script
             }
             '8' { # Repair-Volume Scan
                Show-MenuHeader -Title "Check Drive (Scan)"
                Write-Host "This checks the file system for errors without making changes." -ForegroundColor $ColorInfo
                try {
                    $drive = Get-DriveLetter "For which drive?" # Changed prompt
                    Show-ActionStart "Scanning drive $drive`: (Repair-Volume)" # Changed action description
                    Repair-Volume -DriveLetter $drive -Scan
                    if ($?) { # Checks if the last command was successful
                         Write-Host "Scan for drive $drive`: completed. No errors reported (or errors were displayed)." -ForegroundColor $ColorInfo
                    }
                    Show-ActionEnd "Scanning drive $drive`: (Repair-Volume)"
                } catch { Write-Error "Error during drive scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Pause-Script
             }
            '9' { # CHKDSK /f
                Show-MenuHeader -Title "Check & Repair Drive (CHKDSK)"
                Write-Warning "CHKDSK with /f attempts to fix errors." # Changed warning
                Write-Warning "If the drive is in use (e.g., C:), the PC MUST BE RESTARTED!" # Changed warning
                $drive = Get-DriveLetter "For which drive?" # Changed prompt
                if (Get-Confirmation -PromptMessage "Do you really want to run CHKDSK /f on drive $drive`:?") {
                    Show-ActionStart "CHKDSK /f for drive $drive`:"
                    Write-Host "Starting 'chkdsk $drive`: /f'..." -ForegroundColor $ColorInfo
                    try { chkdsk.exe $drive`: /f } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                    Write-Host "CHKDSK has been started. Follow the instructions (you might need to confirm a restart)." -ForegroundColor $ColorInfo
                    # No end message here, as it often runs on the next boot
                } else { Write-Host "CHKDSK aborted." -ForegroundColor $ColorInfo }
                Pause-Script
            }
            '10' { # Temp Delete
                Show-MenuHeader -Title "Delete Temporary Files"
                Write-Warning "This deletes content from '$env:TEMP' and 'C:\Windows\Temp'."
                Write-Warning "Close all programs beforehand if possible!" # Changed warning
                if (Get-Confirmation -PromptMessage "Do you really want to delete the temporary files?") {
                    Show-ActionStart "Deleting Temporary Files" # Changed action description
                    Write-Host "Deleting user temp files ($env:TEMP)..." -ForegroundColor $ColorInfo
                    try { Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch { Write-Error "Error (User Temp): $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                    Write-Host "Deleting Windows temp files (C:\Windows\Temp)..." -ForegroundColor $ColorInfo
                    try { Get-ChildItem -Path 'C:\Windows\Temp' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch { Write-Error "Error (Windows Temp): $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                    Write-Host "Deletion attempt finished (errors ignored if files were in use)." -ForegroundColor $ColorInfo # Changed message
                    Show-ActionEnd "Deleting Temporary Files"
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
        Write-Host " Select an action:" -ForegroundColor $ColorMenu
        Show-Separator
        Write-Host "  1. Clear DNS Cache" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Send Ping" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Run Traceroute" -ForegroundColor $ColorSubMenu
        Write-Host "  4. Show Public IP Address" -ForegroundColor $ColorSubMenu
        Show-Separator
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt
        Write-Host "Your choice: " -ForegroundColor $ColorInputPrompt -NoNewline
        $choice = Read-Host

         switch ($choice) {
            '1' { # DNS Flush
                Show-MenuHeader -Title "Clear DNS Cache"
                Show-ActionStart "Clearing DNS Cache" # Changed action description
                Write-Host "Clearing the DNS Client Cache..." -ForegroundColor $ColorInfo
                try { Clear-DnsClientCache; Write-Host "DNS Cache cleared." -ForegroundColor $ColorSuccess } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                Show-ActionEnd "Clearing DNS Cache"
                Pause-Script
            }
            '2' { # Ping
                Show-MenuHeader -Title "Ping"
                $hostToPing = Get-Hostname "Target for Ping" # Changed prompt
                Show-ActionStart "Ping to '$hostToPing'" # Changed action description
                Write-Host "Sending 4 pings to '$hostToPing'..." -ForegroundColor $ColorInfo
                try { Test-Connection -TargetName $hostToPing -Count 4 } catch { Write-Error "Error during ping: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                Show-ActionEnd "Ping to '$hostToPing'"
                Pause-Script
            }
            '3' { # Traceroute
                 Show-MenuHeader -Title "Traceroute"
                 $hostToTrace = Get-Hostname "Target for Traceroute" # Changed prompt
                 Show-ActionStart "Traceroute to '$hostToTrace'" # Changed action description
                 Write-Host "Running traceroute (can take time)..." -ForegroundColor $ColorInfo # Changed message
                 try { Test-NetConnection -ComputerName $hostToTrace -TraceRoute } catch { Write-Error "Error during traceroute: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                 Show-ActionEnd "Traceroute to '$hostToTrace'"
                 Pause-Script
            }
            '4' { # Public IP
                 Show-MenuHeader -Title "Public IP Address"
                 Show-ActionStart "Retrieving Public IP" # Changed action description
                 Write-Host "Attempting to retrieve the public IP from ipinfo.io..." -ForegroundColor $ColorInfo
                 try {
                     $publicIpInfo = Invoke-RestMethod -Uri "http://ipinfo.io/json" -UseBasicParsing -TimeoutSec 10
                     Write-Host "Public IP    : $($publicIpInfo.ip)" -ForegroundColor $ColorSuccess
                     Write-Host "Hostname     : $($publicIpInfo.hostname)" -ForegroundColor $ColorInfo
                     Write-Host "Location     : $($publicIpInfo.city), $($publicIpInfo.region), $($publicIpInfo.country)" -ForegroundColor $ColorInfo
                     Write-Host "Organization : $($publicIpInfo.org)" -ForegroundColor $ColorInfo
                     Show-ActionEnd "Retrieving Public IP"
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
        Write-Host " Select an action:" -ForegroundColor $ColorMenu
        Show-Separator
        Write-Host "  1. Create System Restore Point" -ForegroundColor $ColorSubMenu
        Write-Host "  2. Start Windows Defender Quick Scan" -ForegroundColor $ColorSubMenu
        Write-Host "  3. Start Windows Defender Full Scan" -ForegroundColor $ColorSubMenu -NoNewline; Write-Host " [Takes a long time!]" -ForegroundColor $ColorWarning
        Show-Separator
        Write-Host "  4. RESTART System " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Caution!]" -ForegroundColor $ColorWarning
        Write-Host "  5. SHUT DOWN System " -ForegroundColor $ColorWarning -NoNewline; Write-Host " [Caution!]" -ForegroundColor $ColorWarning
        Show-Separator
        Write-Host "  0. Back to Main Menu" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt
        Write-Host "Your choice: " -ForegroundColor $ColorInputPrompt -NoNewline
        $choice = Read-Host

         switch ($choice) {
            '1' { # Restore Point
                Show-MenuHeader -Title "Create System Restore Point"
                Show-ActionStart "Creating System Restore Point" # Changed action description
                $desc = "Manual Point (Franky's Tool V2.6) - $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
                Write-Host "Creating restore point: '$desc'" -ForegroundColor $ColorInfo
                Write-Host "This may take a moment..." -ForegroundColor $ColorInfo
                try { Checkpoint-Computer -Description $desc ; Write-Host "Restore point created." -ForegroundColor $ColorSuccess } catch { Write-Error "Error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }
                Show-ActionEnd "Creating System Restore Point"
                Pause-Script
            }
            '2' { # Defender Quick Scan
                Show-MenuHeader -Title "Defender Quick Scan"
                Show-ActionStart "Starting Defender Quick Scan" # Changed action description
                Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor $ColorInfo
                try { Start-MpScan -ScanType QuickScan; Write-Host "Quick scan started (runs in the background)." -ForegroundColor $ColorSuccess } catch { Write-Error "Error starting scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                # No end message here, as scan runs in background
                Pause-Script
            }
            '3' { # Defender Full Scan
                Show-MenuHeader -Title "Defender Full Scan"
                Write-Warning "A full scan can take a VERY long time!" # Changed warning
                if (Get-Confirmation -PromptMessage "Do you really want to start a full scan?") {
                    Show-ActionStart "Starting Defender Full Scan" # Changed action description
                    Write-Host "Starting Windows Defender Full Scan..." -ForegroundColor $ColorInfo
                    try { Start-MpScan -ScanType FullScan; Write-Host "Full scan started (runs in the background)." -ForegroundColor $ColorSuccess } catch { Write-Error "Error starting scan: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500}
                     # No end message here, as scan runs in background
                } else { Write-Host "Full scan aborted." -ForegroundColor $ColorInfo }
                Pause-Script
            }
            '4' { # Restart
                 Show-MenuHeader -Title "RESTART System"
                 if (Get-Confirmation -PromptMessage "Are you sure you want to RESTART the computer NOW? All unsaved work will be lost!") {
                     Show-ActionStart "Initiating Restart" # Changed action description
                     Write-Host "Computer will restart in 5 seconds..." -ForegroundColor $ColorWarning
                     Start-Sleep 5
                     Restart-Computer -Force
                 } else { Write-Host "Restart aborted." -ForegroundColor $ColorInfo ; Pause-Script }
            }
             '5' { # Shutdown
                 Show-MenuHeader -Title "SHUT DOWN System"
                 if (Get-Confirmation -PromptMessage "Are you sure you want to SHUT DOWN the computer NOW? All unsaved work will be lost!") {
                     Show-ActionStart "Initiating Shutdown" # Changed action description
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
        Write-Host " Main Menu - Select a category:" -ForegroundColor $ColorMenu # Changed intro
        Show-Separator
        Write-Host "  1. System Information" -ForegroundColor $ColorMenu
        Write-Host "  2. Maintenance & Repair" -ForegroundColor $ColorMenu
        Write-Host "  3. Network Tools" -ForegroundColor $ColorMenu
        Write-Host "  4. System Control" -ForegroundColor $ColorMenu
        Show-Separator
        Write-Host "  0. Exit" -ForegroundColor $ColorMenu
        Write-Host ""
        # Input prompt
        Write-Host "Your choice: " -ForegroundColor $ColorInputPrompt -NoNewline # Changed prompt
        $choice = Read-Host

        switch ($choice) {
            '1' { Show-SystemInfoMenu }
            '2' { Show-MaintenanceMenu }
            '3' { Show-NetworkMenu }
            '4' { Show-ControlMenu }
            '0' {
                Show-Separator
                Write-Host "Exiting Franky's Admin Tool. Goodbye!" -ForegroundColor $ColorTitle # Changed exit message
                Show-Separator
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
