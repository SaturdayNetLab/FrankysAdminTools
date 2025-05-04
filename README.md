# Franky's Admin Tool v2.5

A comprehensive PowerShell script providing a text-based menu for a variety of system administration, maintenance, repair, and diagnostic tasks on Windows.

## Description

This script consolidates frequently needed administrative tasks into an easy-to-use, menu-driven interface. It is designed to simplify the workflow for system administrators and power users. The script checks for administrator privileges and includes warnings and confirmation prompts for potentially disruptive actions.

## Features

The script offers the following main menu categories with various sub-options:

1.  **System Information**
    * Basic system info (Operating System, CPU, RAM, etc.)
    * Network configuration (Active adapters, IP, MAC, DNS)
    * Drive overview (Size, Free Space, Health Status)
    * Running processes (Top 50 CPU usage)
    * Installed programs (from the Registry)
2.  **Maintenance & Repair**
    * Defragment drive (`Optimize-Volume`)
    * Start Disk Cleanup (`cleanmgr.exe`)
    * Check system files (`sfc /scannow`)
    * DISM Image Health (Check, Scan, Restore)
    * Check drive (`Repair-Volume -Scan`)
    * Check & repair drive (`chkdsk /f`) **[Caution, Restart may be required]**
    * Delete temporary files (`$env:TEMP`, `C:\Windows\Temp`) **[Caution]**
3.  **Network Tools**
    * Clear DNS Cache (`Clear-DnsClientCache`)
    * Send Ping (`Test-Connection`)
    * Run Traceroute (`Test-NetConnection -TraceRoute`)
    * Show Public IP Address (via `ipinfo.io`)
4.  **System Control**
    * Create System Restore Point (`Checkpoint-Computer`)
    * Start Windows Defender Quick Scan (`Start-MpScan -QuickScan`)
    * Start Windows Defender Full Scan (`Start-MpScan -FullScan`) **[Takes a long time]**
    * RESTART System (`Restart-Computer -Force`) **[Caution!]**
    * SHUT DOWN System (`Stop-Computer -Force`) **[Caution!]**

## Requirements

* Windows Operating System
* Windows PowerShell
* **Administrator privileges** are mandatory.

## Usage

1.  Download the script `FrankysAdminTool_V2.5_Fixed_EN.ps1` (or the German version `FrankysAdminTool_V2.5_Fixed.ps1`).
2.  Open a **PowerShell console as Administrator**.
    * Right-click the Start Menu -> Windows PowerShell (Admin) or Terminal (Admin).
3.  Navigate to the directory where you saved the script using the `cd` command.
    * Example: `cd C:\Users\YourUser\Downloads`
4.  Execute the script:
    ```powershell
    .\FrankysAdminTool_V2.5_Fixed_EN.ps1
    ```
    *(Adjust the filename if using the German version)*
5.  Follow the on-screen menu instructions.

## Important Notes

* **Administrator Privileges:** The script will only function correctly when run with administrator rights. It includes a built-in check.
* **System Changes:** Some actions (especially under "Maintenance & Repair" and "System Control") can make significant changes to the system or require a restart. The script includes warnings and confirmation prompts for critical actions.
* **Data Backup:** It is recommended to back up important data before performing any repair operations.
* **Use at Your Own Risk:** The author assumes no liability for any potential damage caused by using this script.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details (if available).

## Author

Developed by Franky (with AI assistance).
