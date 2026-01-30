# ================================================
# Complete Windows Enumeration Automation Script
# Author: OffSec Platform
# Version: 2.0
# Date: 2024
# ================================================

# ================================================
# CONFIGURATION
# ================================================
$OutputDirectory = "C:\Enumeration_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$LogFile = "$OutputDirectory\enumeration.log"
$Domain = $env:USERDOMAIN
$ComputerName = $env:COMPUTERNAME
$CurrentUser = $env:USERNAME

# ================================================
# FUNCTIONS
# ================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

function Create-OutputDirectory {
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Log "Created output directory: $OutputDirectory"
    }
}

function Get-SystemInformation {
    Write-Log "Starting System Information Enumeration..."
    
    $SystemInfoFile = "$OutputDirectory\system_information.txt"
    
    # Basic System Info
    Write-Log "  Collecting basic system information..."
    "=== BASIC SYSTEM INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    systeminfo | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # Hostname
    Write-Log "  Collecting hostname information..."
    "=== HOSTNAME ===" | Out-File -FilePath $SystemInfoFile -Append
    hostname | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # OS Details via WMI
    Write-Log "  Collecting OS details..."
    "=== OS DETAILS (WMI) ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, BuildNumber, SerialNumber, InstallDate | Format-List | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # Hardware Information
    Write-Log "  Collecting hardware information..."
    "=== HARDWARE INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory | Format-List | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # CPU Information
    Write-Log "  Collecting CPU information..."
    "=== CPU INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # Memory Information
    Write-Log "  Collecting memory information..."
    "=== MEMORY INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_PhysicalMemory | Select-Object Capacity, Manufacturer, PartNumber, Speed | Format-Table -AutoSize | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # Disk Information
    Write-Log "  Collecting disk information..."
    "=== DISK INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_DiskDrive | Select-Object Model, Size, InterfaceType | Format-Table -AutoSize | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, DriveType, Size, FreeSpace, FileSystem | Format-Table -AutoSize | Out-File -FilePath $SystemInfoFile -Append
    "" | Out-File -FilePath $SystemInfoFile -Append
    
    # BIOS Information
    Write-Log "  Collecting BIOS information..."
    "=== BIOS INFORMATION ===" | Out-File -FilePath $SystemInfoFile -Append
    Get-WmiObject Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber | Format-List | Out-File -FilePath $SystemInfoFile -Append
    
    Write-Log "System Information Enumeration Complete"
}

function Get-UserAndGroupInformation {
    Write-Log "Starting User and Group Enumeration..."
    
    $UserInfoFile = "$OutputDirectory\user_group_information.txt"
    
    # Current User Context
    Write-Log "  Collecting current user context..."
    "=== CURRENT USER CONTEXT ===" | Out-File -FilePath $UserInfoFile -Append
    whoami /all | Out-File -FilePath $UserInfoFile -Append
    "" | Out-File -FilePath $UserInfoFile -Append
    
    # Local Users
    Write-Log "  Collecting local user information..."
    "=== LOCAL USERS ===" | Out-File -FilePath $UserInfoFile -Append
    net user | Out-File -FilePath $UserInfoFile -Append
    "" | Out-File -FilePath $UserInfoFile -Append
    
    # Local Groups
    Write-Log "  Collecting local group information..."
    "=== LOCAL GROUPS ===" | Out-File -FilePath $UserInfoFile -Append
    net localgroup | Out-File -FilePath $UserInfoFile -Append
    "" | Out-File -FilePath $UserInfoFile -Append
    
    # Administrators Group
    Write-Log "  Collecting Administrators group..."
    "=== ADMINISTRATORS GROUP ===" | Out-File -FilePath $UserInfoFile -Append
    net localgroup Administrators | Out-File -FilePath $UserInfoFile -Append
    "" | Out-File -FilePath $UserInfoFile -Append
    
    # Remote Desktop Users
    Write-Log "  Collecting Remote Desktop Users..."
    "=== REMOTE DESKTOP USERS ===" | Out-File -FilePath $UserInfoFile -Append
    net localgroup "Remote Desktop Users" | Out-File -FilePath $UserInfoFile -Append
    "" | Out-File -FilePath $UserInfoFile -Append
    
    # Account Policies
    Write-Log "  Collecting account policies..."
    "=== ACCOUNT POLICIES ===" | Out-File -FilePath $UserInfoFile -Append
    net accounts | Out-File -FilePath $UserInfoFile -Append
    
    Write-Log "User and Group Enumeration Complete"
}

function Get-NetworkInformation {
    Write-Log "Starting Network Enumeration..."
    
    $NetworkInfoFile = "$OutputDirectory\network_information.txt"
    
    # Network Interfaces
    Write-Log "  Collecting network interfaces..."
    "=== NETWORK INTERFACES ===" | Out-File -FilePath $NetworkInfoFile -Append
    ipconfig /all | Out-File -FilePath $NetworkInfoFile -Append
    "" | Out-File -FilePath $NetworkInfoFile -Append
    
    # Routing Table
    Write-Log "  Collecting routing table..."
    "=== ROUTING TABLE ===" | Out-File -FilePath $NetworkInfoFile -Append
    route print | Out-File -FilePath $NetworkInfoFile -Append
    "" | Out-File -FilePath $NetworkInfoFile -Append
    
    # ARP Cache
    Write-Log "  Collecting ARP cache..."
    "=== ARP CACHE ===" | Out-File -FilePath $NetworkInfoFile -Append
    arp -a | Out-File -FilePath $NetworkInfoFile -Append
    "" | Out-File -FilePath $NetworkInfoFile -Append
    
    # Active Connections
    Write-Log "  Collecting active connections..."
    "=== ACTIVE CONNECTIONS ===" | Out-File -FilePath $NetworkInfoFile -Append
    netstat -ano | Out-File -FilePath $NetworkInfoFile -Append
    "" | Out-File -FilePath $NetworkInfoFile -Append
    
    # DNS Cache
    Write-Log "  Collecting DNS cache..."
    "=== DNS CACHE ===" | Out-File -FilePath $NetworkInfoFile -Append
    ipconfig /displaydns | Out-File -FilePath $NetworkInfoFile -Append
    "" | Out-File -FilePath $NetworkInfoFile -Append
    
    # Hosts File
    Write-Log "  Collecting hosts file..."
    "=== HOSTS FILE ===" | Out-File -FilePath $NetworkInfoFile -Append
    if (Test-Path "$env:SystemRoot\System32\drivers\etc\hosts") {
        Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Out-File -FilePath $NetworkInfoFile -Append
    }
    
    Write-Log "Network Enumeration Complete"
}

function Get-ProcessAndServiceInformation {
    Write-Log "Starting Process and Service Enumeration..."
    
    $ProcessInfoFile = "$OutputDirectory\process_service_information.txt"
    
    # Running Processes
    Write-Log "  Collecting running processes..."
    "=== RUNNING PROCESSES ===" | Out-File -FilePath $ProcessInfoFile -Append
    tasklist /SVC | Out-File -FilePath $ProcessInfoFile -Append
    "" | Out-File -FilePath $ProcessInfoFile -Append
    
    # Services
    Write-Log "  Collecting services..."
    "=== SERVICES ===" | Out-File -FilePath $ProcessInfoFile -Append
    sc query | Out-File -FilePath $ProcessInfoFile -Append
    "" | Out-File -FilePath $ProcessInfoFile -Append
    
    # Running Services
    Write-Log "  Collecting running services..."
    "=== RUNNING SERVICES ===" | Out-File -FilePath $ProcessInfoFile -Append
    net start | Out-File -FilePath $ProcessInfoFile -Append
    
    Write-Log "Process and Service Enumeration Complete"
}

function Get-RegistryInformation {
    Write-Log "Starting Registry Enumeration..."
    
    $RegistryInfoFile = "$OutputDirectory\registry_information.txt"
    
    # Startup Locations
    Write-Log "  Collecting startup registry keys..."
    "=== STARTUP REGISTRY KEYS ===" | Out-File -FilePath $RegistryInfoFile -Append
    
    $RegistryPaths = @(
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    
    foreach ($Path in $RegistryPaths) {
        try {
            $result = reg query $Path 2>$null
            if ($result) {
                "`n=== $Path ===" | Out-File -FilePath $RegistryInfoFile -Append
                $result | Out-File -FilePath $RegistryInfoFile -Append
            }
        } catch {
            Write-Log "  Failed to query registry path: $Path" -Level "WARNING"
        }
    }
    
    # Environment Variables in Registry
    Write-Log "  Collecting environment variables..."
    "`n=== ENVIRONMENT VARIABLES IN REGISTRY ===" | Out-File -FilePath $RegistryInfoFile -Append
    try {
        reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" 2>$null | Out-File -FilePath $RegistryInfoFile -Append
    } catch {
        Write-Log "  Failed to query environment registry" -Level "WARNING"
    }
    
    Write-Log "Registry Enumeration Complete"
}

function Get-FileSystemInformation {
    Write-Log "Starting File System Enumeration..."
    
    $FileSystemInfoFile = "$OutputDirectory\filesystem_information.txt"
    
    # Sensitive Files
    Write-Log "  Checking for sensitive files..."
    "=== SENSITIVE FILES CHECK ===" | Out-File -FilePath $FileSystemInfoFile -Append
    
    $SensitivePaths = @(
        "$env:SystemRoot\System32\config\SAM",
        "$env:SystemRoot\repair\SAM",
        "$env:SystemRoot\System32\drivers\etc\hosts",
        "C:\ProgramData",
        "C:\Users\$CurrentUser\Desktop",
        "C:\Users\$CurrentUser\Documents",
        "C:\Users\$CurrentUser\AppData"
    )
    
    foreach ($Path in $SensitivePaths) {
        if (Test-Path $Path) {
            "`n=== $Path ===" | Out-File -FilePath $FileSystemInfoFile -Append
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $FileSystemInfoFile -Append
        }
    }
    
    # Configuration Files
    Write-Log "  Searching for configuration files..."
    "`n=== CONFIGURATION FILES SEARCH ===" | Out-File -FilePath $FileSystemInfoFile -Append
    
    # Search for common config files in user directories
    $Extensions = @("*.config", "*.xml", "*.ini", "*.conf", "*.txt", "*.log")
    $SearchPaths = @("C:\Users\$CurrentUser", "C:\ProgramData")
    
    foreach ($SearchPath in $SearchPaths) {
        if (Test-Path $SearchPath) {
            foreach ($Extension in $Extensions) {
                try {
                    $files = Get-ChildItem -Path $SearchPath -Filter $Extension -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
                    if ($files) {
                        "`n=== $Extension files in $SearchPath ===" | Out-File -FilePath $FileSystemInfoFile -Append
                        $files | Select-Object FullName, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $FileSystemInfoFile -Append
                    }
                } catch {
                    # Continue on error
                }
            }
        }
    }
    
    Write-Log "File System Enumeration Complete"
}

function Get-ScheduledTasksInformation {
    Write-Log "Starting Scheduled Tasks Enumeration..."
    
    $TasksInfoFile = "$OutputDirectory\scheduled_tasks.txt"
    
    # All Scheduled Tasks
    Write-Log "  Collecting scheduled tasks..."
    "=== SCHEDULED TASKS ===" | Out-File -FilePath $TasksInfoFile -Append
    schtasks /query /fo LIST /v | Out-File -FilePath $TasksInfoFile -Append
    
    Write-Log "Scheduled Tasks Enumeration Complete"
}

function Get-InstalledApplications {
    Write-Log "Starting Installed Applications Enumeration..."
    
    $AppsInfoFile = "$OutputDirectory\installed_applications.txt"
    
    # WMI Product Enumeration
    Write-Log "  Collecting installed applications via WMI..."
    "=== INSTALLED APPLICATIONS (WMI) ===" | Out-File -FilePath $AppsInfoFile -Append
    try {
        Get-WmiObject Win32_Product | Select-Object Name, Version, Vendor, InstallDate | Sort-Object Name | Format-Table -AutoSize | Out-File -FilePath $AppsInfoFile -Append
    } catch {
        Write-Log "  Failed to get WMI product information" -Level "WARNING"
    }
    
    # Program Files Directories
    Write-Log "  Checking Program Files directories..."
    "`n=== PROGRAM FILES DIRECTORIES ===" | Out-File -FilePath $AppsInfoFile -Append
    
    $ProgramPaths = @("C:\Program Files", "C:\Program Files (x86)")
    foreach ($Path in $ProgramPaths) {
        if (Test-Path $Path) {
            "`n=== $Path ===" | Out-File -FilePath $AppsInfoFile -Append
            Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | Select-Object -First 50 Name | Sort-Object Name | Format-Table -AutoSize | Out-File -FilePath $AppsInfoFile -Append
        }
    }
    
    Write-Log "Installed Applications Enumeration Complete"
}

function Get-EnvironmentVariables {
    Write-Log "Starting Environment Variables Enumeration..."
    
    $EnvInfoFile = "$OutputDirectory\environment_variables.txt"
    
    # All Environment Variables
    Write-Log "  Collecting environment variables..."
    "=== ENVIRONMENT VARIABLES ===" | Out-File -FilePath $EnvInfoFile -Append
    Get-ChildItem Env: | Sort-Object Name | Format-Table Name, Value -AutoSize | Out-File -FilePath $EnvInfoFile -Append
    
    # PATH Variable
    Write-Log "  Collecting PATH variable..."
    "`n=== PATH VARIABLE ===" | Out-File -FilePath $EnvInfoFile -Append
    $env:PATH -split ';' | Out-File -FilePath $EnvInfoFile -Append
    
    Write-Log "Environment Variables Enumeration Complete"
}

function Get-HotfixInformation {
    Write-Log "Starting Hotfix Enumeration..."
    
    $HotfixInfoFile = "$OutputDirectory\hotfix_information.txt"
    
    # Installed Hotfixes
    Write-Log "  Collecting installed hotfixes..."
    "=== INSTALLED HOTFIXES ===" | Out-File -FilePath $HotfixInfoFile -Append
    try {
        Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn -AutoSize | Out-File -FilePath $HotfixInfoFile -Append
    } catch {
        Write-Log "  Failed to get hotfix information" -Level "WARNING"
    }
    
    Write-Log "Hotfix Enumeration Complete"
}

function Get-BrowserArtifacts {
    Write-Log "Starting Browser Artifacts Enumeration..."
    
    $BrowserInfoFile = "$OutputDirectory\browser_artifacts.txt"
    
    Write-Log "  Checking browser directories..."
    "=== BROWSER ARTIFACTS ===" | Out-File -FilePath $BrowserInfoFile -Append
    
    # Chrome
    $ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $ChromePath) {
        "`n=== CHROME ARTIFACTS ===" | Out-File -FilePath $BrowserInfoFile -Append
        Get-ChildItem -Path $ChromePath -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $BrowserInfoFile -Append
    }
    
    # Firefox
    $FirefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $FirefoxPath) {
        "`n=== FIREFOX ARTIFACTS ===" | Out-File -FilePath $BrowserInfoFile -Append
        Get-ChildItem -Path $FirefoxPath -Directory -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $BrowserInfoFile -Append
    }
    
    # Credential Manager
    Write-Log "  Checking credential manager..."
    "`n=== CREDENTIAL MANAGER ===" | Out-File -FilePath $BrowserInfoFile -Append
    try {
        cmdkey /list 2>$null | Out-File -FilePath $BrowserInfoFile -Append
    } catch {
        Write-Log "  Failed to list saved credentials" -Level "WARNING"
    }
    
    Write-Log "Browser Artifacts Enumeration Complete"
}

function Get-PowerShellInformation {
    Write-Log "Starting PowerShell Enumeration..."
    
    $PSInfoFile = "$OutputDirectory\powershell_information.txt"
    
    # PowerShell Configuration
    Write-Log "  Collecting PowerShell configuration..."
    "=== POWERSHELL CONFIGURATION ===" | Out-File -FilePath $PSInfoFile -Append
    
    # Execution Policy
    "`n=== EXECUTION POLICY ===" | Out-File -FilePath $PSInfoFile -Append
    Get-ExecutionPolicy -List | Out-File -FilePath $PSInfoFile -Append
    
    # Language Mode
    "`n=== LANGUAGE MODE ===" | Out-File -FilePath $PSInfoFile -Append
    $ExecutionContext.SessionState.LanguageMode | Out-File -FilePath $PSInfoFile -Append
    
    # Installed Modules
    Write-Log "  Collecting installed modules..."
    "`n=== INSTALLED MODULES ===" | Out-File -FilePath $PSInfoFile -Append
    Get-Module -ListAvailable | Select-Object Name, Version | Sort-Object Name | Select-Object -First 50 | Format-Table -AutoSize | Out-File -FilePath $PSInfoFile -Append
    
    # PowerShell History
    Write-Log "  Checking PowerShell history..."
    "`n=== POWERSHELL HISTORY ===" | Out-File -FilePath $PSInfoFile -Append
    $HistoryPath = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path $HistoryPath) {
        "History file location: $HistoryPath" | Out-File -FilePath $PSInfoFile -Append
        "Last 20 commands:" | Out-File -FilePath $PSInfoFile -Append
        Get-Content $HistoryPath -Tail 20 | Out-File -FilePath $PSInfoFile -Append
    }
    
    Write-Log "PowerShell Enumeration Complete"
}

function Get-WMIInformation {
    Write-Log "Starting WMI Enumeration..."
    
    $WMIInfoFile = "$OutputDirectory\wmi_information.txt"
    
    # WMI Namespaces
    Write-Log "  Collecting WMI namespaces..."
    "=== WMI NAMESPACES ===" | Out-File -FilePath $WMIInfoFile -Append
    try {
        Get-WmiObject -Namespace root -Class __Namespace | Select-Object Name | Sort-Object Name | Format-Table -AutoSize | Out-File -FilePath $WMIInfoFile -Append
    } catch {
        Write-Log "  Failed to get WMI namespaces" -Level "WARNING"
    }
    
    # WMI Event Subscriptions
    Write-Log "  Checking for WMI event subscriptions..."
    "`n=== WMI EVENT SUBSCRIPTIONS ===" | Out-File -FilePath $WMIInfoFile -Append
    try {
        Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query | Format-Table -AutoSize | Out-File -FilePath $WMIInfoFile -Append
    } catch {
        Write-Log "  Failed to get WMI event subscriptions" -Level "WARNING"
    }
    
    Write-Log "WMI Enumeration Complete"
}

function Get-CertificateInformation {
    Write-Log "Starting Certificate Store Enumeration..."
    
    $CertInfoFile = "$OutputDirectory\certificate_information.txt"
    
    # Certificate Store
    Write-Log "  Collecting certificate information..."
    "=== CERTIFICATE STORE ===" | Out-File -FilePath $CertInfoFile -Append
    
    try {
        # Personal Certificates
        "`n=== PERSONAL CERTIFICATES (Current User) ===" | Out-File -FilePath $CertInfoFile -Append
        Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotBefore, NotAfter | Format-Table -AutoSize | Out-File -FilePath $CertInfoFile -Append
        
        # Personal Certificates (Local Machine)
        "`n=== PERSONAL CERTIFICATES (Local Machine) ===" | Out-File -FilePath $CertInfoFile -Append
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotBefore, NotAfter | Format-Table -AutoSize | Out-File -FilePath $CertInfoFile -Append
        
        # Root Certificates
        "`n=== ROOT CERTIFICATES (Local Machine) ===" | Out-File -FilePath $CertInfoFile -Append
        Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint | Select-Object -First 20 | Format-Table -AutoSize | Out-File -FilePath $CertInfoFile -Append
    } catch {
        Write-Log "  Failed to get certificate information" -Level "WARNING"
    }
    
    Write-Log "Certificate Store Enumeration Complete"
}

function Get-EventLogs {
    Write-Log "Starting Event Logs Enumeration..."
    
    $EventLogsFile = "$OutputDirectory\event_logs.txt"
    
    # Available Event Logs
    Write-Log "  Collecting event logs information..."
    "=== EVENT LOGS ===" | Out-File -FilePath $EventLogsFile -Append
    
    try {
        # List available logs
        "`n=== AVAILABLE EVENT LOGS ===" | Out-File -FilePath $EventLogsFile -Append
        Get-EventLog -List | Select-Object Log, MaximumKilobytes, Entries | Format-Table -AutoSize | Out-File -FilePath $EventLogsFile -Append
        
        # Recent Security Events
        "`n=== RECENT SECURITY EVENTS (Last 20) ===" | Out-File -FilePath $EventLogsFile -Append
        Get-EventLog -LogName Security -Newest 20 | Select-Object TimeGenerated, EntryType, Source, InstanceID, Message | Format-Table -AutoSize | Out-File -FilePath $EventLogsFile -Append
        
        # Recent System Events
        "`n=== RECENT SYSTEM EVENTS (Last 20) ===" | Out-File -FilePath $EventLogsFile -Append
        Get-EventLog -LogName System -Newest 20 | Select-Object TimeGenerated, EntryType, Source, InstanceID, Message | Format-Table -AutoSize | Out-File -FilePath $EventLogsFile -Append
    } catch {
        Write-Log "  Failed to get event logs" -Level "WARNING"
    }
    
    Write-Log "Event Logs Enumeration Complete"
}

function Get-RDPInformation {
    Write-Log "Starting RDP/Terminal Services Enumeration..."
    
    $RDPInfoFile = "$OutputDirectory\rdp_information.txt"
    
    # RDP Configuration
    Write-Log "  Collecting RDP configuration..."
    "=== RDP/TERMINAL SERVICES CONFIGURATION ===" | Out-File -FilePath $RDPInfoFile -Append
    
    try {
        # Check if RDP is enabled
        $RDPEnabled = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>$null
        if ($RDPEnabled) {
            "RDP Enabled: $RDPEnabled" | Out-File -FilePath $RDPInfoFile -Append
        }
        
        # RDP Port
        $RDPPort = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber 2>$null
        if ($RDPPort) {
            "RDP Port: $RDPPort" | Out-File -FilePath $RDPInfoFile -Append
        }
    } catch {
        Write-Log "  Failed to get RDP configuration" -Level "WARNING"
    }
    
    # Active Sessions
    Write-Log "  Checking active sessions..."
    "`n=== ACTIVE SESSIONS ===" | Out-File -FilePath $RDPInfoFile -Append
    try {
        qwinsta 2>$null | Out-File -FilePath $RDPInfoFile -Append
    } catch {
        query session 2>$null | Out-File -FilePath $RDPInfoFile -Append
    }
    
    Write-Log "RDP/Terminal Services Enumeration Complete"
}

function Get-DomainInformation {
    Write-Log "Starting Domain Enumeration..."
    
    $DomainInfoFile = "$OutputDirectory\domain_information.txt"
    
    # Check if domain joined
    Write-Log "  Checking domain membership..."
    "=== DOMAIN INFORMATION ===" | Out-File -FilePath $DomainInfoFile -Append
    
    $ComputerInfo = Get-WmiObject Win32_ComputerSystem
    if ($ComputerInfo.PartOfDomain) {
        "Computer is domain joined" | Out-File -FilePath $DomainInfoFile -Append
        "Domain: $($ComputerInfo.Domain)" | Out-File -FilePath $DomainInfoFile -Append
        "Workgroup: $($ComputerInfo.Workgroup)" | Out-File -FilePath $DomainInfoFile -Append
        
        # Try to get domain users
        Write-Log "  Attempting to get domain users..."
        "`n=== DOMAIN USERS (if accessible) ===" | Out-File -FilePath $DomainInfoFile -Append
        try {
            net user /domain 2>$null | Out-File -FilePath $DomainInfoFile -Append
        } catch {
            "Unable to enumerate domain users (requires domain credentials)" | Out-File -FilePath $DomainInfoFile -Append
        }
        
        # Try to get domain groups
        Write-Log "  Attempting to get domain groups..."
        "`n=== DOMAIN GROUPS (if accessible) ===" | Out-File -FilePath $DomainInfoFile -Append
        try {
            net group /domain 2>$null | Out-File -FilePath $DomainInfoFile -Append
        } catch {
            "Unable to enumerate domain groups (requires domain credentials)" | Out-File -FilePath $DomainInfoFile -Append
        }
    } else {
        "Computer is NOT domain joined (Workgroup: $($ComputerInfo.Workgroup))" | Out-File -FilePath $DomainInfoFile -Append
    }
    
    Write-Log "Domain Enumeration Complete"
}

function Get-PrivilegeEscalationChecks {
    Write-Log "Starting Privilege Escalation Checks..."
    
    $PrivEscFile = "$OutputDirectory\privilege_escalation_checks.txt"
    
    Write-Log "  Running privilege escalation vulnerability checks..."
    "=== PRIVILEGE ESCALATION CHECKS ===" | Out-File -FilePath $PrivEscFile -Append
    
    # AlwaysInstallElevated
    Write-Log "  Checking AlwaysInstallElevated..."
    "`n=== ALWAYSINSTALLELEVATED ===" | Out-File -FilePath $PrivEscFile -Append
    try {
        $AlwaysInstallUser = reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
        $AlwaysInstallMachine = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
        
        "Current User: $AlwaysInstallUser" | Out-File -FilePath $PrivEscFile -Append
        "Local Machine: $AlwaysInstallMachine" | Out-File -FilePath $PrivEscFile -Append
        
        if ($AlwaysInstallUser -like "*0x1*" -and $AlwaysInstallMachine -like "*0x1*") {
            "VULNERABLE: AlwaysInstallElevated is enabled!" | Out-File -FilePath $PrivEscFile -Append
        } else {
            "NOT VULNERABLE: AlwaysInstallElevated is not fully enabled" | Out-File -FilePath $PrivEscFile -Append
        }
    } catch {
        "Unable to check AlwaysInstallElevated" | Out-File -FilePath $PrivEscFile -Append
    }
    
    # Service Permissions (basic check)
    Write-Log "  Checking service permissions..."
    "`n=== SERVICE PERMISSIONS CHECK ===" | Out-File -FilePath $PrivEscFile -Append
    "Note: This requires accesschk.exe from Sysinternals for detailed checks" | Out-File -FilePath $PrivEscFile -Append
    
    # Check for unquoted service paths
    Write-Log "  Checking for unquoted service paths..."
    "`n=== UNQUOTED SERVICE PATHS ===" | Out-File -FilePath $PrivEscFile -Append
    try {
        $services = Get-WmiObject Win32_Service | Where-Object {
            $_.PathName -notlike '"*"' -and $_.PathName -like "* *" -and $_.PathName -notlike "*C:\Windows\*"
        } | Select-Object Name, DisplayName, PathName, StartMode
        
        if ($services) {
            "POTENTIALLY VULNERABLE SERVICES FOUND:" | Out-File -FilePath $PrivEscFile -Append
            $services | Format-Table -AutoSize | Out-File -FilePath $PrivEscFile -Append
        } else {
            "No obvious unquoted service paths found" | Out-File -FilePath $PrivEscFile -Append
        }
    } catch {
        "Unable to check for unquoted service paths" | Out-File -FilePath $PrivEscFile -Append
    }
    
    # Check current privileges
    Write-Log "  Checking current privileges..."
    "`n=== CURRENT PRIVILEGES ===" | Out-File -FilePath $PrivEscFile -Append
    whoami /priv | Out-File -FilePath $PrivEscFile -Append
    
    Write-Log "Privilege Escalation Checks Complete"
}

function Get-CredentialAccessChecks {
    Write-Log "Starting Credential Access Checks..."
    
    $CredAccessFile = "$OutputDirectory\credential_access_checks.txt"
    
    Write-Log "  Running credential access checks..."
    "=== CREDENTIAL ACCESS CHECKS ===" | Out-File -FilePath $CredAccessFile -Append
    
    # Check for SAM backups
    Write-Log "  Checking for SAM backups..."
    "`n=== SAM BACKUP FILES ===" | Out-File -FilePath $CredAccessFile -Append
    $SAMBackupPaths = @(
        "$env:SystemRoot\System32\config\SAM",
        "$env:SystemRoot\repair\SAM",
        "$env:SystemRoot\System32\config\RegBack\SAM"
    )
    
    foreach ($Path in $SAMBackupPaths) {
        if (Test-Path $Path) {
            "Found: $Path" | Out-File -FilePath $CredAccessFile -Append
        } else {
            "Not found: $Path" | Out-File -FilePath $CredAccessFile -Append
        }
    }
    
    # Check for DPAPI files
    Write-Log "  Checking for DPAPI files..."
    "`n=== DPAPI FILES ===" | Out-File -FilePath $CredAccessFile -Append
    $DPAPIPaths = @(
        "$env:APPDATA\Microsoft\Protect",
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Microsoft\Credentials"
    )
    
    foreach ($Path in $DPAPIPaths) {
        if (Test-Path $Path) {
            "Found: $Path" | Out-File -FilePath $CredAccessFile -Append
            $FileCount = (Get-ChildItem $Path -File -ErrorAction SilentlyContinue).Count
            "  Files in directory: $FileCount" | Out-File -FilePath $CredAccessFile -Append
        }
    }
    
    # Check for saved RDP credentials
    Write-Log "  Checking for saved RDP credentials..."
    "`n=== SAVED RDP CREDENTIALS ===" | Out-File -FilePath $CredAccessFile -Append
    $RDPCredPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
    if (Test-Path $RDPCredPath) {
        "RDP credentials registry path exists" | Out-File -FilePath $CredAccessFile -Append
        Get-ChildItem $RDPCredPath -ErrorAction SilentlyContinue | Select-Object PSChildName | Out-File -FilePath $CredAccessFile -Append
    } else {
        "No saved RDP credentials found" | Out-File -FilePath $CredAccessFile -Append
    }
    
    Write-Log "Credential Access Checks Complete"
}

function Get-SummaryReport {
    Write-Log "Generating Summary Report..."
    
    $SummaryFile = "$OutputDirectory\SUMMARY_REPORT.txt"
    
    "================================================" | Out-File -FilePath $SummaryFile
    "           WINDOWS ENUMERATION SUMMARY           " | Out-File -FilePath $SummaryFile
    "================================================" | Out-File -FilePath $SummaryFile
    "" | Out-File -FilePath $SummaryFile
    "Enumeration Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $SummaryFile
    "" | Out-File -FilePath $SummaryFile
    "=== SYSTEM INFORMATION ===" | Out-File -FilePath $SummaryFile
    "Computer Name: $ComputerName" | Out-File -FilePath $SummaryFile
    "Current User: $CurrentUser" | Out-File -FilePath $SummaryFile
    "Domain/Workgroup: $Domain" | Out-File -FilePath $SummaryFile
    "Operating System: $(Get-WmiObject Win32_OperatingSystem).Caption" | Out-File -FilePath $SummaryFile
    "Architecture: $(Get-WmiObject Win32_OperatingSystem).OSArchitecture" | Out-File -FilePath $SummaryFile
    "" | Out-File -FilePath $SummaryFile
    "=== ENUMERATION FILES GENERATED ===" | Out-File -FilePath $SummaryFile
    "" | Out-File -FilePath $SummaryFile
    
    $Files = Get-ChildItem -Path $OutputDirectory -File | Sort-Object Name
    foreach ($File in $Files) {
        $Size = "{0:N2} KB" -f ($File.Length / 1KB)
        "$($File.Name) - $Size" | Out-File -FilePath $SummaryFile -Append
    }
    
    "" | Out-File -FilePath $SummaryFile
    "Total Files: $($Files.Count)" | Out-File -FilePath $SummaryFile
    "Output Directory: $OutputDirectory" | Out-File -FilePath $SummaryFile
    "" | Out-File -FilePath $SummaryFile
    "================================================" | Out-File -FilePath $SummaryFile
    "       ENUMERATION COMPLETED SUCCESSFULLY       " | Out-File -FilePath $SummaryFile
    "================================================" | Out-File -FilePath $SummaryFile
    
    Write-Log "Summary Report Generated"
}

function Show-Menu {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    COMPLETE WINDOWS ENUMERATION SCRIPT" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Run ALL Enumeration Modules" -ForegroundColor Yellow
    Write-Host "2. Run Specific Module" -ForegroundColor Yellow
    Write-Host "3. Quick Enumeration (Basic Info Only)" -ForegroundColor Yellow
    Write-Host "4. Show Output Directory" -ForegroundColor Yellow
    Write-Host "5. Exit" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
}

function Show-ModuleMenu {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    SELECT ENUMERATION MODULE" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1.  System Information" -ForegroundColor Yellow
    Write-Host "2.  User and Group Information" -ForegroundColor Yellow
    Write-Host "3.  Network Information" -ForegroundColor Yellow
    Write-Host "4.  Process and Service Information" -ForegroundColor Yellow
    Write-Host "5.  Registry Information" -ForegroundColor Yellow
    Write-Host "6.  File System Information" -ForegroundColor Yellow
    Write-Host "7.  Scheduled Tasks" -ForegroundColor Yellow
    Write-Host "8.  Installed Applications" -ForegroundColor Yellow
    Write-Host "9.  Environment Variables" -ForegroundColor Yellow
    Write-Host "10. Hotfix Information" -ForegroundColor Yellow
    Write-Host "11. Browser Artifacts" -ForegroundColor Yellow
    Write-Host "12. PowerShell Information" -ForegroundColor Yellow
    Write-Host "13. WMI Information" -ForegroundColor Yellow
    Write-Host "14. Certificate Information" -ForegroundColor Yellow
    Write-Host "15. Event Logs" -ForegroundColor Yellow
    Write-Host "16. RDP/Terminal Services" -ForegroundColor Yellow
    Write-Host "17. Domain Information" -ForegroundColor Yellow
    Write-Host "18. Privilege Escalation Checks" -ForegroundColor Yellow
    Write-Host "19. Credential Access Checks" -ForegroundColor Yellow
    Write-Host "20. Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
}

# ================================================
# MAIN EXECUTION
# ================================================

function Main {
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "Warning: Not running as Administrator. Some checks may be limited." -ForegroundColor Red
        Write-Host "For full enumeration, run this script as Administrator." -ForegroundColor Yellow
        Write-Host ""
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -notmatch '^[Yy]') {
            exit
        }
    }
    
    # Create output directory
    Create-OutputDirectory
    
    # Main menu loop
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option (1-5)"
        
        switch ($choice) {
            '1' {
                # Run ALL enumeration
                Write-Host "`nStarting Complete Enumeration..." -ForegroundColor Green
                
                Get-SystemInformation
                Get-UserAndGroupInformation
                Get-NetworkInformation
                Get-ProcessAndServiceInformation
                Get-RegistryInformation
                Get-FileSystemInformation
                Get-ScheduledTasksInformation
                Get-InstalledApplications
                Get-EnvironmentVariables
                Get-HotfixInformation
                Get-BrowserArtifacts
                Get-PowerShellInformation
                Get-WMIInformation
                Get-CertificateInformation
                Get-EventLogs
                Get-RDPInformation
                Get-DomainInformation
                Get-PrivilegeEscalationChecks
                Get-CredentialAccessChecks
                Get-SummaryReport
                
                Write-Host "`nComplete Enumeration Finished!" -ForegroundColor Green
                Write-Host "Results saved to: $OutputDirectory" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            
            '2' {
                # Run specific module
                do {
                    Show-ModuleMenu
                    $moduleChoice = Read-Host "`nSelect module (1-20)"
                    
                    switch ($moduleChoice) {
                        '1' { Get-SystemInformation }
                        '2' { Get-UserAndGroupInformation }
                        '3' { Get-NetworkInformation }
                        '4' { Get-ProcessAndServiceInformation }
                        '5' { Get-RegistryInformation }
                        '6' { Get-FileSystemInformation }
                        '7' { Get-ScheduledTasksInformation }
                        '8' { Get-InstalledApplications }
                        '9' { Get-EnvironmentVariables }
                        '10' { Get-HotfixInformation }
                        '11' { Get-BrowserArtifacts }
                        '12' { Get-PowerShellInformation }
                        '13' { Get-WMIInformation }
                        '14' { Get-CertificateInformation }
                        '15' { Get-EventLogs }
                        '16' { Get-RDPInformation }
                        '17' { Get-DomainInformation }
                        '18' { Get-PrivilegeEscalationChecks }
                        '19' { Get-CredentialAccessChecks }
                        '20' { break }
                        default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
                    }
                    
                    if ($moduleChoice -ne '20') {
                        Write-Host "`nModule execution complete!" -ForegroundColor Green
                        Read-Host "Press Enter to continue"
                    }
                    
                } while ($moduleChoice -ne '20')
            }
            
            '3' {
                # Quick enumeration
                Write-Host "`nStarting Quick Enumeration..." -ForegroundColor Green
                
                Get-SystemInformation
                Get-UserAndGroupInformation
                Get-NetworkInformation
                Get-ProcessAndServiceInformation
                Get-SummaryReport
                
                Write-Host "`nQuick Enumeration Finished!" -ForegroundColor Green
                Write-Host "Results saved to: $OutputDirectory" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            
            '4' {
                # Show output directory
                if (Test-Path $OutputDirectory) {
                    Write-Host "`nOutput Directory: $OutputDirectory" -ForegroundColor Green
                    Write-Host "`nFiles in directory:" -ForegroundColor Yellow
                    Get-ChildItem -Path $OutputDirectory -File | Format-Table Name, LastWriteTime, Length -AutoSize
                } else {
                    Write-Host "Output directory does not exist yet." -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            
            '5' {
                # Exit
                Write-Host "`nExiting Windows Enumeration Script..." -ForegroundColor Yellow
                exit
            }
            
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

# ================================================
# SCRIPT EXECUTION
# ================================================

# Banner
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "    COMPLETE WINDOWS ENUMERATION SCRIPT" -ForegroundColor Cyan
Write-Host "    Version 2.0 - OffSec Platform" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "Warning: PowerShell version is below 3.0. Some features may not work." -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host ""
}

# Start main execution
Main
