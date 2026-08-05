<#
.SYNOPSIS
    Windows Telemetry Reference Builder - MedDefense Health Systems
    Task 3: Windows Telemetry Reference Builder

.DESCRIPTION
    Purpose: Build a machine-readable Windows event reference that connects
    security events to MedDefense detection use cases.
    
    WHAT IT DOES: Generates windows_event_reference.json mapping 17 Event IDs
    (9 Security, 2 PowerShell, 6 Sysmon) to audit dependency, detection
    meaning, Crimson Tide phase, triage priority, and validation method.
    
    WHY: This is the bridge between audit policy configuration, Sysmon
    deployment, PowerShell logging, and Module 3 SOC detection work.
    Without this reference, analysts don't know what each Event ID means
    or how to respond to it.
    
    WHEN TO USE: Before deploying audit policy (Task 6). Before Sysmon
    deployment (Task 10). SOC analyst training. SIEM rule creation.

.REFERENCES
    Crimson Tide Phases 1-7
    CISA Advisory: 5 hospitals breached
    Microsoft Advanced Audit Policy Documentation
    Sysinternals Sysmon Documentation

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local - Windows Server 2022 Domain Controller
#>

# Author: shamshed rajput
# Script Purpose: Build Windows event telemetry reference for MedDefense SOC

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ReportFile = "windows_event_reference.json"

Write-Host "[*] Building Windows telemetry reference..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# ALL EVENTS
# ------------------------------------------------------------------------------
$Events = @(
    # SECURITY LOG (9 events)
    [PSCustomObject]@{
        event_id = 4624
        event_name = "Successful Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon (Success)"
        security_meaning = "A user or computer successfully authenticated to the domain"
        normal_frequency = "High - hundreds per hour"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 2 (Credential Access), Phase 4 (Lateral Movement)"
        example_suspicious_pattern = "Multiple 4624 events from same source IP to different destination hosts within minutes (lateral movement)"
        validation_method = "Check LogonType field: 2=Console, 3=Network, 10=RemoteInteractive. Network logons from non-domain systems are suspicious."
    }
    [PSCustomObject]@{
        event_id = 4625
        event_name = "Failed Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon (Failure)"
        security_meaning = "A user or computer failed to authenticate"
        normal_frequency = "Low - few per day"
        triage_priority = "High"
        crimson_tide_phase = "Phase 2 (Credential Brute Force), Phase 3 (Password Spraying)"
        example_suspicious_pattern = "Dozens of 4625 events for same account from different workstations (password spraying attack)"
        validation_method = "Check FailureReason field and count per account per hour. >5 failures in 15 minutes for same account = investigate."
    }
    [PSCustomObject]@{
        event_id = 4648
        event_name = "Explicit Credential Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon"
        security_meaning = "A process logged on using explicit credentials (runas, PSExec, scheduled task)"
        normal_frequency = "Low - few per day"
        triage_priority = "High"
        crimson_tide_phase = "Phase 2 (Credential Theft), Phase 4 (Lateral Movement with stolen credentials)"
        example_suspicious_pattern = "4648 from svchost.exe or unknown process using Domain Admin credentials on a workstation"
        validation_method = "Check ProcessName field. If process is not lsass.exe or winlogon.exe and uses privileged account = suspicious."
    }
    [PSCustomObject]@{
        event_id = 4672
        event_name = "Special Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Special Logon"
        security_meaning = "An account with administrator privileges logged on"
        normal_frequency = "Low - admins logging in for maintenance"
        triage_priority = "High"
        crimson_tide_phase = "Phase 3 (Privilege Escalation), Phase 4 (Lateral Movement with admin rights)"
        example_suspicious_pattern = "4672 for service account (svc_*) that should never have interactive admin sessions"
        validation_method = "Check if the account is a service account. Service accounts should NEVER generate 4672 events."
    }
    [PSCustomObject]@{
        event_id = 4688
        event_name = "Process Creation"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Process Creation (Process Tracking)"
        security_meaning = "A new process was created on the system"
        normal_frequency = "High - hundreds per minute"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 3 (Tool Execution), Phase 5 (Defense Evasion), Phase 7 (Ransomware Execution)"
        example_suspicious_pattern = "4688 showing cmd.exe spawning from w3wp.exe (IIS worker) or powershell.exe -enc (encoded command)"
        validation_method = "Check ParentProcessName field. Unexpected parent-child relationships = suspicious. powershell.exe parent of cmd.exe = common attacker pattern."
    }
    [PSCustomObject]@{
        event_id = 4720
        event_name = "Account Created"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Account Management"
        security_meaning = "A new user account was created in Active Directory"
        normal_frequency = "Very Low - only during onboarding"
        triage_priority = "Critical"
        crimson_tide_phase = "Phase 2 (Persistence), Phase 5 (Backdoor Account Creation)"
        example_suspicious_pattern = "4720 for account named 'helpdesk' or 'support' created outside business hours by unexpected admin"
        validation_method = "Check InitiatingUser field. If account creator is not HR or IT admin and outside 8am-6pm = investigate immediately."
    }
    [PSCustomObject]@{
        event_id = 4726
        event_name = "Account Deleted"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Account Management"
        security_meaning = "A user account was deleted from Active Directory"
        normal_frequency = "Very Low - only during offboarding"
        triage_priority = "Critical"
        crimson_tide_phase = "Phase 5 (Covering Tracks), Phase 7 (Destruction before ransomware)"
        example_suspicious_pattern = "4726 for multiple accounts deleted in rapid succession before ransomware execution"
        validation_method = "Check if deleted accounts were privileged. Multiple deletions in <1 minute = active attack in progress."
    }
    [PSCustomObject]@{
        event_id = 4732
        event_name = "Member Added to Group"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Account Management"
        security_meaning = "A user was added to a security group"
        normal_frequency = "Low - permission changes"
        triage_priority = "Critical"
        crimson_tide_phase = "Phase 2 (Privilege Escalation), Phase 5 (Adding backdoor to Domain Admins)"
        example_suspicious_pattern = "4732 showing user added to Domain Admins group by unexpected admin account"
        validation_method = "Check TargetGroupName. If group is Domain Admins, Enterprise Admins, or Schema Admins = immediate investigation."
    }
    [PSCustomObject]@{
        event_id = 1102
        event_name = "Audit Log Cleared"
        log_source = "Security"
        audit_or_sensor_dependency = "System Integrity (built-in)"
        security_meaning = "The Security event log was cleared"
        normal_frequency = "Almost Never - only during maintenance"
        triage_priority = "Critical"
        crimson_tide_phase = "Phase 5 (Defense Evasion - clearing forensic evidence)"
        example_suspicious_pattern = "1102 event outside scheduled maintenance window. No corresponding change ticket."
        validation_method = "Check timestamp. If not during approved maintenance window (Sunday 02:00-04:00) = incident. Immediate response required."
    }
    # POWERSHELL LOG (2 events)
    [PSCustomObject]@{
        event_id = 4103
        event_name = "PowerShell Pipeline Execution"
        log_source = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Script Block Logging (via GPO)"
        security_meaning = "PowerShell executed a pipeline (command or script block)"
        normal_frequency = "Medium - admin scripts, automation"
        triage_priority = "High"
        crimson_tide_phase = "Phase 3 (PowerShell exploitation), Phase 5 (Defense evasion scripts), Phase 6 (Data exfiltration scripts)"
        example_suspicious_pattern = "4103 containing 'Invoke-Mimikatz', 'Invoke-Kerberoast', 'DownloadString', or '-enc' (encoded command)"
        validation_method = "Search for known offensive PowerShell keywords: Mimikatz, Kerberoast, WebClient.DownloadString, -enc, FromBase64String"
    }
    [PSCustomObject]@{
        event_id = 4104
        event_name = "PowerShell Script Block Logging"
        log_source = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Script Block Logging (via GPO)"
        security_meaning = "PowerShell executed a script block (full code captured)"
        normal_frequency = "Medium - admin scripts"
        triage_priority = "High"
        crimson_tide_phase = "Phase 3 (PowerShell tools), Phase 5 (Defense evasion), Phase 7 (Ransomware deployment via PS)"
        example_suspicious_pattern = "4104 with ScriptBlockText containing obfuscated code, Base64 strings, or lateral movement commands"
        validation_method = "Check ScriptBlockText length. Obfuscated scripts often have very long lines. Decode Base64 strings found in the output."
    }
    # SYSMON LOG (6 events)
    [PSCustomObject]@{
        event_id = 1
        event_name = "Sysmon Process Creation"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A process was created (richer than 4688: includes hashes, parent info, command line, user)"
        normal_frequency = "High - hundreds per minute"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 3 (Malware execution), Phase 7 (Ransomware)"
        example_suspicious_pattern = "Sysmon EID 1 showing cmd.exe with parent process msbuild.exe or wscript.exe (living-off-the-land)"
        validation_method = "Check Hashes field against VirusTotal. Check ParentImage for unexpected process trees."
    }
    [PSCustomObject]@{
        event_id = 3
        event_name = "Sysmon Network Connection"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A process initiated a TCP/UDP network connection"
        normal_frequency = "High - hundreds per minute"
        triage_priority = "High"
        crimson_tide_phase = "Phase 4 (Lateral Movement), Phase 6 (C2 Communication), Phase 7 (Ransomware spread via SMB)"
        example_suspicious_pattern = "Sysmon EID 3 from sqlservr.exe or www-data connecting to external IP on port 445 (SMB) or 3389 (RDP)"
        validation_method = "Check DestinationIp against threat intelligence feeds. Internal processes connecting to external IPs on administrative ports = suspicious."
    }
    [PSCustomObject]@{
        event_id = 7
        event_name = "Sysmon Image Load"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A DLL was loaded by a process"
        normal_frequency = "Very High - thousands per minute"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 3 (DLL injection), Phase 5 (Security tool tampering)"
        example_suspicious_pattern = "Sysmon EID 7 showing unsigned DLL loaded by lsass.exe (credential dumping via DLL injection)"
        validation_method = "Check Signed field. Unsigned DLLs loaded by critical system processes (lsass.exe, winlogon.exe) = investigate."
    }
    [PSCustomObject]@{
        event_id = 11
        event_name = "Sysmon File Create"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A file was created or overwritten"
        normal_frequency = "High - hundreds per minute"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 3 (Dropping tools), Phase 7 (Ransomware file creation)"
        example_suspicious_pattern = "Sysmon EID 11 showing .exe or .dll created in C:\Windows\Temp\ or %APPDATA% by a non-installer process"
        validation_method = "Check TargetFilename extension and path. Executables in temp directories from unexpected processes = suspicious."
    }
    [PSCustomObject]@{
        event_id = 13
        event_name = "Sysmon Registry Event"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A registry key was created, modified, or deleted"
        normal_frequency = "Medium - hundreds per hour"
        triage_priority = "High"
        crimson_tide_phase = "Phase 2 (Persistence via Run keys), Phase 5 (Disabling security tools via registry)"
        example_suspicious_pattern = "Sysmon EID 13 showing modification to HKLM\...\Run or HKLM\...\Winlogon\Shell (persistence mechanism)"
        validation_method = "Check TargetObject path. Run keys, Winlogon, and services registry paths modified by unexpected processes = persistence attempt."
    }
    [PSCustomObject]@{
        event_id = 22
        event_name = "Sysmon DNS Query"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon driver + config (Task 10)"
        security_meaning = "A process performed a DNS query"
        normal_frequency = "Very High - thousands per minute"
        triage_priority = "Medium"
        crimson_tide_phase = "Phase 6 (C2 communication via DNS), Phase 7 (Ransomware beaconing)"
        example_suspicious_pattern = "Sysmon EID 22 showing DNS queries to newly registered domains or domains with random-looking names (DGA)"
        validation_method = "Check QueryName against threat intelligence. High entropy domain names or queries to .xyz, .top TLDs from system processes = suspicious."
    }
)

# ------------------------------------------------------------------------------
# COUNTS
# ------------------------------------------------------------------------------
$SecurityCount = ($Events | Where-Object { $_.log_source -eq "Security" } | Measure-Object).Count
$PowerShellCount = ($Events | Where-Object { $_.log_source -like "*PowerShell*" } | Measure-Object).Count
$SysmonCount = ($Events | Where-Object { $_.log_source -like "*Sysmon*" } | Measure-Object).Count
$TotalEvents = ($Events | Measure-Object).Count

# ------------------------------------------------------------------------------
# BUILD AND EXPORT JSON
# ------------------------------------------------------------------------------
$Reference = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        Script = "3-telemetry_reference.ps1"
        Author = "shamshed rajput"
        Purpose = "Build Windows event telemetry reference for MedDefense SOC"
        Date = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        Organization = "MedDefense Health Systems"
    }
    Summary = [PSCustomObject]@{
        TotalEvents = $TotalEvents
        SecurityEvents = $SecurityCount
        PowerShellEvents = $PowerShellCount
        SysmonEvents = $SysmonCount
    }
    Events = $Events
}

$Reference | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportFile -Encoding UTF8

# ------------------------------------------------------------------------------
# PRINT SUMMARY
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "Security events mapped: $SecurityCount" -ForegroundColor Green
Write-Host "PowerShell events mapped: $PowerShellCount" -ForegroundColor Green
Write-Host "Sysmon events mapped: $SysmonCount" -ForegroundColor Green
Write-Host "Total events documented: $TotalEvents" -ForegroundColor Cyan
Write-Host "Reference saved to: $ReportFile" -ForegroundColor Green

exit 0
