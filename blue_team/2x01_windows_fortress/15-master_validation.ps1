<#
.SYNOPSIS
Master Validation Script - MedDefense Health Systems
Task 15: Weekly Compliance Check

.DESCRIPTION
Purpose: Comprehensive validation script that checks every hardening setting.
WHAT IT DOES: Reads every setting deployed, compares against expected values,
produces a compliance dashboard. Makes no changes to the system.
Exits with code 0 if all critical checks pass, code 1 if any critical check fails.

Author: shamshed rajput
Date: 30/07/2026
Target: DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ------------------------------------------------------------------------------
# GLOBAL VARIABLES
# ------------------------------------------------------------------------------
$Global:PassCount = 0
$Global:FailCount = 0
$Global:WarnCount = 0
$Global:CriticalFail = $false
$Global:Results = @()

# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
function Write-Result {
    param(
        [string]$Status,
        [string]$Message,
        [bool]$Critical = $false
    )
    
    $Color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Message" -ForegroundColor $Color
    
    $Global:Results += @{
        Status = $Status
        Message = $Message
        Critical = $Critical
    }
    
    switch ($Status) {
        "PASS" { $Global:PassCount++ }
        "WARN" { $Global:WarnCount++ }
        "FAIL" { 
            $Global:FailCount++
            if ($Critical) { $Global:CriticalFail = $true }
        }
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue,
        [string]$Description,
        [string]$ValueType = "DWord",
        [bool]$Critical = $false
    )
    
    try {
        $Value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($Value -eq $ExpectedValue) {
            Write-Result -Status "PASS" -Message "$Description: $Value" -Critical $Critical
        } else {
            Write-Result -Status "FAIL" -Message "$Description: Expected $ExpectedValue, got $Value" -Critical $Critical
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$Description: Not found or not configured" -Critical $Critical
    }
}

function Test-GroupMember {
    param(
        [string]$GroupName,
        [string]$ExpectedMember,
        [string]$Description,
        [bool]$Critical = $false
    )
    
    try {
        $Members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
        $MemberNames = $Members | ForEach-Object { $_.Name }
        
        if ($MemberNames -contains $ExpectedMember) {
            Write-Result -Status "PASS" -Message "$Description: $ExpectedMember present" -Critical $Critical
        } else {
            $Current = $MemberNames -join ", "
            Write-Result -Status "FAIL" -Message "$Description: Expected $ExpectedMember, got $Current" -Critical $Critical
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$Description: Group not found" -Critical $Critical
    }
}

# ------------------------------------------------------------------------------
# 1. PASSWORD & LOCKOUT POLICY
# ------------------------------------------------------------------------------
Write-Host "--- Password & Lockout ---" -ForegroundColor Cyan

# Minimum password length
Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "MinimumPasswordLength" -ExpectedValue 14 `
    -Description "Minimum password length" -Critical $true

# Lockout threshold
Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "LockoutBadCount" -ExpectedValue 5 `
    -Description "Lockout threshold" -Critical $true

# Lockout duration
Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "LockoutDuration" -ExpectedValue 30 `
    -Description "Lockout duration (minutes)" -Critical $true

# ------------------------------------------------------------------------------
# 2. AUDIT POLICY
# ------------------------------------------------------------------------------
Write-Host "--- Audit Policy ---" -ForegroundColor Cyan

# Process Creation auditing
try {
    $Audit = auditpol /get /subcategory:"Process Creation" /r 2>$null
    if ($Audit -match "Success") {
        Write-Result -Status "PASS" -Message "Process Creation: Success" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Process Creation: Not configured" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Process Creation: Unable to check" -Critical $true
}

# Command-line logging
Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -ExpectedValue 1 `
    -Description "Command-line logging" -Critical $true

# Security log size
try {
    $LogSize = (Get-WmiObject -Class Win32_NTEventlogFile -Filter "LogFileName='Security'").MaxFileSize
    if ($LogSize -ge 1073741824) { # 1 GB
        Write-Result -Status "PASS" -Message "Security log: 1 GB" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Security log: $([math]::Round($LogSize/1024/1024)) MB" -Critical $true
    }
} catch {
    Write-Result -Status "WARN" -Message "Security log: Unable to check" -Critical $false
}

# ------------------------------------------------------------------------------
# 3. POWERSHELL
# ------------------------------------------------------------------------------
Write-Host "--- PowerShell ---" -ForegroundColor Cyan

# Script Block Logging
Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ExpectedValue 1 `
    -Description "Script Block Logging" -Critical $true

# Transcription
Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -ExpectedValue 1 `
    -Description "Transcription" -Critical $true

# ------------------------------------------------------------------------------
# 4. SYSMON
# ------------------------------------------------------------------------------
Write-Host "--- Sysmon ---" -ForegroundColor Cyan

# Sysmon service running
try {
    $Service = Get-Service -Name "Sysmon" -ErrorAction Stop
    if ($Service.Status -eq "Running") {
        Write-Result -Status "PASS" -Message "Service: Running" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Service: $($Service.Status)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Service: Not installed" -Critical $true
}

# Custom rules present
try {
    $ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
    if (Test-Path $ConfigPath) {
        $Xml = [xml](Get-Content $ConfigPath)
        $Rules = $Xml.Sysmon.EventFiltering.ChildNodes | Where-Object { $_.LocalName -match "ProcessCreate|RegistryEvent|FileCreate" }
        $RuleCount = $Rules.Count
        if ($RuleCount -ge 6) {
            Write-Result -Status "PASS" -Message "Custom rules: $RuleCount present" -Critical $true
        } else {
            Write-Result -Status "FAIL" -Message "Custom rules: $RuleCount present (expected 6+)" -Critical $true
        }
    } else {
        Write-Result -Status "FAIL" -Message "Custom rules: Config file not found" -Critical $true
    }
} catch {
    Write-Result -Status "WARN" -Message "Custom rules: Unable to parse XML" -Critical $false
}

# ------------------------------------------------------------------------------
# 5. KERBEROS
# ------------------------------------------------------------------------------
Write-Host "--- Kerberos ---" -ForegroundColor Cyan

# DES encryption disabled
Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -Name "SupportedEncryptionTypes" -ExpectedValue 2147483640 `
    -Description "DES encryption (disabled)" -Critical $true

# RC4 encryption disabled
try {
    $RC4 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes
    if ($RC4 -band 4) {
        Write-Result -Status "FAIL" -Message "RC4: Enabled (should be disabled)" -Critical $true
    } else {
        Write-Result -Status "PASS" -Message "RC4: Disabled" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "RC4: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 6. SMB
# ------------------------------------------------------------------------------
Write-Host "--- SMB ---" -ForegroundColor Cyan

# SMBv1 disabled
Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" -ExpectedValue 0 `
    -Description "SMBv1 (disabled)" -Critical $true

# SMB signing required
try {
    $Signing = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($Signing -eq 1) {
        Write-Result -Status "PASS" -Message "SMB signing: Required" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "SMB signing: Not required" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "SMB signing: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 7. FIREWALL
# ------------------------------------------------------------------------------
Write-Host "--- Firewall ---" -ForegroundColor Cyan

$AllProfilesBlock = $true
$ProfileNames = @("Domain", "Private", "Public")
foreach ($ProfileName in $ProfileNames) {
    try {
        $Profile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction Stop
        $Status = if ($Profile.Enabled) { "ON" } else { "OFF" }
        $Inbound = $Profile.DefaultInboundAction
        
        if ($Profile.Enabled -eq $true -and $Inbound -eq "Block") {
            Write-Result -Status "PASS" -Message "$ProfileName profile: ON, DefaultInbound: Block" -Critical $true
        } else {
            Write-Result -Status "FAIL" -Message "$ProfileName profile: $Status, DefaultInbound: $Inbound" -Critical $true
            $AllProfilesBlock = $false
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$ProfileName profile: Unable to check" -Critical $true
        $AllProfilesBlock = $false
    }
}

# ------------------------------------------------------------------------------
# 8. RDP
# ------------------------------------------------------------------------------
Write-Host "--- RDP ---" -ForegroundColor Cyan

# NLA required
Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -ExpectedValue 1 `
    -Description "NLA" -Critical $true

# RDP access restricted to G_IT_Admins
Test-GroupMember -GroupName "Remote Desktop Users" `
    -ExpectedMember "G_IT_Admins" `
    -Description "RDP access" -Critical $true

# ------------------------------------------------------------------------------
# 9. SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "--- Service Accounts ---" -ForegroundColor Cyan

# Check service accounts
$ServiceAccounts = @("svc_backup", "svc_monitoring", "svc_deployment")
$DelegationRestricted = 0

foreach ($Account in $ServiceAccounts) {
    try {
        $User = Get-ADUser -Identity $Account -Properties PasswordLastSet, ServicePrincipalName, TrustedForDelegation -ErrorAction SilentlyContinue
        if ($User) {
            # Check if delegation is restricted
            if ($User.TrustedForDelegation -eq $false -and $User.ServicePrincipalName.Count -eq 0) {
                $DelegationRestricted++
            }
            
            # Check password age
            $PasswordAge = (Get-Date) - $User.PasswordLastSet
            $Days = $PasswordAge.Days
            if ($Days -gt 90) {
                Write-Result -Status "WARN" -Message "$Account password age: $Days days" -Critical $false
            } else {
                Write-Result -Status "PASS" -Message "$Account password age: $Days days" -Critical $false
            }
        } else {
            Write-Result -Status "WARN" -Message "$Account: Not found" -Critical $false
        }
    } catch {
        Write-Result -Status "WARN" -Message "$Account: Unable to check (AD module not loaded?)" -Critical $false
    }
}

if ($DelegationRestricted -eq $ServiceAccounts.Count) {
    Write-Result -Status "PASS" -Message "Delegation restricted: $DelegationRestricted/$($ServiceAccounts.Count)" -Critical $true
} else {
    Write-Result -Status "FAIL" -Message "Delegation restricted: $DelegationRestricted/$($ServiceAccounts.Count)" -Critical $true
}

# ------------------------------------------------------------------------------
# 10. FINAL SUMMARY
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Cyan
Write-Host "PASS: $Global:PassCount" -ForegroundColor Green
Write-Host "WARN: $Global:WarnCount" -ForegroundColor Yellow
Write-Host "FAIL: $Global:FailCount" -ForegroundColor Red

if ($Global:CriticalFail) {
    Write-Host ""
    Write-Host "[FAIL] Critical checks failed!" -ForegroundColor Red
    Write-Host "      Please review and remediate critical issues." -ForegroundColor Red
    exit 1
} else {
    Write-Host ""
    Write-Host "[PASS] All critical checks passed!" -ForegroundColor Green
    Write-Host "      System is compliant." -ForegroundColor Green
    exit 0
}
<#
.SYNOPSIS
Master Validation Script - MedDefense Health Systems
Task 15: Weekly Compliance Check

.DESCRIPTION
Purpose: Comprehensive validation script that checks every hardening setting.
WHAT IT DOES: Reads every setting deployed, compares against expected values,
produces a compliance dashboard. Makes no changes to the system.
Exits with code 0 if all critical checks pass, code 1 if any critical check fails.

Author: shamshed rajput
Date: 30/07/2026
Target: DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ------------------------------------------------------------------------------
# GLOBAL VARIABLES
# ------------------------------------------------------------------------------
$Global:PassCount = 0
$Global:FailCount = 0
$Global:WarnCount = 0
$Global:CriticalFail = $false
$Global:Results = @()

# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
function Write-Result {
    param(
        [string]$Status,
        [string]$Message,
        [bool]$Critical = $false
    )
    
    $Color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Message" -ForegroundColor $Color
    
    $Global:Results += @{
        Status = $Status
        Message = $Message
        Critical = $Critical
    }
    
    switch ($Status) {
        "PASS" { $Global:PassCount++ }
        "WARN" { $Global:WarnCount++ }
        "FAIL" { 
            $Global:FailCount++
            if ($Critical) { $Global:CriticalFail = $true }
        }
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue,
        [string]$Description,
        [string]$ValueType = "DWord",
        [bool]$Critical = $false
    )
    
    try {
        $Value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($Value -eq $ExpectedValue) {
            Write-Result -Status "PASS" -Message "$Description: $Value" -Critical $Critical
        } else {
            Write-Result -Status "FAIL" -Message "$Description: Expected $ExpectedValue, got $Value" -Critical $Critical
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$Description: Not found or not configured" -Critical $Critical
    }
}

function Test-GroupMember {
    param(
        [string]$GroupName,
        [string]$ExpectedMember,
        [string]$Description,
        [bool]$Critical = $false
    )
    
    try {
        $Members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
        $MemberNames = $Members | ForEach-Object { $_.Name }
        
        if ($MemberNames -contains $ExpectedMember) {
            Write-Result -Status "PASS" -Message "$Description: $ExpectedMember present" -Critical $Critical
        } else {
            $Current = $MemberNames -join ", "
            Write-Result -Status "FAIL" -Message "$Description: Expected $ExpectedMember, got $Current" -Critical $Critical
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$Description: Group not found" -Critical $Critical
    }
}

# ------------------------------------------------------------------------------
# 1. PASSWORD & LOCKOUT POLICY
# ------------------------------------------------------------------------------
Write-Host "--- Password & Lockout ---" -ForegroundColor Cyan

# Check Minimum password length
try {
    $MinLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "MinimumPasswordLength" -ErrorAction Stop).MinimumPasswordLength
    if ($MinLength -ge 14) {
        Write-Result -Status "PASS" -Message "Minimum length: $MinLength" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Minimum length: $MinLength (expected 14+)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Minimum length: Not configured" -Critical $true
}

# Check Lockout threshold
try {
    $LockoutBad = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "LockoutBadCount" -ErrorAction Stop).LockoutBadCount
    if ($LockoutBad -eq 5) {
        Write-Result -Status "PASS" -Message "Lockout threshold: $LockoutBad" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Lockout threshold: $LockoutBad (expected 5)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Lockout threshold: Not configured" -Critical $true
}

# Check Lockout duration
try {
    $LockoutDuration = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        -Name "LockoutDuration" -ErrorAction Stop).LockoutDuration
    if ($LockoutDuration -eq 30) {
        Write-Result -Status "PASS" -Message "Lockout duration: $LockoutDuration minutes" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Lockout duration: $LockoutDuration (expected 30)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Lockout duration: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 2. AUDIT POLICY
# ------------------------------------------------------------------------------
Write-Host "--- Audit Policy ---" -ForegroundColor Cyan

# Check Process Creation auditing
try {
    $Audit = auditpol /get /subcategory:"Process Creation" /r 2>$null
    if ($Audit -match "Success") {
        Write-Result -Status "PASS" -Message "Process Creation: Success" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Process Creation: Not configured" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Process Creation: Unable to check" -Critical $true
}

# Check Command-line logging
try {
    $CmdLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction Stop).ProcessCreationIncludeCmdLine_Enabled
    if ($CmdLogging -eq 1) {
        Write-Result -Status "PASS" -Message "Command-line logging: Enabled" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Command-line logging: Disabled" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Command-line logging: Not configured" -Critical $true
}

# Check Security log size
try {
    $LogSize = (Get-WmiObject -Class Win32_NTEventlogFile -Filter "LogFileName='Security'").MaxFileSize
    if ($LogSize -ge 1073741824) {
        Write-Result -Status "PASS" -Message "Security log: 1 GB" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Security log: $([math]::Round($LogSize/1024/1024)) MB (expected 1 GB)" -Critical $true
    }
} catch {
    Write-Result -Status "WARN" -Message "Security log: Unable to check" -Critical $false
}

# ------------------------------------------------------------------------------
# 3. POWERSHELL
# ------------------------------------------------------------------------------
Write-Host "--- PowerShell ---" -ForegroundColor Cyan

# Check Script Block Logging
try {
    $ScriptBlock = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -ErrorAction Stop).EnableScriptBlockLogging
    if ($ScriptBlock -eq 1) {
        Write-Result -Status "PASS" -Message "Script Block Logging: Enabled" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Script Block Logging: Disabled" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Script Block Logging: Not configured" -Critical $true
}

# Check Transcription
try {
    $Transcript = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableTranscripting" -ErrorAction Stop).EnableTranscripting
    if ($Transcript -eq 1) {
        Write-Result -Status "PASS" -Message "Transcription: Enabled" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Transcription: Disabled" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Transcription: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 4. SYSMON
# ------------------------------------------------------------------------------
Write-Host "--- Sysmon ---" -ForegroundColor Cyan

# Check Sysmon service
try {
    $Service = Get-Service -Name "Sysmon" -ErrorAction Stop
    if ($Service.Status -eq "Running") {
        Write-Result -Status "PASS" -Message "Service: Running" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Service: $($Service.Status)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Service: Not installed" -Critical $true
}

# Check Custom rules
try {
    $ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
    if (Test-Path $ConfigPath) {
        $Xml = [xml](Get-Content $ConfigPath)
        $Rules = $Xml.Sysmon.EventFiltering.ChildNodes | Where-Object { $_.LocalName -match "ProcessCreate|RegistryEvent|FileCreate" }
        $RuleCount = $Rules.Count
        if ($RuleCount -ge 6) {
            Write-Result -Status "PASS" -Message "Custom rules: $RuleCount present" -Critical $true
        } else {
            Write-Result -Status "FAIL" -Message "Custom rules: $RuleCount present (expected 6+)" -Critical $true
        }
    } else {
        Write-Result -Status "FAIL" -Message "Custom rules: Config file not found" -Critical $true
    }
} catch {
    Write-Result -Status "WARN" -Message "Custom rules: Unable to parse XML" -Critical $false
}

# ------------------------------------------------------------------------------
# 5. KERBEROS
# ------------------------------------------------------------------------------
Write-Host "--- Kerberos ---" -ForegroundColor Cyan

# Check DES encryption disabled
try {
    $EncryptionTypes = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" -ErrorAction Stop).SupportedEncryptionTypes
    if ($EncryptionTypes -eq 2147483640) {
        Write-Result -Status "PASS" -Message "DES: Disabled" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "DES: Enabled (should be disabled)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "DES: Not configured" -Critical $true
}

# Check RC4 encryption disabled
try {
    $RC4 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" -ErrorAction Stop).SupportedEncryptionTypes
    if ($RC4 -band 4) {
        Write-Result -Status "FAIL" -Message "RC4: Enabled (should be disabled)" -Critical $true
    } else {
        Write-Result -Status "PASS" -Message "RC4: Disabled" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "RC4: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 6. SMB
# ------------------------------------------------------------------------------
Write-Host "--- SMB ---" -ForegroundColor Cyan

# Check SMBv1 disabled
try {
    $SMB1 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" -ErrorAction Stop).SMB1
    if ($SMB1 -eq 0) {
        Write-Result -Status "PASS" -Message "SMBv1: Disabled" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "SMBv1: Enabled (should be disabled)" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "SMBv1: Not configured" -Critical $true
}

# Check SMB signing required
try {
    $Signing = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RequireSecuritySignature" -ErrorAction Stop).RequireSecuritySignature
    if ($Signing -eq 1) {
        Write-Result -Status "PASS" -Message "Signing: Required" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "Signing: Not required" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "Signing: Not configured" -Critical $true
}

# ------------------------------------------------------------------------------
# 7. FIREWALL
# ------------------------------------------------------------------------------
Write-Host "--- Firewall ---" -ForegroundColor Cyan

$AllProfilesBlock = $true
$ProfileNames = @("Domain", "Private", "Public")
foreach ($ProfileName in $ProfileNames) {
    try {
        $Profile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction Stop
        $Status = if ($Profile.Enabled) { "ON" } else { "OFF" }
        $Inbound = $Profile.DefaultInboundAction
        
        if ($Profile.Enabled -eq $true -and $Inbound -eq "Block") {
            Write-Result -Status "PASS" -Message "$ProfileName profile: ON, DefaultInbound: Block" -Critical $true
        } else {
            Write-Result -Status "FAIL" -Message "$ProfileName profile: $Status, DefaultInbound: $Inbound" -Critical $true
            $AllProfilesBlock = $false
        }
    } catch {
        Write-Result -Status "FAIL" -Message "$ProfileName profile: Unable to check" -Critical $true
        $AllProfilesBlock = $false
    }
}

# ------------------------------------------------------------------------------
# 8. RDP
# ------------------------------------------------------------------------------
Write-Host "--- RDP ---" -ForegroundColor Cyan

# Check NLA required
try {
    $NLA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -ErrorAction Stop).UserAuthentication
    if ($NLA -eq 1) {
        Write-Result -Status "PASS" -Message "NLA: Required" -Critical $true
    } else {
        Write-Result -Status "FAIL" -Message "NLA: Not required" -Critical $true
    }
} catch {
    Write-Result -Status "FAIL" -Message "NLA: Not configured" -Critical $true
}

# Check RDP access restricted to G_IT_Admins
try {
    $Members = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction Stop
    $MemberNames = $Members | ForEach-Object { $_.Name }
    $HasITAdmins = $MemberNames -contains "G_IT_Admins"
    $HasDomainUsers = $MemberNames -contains "Domain Users"
    
    if ($HasITAdmins -and -not $HasDomainUsers -and $MemberNames.Count -eq 1) {
        Write-Result -Status "PASS" -Message "RDP access: G_IT_Admins only" -Critical $true
    } else {
        if ($HasDomainUsers) {
            Write-Result -Status "FAIL" -Message "RDP access: Domain Users still present" -Critical $true
        } elseif (-not $HasITAdmins) {
            Write-Result -Status "FAIL" -Message "RDP access: G_IT_Admins not present" -Critical $true
        } else {
            Write-Result -Status "FAIL" -Message "RDP access: $($MemberNames.Count) members present" -Critical $true
        }
    }
} catch {
    Write-Result -Status "FAIL" -Message "RDP access: Group not found" -Critical $true
}

# ------------------------------------------------------------------------------
# 9. SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "--- Service Accounts ---" -ForegroundColor Cyan

# Check service accounts
$ServiceAccounts = @("svc_backup", "svc_monitoring", "svc_deployment")
$DelegationRestricted = 0
$AccountChecks = 0

foreach ($Account in $ServiceAccounts) {
    try {
        $User = Get-ADUser -Identity $Account -Properties PasswordLastSet, ServicePrincipalName, TrustedForDelegation -ErrorAction SilentlyContinue
        if ($User) {
            $AccountChecks++
            # Check if delegation is restricted
            if ($User.TrustedForDelegation -eq $false -and $User.ServicePrincipalName.Count -eq 0) {
                $DelegationRestricted++
            }
            
            # Check password age
            $PasswordAge = (Get-Date) - $User.PasswordLastSet
            $Days = $PasswordAge.Days
            if ($Days -gt 90) {
                Write-Result -Status "WARN" -Message "$Account password age: $Days days" -Critical $false
            } else {
                Write-Result -Status "PASS" -Message "$Account password age: $Days days" -Critical $false
            }
        } else {
            Write-Result -Status "WARN" -Message "$Account: Not found" -Critical $false
        }
    } catch {
        Write-Result -Status "WARN" -Message "$Account: Unable to check (AD module not loaded?)" -Critical $false
    }
}

if ($DelegationRestricted -eq $ServiceAccounts.Count -and $AccountChecks -eq $ServiceAccounts.Count) {
    Write-Result -Status "PASS" -Message "Delegation restricted: $DelegationRestricted/$($ServiceAccounts.Count)" -Critical $true
} else {
    Write-Result -Status "FAIL" -Message "Delegation restricted: $DelegationRestricted/$($ServiceAccounts.Count)" -Critical $true
}

# ------------------------------------------------------------------------------
# 10. FINAL SUMMARY
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Cyan
Write-Host "PASS: $Global:PassCount" -ForegroundColor Green
Write-Host "WARN: $Global:WarnCount" -ForegroundColor Yellow
Write-Host "FAIL: $Global:FailCount" -ForegroundColor Red

if ($Global:CriticalFail) {
    Write-Host ""
    Write-Host "[FAIL] Critical checks failed!" -ForegroundColor Red
    Write-Host "      Please review and remediate critical issues." -ForegroundColor Red
    exit 1
} else {
    Write-Host ""
    Write-Host "[PASS] All critical checks passed!" -ForegroundColor Green
    Write-Host "      System is compliant." -ForegroundColor Green
    exit 0
}
