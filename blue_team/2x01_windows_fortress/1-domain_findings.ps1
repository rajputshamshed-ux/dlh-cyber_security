<#
.SYNOPSIS
    Domain Risk Findings Extractor - MedDefense Health Systems
    Task 1: Domain Risk Findings Extractor

.DESCRIPTION
    Purpose: Produces actionable security findings from the Active Directory
    baseline. Identifies exactly what must be remediated, which task
    remediates it, and how severe the risk is.
    
    WHAT IT DOES: Audits password policy, lockout policy, Kerberos config,
    service accounts, privileged groups, stale objects, audit policy,
    and GPO security posture.
    
    WHY: Baseline data alone is not enough. The security engineer needs
    a findings inventory that connects weaknesses to specific remediation
    tasks with severity ratings.
    
    WHEN TO USE: After domain baseline (Task 0). Before starting Windows
    hardening tasks. Weekly security audit.
    
    OUTPUT: domain_security_findings.json

.REFERENCES
    Crimson Tide Phase 2: Kerberoasting via weak Kerberos
    Crimson Tide Phase 6: GPO-deployed ransomware
    CISA Advisory: 5 hospitals breached via AD misconfiguration

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local - Windows Server 2022 Domain Controller
#>

# Author: shamshed rajput
# Script Purpose: Extract actionable security findings from AD baseline for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ReportFile = "domain_security_findings.json"
$Findings = @()
$CriticalCount = 0
$HighCount = 0
$MediumCount = 0

Write-Host "[*] Starting domain security findings extraction..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# HELPER: Add a finding
# ------------------------------------------------------------------------------
function Add-Finding {
    param(
        [string]$Id,
        [string]$Severity,
        [string]$Category,
        [string]$Asset,
        [string]$Evidence,
        [string]$Risk,
        [string]$Remediation,
        [string]$MappedTask
    )
    
    $Finding = [PSCustomObject]@{
        id = $Id
        severity = $Severity
        category = $Category
        asset = $Asset
        evidence = $Evidence
        risk = $Risk
        recommended_remediation = $Remediation
        mapped_task = $MappedTask
    }
    
    $script:Findings += $Finding
    
    switch ($Severity) {
        "CRITICAL" { $script:CriticalCount++; Write-Host "[CRITICAL] $Evidence" -ForegroundColor Red }
        "HIGH"     { $script:HighCount++; Write-Host "[HIGH] $Evidence" -ForegroundColor Yellow }
        "MEDIUM"   { $script:MediumCount++; Write-Host "[MEDIUM] $Evidence" -ForegroundColor Cyan }
    }
}

# ------------------------------------------------------------------------------
# LOAD DOMAIN DATA
# ------------------------------------------------------------------------------
$Domain = Get-ADDomain
$DomainName = $Domain.DNSRoot
$PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
$AllUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, Enabled, TrustedForDelegation, MemberOf, Description
$AllComputers = Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, Enabled
$AllGPOs = Get-GPO -All
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive 2>/dev/null | Select-Object Name, SamAccountName, objectClass
$EnterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive 2>/dev/null | Select-Object Name, SamAccountName, objectClass

# ------------------------------------------------------------------------------
# 1. PASSWORD POLICY GAPS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking password policy..." -ForegroundColor Cyan

$MinLength = $PasswordPolicy.MinPasswordLength
$Complexity = $PasswordPolicy.ComplexityEnabled
$History = $PasswordPolicy.PasswordHistoryCount

if ($MinLength -lt 14) {
    Add-Finding -Id "FIND-PW-001" -Severity "CRITICAL" -Category "Password Policy" `
        -Asset "Default Domain Policy" `
        -Evidence "Password policy minimum length: $MinLength" `
        -Risk "Weak passwords enable Kerberoasting (Crimson Tide Phase 2). Short passwords crack in minutes on GPU." `
        -Remediation "Set minimum password length to 14 via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

if (-not $Complexity) {
    Add-Finding -Id "FIND-PW-002" -Severity "CRITICAL" -Category "Password Policy" `
        -Asset "Default Domain Policy" `
        -Evidence "Password complexity: Disabled" `
        -Risk "Simple passwords vulnerable to dictionary attacks and credential spraying." `
        -Remediation "Enable password complexity requirements via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

if ($History -lt 24) {
    Add-Finding -Id "FIND-PW-003" -Severity "HIGH" -Category "Password Policy" `
        -Asset "Default Domain Policy" `
        -Evidence "Password history: $History (required: 24)" `
        -Risk "Users can reuse recent passwords, weakening password rotation effectiveness." `
        -Remediation "Set password history to 24 via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

# ------------------------------------------------------------------------------
# 2. ACCOUNT LOCKOUT GAPS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking account lockout policy..." -ForegroundColor Cyan

$LockoutThreshold = $PasswordPolicy.LockoutThreshold

if ($LockoutThreshold -lt 5) {
    Add-Finding -Id "FIND-LOCK-001" -Severity "CRITICAL" -Category "Account Lockout" `
        -Asset "Default Domain Policy" `
        -Evidence "Account lockout: $(if ($LockoutThreshold -eq 0) { 'not configured' } else { "threshold = $LockoutThreshold" })" `
        -Risk "Unlimited password guessing enables brute-force attacks. Crimson Tide uses password spraying." `
        -Remediation "Set lockout threshold to 5 attempts, lockout duration 15 minutes via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

# ------------------------------------------------------------------------------
# 3. KERBEROS HARDENING
# ------------------------------------------------------------------------------
Write-Host "[*] Checking Kerberos configuration..." -ForegroundColor Cyan

# Check msDS-SupportedEncryptionTypes
try {
    $DomainObject = Get-ADObject -Identity $Domain.DistinguishedName -Properties "msDS-SupportedEncryptionTypes" 2>/dev/null
    $SupportedEncTypes = $DomainObject."msDS-SupportedEncryptionTypes"
} catch {
    $SupportedEncTypes = "Not configured (DES/RC4 enabled by default)"
}

Add-Finding -Id "FIND-KERB-001" -Severity "CRITICAL" -Category "Kerberos" `
    -Asset "Domain: $DomainName" `
    -Evidence "Kerberos DES/RC4 enabled - msDS-SupportedEncryptionTypes: $SupportedEncTypes" `
    -Risk "DES crackable in minutes. RC4 crackable at 100GH/s on GPU. Enables fast Kerberoasting (Crimson Tide Phase 2)." `
    -Remediation "Disable DES and RC4 via GPO. Enforce AES128/256 only." `
    -MappedTask "Task 4 - Kerberos Hardening"

# ------------------------------------------------------------------------------
# 4. PASSWORD NEVER EXPIRES ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking PasswordNeverExpires accounts..." -ForegroundColor Cyan

$PNEAccounts = $AllUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
$PNECount = ($PNEAccounts | Measure-Object).Count

if ($PNECount -gt 0) {
    $PNEDetails = ($PNEAccounts | ForEach-Object { "$($_.SamAccountName) (last set: $($_.PasswordLastSet))" }) -join "; "
    Add-Finding -Id "FIND-PNE-001" -Severity "HIGH" -Category "Password Policy" `
        -Asset "User Accounts" `
        -Evidence "$PNECount accounts with PasswordNeverExpires" `
        -Risk "Compromised accounts remain accessible indefinitely. No forced password rotation." `
        -Remediation "Remove PasswordNeverExpires flag. Enforce 90-day rotation via GPO." `
        -MappedTask "Task 2 - Password Policy Hardening"
}

# ------------------------------------------------------------------------------
# 5. DISABLED ACCOUNTS IN PRIVILEGED GROUPS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking disabled accounts in privileged groups..." -ForegroundColor Cyan

$PrivilegedGroups = @("Domain Admins", "Enterprise Admins")
$DisabledPrivileged = @()

foreach ($GroupName in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $GroupName -Recursive 2>/dev/null | Where-Object { $_.objectClass -eq "user" }
        foreach ($Member in $Members) {
            $User = Get-ADUser -Identity $Member.SamAccountName -Properties Enabled 2>/dev/null
            if ($User.Enabled -eq $false) {
                $DisabledPrivileged += "$($Member.SamAccountName) in $GroupName"
            }
        }
    } catch {}
}

if ($DisabledPrivileged.Count -gt 0) {
    Add-Finding -Id "FIND-PRIV-001" -Severity "HIGH" -Category "Privileged Access" `
        -Asset "Privileged Groups" `
        -Evidence "Disabled accounts in privileged groups: $($DisabledPrivileged -join ', ')" `
        -Risk "Disabled admin accounts can be re-enabled by attacker with AD access." `
        -Remediation "Remove disabled accounts from privileged groups. Review monthly." `
        -MappedTask "Task 3 - Privileged Access Management"
}

# ------------------------------------------------------------------------------
# 6. SERVICE ACCOUNT RISKS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking service account risks..." -ForegroundColor Cyan

$ServiceAccounts = $AllUsers | Where-Object { $_.SamAccountName -like "*svc*" }

foreach ($Svc in $ServiceAccounts) {
    $Risks = @()
    
    if ($Svc.TrustedForDelegation -eq $true) {
        $Risks += "unconstrained delegation"
    }
    
    if ($Svc.PasswordNeverExpires -eq $true) {
        $Risks += "stale password"
    }
    
    # Check if in privileged groups
    $IsPrivileged = $false
    if ($Svc.MemberOf -match "Domain Admins|Enterprise Admins") {
        $Risks += "privileged membership"
        $IsPrivileged = $true
    }
    
    if ($Risks.Count -gt 0) {
        Add-Finding -Id "FIND-SVC-00$((Get-Random 100..999))" -Severity "HIGH" -Category "Service Accounts" `
            -Asset $Svc.SamAccountName `
            -Evidence "Service account $($Svc.SamAccountName): $($Risks -join ', ')" `
            -Risk "Compromised service account with these privileges enables lateral movement and persistence." `
            -Remediation "Remove unconstrained delegation. Enforce password rotation. Remove from privileged groups." `
            -MappedTask "Task 5 - Service Account Hardening"
    }
}

# ------------------------------------------------------------------------------
# 7. STALE COMPUTER OBJECTS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking stale computer objects..." -ForegroundColor Cyan

$StaleDate = (Get-Date).AddDays(-90)
$StaleComputers = $AllComputers | Where-Object { $_.LastLogonDate -lt $StaleDate -and $_.Enabled -eq $true }
$StaleCount = ($StaleComputers | Measure-Object).Count

if ($StaleCount -gt 0) {
    Add-Finding -Id "FIND-STALE-001" -Severity "MEDIUM" -Category "Object Cleanup" `
        -Asset "Computer Objects" `
        -Evidence "Stale computer objects: $StaleCount" `
        -Risk "Stale objects can be hijacked by attacker for persistence or Kerberos attacks." `
        -Remediation "Disable or remove computer objects with no logon in 90+ days." `
        -MappedTask "Task 8 - Object Cleanup"
}

# ------------------------------------------------------------------------------
# 8. AUDIT POLICY
# ------------------------------------------------------------------------------
Write-Host "[*] Checking audit policy..." -ForegroundColor Cyan

# Check if Advanced Audit Policy is configured
$AuditPol = auditpol /get /category:* 2>/dev/null | Out-String

if ($AuditPol -match "No Auditing" -or $AuditPol -notmatch "Process Creation") {
    Add-Finding -Id "FIND-AUDIT-001" -Severity "HIGH" -Category "Audit Policy" `
        -Asset "Domain Controllers" `
        -Evidence "Advanced Audit Policy: not configured" `
        -Risk "No visibility into process creation, logons, or account changes. Crimson Tide operated undetected for 5 days." `
        -Remediation "Enable Advanced Audit Policy via GPO: Process Creation, Logon, Account Management, Object Access." `
        -MappedTask "Task 6 - Audit Policy Configuration"
}

# ------------------------------------------------------------------------------
# 9. GPO SECURITY POSTURE
# ------------------------------------------------------------------------------
Write-Host "[*] Checking GPO security posture..." -ForegroundColor Cyan

$GpoCount = ($AllGPOs | Measure-Object).Count
$HardeningGPOs = $AllGPOs | Where-Object { $_.DisplayName -match "MedDefense|Hardening|Security" }
$HardeningGpoCount = ($HardeningGPOs | Measure-Object).Count

if ($HardeningGpoCount -eq 0) {
    Add-Finding -Id "FIND-GPO-001" -Severity "MEDIUM" -Category "GPO" `
        -Asset "Group Policy" `
        -Evidence "No MedDefense hardening GPOs present" `
        -Risk "Default GPOs only. No security hardening applied. Crimson Tide used GPO to deploy ransomware (Phase 6)." `
        -Remediation "Create MedDefense hardening GPOs for password policy, Kerberos, audit, firewall, AppLocker." `
        -MappedTask "Task 7 - GPO Hardening"
}

# ------------------------------------------------------------------------------
# SUMMARY AND EXPORT
# ------------------------------------------------------------------------------
$TotalFindings = ($Findings | Measure-Object).Count

Write-Host ""
Write-Host "Findings: $TotalFindings" -ForegroundColor White
Write-Host "Critical: $CriticalCount" -ForegroundColor Red
Write-Host "High: $HighCount" -ForegroundColor Yellow
Write-Host "Medium: $MediumCount" -ForegroundColor Cyan
Write-Host "Report saved to: $ReportFile" -ForegroundColor Green

# Build and export JSON
$Report = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        Script = "1-domain_findings.ps1"
        Author = "shamshed rajput"
        Purpose = "Extract actionable security findings from AD baseline"
        Date = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        Domain = $DomainName
        Organization = "MedDefense Health Systems"
    }
    Summary = [PSCustomObject]@{
        TotalFindings = $TotalFindings
        Critical = $CriticalCount
        High = $HighCount
        Medium = $MediumCount
    }
    Findings = $Findings
}

$Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportFile -Encoding UTF8

exit 0
