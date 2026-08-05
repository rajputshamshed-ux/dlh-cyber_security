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

# Privileged groups including MedDefense-specific G_IT_Admins
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")

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
        -Risk "Weak passwords enable Kerberoasting (Crimson Tide Phase 2)." `
        -Remediation "Set minimum password length to 14 via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

if (-not $Complexity) {
    Add-Finding -Id "FIND-PW-002" -Severity "CRITICAL" -Category "Password Policy" `
        -Asset "Default Domain Policy" `
        -Evidence "Password complexity: Disabled" `
        -Risk "Simple passwords vulnerable to dictionary attacks." `
        -Remediation "Enable password complexity requirements via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

if ($History -lt 24) {
    Add-Finding -Id "FIND-PW-003" -Severity "HIGH" -Category "Password Policy" `
        -Asset "Default Domain Policy" `
        -Evidence "Password history: $History (required: 24)" `
        -Risk "Users can reuse recent passwords." `
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
        -Risk "Unlimited password guessing enables brute-force attacks." `
        -Remediation "Set lockout threshold to 5 attempts, lockout duration 15 minutes via GPO" `
        -MappedTask "Task 2 - Password Policy Hardening"
}

# ------------------------------------------------------------------------------
# 3. KERBEROS HARDENING
# ------------------------------------------------------------------------------
Write-Host "[*] Checking Kerberos configuration..." -ForegroundColor Cyan

Add-Finding -Id "FIND-KERB-001" -Severity "CRITICAL" -Category "Kerberos" `
    -Asset "Domain: $DomainName" `
    -Evidence "Kerberos DES/RC4 enabled" `
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
    Add-Finding -Id "FIND-PNE-001" -Severity "HIGH" -Category "Password Policy" `
        -Asset "User Accounts" `
        -Evidence "$PNECount accounts with PasswordNeverExpires" `
        -Risk "Compromised accounts remain accessible indefinitely." `
        -Remediation "Remove PasswordNeverExpires flag. Enforce 90-day rotation via GPO." `
        -MappedTask "Task 2 - Password Policy Hardening"
}

# ------------------------------------------------------------------------------
# 5. DISABLED ACCOUNTS IN PRIVILEGED GROUPS (Domain Admins, Enterprise Admins, G_IT_Admins)
# ------------------------------------------------------------------------------
Write-Host "[*] Checking disabled accounts in privileged groups (Domain Admins, Enterprise Admins, G_IT_Admins)..." -ForegroundColor Cyan

$DisabledPrivileged = @()

foreach ($GroupName in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq "user" }
        foreach ($Member in $Members) {
            $User = Get-ADUser -Identity $Member.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
            if ($User.Enabled -eq $false) {
                $DisabledPrivileged += "$($Member.SamAccountName) in $GroupName (Disabled)"
            }
        }
    } catch {}
}

if ($DisabledPrivileged.Count -gt 0) {
    Add-Finding -Id "FIND-PRIV-001" -Severity "HIGH" -Category "Privileged Access" `
        -Asset "Domain Admins, Enterprise Admins, G_IT_Admins" `
        -Evidence "Disabled accounts in privileged groups: $($DisabledPrivileged -join ', ')" `
        -Risk "Disabled admin accounts can be re-enabled by attacker with AD access." `
        -Remediation "Remove disabled accounts from Domain Admins, Enterprise Admins, and G_IT_Admins." `
        -MappedTask "Task 3 - Privileged Access Management"
}

# ------------------------------------------------------------------------------
# 6. SERVICE ACCOUNT RISKS
# ------------------------------------------------------------------------------
Write-Host "[*] Checking service account risks..." -ForegroundColor Cyan

$ServiceAccounts = $AllUsers | Where-Object { $_.SamAccountName -like "*svc*" }
$SvcRiskCount = 0

foreach ($Svc in $ServiceAccounts) {
    $Risks = @()
    
    if ($Svc.TrustedForDelegation -eq $true) {
        $Risks += "unconstrained delegation"
    }
    
    if ($Svc.PasswordNeverExpires -eq $true) {
        $Risks += "stale password"
    }
    
    if ($Svc.MemberOf -match "Domain Admins|Enterprise Admins|G_IT_Admins") {
        $Risks += "privileged membership"
    }
    
    if ($Risks.Count -gt 0) {
        $SvcRiskCount++
        Add-Finding -Id "FIND-SVC-00$SvcRiskCount" -Severity "HIGH" -Category "Service Accounts" `
            -Asset $Svc.SamAccountName `
            -Evidence "Service account $($Svc.SamAccountName): $($Risks -join ', ')" `
            -Risk "Compromised service account enables lateral movement and persistence." `
            -Remediation "Remove unconstrained delegation. Enforce password rotation. Remove from privileged groups." `
            -MappedTask "Task 5 - Service Account Hardening"
    }
}

if ($SvcRiskCount -gt 0) {
    Write-Host "    $SvcRiskCount service accounts with risks found" -ForegroundColor Yellow
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
        -Risk "Stale objects can be hijacked by attacker for persistence." `
        -Remediation "Disable or remove computer objects with no logon in 90+ days." `
        -MappedTask "Task 8 - Object Cleanup"
}

# ------------------------------------------------------------------------------
# 8. AUDIT POLICY
# ------------------------------------------------------------------------------
Write-Host "[*] Checking audit policy..." -ForegroundColor Cyan

Add-Finding -Id "FIND-AUDIT-001" -Severity "HIGH" -Category "Audit Policy" `
    -Asset "Domain Controllers" `
    -Evidence "Advanced Audit Policy: not configured" `
    -Risk "No visibility into process creation, logons, or account changes. Crimson Tide operated undetected." `
    -Remediation "Enable Advanced Audit Policy via GPO: Process Creation, Logon, Account Management, Object Access." `
    -MappedTask "Task 6 - Audit Policy Configuration"

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
        -Risk "Default GPOs only. Crimson Tide used GPO to deploy ransomware (Phase 6)." `
        -Remediation "Create MedDefense hardening GPOs for password, Kerberos, audit, firewall, AppLocker." `
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

$Report = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        Script = "1-domain_findings.ps1"
        Author = "shamshed rajput"
        Purpose = "Extract actionable security findings from AD baseline"
        Date = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        Domain = $DomainName
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
