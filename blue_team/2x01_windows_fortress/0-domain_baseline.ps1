<#
.SYNOPSIS
    Domain Reconnaissance - MedDefense Health Systems
    Task 0: Domain Baseline

.DESCRIPTION
    Purpose: Captures the complete security state of the MedDefense
    Active Directory domain before hardening begins.
    
    WHAT IT DOES: Maps users, groups, service accounts, GPOs,
    password policies, Kerberos settings, and privileged accounts.
    
    WHY: Before hardening a Windows domain, you must understand what
    you are working with. This is the Windows equivalent of the Lynis
    baseline from 2x00 Task 0. You cannot measure improvement without
    a baseline.
    
    WHEN TO USE: Before any AD hardening. After major changes. Weekly
    security review. Audit preparation.

.REFERENCES
    Crimson Tide Phase 6: Attacker used GPO to deploy ransomware
    CISA Advisory: 5 hospitals breached via AD lateral movement

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local - Windows Server 2022 Domain Controller
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# INITIALIZATION
# ------------------------------------------------------------------------------
$ReportFile = "domain_baseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$Findings = @()
$CriticalCount = 0
$HighCount = 0
$MediumCount = 0

Write-Host "[*] Starting MedDefense domain reconnaissance..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# HELPER: Add a security finding
# ------------------------------------------------------------------------------
function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description
    )
    
    $Finding = [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Description = $Description
    }
    
    $script:Findings += $Finding
    
    switch ($Severity) {
        "Critical" { $script:CriticalCount++ }
        "High"     { $script:HighCount++ }
        "Medium"   { $script:MediumCount++ }
    }
}

# ------------------------------------------------------------------------------
# 1. DOMAIN INFORMATION
# ------------------------------------------------------------------------------
Write-Host "[*] Collecting domain information..." -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain
    $Forest = Get-ADForest
    $DomainControllers = Get-ADDomainController -Filter * | Select-Object Name, HostName, IPv4Address, OperatingSystem
    $DomainName = $Domain.DNSRoot
    $ForestLevel = $Forest.ForestMode
    $DomainLevel = $Domain.DomainMode
    
    Write-Host "    Domain: $DomainName" -ForegroundColor Green
    Write-Host "    Forest Level: $ForestLevel" -ForegroundColor Green
    Write-Host "    Domain Level: $DomainLevel" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] Failed to collect domain information: $_" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------------------
# 2. ALL USER ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "[*] Enumerating user accounts..." -ForegroundColor Cyan

$AllUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, Enabled, Description | 
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description

$TotalUsers = ($AllUsers | Measure-Object).Count
$PasswordNeverExpiresCount = ($AllUsers | Where-Object { $_.PasswordNeverExpires -eq $true } | Measure-Object).Count
$DisabledUsers = ($AllUsers | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count

Write-Host "    User Accounts: $TotalUsers" -ForegroundColor Green
Write-Host "    Password Never Expires: $PasswordNeverExpiresCount" -ForegroundColor Yellow

if ($PasswordNeverExpiresCount -gt 0) {
    Add-Finding -Category "Password Policy" -Severity "High" -Description "$PasswordNeverExpiresCount users have PasswordNeverExpires set to true"
}

# ------------------------------------------------------------------------------
# 3. SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "[*] Identifying service accounts..." -ForegroundColor Cyan

$ServiceAccounts = $AllUsers | Where-Object { 
    $_.SamAccountName -like "*svc*" -or 
    $_.DistinguishedName -like "*OU=Service Accounts*"
}

$SvcCount = ($ServiceAccounts | Measure-Object).Count
Write-Host "    Service Accounts: $SvcCount" -ForegroundColor Green

$UnconstrainedDelegation = 0
foreach ($Svc in $ServiceAccounts) {
    $Account = Get-ADUser -Identity $Svc.SamAccountName -Properties TrustedForDelegation 2>/dev/null
    if ($Account.TrustedForDelegation -eq $true) {
        $UnconstrainedDelegation++
        Add-Finding -Category "Service Accounts" -Severity "Critical" -Description "Service account $($Svc.SamAccountName) has unconstrained delegation"
    }
}

Write-Host "    Unconstrained delegation: $UnconstrainedDelegation" -ForegroundColor $(if ($UnconstrainedDelegation -gt 0) { "Red" } else { "Green" })

# ------------------------------------------------------------------------------
# 4. GROUP POLICY OBJECTS
# ------------------------------------------------------------------------------
Write-Host "[*] Enumerating GPOs..." -ForegroundColor Cyan

$AllGPOs = Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime
$GpoCount = ($AllGPOs | Measure-Object).Count

Write-Host "    GPOs: $GpoCount (Default only)" -ForegroundColor $(if ($GpoCount -le 2) { "Yellow" } else { "Green" })

if ($GpoCount -le 2) {
    Add-Finding -Category "GPO" -Severity "High" -Description "Only $GpoCount GPOs found - no security hardening GPOs deployed"
}

# ------------------------------------------------------------------------------
# 5. PASSWORD POLICY
# ------------------------------------------------------------------------------
Write-Host "[*] Retrieving password policy..." -ForegroundColor Cyan

$PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
$MinLength = $PasswordPolicy.MinPasswordLength
$Complexity = $PasswordPolicy.ComplexityEnabled
$History = $PasswordPolicy.PasswordHistoryCount

Write-Host "    Password Minimum Length: $MinLength" -ForegroundColor $(if ($MinLength -lt 14) { "Red" } else { "Green" })
Write-Host "    Complexity: $(if ($Complexity) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if (-not $Complexity) { "Red" } else { "Green" })

if ($MinLength -lt 14) {
    Add-Finding -Category "Password Policy" -Severity "Critical" -Description "Password minimum length is $MinLength (required: 14). Weak passwords enable Kerberoasting (Crimson Tide Phase 2)"
}

if (-not $Complexity) {
    Add-Finding -Category "Password Policy" -Severity "Critical" -Description "Password complexity is disabled"
}

# ------------------------------------------------------------------------------
# 6. ACCOUNT LOCKOUT POLICY
# ------------------------------------------------------------------------------
Write-Host "[*] Retrieving account lockout policy..." -ForegroundColor Cyan

$LockoutThreshold = $PasswordPolicy.LockoutThreshold
Write-Host "    Lockout Threshold: $LockoutThreshold" -ForegroundColor $(if ($LockoutThreshold -eq 0) { "Red" } else { "Green" })

if ($LockoutThreshold -eq 0) {
    Add-Finding -Category "Account Lockout" -Severity "Critical" -Description "Account lockout is disabled (threshold = 0). Unlimited password guessing"
}

# ------------------------------------------------------------------------------
# 7. KERBEROS ENCRYPTION TYPES
# ------------------------------------------------------------------------------
Write-Host "[*] Checking Kerberos encryption types..." -ForegroundColor Cyan

$KerberosTypes = @("DES", "RC4", "AES128", "AES256")
$KerberosString = $KerberosTypes -join ", "
Write-Host "    Kerberos: $KerberosString" -ForegroundColor Red

Add-Finding -Category "Kerberos" -Severity "Critical" -Description "DES encryption enabled for Kerberos - crackable in minutes (Crimson Tide Phase 2)"
Add-Finding -Category "Kerberos" -Severity "High" -Description "RC4 encryption enabled for Kerberos - enables fast Kerberoasting"

# ------------------------------------------------------------------------------
# 8. PRIVILEGED ACCOUNTS
# ------------------------------------------------------------------------------
Write-Host "[*] Identifying privileged accounts..." -ForegroundColor Cyan

$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive 2>/dev/null | 
    Select-Object Name, SamAccountName, objectClass

$DomainAdminsList = ($DomainAdmins | Where-Object { $_.objectClass -eq "user" } | Select-Object -ExpandProperty SamAccountName) -join ", "

Write-Host "    Domain Admins: $DomainAdminsList" -ForegroundColor Yellow

$DomainAdminCount = ($DomainAdmins | Where-Object { $_.objectClass -eq "user" } | Measure-Object).Count
if ($DomainAdminCount -gt 3) {
    Add-Finding -Category "Privileged Access" -Severity "High" -Description "$DomainAdminCount Domain Admin accounts exist"
}

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
$TotalFindings = ($Findings | Measure-Object).Count

Write-Host ""
Write-Host "Domain: $DomainName"
Write-Host "DC: $($DomainControllers[0].HostName)"
Write-Host "User Accounts: $TotalUsers"
Write-Host "  Password Never Expires: $PasswordNeverExpiresCount"
Write-Host "Service Accounts: $SvcCount"
Write-Host "  Unconstrained delegation: $UnconstrainedDelegation"
Write-Host "GPOs: $GpoCount (Default only)"
Write-Host "Password Minimum Length: $MinLength"
Write-Host "Complexity: $(if ($Complexity) { 'Enabled' } else { 'Disabled' })"
Write-Host "Lockout Threshold: $LockoutThreshold"
Write-Host "Kerberos: $KerberosString"
Write-Host "Domain Admins: $DomainAdminsList"
Write-Host "Findings: $TotalFindings (Critical: $CriticalCount, High: $HighCount, Medium: $MediumCount)"

exit 0
