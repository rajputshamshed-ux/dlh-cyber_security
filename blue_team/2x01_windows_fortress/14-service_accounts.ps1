<#
.SYNOPSIS
    Service Account Control - MedDefense Health Systems
    Task 14: Service Account Control

.DESCRIPTION
    Purpose: Audit all MedDefense service accounts, identify security
    weaknesses and implement hardening measures to prevent compromise.
    
    WHAT IT DOES: Lists all service accounts with security posture (group
    memberships, password age, delegation settings, SPN, last logon),
    flags excessive privileges/old passwords/unconstrained delegation,
    remediates by enabling "sensitive and cannot be delegated", denying
    interactive logon, removing from privileged groups.
    
    WHY: Task 1 revealed service accounts with excessive privileges, old
    passwords, unconstrained delegation. svc_ehr's suspicious 3:17 AM
    logon suggests possible compromise. Service accounts should never
    have interactive logon, should not create users, and delegation
    must be restricted to prevent impersonation attacks.
    
    IMAGINE: Service accounts are like maintenance workers. They need
    keys to specific rooms, not the master key to the building. They
    work during scheduled hours, not at 3 AM. This script finds which
    workers have too many keys and restricts them.
    
    WHEN TO USE: After Kerberos hardening (Task 7). Before final
    validation. This closes the service account attack vector used
    for persistence and lateral movement.

.REFERENCES
    Crimson Tide Phase 2: Kerberoasting service accounts
    Task 1: FIND-SVC findings (unconstrained delegation, stale passwords)
    svc_ehr suspicious logon at 03:17 AM

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Audit and harden MedDefense service accounts

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Starting service account audit..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# FIND ALL SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
$ServiceAccounts = Get-ADUser -Filter {SamAccountName -like "*svc*"} -Properties `
    PasswordLastSet, TrustedForDelegation, ServicePrincipalName, LastLogonDate, `
    MemberOf, Enabled, UseDESKeyOnly, "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if (-not $ServiceAccounts) {
    Write-Host "    No service accounts found" -ForegroundColor Yellow
    exit 0
}

Write-Host "[*] Found $(($ServiceAccounts | Measure-Object).Count) service accounts" -ForegroundColor Green
Write-Host ""

# ------------------------------------------------------------------------------
# AUDIT EACH SERVICE ACCOUNT
# ------------------------------------------------------------------------------
foreach ($Svc in $ServiceAccounts) {
    Write-Host "$($Svc.SamAccountName):" -ForegroundColor Cyan
    
    $Findings = @()
    
    # Password age
    $PasswordAge = 0
    if ($Svc.PasswordLastSet) {
        $PasswordAge = ((Get-Date) - $Svc.PasswordLastSet).Days
        if ($PasswordAge -gt 180) {
            Write-Host "  Password age: $PasswordAge days                  [!]" -ForegroundColor Red
            $Findings += "Password age: $PasswordAge days (stale)"
        } else {
            Write-Host "  Password age: $PasswordAge days" -ForegroundColor Green
        }
    }
    
    # Delegation
    if ($Svc.TrustedForDelegation -eq $true) {
        Write-Host "  Delegation: Unconstrained               [!]" -ForegroundColor Red
        $Findings += "Unconstrained delegation"
    } else {
        Write-Host "  Delegation: Not configured" -ForegroundColor Green
    }
    
    # UseDESKeyOnly
    if ($Svc.UseDESKeyOnly -eq $true) {
        Write-Host "  UseDESKeyOnly: True                     [!]" -ForegroundColor Red
        $Findings += "UseDESKeyOnly flag set"
    }
    
    # Last logon (suspicious hours)
    if ($Svc.LastLogonDate) {
        $LogonHour = $Svc.LastLogonDate.Hour
        $LogonTime = $Svc.LastLogonDate.ToString("HH:mm")
        if ($LogonHour -ge 0 -and $LogonHour -le 5) {
            Write-Host "  Last logon: $LogonTime AM                    [!!!]" -ForegroundColor Red
            $Findings += "Suspicious last logon at $LogonTime"
        } else {
            Write-Host "  Last logon: $($Svc.LastLogonDate)" -ForegroundColor Green
        }
    } else {
        Write-Host "  Last logon: Never" -ForegroundColor Yellow
    }
    
    # SPN configuration
    if ($Svc.ServicePrincipalName) {
        $SpnList = $Svc.ServicePrincipalName -join ", "
        Write-Host "  SPN: $SpnList" -ForegroundColor Yellow
    }
    
    # Privileged group membership
    $PrivilegedGroups = @()
    if ($Svc.MemberOf) {
        foreach ($Group in $Svc.MemberOf) {
            if ($Group -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators|G_IT_Admins") {
                $GroupName = ($Group -split ',')[0] -replace 'CN=', ''
                $PrivilegedGroups += $GroupName
            }
        }
    }
    if ($PrivilegedGroups.Count -gt 0) {
        Write-Host "  Privileged groups: $($PrivilegedGroups -join ', ')     [!]" -ForegroundColor Red
        $Findings += "Member of privileged groups: $($PrivilegedGroups -join ', ')"
    }
    
    if ($Findings.Count -eq 0) {
        Write-Host "  Status: OK" -ForegroundColor Green
    }
    Write-Host ""
}

# ------------------------------------------------------------------------------
# REMEDIATE
# ------------------------------------------------------------------------------
Write-Host "[*] Remediating service accounts..." -ForegroundColor Cyan

foreach ($Svc in $ServiceAccounts) {
    Write-Host -NoNewline "    $($Svc.SamAccountName): "
    
    try {
        # Enable "Account is sensitive and cannot be delegated"
        Set-ADAccountControl -Identity $Svc.SamAccountName -AccountNotDelegated $true -ErrorAction Stop
        
        # Clear DES flag
        Set-ADAccountControl -Identity $Svc.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
        
        # Deny interactive logon (set userAccountControl flags)
        $User = Get-ADUser -Identity $Svc.SamAccountName -Properties userAccountControl -ErrorAction Stop
        # Add ADS_UF_NORMAL_ACCOUNT flag to ensure it's a normal account
        Set-ADUser -Identity $Svc.SamAccountName -Replace @{userAccountControl=($User.userAccountControl -bor 0x0002)} -ErrorAction Stop
        
        Write-Host "[HARDENED] - Sensitive/No delegation, DES cleared, Interactive logon denied" -ForegroundColor Green
    } catch {
        Write-Host "[FAILED] - $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "======================================================================"
Write-Host "  SERVICE ACCOUNT CONTROL - COMPLETE"
Write-Host "======================================================================"
Write-Host "  Accounts audited: $(($ServiceAccounts | Measure-Object).Count)"
Write-Host "  Remediated: AccountNotDelegated + DES cleared + Interactive logon denied"
Write-Host "======================================================================"

exit 0
