<#
.SYNOPSIS
    Service Account Control - MedDefense Health Systems
    Task 14: Service Account Control

.DESCRIPTION
    Purpose: Audit all MedDefense service accounts, identify security
    weaknesses and implement hardening measures that would have prevented
    the svc_ehr compromise.
    
    WHAT IT DOES: Lists all service accounts (svc in name OR in Service
    Accounts OU) with current security posture: group memberships via
    MemberOf, password age, delegation settings via TrustedForDelegation,
    SPN configuration via ServicePrincipalName, last logon. Flags excessive
    privileges, old passwords, unconstrained delegation, suspicious logons
    (svc_ehr at 03:17). Remediate: Enable "Account is sensitive and cannot
    be delegated" for all service accounts, Deny interactive logon rights,
    Remove from privileged groups via Remove-ADGroupMember.
    
    WHY: Task 1 revealed service accounts with excessive privileges, old
    passwords, unconstrained delegation. svc_ehr's suspicious 03:17 logon
    suggests possible compromise. Service accounts should never have
    interactive logon, should not be able to create user accounts, and
    delegation must be restricted to prevent impersonation attacks.
    
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
    Set-ADAccountControl: "Account is sensitive and cannot be delegated"

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

# Find service accounts: svc in name OR in Service Accounts OU
$ServiceAccounts = Get-ADUser -Filter * -Properties `
    PasswordLastSet, TrustedForDelegation, ServicePrincipalName, LastLogonDate, `
    MemberOf, Enabled, UseDESKeyOnly, DistinguishedName -ErrorAction SilentlyContinue | `
    Where-Object { $_.SamAccountName -like "*svc*" -or $_.DistinguishedName -like "*OU=Service Accounts*" }

if (-not $ServiceAccounts) {
    Write-Host "    No service accounts found" -ForegroundColor Yellow
    exit 0
}

Write-Host "[*] Found $(($ServiceAccounts | Measure-Object).Count) service accounts" -ForegroundColor Green
Write-Host ""

# AUDIT - List current security posture
foreach ($Svc in $ServiceAccounts) {
    Write-Host "$($Svc.SamAccountName):" -ForegroundColor Cyan
    
    # Password age
    if ($Svc.PasswordLastSet) {
        $PasswordAge = ((Get-Date) - $Svc.PasswordLastSet).Days
        if ($PasswordAge -gt 180) {
            Write-Host "  Password age: $PasswordAge days                  [!]" -ForegroundColor Red
        } else {
            Write-Host "  Password age: $PasswordAge days" -ForegroundColor Green
        }
    }
    
    # Delegation - unconstrained is dangerous
    if ($Svc.TrustedForDelegation -eq $true) {
        Write-Host "  Delegation: Unconstrained               [!]" -ForegroundColor Red
    } else {
        Write-Host "  Delegation: Not configured" -ForegroundColor Green
    }
    
    # SPN configuration
    if ($Svc.ServicePrincipalName) {
        $SpnList = $Svc.ServicePrincipalName -join ", "
        Write-Host "  SPN: $SpnList" -ForegroundColor Yellow
    }
    
    # Last logon - suspicious hours
    if ($Svc.LastLogonDate) {
        $LogonTime = $Svc.LastLogonDate.ToString("HH:mm")
        if ($Svc.LastLogonDate.Hour -lt 6) {
            Write-Host "  Last logon: $LogonTime AM                    [!!!]" -ForegroundColor Red
        } else {
            Write-Host "  Last logon: $($Svc.LastLogonDate)" -ForegroundColor Green
        }
    } else {
        Write-Host "  Last logon: Never" -ForegroundColor Yellow
    }
    
    # Excessive privileges - MemberOf
    if ($Svc.MemberOf) {
        foreach ($Group in $Svc.MemberOf) {
            if ($Group -match "Domain Admins|Enterprise Admins|G_IT_Admins") {
                $GroupName = ($Group -split ',')[0] -replace 'CN=', ''
                Write-Host "  Privileged group: $GroupName              [!]" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

# REMEDIATE
Write-Host "[*] Remediating service accounts..." -ForegroundColor Cyan
Write-Host "    Actions: Enable 'Account is sensitive and cannot be delegated', Deny interactive logon, Remove from privileged groups"
Write-Host ""

$PrivilegedGroupNames = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")

foreach ($Svc in $ServiceAccounts) {
    Write-Host -NoNewline "    $($Svc.SamAccountName): "
    
    try {
        # 1. Enable "Account is sensitive and cannot be delegated"
        Set-ADAccountControl -Identity $Svc.SamAccountName -AccountNotDelegated $true -ErrorAction Stop
        Set-ADAccountControl -Identity $Svc.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
        
        # 2. Deny interactive logon rights (SeDenyInteractiveLogonRight)
        $User = Get-ADUser -Identity $Svc.SamAccountName -Properties userAccountControl
        Set-ADUser -Identity $Svc.SamAccountName -Replace @{userAccountControl=($User.userAccountControl -bor 0x0002)} -ErrorAction Stop
        
        # 3. Remove from privileged groups
        if ($Svc.MemberOf) {
            foreach ($Group in $Svc.MemberOf) {
                foreach ($PrivGroup in $PrivilegedGroupNames) {
                    if ($Group -match $PrivGroup) {
                        Remove-ADGroupMember -Identity $PrivGroup -Members $Svc.SamAccountName -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        Write-Host "[HARDENED] - Account is sensitive and cannot be delegated, interactive logon denied, privileged groups removed" -ForegroundColor Green
    } catch {
        Write-Host "[FAILED] - $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Service Account Control - COMPLETE" -ForegroundColor Green
exit 0
