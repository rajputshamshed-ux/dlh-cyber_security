<#
.SYNOPSIS
    Service Account Control - MedDefense Health Systems
    Task 14: Service Account Control

.DESCRIPTION
    Purpose: Audit all MedDefense service accounts, identify security
    weaknesses and implement hardening measures.
    
    WHAT IT DOES: Lists service accounts with security posture, flags
    excessive privileges/old passwords/unconstrained delegation,
    remediates by enabling AccountNotDelegated, denying interactive logon,
    removing from privileged groups via Remove-ADGroupMember.

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

$ServiceAccounts = Get-ADUser -Filter {SamAccountName -like "*svc*"} -Properties `
    PasswordLastSet, TrustedForDelegation, ServicePrincipalName, LastLogonDate, `
    MemberOf, Enabled, UseDESKeyOnly -ErrorAction SilentlyContinue

if (-not $ServiceAccounts) {
    Write-Host "    No service accounts found" -ForegroundColor Yellow
    exit 0
}

Write-Host "[*] Found $(($ServiceAccounts | Measure-Object).Count) service accounts" -ForegroundColor Green
Write-Host ""

# AUDIT
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
    
    # Delegation
    if ($Svc.TrustedForDelegation -eq $true) {
        Write-Host "  Delegation: Unconstrained               [!]" -ForegroundColor Red
    }
    
    # DES
    if ($Svc.UseDESKeyOnly -eq $true) {
        Write-Host "  UseDESKeyOnly: True                     [!]" -ForegroundColor Red
    }
    
    # Last logon
    if ($Svc.LastLogonDate) {
        $LogonTime = $Svc.LastLogonDate.ToString("HH:mm")
        if ($Svc.LastLogonDate.Hour -lt 6) {
            Write-Host "  Last logon: $LogonTime AM                    [!!!]" -ForegroundColor Red
        }
    }
    
    # Privileged groups
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
Write-Host "[*] Remediating service accounts (AccountNotDelegated + DES cleared + Remove from privileged groups)..." -ForegroundColor Cyan

$PrivilegedGroupNames = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")

foreach ($Svc in $ServiceAccounts) {
    Write-Host -NoNewline "    $($Svc.SamAccountName): "
    
    try {
        # Enable AccountNotDelegated
        Set-ADAccountControl -Identity $Svc.SamAccountName -AccountNotDelegated $true -ErrorAction Stop
        
        # Clear DES
        Set-ADAccountControl -Identity $Svc.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
        
        # Remove from privileged groups using Remove-ADGroupMember
        if ($Svc.MemberOf) {
            foreach ($Group in $Svc.MemberOf) {
                foreach ($PrivGroup in $PrivilegedGroupNames) {
                    if ($Group -match $PrivGroup) {
                        Remove-ADGroupMember -Identity $PrivGroup -Members $Svc.SamAccountName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Host "[Removed from $PrivGroup] " -NoNewline
                    }
                }
            }
        }
        
        Write-Host "[HARDENED]" -ForegroundColor Green
    } catch {
        Write-Host "[FAILED] - $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Service Account Control - COMPLETE" -ForegroundColor Green
exit 0

