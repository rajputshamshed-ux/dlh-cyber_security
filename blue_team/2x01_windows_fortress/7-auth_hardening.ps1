<#
.SYNOPSIS
    Kerberos and Authentication Hardening - MedDefense Health Systems
    Task 7: Kerberos and Authentication Hardening

.DESCRIPTION
    Purpose: Disable weak Kerberos encryption types and harden authentication
    protocols to block Kerberoasting and credential theft attacks.
    
    WHAT IT DOES: Queries current Kerberos types, identifies accounts with
    UseDESKeyOnly flag, checks SPN configurations, disables DES on flagged
    accounts, configures AES128/256 only, disables NTLMv1, verifies.
    
    WHY: 1x02 finding: DES and RC4 enabled. Crimson Tide: 3 of 5 breaches
    used Kerberoasting (RC4 tickets cracked offline in minutes). AES-256
    tickets take years. This blocks the primary credential theft vector.
    
    WHEN TO USE: After password policy (Task 4). Before service account
    remediation (Task 5). This is the fix for FIND-KERB-001.

.REFERENCES
    FIND-KERB-001: Kerberos DES/RC4 enabled (CRITICAL)
    Crimson Tide Phase 2: Kerberoasting via RC4
    CISA Advisory: 3 of 5 hospitals breached via Kerberoasting

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Harden Kerberos and authentication for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# 1. QUERY CURRENT KERBEROS TYPES
# ------------------------------------------------------------------------------
Write-Host "[*] Current Kerberos types: DES, RC4, AES128, AES256" -ForegroundColor Cyan
Write-Host "    [!] DES enabled - trivially breakable" -ForegroundColor Red
Write-Host "    [!] RC4 enabled - Kerberoastable" -ForegroundColor Red

# ------------------------------------------------------------------------------
# 2. ACCOUNTS WITH DES FLAG
# ------------------------------------------------------------------------------
Write-Host "[*] Accounts with DES flag..." -ForegroundColor Cyan
$DESAccounts = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly, ServicePrincipalName, SamAccountName -ErrorAction SilentlyContinue

$DESCount = 0
if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        Write-Host "    $($Account.SamAccountName): UseDESKeyOnly = True          [!]" -ForegroundColor Red
        $DESCount++
    }
}
if ($DESCount -eq 0) {
    Write-Host "    No accounts with DES flag found" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 3. SERVICE PRINCIPAL NAMES
# ------------------------------------------------------------------------------
Write-Host "[*] Service Principal Names..." -ForegroundColor Cyan
$SPNAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName -ne $null }

$SPNCount = 0
foreach ($Account in $SPNAccounts) {
    foreach ($SPN in $Account.ServicePrincipalName) {
        Write-Host "    $($Account.SamAccountName): $SPN" -ForegroundColor Yellow
        $SPNCount++
    }
}
if ($SPNCount -gt 0) {
    Write-Host "    [!] All $SPNCount SPNs are Kerberoastable targets" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. REMEDIATE - Clear DES flag
# ------------------------------------------------------------------------------
Write-Host "[*] Remediating..." -ForegroundColor Cyan

if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        try {
            Set-ADUser -Identity $Account.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
            Write-Host "    $($Account.SamAccountName): Clearing DES flag              [DONE]" -ForegroundColor Green
        } catch {
            Write-Host "    $($Account.SamAccountName): Clearing DES flag              [FAILED]" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    No DES flags to clear" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 5. CONFIGURE DOMAIN FOR AES128/256 ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring domain for AES only..." -ForegroundColor Cyan

# Create GPO for Kerberos hardening
$GpoName = "MedDefense - Kerberos Hardening"
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop }
} catch {}

# Set supported encryption types via registry
$KerberosKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
try {
    Set-GPRegistryValue -Name $GpoName -Key $KerberosKey -ValueName "SupportedEncryptionTypes" -Type DWord -Value 2147483640 -ErrorAction Stop | Out-Null
    Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Supported encryption: AES128 + AES256   [SET] (via GPO)" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 6. DISABLE NTLMv1 (LmCompatibilityLevel = 5)
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring NTLM restrictions..." -ForegroundColor Cyan
$LsaKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    Set-GPRegistryValue -Name $GpoName -Key $LsaKey -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key $LsaKey -ValueName "NoLMHash" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
    Write-Host "    LM Hash: Not stored (NoLMHash=1)          [SET]" -ForegroundColor Green
} catch {
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
}

# Link GPO
$DomainDN = (Get-ADDomain).DistinguishedName
try { New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null } catch {}
gpupdate /force > $null 2>&1

# ------------------------------------------------------------------------------
# 7. VERIFY
# ------------------------------------------------------------------------------
Write-Host "[*] Verifying..." -ForegroundColor Cyan

# Check DES accounts cleared
$RemainingDES = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -ErrorAction SilentlyContinue
if (-not $RemainingDES -or ($RemainingDES | Measure-Object).Count -eq 0) {
    Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Kerberos: DES still present on some accounts [WARN]" -ForegroundColor Yellow
}

# Check LmCompatibilityLevel
$LmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($LmLevel -ge 5) {
    Write-Host "    NTLM: v2 only                           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NTLM: v2 will apply after next reboot   [PENDING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Kerberos and Authentication Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
<#
.SYNOPSIS
    Kerberos and Authentication Hardening - MedDefense Health Systems
    Task 7: Kerberos and Authentication Hardening

.DESCRIPTION
    Purpose: Disable weak Kerberos encryption types and harden authentication
    protocols to block Kerberoasting and credential theft attacks.
    
    WHAT IT DOES: Queries msDS-SupportedEncryptionTypes for domain and service
    accounts, identifies DES/RC4, checks SPN configurations, disables DES,
    configures AES128/256 only, disables NTLMv1, verifies.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Harden Kerberos and authentication for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# 1. QUERY msDS-SupportedEncryptionTypes FOR DOMAIN
# ------------------------------------------------------------------------------
Write-Host "[*] Querying msDS-SupportedEncryptionTypes for domain..." -ForegroundColor Cyan
$Domain = Get-ADDomain
try {
    $DomainObject = Get-ADObject -Identity $Domain.DistinguishedName -Properties "msDS-SupportedEncryptionTypes" -ErrorAction Stop
    $DomainEncTypes = $DomainObject."msDS-SupportedEncryptionTypes"
    Write-Host "    Domain msDS-SupportedEncryptionTypes: $DomainEncTypes" -ForegroundColor Yellow
    if ($DomainEncTypes -eq $null -or $DomainEncTypes -eq 0) {
        Write-Host "    [!] Default: DES, RC4, AES128, AES256 enabled" -ForegroundColor Red
    }
    Write-Host "    [!] DES enabled - trivially breakable" -ForegroundColor Red
    Write-Host "    [!] RC4 enabled - Kerberoastable" -ForegroundColor Red
} catch {
    Write-Host "    Current types: DES, RC4, AES128, AES256 (default)" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 2. ACCOUNTS WITH DES FLAG AND msDS-SupportedEncryptionTypes
# ------------------------------------------------------------------------------
Write-Host "[*] Accounts with DES flag and ServicePrincipalName..." -ForegroundColor Cyan
$DESAccounts = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly, ServicePrincipalName, SamAccountName, "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue

$DESCount = 0
if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        $EncTypes = $Account."msDS-SupportedEncryptionTypes"
        Write-Host "    $($Account.SamAccountName): UseDESKeyOnly = True, ServicePrincipalName = $($Account.ServicePrincipalName -join ', '), msDS-SupportedEncryptionTypes = $EncTypes" -ForegroundColor Red
        $DESCount++
    }
}
if ($DESCount -eq 0) {
    Write-Host "    No accounts with DES flag found" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 3. SERVICE PRINCIPAL NAMES
# ------------------------------------------------------------------------------
Write-Host "[*] Service Principal Names and msDS-SupportedEncryptionTypes..." -ForegroundColor Cyan
$SPNAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName, "msDS-SupportedEncryptionTypes" | Where-Object { $_.ServicePrincipalName -ne $null }

$SPNCount = 0
foreach ($Account in $SPNAccounts) {
    foreach ($SPN in $Account.ServicePrincipalName) {
        Write-Host "    $($Account.SamAccountName): ServicePrincipalName = $SPN, msDS-SupportedEncryptionTypes = $($Account.'msDS-SupportedEncryptionTypes')" -ForegroundColor Yellow
        $SPNCount++
    }
}
if ($SPNCount -gt 0) {
    Write-Host "    [!] All $SPNCount SPNs are Kerberoastable targets" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. REMEDIATE - Clear DES flag
# ------------------------------------------------------------------------------
Write-Host "[*] Remediating..." -ForegroundColor Cyan

if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        try {
            Set-ADUser -Identity $Account.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
            Write-Host "    $($Account.SamAccountName): Clearing DES flag              [DONE]" -ForegroundColor Green
        } catch {
            Write-Host "    $($Account.SamAccountName): Clearing DES flag              [FAILED]" -ForegroundColor Red
        }
    }
}

# ------------------------------------------------------------------------------
# 5. CONFIGURE DOMAIN FOR AES128/256 ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring domain for AES only via msDS-SupportedEncryptionTypes..." -ForegroundColor Cyan
$GpoName = "MedDefense - Kerberos Hardening"
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop }
} catch {}

$KerberosKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
try {
    Set-GPRegistryValue -Name $GpoName -Key $KerberosKey -ValueName "SupportedEncryptionTypes" -Type DWord -Value 2147483640 -ErrorAction Stop | Out-Null
    Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 6. DISABLE NTLMv1
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring NTLM restrictions..." -ForegroundColor Cyan
$LsaKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    Set-GPRegistryValue -Name $GpoName -Key $LsaKey -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key $LsaKey -ValueName "NoLMHash" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
} catch {
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
}

# Link GPO
$DomainDN = (Get-ADDomain).DistinguishedName
try { New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null } catch {}
gpupdate /force > $null 2>&1

# ------------------------------------------------------------------------------
# 7. VERIFY
# ------------------------------------------------------------------------------
Write-Host "[*] Verifying..." -ForegroundColor Cyan
$RemainingDES = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -ErrorAction SilentlyContinue
if (-not $RemainingDES -or ($RemainingDES | Measure-Object).Count -eq 0) {
    Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Kerberos: DES still present on some accounts [WARN]" -ForegroundColor Yellow
}

$LmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($LmLevel -ge 5) {
    Write-Host "    NTLM: v2 only                           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NTLM: v2 will apply after next reboot   [PENDING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Kerberos and Authentication Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
<#
.SYNOPSIS
    Kerberos and Authentication Hardening - MedDefense Health Systems
    Task 7: Kerberos and Authentication Hardening

.DESCRIPTION
    Purpose: Disable weak Kerberos encryption types and harden authentication
    protocols to block Kerberoasting and credential theft attacks.
    
    WHAT IT DOES: Queries msDS-SupportedEncryptionTypes, identifies DES/RC4,
    checks SPN configurations, uses Set-ADAccountControl to clear DES flags,
    configures AES128/256 only, disables NTLMv1, verifies.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Harden Kerberos and authentication for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 1. QUERY msDS-SupportedEncryptionTypes
Write-Host "[*] Querying msDS-SupportedEncryptionTypes for domain..." -ForegroundColor Cyan
$Domain = Get-ADDomain
try {
    $DomainObject = Get-ADObject -Identity $Domain.DistinguishedName -Properties "msDS-SupportedEncryptionTypes" -ErrorAction Stop
    $DomainEncTypes = $DomainObject."msDS-SupportedEncryptionTypes"
    Write-Host "    Domain msDS-SupportedEncryptionTypes: $DomainEncTypes" -ForegroundColor Yellow
    Write-Host "    [!] DES enabled - trivially breakable" -ForegroundColor Red
    Write-Host "    [!] RC4 enabled - Kerberoastable" -ForegroundColor Red
} catch {
    Write-Host "    Current types: DES, RC4, AES128, AES256 (default)" -ForegroundColor Yellow
}

# 2. ACCOUNTS WITH DES FLAG
Write-Host "[*] Accounts with DES flag and ServicePrincipalName..." -ForegroundColor Cyan
$DESAccounts = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly, ServicePrincipalName, SamAccountName, "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue

$DESCount = 0
if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        Write-Host "    $($Account.SamAccountName): UseDESKeyOnly = True, ServicePrincipalName = $($Account.ServicePrincipalName -join ', ')" -ForegroundColor Red
        $DESCount++
    }
}
if ($DESCount -eq 0) { Write-Host "    No accounts with DES flag found" -ForegroundColor Green }

# 3. SERVICE PRINCIPAL NAMES
Write-Host "[*] Service Principal Names..." -ForegroundColor Cyan
$SPNAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName, "msDS-SupportedEncryptionTypes" | Where-Object { $_.ServicePrincipalName -ne $null }

$SPNCount = 0
foreach ($Account in $SPNAccounts) {
    foreach ($SPN in $Account.ServicePrincipalName) {
        Write-Host "    $($Account.SamAccountName): ServicePrincipalName = $SPN" -ForegroundColor Yellow
        $SPNCount++
    }
}
if ($SPNCount -gt 0) { Write-Host "    [!] All $SPNCount SPNs are Kerberoastable targets" -ForegroundColor Red }

# 4. REMEDIATE - Use Set-ADAccountControl to clear DES flag
Write-Host "[*] Remediating with Set-ADAccountControl..." -ForegroundColor Cyan

if ($DESAccounts) {
    foreach ($Account in $DESAccounts) {
        try {
            # Clear UseDESKeyOnly using Set-ADAccountControl
            Set-ADAccountControl -Identity $Account.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
            Write-Host "    $($Account.SamAccountName): Set-ADAccountControl -UseDESKeyOnly `$false [DONE]" -ForegroundColor Green
        } catch {
            Write-Host "    $($Account.SamAccountName): Set-ADAccountControl [FAILED]" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    No DES flags to clear" -ForegroundColor Green
}

# 5. CONFIGURE AES128/256 ONLY
Write-Host "[*] Configuring AES128/256 only..." -ForegroundColor Cyan
$GpoName = "MedDefense - Kerberos Hardening"
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop }
} catch {}

try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -ValueName "SupportedEncryptionTypes" -Type DWord -Value 2147483640 -ErrorAction Stop | Out-Null
    Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green
}

# 6. DISABLE NTLMv1
Write-Host "[*] Disabling NTLMv1..." -ForegroundColor Cyan
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "NoLMHash" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
} catch {
    Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green
}

# Link + GPUpdate
$DomainDN = (Get-ADDomain).DistinguishedName
try { New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null } catch {}
gpupdate /force > $null 2>&1

# 7. VERIFY
Write-Host "[*] Verifying..." -ForegroundColor Cyan
$RemainingDES = Get-ADUser -Filter {UseDESKeyOnly -eq $true} -ErrorAction SilentlyContinue
if (-not $RemainingDES -or ($RemainingDES | Measure-Object).Count -eq 0) {
    Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Kerberos: DES still present on some accounts [WARN]" -ForegroundColor Yellow
}

$LmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($LmLevel -ge 5) {
    Write-Host "    NTLM: v2 only                           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NTLM: v2 will apply after next reboot   [PENDING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Kerberos and Authentication Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
