<#
.SYNOPSIS
    Password and Lockout Policy - MedDefense Health Systems
    Task 4: Password and Lockout Policy

.DESCRIPTION
    Purpose: Deploy a CIS-compliant password and account lockout policy
    via Group Policy, fixing the two most critical findings from the
    domain assessment (FIND-PW-001 and FIND-LOCK-001).
    
    WHAT IT DOES: Creates a GPO named "MedDefense - Password and Lockout
    Policy", configures password settings (min length 14, complexity
    enabled, history 24), configures account lockout (threshold 5,
    duration 15 min), links to domain root, and forces GPUpdate.
    
    WHY: Finding password min length is 7, complexity disabled, no
    lockout. Crimson Tide used weak passwords and absent lockout for
    brute-force and credential harvesting in all 5 hospital breaches.
    This is the single highest-impact GPO you will create.
    
    WHEN TO USE: Immediately after domain baseline (Task 0). Before
    any other hardening. This fixes the root cause of Kerberoasting.

.REFERENCES
    FIND-PW-001: Password minimum length 7 (CRITICAL)
    FIND-PW-002: Password complexity disabled (CRITICAL)
    FIND-LOCK-001: Account lockout not configured (CRITICAL)
    Crimson Tide Phase 2: Credential brute-force via weak passwords
    CIS Windows Server 2022 Benchmark Section 1.1

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local - Windows Server 2022 Domain Controller
#>

# Author: shamshed rajput
# Script Purpose: Deploy CIS-compliant password and lockout policy for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - Password and Lockout Policy"
$DomainDN = (Get-ADDomain).DistinguishedName

Write-Host "[*] Creating GPO: `"$GpoName`"..." -NoNewline -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. CREATE GPO
# ------------------------------------------------------------------------------
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) {
        $Gpo = New-GPO -Name $GpoName -ErrorAction Stop
        Write-Host " CREATED" -ForegroundColor Green
    } else {
        Write-Host " EXISTS" -ForegroundColor Yellow
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------------------
# 2. CONFIGURE PASSWORD POLICY
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Password Policy..." -ForegroundColor Cyan

$PasswordSettings = @(
    @{Key="MinimumPasswordLength"; Value=14; Display="Minimum Length: 14"}
    @{Key="ComplexityEnabled"; Value=$true; Display="Complexity: Enabled"}
    @{Key="PasswordHistoryCount"; Value=24; Display="History: 24"}
    @{Key="MaxPasswordAge"; Value="0"; Display="Maximum Age: 0"}
    @{Key="MinPasswordAge"; Value="1"; Display="Minimum Age: 1 day"}
)

foreach ($Setting in $PasswordSettings) {
    try {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName $Setting.Key -Type DWord -Value $Setting.Value -ErrorAction Stop | Out-Null
        Write-Host "    $($Setting.Display.PadRight(30)) [SET]" -ForegroundColor Green
    } catch {
        Write-Host "    $($Setting.Display.PadRight(30)) [FAILED]" -ForegroundColor Red
    }
}

# ------------------------------------------------------------------------------
# 3. CONFIGURE ACCOUNT LOCKOUT
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Account Lockout..." -ForegroundColor Cyan

$LockoutSettings = @(
    @{Key="LockoutBadCount"; Value=5; Display="Threshold: 5 attempts"}
    @{Key="LockoutDuration"; Value=-15; Display="Duration: 15 minutes"}
    @{Key="ResetLockoutCount"; Value=-15; Display="Reset Counter: 15 minutes"}
)

foreach ($Setting in $LockoutSettings) {
    try {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName $Setting.Key -Type DWord -Value $Setting.Value -ErrorAction Stop | Out-Null
        Write-Host "    $($Setting.Display.PadRight(30)) [SET]" -ForegroundColor Green
    } catch {
        Write-Host "    $($Setting.Display.PadRight(30)) [FAILED]" -ForegroundColor Red
    }
}

# ------------------------------------------------------------------------------
# 4. LINK GPO TO DOMAIN ROOT
# ------------------------------------------------------------------------------
Write-Host "[*] Linking GPO to domain root..." -NoNewline -ForegroundColor Cyan

try {
    $ExistingLink = Get-GPLinks -Domain $DomainDN | Where-Object { $_.DisplayName -eq $GpoName } -ErrorAction SilentlyContinue
    if (-not $ExistingLink) {
        New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host " LINKED" -ForegroundColor Green
    } else {
        Write-Host " ALREADY LINKED" -ForegroundColor Yellow
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 5. FORCE GROUP POLICY UPDATE
# ------------------------------------------------------------------------------
Write-Host "[*] Forcing Group Policy update..." -NoNewline -ForegroundColor Cyan

try {
    gpupdate /force > $null 2>&1
    Write-Host " COMPLETE" -ForegroundColor Green
} catch {
    Write-Host " COMPLETE (with warnings)" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 6. VERIFY POLICY
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Verifying effective password policy..." -ForegroundColor Cyan

$EffectivePolicy = Get-ADDefaultDomainPasswordPolicy

Write-Host "    Minimum Length: $($EffectivePolicy.MinPasswordLength)" -ForegroundColor $(if ($EffectivePolicy.MinPasswordLength -ge 14) { "Green" } else { "Red" })
Write-Host "    Complexity: $(if ($EffectivePolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($EffectivePolicy.ComplexityEnabled) { "Green" } else { "Red" })
Write-Host "    History: $($EffectivePolicy.PasswordHistoryCount)" -ForegroundColor $(if ($EffectivePolicy.PasswordHistoryCount -ge 24) { "Green" } else { "Red" })
Write-Host "    Lockout Threshold: $($EffectivePolicy.LockoutThreshold)" -ForegroundColor $(if ($EffectivePolicy.LockoutThreshold -ge 5) { "Green" } else { "Red" })
Write-Host "    Lockout Duration: $($EffectivePolicy.LockoutDuration.TotalMinutes) minutes" -ForegroundColor $(if ($EffectivePolicy.LockoutDuration.TotalMinutes -ge 15) { "Green" } else { "Red" })

Write-Host ""
Write-Host "======================================================================"
Write-Host "  PASSWORD AND LOCKOUT POLICY - COMPLETE"
Write-Host "======================================================================"

exit 0
<#
.SYNOPSIS
    Password and Lockout Policy - MedDefense Health Systems
    Task 4: Password and Lockout Policy

.DESCRIPTION
    Purpose: Deploy a CIS-compliant password and account lockout policy
    via Group Policy, fixing the two most critical findings from the
    domain assessment (FIND-PW-001 and FIND-LOCK-001).
    
    WHAT IT DOES: Creates a GPO named "MedDefense - Password and Lockout
    Policy", configures password settings (min length 14, complexity
    enabled, history 24), configures account lockout (threshold 5,
    duration 15 min), links to domain root, and forces GPUpdate.
    
    WHY: Finding password min length is 7, complexity disabled, no
    lockout. Crimson Tide used weak passwords and absent lockout for
    brute-force and credential harvesting in all 5 hospital breaches.
    
    WHEN TO USE: Immediately after domain baseline (Task 0).

.REFERENCES
    FIND-PW-001, FIND-PW-002, FIND-LOCK-001
    Crimson Tide Phase 2

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy CIS-compliant password and lockout policy for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - Password and Lockout Policy"
$DomainDN = (Get-ADDomain).DistinguishedName

Write-Host "[*] Creating GPO: `"$GpoName`"..." -NoNewline -ForegroundColor Cyan

# 1. CREATE GPO
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) {
        $Gpo = New-GPO -Name $GpoName -ErrorAction Stop
        Write-Host " CREATED" -ForegroundColor Green
    } else {
        Write-Host " EXISTS" -ForegroundColor Yellow
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# 2. CONFIGURE PASSWORD POLICY
Write-Host "[*] Configuring Password Policy..." -ForegroundColor Cyan

$PasswordSettings = @(
    @{Key="MinimumPasswordLength"; Value=14; Display="Minimum Length: 14"}
    @{Key="ComplexityEnabled"; Value=$true; Display="Complexity: Enabled"}
    @{Key="PasswordHistoryCount"; Value=24; Display="History: 24"}
    @{Key="MaxPasswordAge"; Value="0"; Display="Maximum Age: 0"}
    @{Key="MinPasswordAge"; Value="1"; Display="Minimum Age: 1 day"}
)

foreach ($Setting in $PasswordSettings) {
    try {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName $Setting.Key -Type DWord -Value $Setting.Value -ErrorAction Stop | Out-Null
        Write-Host "    $($Setting.Display.PadRight(30)) [SET]" -ForegroundColor Green
    } catch {
        Write-Host "    $($Setting.Display.PadRight(30)) [FAILED]" -ForegroundColor Red
    }
}

# 3. CONFIGURE ACCOUNT LOCKOUT
Write-Host "[*] Configuring Account Lockout..." -ForegroundColor Cyan

$LockoutSettings = @(
    @{Key="LockoutBadCount"; Value=5; Display="Threshold: 5 attempts"}
    @{Key="LockoutDuration"; Value=-15; Display="Duration: 15 minutes"}
    @{Key="ResetLockoutCount"; Value=-15; Display="Reset Counter: 15 minutes"}
)

foreach ($Setting in $LockoutSettings) {
    try {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName $Setting.Key -Type DWord -Value $Setting.Value -ErrorAction Stop | Out-Null
        Write-Host "    $($Setting.Display.PadRight(30)) [SET]" -ForegroundColor Green
    } catch {
        Write-Host "    $($Setting.Display.PadRight(30)) [FAILED]" -ForegroundColor Red
    }
}

# 4. LINK GPO TO DOMAIN ROOT
Write-Host "[*] Linking GPO to domain root..." -NoNewline -ForegroundColor Cyan

try {
    $ExistingLink = Get-GPLinks -Domain $DomainDN | Where-Object { $_.DisplayName -eq $GpoName } -ErrorAction SilentlyContinue
    if (-not $ExistingLink) {
        New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host " LINKED" -ForegroundColor Green
    } else {
        Write-Host " ALREADY LINKED" -ForegroundColor Yellow
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
}

# 5. FORCE GROUP POLICY UPDATE
Write-Host "[*] Forcing Group Policy update..." -NoNewline -ForegroundColor Cyan
gpupdate /force > $null 2>&1
Write-Host " COMPLETE" -ForegroundColor Green

# 6. VERIFY POLICY
Write-Host ""
Write-Host "[*] Verifying effective password policy..." -ForegroundColor Cyan
$EffectivePolicy = Get-ADDefaultDomainPasswordPolicy

Write-Host "    Minimum Length: $($EffectivePolicy.MinPasswordLength)" -ForegroundColor $(if ($EffectivePolicy.MinPasswordLength -ge 14) { "Green" } else { "Red" })
Write-Host "    Complexity: $(if ($EffectivePolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($EffectivePolicy.ComplexityEnabled) { "Green" } else { "Red" })
Write-Host "    History: $($EffectivePolicy.PasswordHistoryCount)" -ForegroundColor $(if ($EffectivePolicy.PasswordHistoryCount -ge 24) { "Green" } else { "Red" })
Write-Host "    Lockout Threshold: $($EffectivePolicy.LockoutThreshold)" -ForegroundColor $(if ($EffectivePolicy.LockoutThreshold -ge 5) { "Green" } else { "Red" })
Write-Host "    Lockout Duration: $($EffectivePolicy.LockoutDuration.TotalMinutes) minutes" -ForegroundColor $(if ($EffectivePolicy.LockoutDuration.TotalMinutes -ge 15) { "Green" } else { "Red" })

Write-Host ""
Write-Host "======================================================================"
Write-Host "  PASSWORD AND LOCKOUT POLICY - COMPLETE"
Write-Host "======================================================================"

exit 0
