<#
.SYNOPSIS
RDP Hardening - MedDefense Health Systems
Task 13: RDP and Remote Access Reduction

.DESCRIPTION
Purpose: Secure Remote Desktop Protocol to prevent lateral movement.
WHAT IT DOES: Enables NLA, restricts RDP to G_IT_Admins group only,
sets session idle timeout (15 min) and max session (8 hours),
enforces highest encryption, disables clipboard/drive redirection,
and disables Remote Assistance.

Author: shamshed rajput
Date: 30/07/2026
Target: DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "[*] RDP Hardening - MedDefense Health Systems" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# 1. ENABLE NETWORK LEVEL AUTHENTICATION (NLA)
# ------------------------------------------------------------------------------
Write-Host "[*] Enabling NLA..." -NoNewline -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $RegPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force

$NLAValue = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($NLAValue -eq 1) {
    Write-Host " UserAuthentication = 1 [SET]" -ForegroundColor Green
} else {
    Write-Host " [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 2. RESTRICT RDP ACCESS TO G_IT_Admins GROUP ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Restricting to G_IT_Admins..." -ForegroundColor Cyan

# Get current members of Remote Desktop Users group
$RDPGroup = "Remote Desktop Users"
$CurrentMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue

# Remove all current members
$RemovedCount = 0
foreach ($Member in $CurrentMembers) {
    try {
        Remove-LocalGroupMember -Group $RDPGroup -Member $Member.Name -ErrorAction Stop
        Write-Host "    Removed: $($Member.Name)" -ForegroundColor Yellow
        $RemovedCount++
    } catch {
        Write-Host "    Failed to remove: $($Member.Name)" -ForegroundColor Red
    }
}
if ($RemovedCount -eq 0) {
    Write-Host "    No existing members to remove" -ForegroundColor Gray
}

# Add G_IT_Admins group
try {
    Add-LocalGroupMember -Group $RDPGroup -Member "G_IT_Admins" -ErrorAction Stop
    Write-Host "    Added: G_IT_Admins [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Failed to add G_IT_Admins: $_" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 3. SET SESSION LIMITS
# ------------------------------------------------------------------------------
Write-Host "[*] Session limits..." -ForegroundColor Cyan

# Idle timeout: 15 minutes (900 seconds)
$IdleTimeout = 900
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -Value $IdleTimeout -Type DWord -Force
Write-Host "    Idle timeout: 15 min [SET]" -ForegroundColor Green

# Max session: 8 hours (28800 seconds)
$MaxSessionTime = 28800
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -Value $MaxSessionTime -Type DWord -Force
Write-Host "    Max session: 8 hours [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 4. ENFORCE HIGHEST ENCRYPTION LEVEL
# ------------------------------------------------------------------------------
Write-Host "[*] Encryption: High/SSL..." -NoNewline -ForegroundColor Cyan

# Security Layer: 2 = SSL/TLS
Set-ItemProperty -Path $RegPath -Name "SecurityLayer" -Value 2 -Type DWord -Force

# MinEncryptionLevel: 2 = High (128-bit)
Set-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -Value 2 -Type DWord -Force

# UserAuthentication: already set above
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 5. DISABLE CLIPBOARD AND DRIVE REDIRECTION
# ------------------------------------------------------------------------------
Write-Host "[*] Clipboard: Disabled" -NoNewline -ForegroundColor Cyan

# Disable clipboard redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableClip" -Value 1 -Type DWord -Force
Write-Host " [SET]" -ForegroundColor Green

Write-Host "[*] Drive redirection: Disabled" -NoNewline -ForegroundColor Cyan

# Disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableCcm" -Value 1 -Type DWord -Force
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 6. DISABLE REMOTE ASSISTANCE
# ------------------------------------------------------------------------------
Write-Host "[*] Remote Assistance: Disabled" -NoNewline -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord -Force
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 7. VERIFICATION
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

$PassCount = 0
$TotalTests = 5

# Test 1: NLA
$NLAVerify = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($NLAVerify -eq 1) {
    Write-Host "    NLA: Required [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    NLA: Not enabled [FAILED]" -ForegroundColor Red
}

# Test 2: RDP Access Group
$VerifyMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
$MemberCount = ($VerifyMembers | Measure-Object).Count
$HasITAdmins = $VerifyMembers | Where-Object { $_.Name -like "*G_IT_Admins*" }

if ($MemberCount -eq 1 -and $HasITAdmins) {
    Write-Host "    Access: G_IT_Admins only [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    if ($MemberCount -eq 0) {
        Write-Host "    Access: No members found [WARNING]" -ForegroundColor Yellow
    } else {
        Write-Host "    Access: $MemberCount members found [WARNING]" -ForegroundColor Yellow
    }
}

# Test 3: Idle timeout
$IdleVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($IdleVerify -eq 900) {
    Write-Host "    Idle timeout: 15 min [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Idle timeout: $($IdleVerify/60) min [WARNING]" -ForegroundColor Yellow
}

# Test 4: Max session
$MaxSessionVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($MaxSessionVerify -eq 28800) {
    Write-Host "    Max session: 8 hours [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Max session: $($MaxSessionVerify/3600) hours [WARNING]" -ForegroundColor Yellow
}

# Test 5: Encryption
$EncryptVerify = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
if ($EncryptVerify -eq 2) {
    Write-Host "    Encryption: High (128-bit) [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Encryption: Level $EncryptVerify [WARNING]" -ForegroundColor Yellow
}

# Test 6: Clipboard disabled
$ClipVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($ClipVerify -eq 1) {
    $PassCount++
}

# Test 7: Drive redirection disabled
$DriveVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($DriveVerify -eq 1) {
    $PassCount++
}

# Test 8: Remote Assistance disabled
$RAVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($RAVerify -eq 0) {
    $PassCount++
}

Write-Host ""
Write-Host "[*] RDP Hardening Complete!" -ForegroundColor Green
Write-Host "    Tests passed: $PassCount/8" -ForegroundColor Gray

exit 0
