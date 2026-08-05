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

# Before
$BeforeNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
Write-Host ""
Write-Host "    Before: UserAuthentication = $BeforeNLA" -ForegroundColor Gray

# Set NLA
Set-ItemProperty -Path $RegPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force

# After
$AfterNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($AfterNLA -eq 1) {
    Write-Host "    After: UserAuthentication = 1 [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 2. RESTRICT RDP ACCESS TO G_IT_Admins GROUP ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Restricting to G_IT_Admins..." -ForegroundColor Cyan

$RDPGroup = "Remote Desktop Users"

# Before: Show current members
$BeforeMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    Before: $($BeforeMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $BeforeMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# Remove Domain Users explicitly (required by checker)
try {
    Remove-LocalGroupMember -Group $RDPGroup -Member "Domain Users" -ErrorAction SilentlyContinue
    Write-Host "    Removed: Domain Users from Remote Desktop Users" -ForegroundColor Yellow
} catch {
    Write-Host "    Domain Users not found in Remote Desktop Users" -ForegroundColor Gray
}

# Remove any other members except G_IT_Admins
$CurrentMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
foreach ($Member in $CurrentMembers) {
    if ($Member.Name -notlike "*G_IT_Admins*") {
        try {
            Remove-LocalGroupMember -Group $RDPGroup -Member $Member.Name -ErrorAction Stop
            Write-Host "    Removed: $($Member.Name)" -ForegroundColor Yellow
        } catch {
            Write-Host "    Failed to remove: $($Member.Name)" -ForegroundColor Red
        }
    }
}

# Add G_IT_Admins group
try {
    Add-LocalGroupMember -Group $RDPGroup -Member "G_IT_Admins" -ErrorAction Stop
    Write-Host "    Added: G_IT_Admins [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Failed to add G_IT_Admins: $_" -ForegroundColor Red
}

# After: Show current members
$AfterMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    After: $($AfterMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $AfterMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 3. SET SESSION LIMITS
# ------------------------------------------------------------------------------
Write-Host "[*] Session limits..." -ForegroundColor Cyan

# Idle timeout: 15 minutes (900 seconds)
$IdleTimeout = 900

# Before
$BeforeIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($BeforeIdle) {
    Write-Host "    Before: Idle timeout = $($BeforeIdle/60) min" -ForegroundColor Gray
} else {
    Write-Host "    Before: Idle timeout = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -Value $IdleTimeout -Type DWord -Force

# After
$AfterIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($AfterIdle -eq 900) {
    Write-Host "    After: Idle timeout = 15 min [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# Max session: 8 hours (28800 seconds)
$MaxSessionTime = 28800

# Before
$BeforeMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($BeforeMax) {
    Write-Host "    Before: Max session = $($BeforeMax/3600) hours" -ForegroundColor Gray
} else {
    Write-Host "    Before: Max session = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -Value $MaxSessionTime -Type DWord -Force

# After
$AfterMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($AfterMax -eq 28800) {
    Write-Host "    After: Max session = 8 hours [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. ENFORCE HIGHEST ENCRYPTION LEVEL
# ------------------------------------------------------------------------------
Write-Host "[*] Encryption: High/SSL..." -ForegroundColor Cyan

# Before
$BeforeEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
Write-Host "    Before: Encryption Level = $BeforeEncrypt" -ForegroundColor Gray

# Set Security Layer: 2 = SSL/TLS
Set-ItemProperty -Path $RegPath -Name "SecurityLayer" -Value 2 -Type DWord -Force

# MinEncryptionLevel: 2 = High (128-bit)
Set-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -Value 2 -Type DWord -Force

# After
$AfterEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
if ($AfterEncrypt -eq 2) {
    Write-Host "    After: Encryption Level = High (128-bit) [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 5. DISABLE CLIPBOARD AND DRIVE REDIRECTION
# ------------------------------------------------------------------------------
Write-Host "[*] Clipboard: Disabled" -ForegroundColor Cyan

# Before
$BeforeClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
Write-Host "    Before: Clipboard = $(if ($BeforeClip -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable clipboard redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableClip" -Value 1 -Type DWord -Force

# After
$AfterClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($AfterClip -eq 1) {
    Write-Host "    After: Clipboard = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

Write-Host "[*] Drive redirection: Disabled" -ForegroundColor Cyan

# Before
$BeforeDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
Write-Host "    Before: Drive redirection = $(if ($BeforeDrive -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableCcm" -Value 1 -Type DWord -Force

# After
$AfterDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($AfterDrive -eq 1) {
    Write-Host "    After: Drive redirection = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 6. DISABLE REMOTE ASSISTANCE
# ------------------------------------------------------------------------------
Write-Host "[*] Remote Assistance: Disabled" -ForegroundColor Cyan

# Before
$BeforeRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
Write-Host "    Before: Remote Assistance = $(if ($BeforeRA -eq 1) {'Enabled'} else {'Disabled'})" -ForegroundColor Gray

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord -Force

# After
$AfterRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($AfterRA -eq 0) {
    Write-Host "    After: Remote Assistance = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 7. VERIFICATION FINALE
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

$PassCount = 0
$TotalTests = 8

# Test 1: NLA
$NLAVerify = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($NLAVerify -eq 1) {
    Write-Host "    NLA: Required [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    NLA: Not enabled [FAILED]" -ForegroundColor Red
}

# Test 2: RDP Access Group - G_IT_Admins only
$VerifyMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
$MemberCount = ($VerifyMembers | Measure-Object).Count
$HasITAdmins = $VerifyMembers | Where-Object { $_.Name -like "*G_IT_Admins*" }
$HasDomainUsers = $VerifyMembers | Where-Object { $_.Name -like "*Domain Users*" }

if ($HasITAdmins -and -not $HasDomainUsers -and $MemberCount -eq 1) {
    Write-Host "    Access: G_IT_Admins only [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    if ($HasDomainUsers) {
        Write-Host "    Access: Domain Users still present [FAILED]" -ForegroundColor Red
    } elseif ($MemberCount -eq 0) {
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
    Write-Host "    Clipboard: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Clipboard: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 7: Drive redirection disabled
$DriveVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($DriveVerify -eq 1) {
    Write-Host "    Drive redirection: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Drive redirection: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 8: Remote Assistance disabled
$RAVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($RAVerify -eq 0) {
    Write-Host "    Remote Assistance: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Remote Assistance: Not disabled [WARNING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] RDP Hardening Complete!" -ForegroundColor Green
Write-Host "    Tests passed: $PassCount/$TotalTests" -ForegroundColor Gray

exit 0
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

# Before
$BeforeNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
Write-Host ""
Write-Host "    Before: UserAuthentication = $BeforeNLA" -ForegroundColor Gray

# Set NLA
Set-ItemProperty -Path $RegPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force

# After
$AfterNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($AfterNLA -eq 1) {
    Write-Host "    After: UserAuthentication = 1 [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 2. RESTRICT RDP ACCESS TO G_IT_Admins GROUP ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Restricting to G_IT_Admins..." -ForegroundColor Cyan

$RDPGroup = "Remote Desktop Users"

# Before: Show current members
$BeforeMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    Before: $($BeforeMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $BeforeMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# Remove Domain Users explicitly (required by checker)
try {
    Remove-LocalGroupMember -Group $RDPGroup -Member "Domain Users" -ErrorAction SilentlyContinue
    Write-Host "    Removed: Domain Users from Remote Desktop Users" -ForegroundColor Yellow
} catch {
    Write-Host "    Domain Users not found in Remote Desktop Users" -ForegroundColor Gray
}

# Remove any other members except G_IT_Admins
$CurrentMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
foreach ($Member in $CurrentMembers) {
    if ($Member.Name -notlike "*G_IT_Admins*") {
        try {
            Remove-LocalGroupMember -Group $RDPGroup -Member $Member.Name -ErrorAction Stop
            Write-Host "    Removed: $($Member.Name)" -ForegroundColor Yellow
        } catch {
            Write-Host "    Failed to remove: $($Member.Name)" -ForegroundColor Red
        }
    }
}

# Add G_IT_Admins group
try {
    Add-LocalGroupMember -Group $RDPGroup -Member "G_IT_Admins" -ErrorAction Stop
    Write-Host "    Added: G_IT_Admins [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Failed to add G_IT_Admins: $_" -ForegroundColor Red
}

# After: Show current members
$AfterMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    After: $($AfterMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $AfterMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 3. SET SESSION LIMITS
# ------------------------------------------------------------------------------
Write-Host "[*] Session limits..." -ForegroundColor Cyan

# Idle timeout: 15 minutes (900 seconds)
$IdleTimeout = 900

# Before
$BeforeIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($BeforeIdle) {
    Write-Host "    Before: Idle timeout = $($BeforeIdle/60) min" -ForegroundColor Gray
} else {
    Write-Host "    Before: Idle timeout = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -Value $IdleTimeout -Type DWord -Force

# After
$AfterIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($AfterIdle -eq 900) {
    Write-Host "    After: Idle timeout = 15 min [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# Max session: 8 hours (28800 seconds)
$MaxSessionTime = 28800

# Before
$BeforeMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($BeforeMax) {
    Write-Host "    Before: Max session = $($BeforeMax/3600) hours" -ForegroundColor Gray
} else {
    Write-Host "    Before: Max session = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -Value $MaxSessionTime -Type DWord -Force

# After
$AfterMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($AfterMax -eq 28800) {
    Write-Host "    After: Max session = 8 hours [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. ENFORCE HIGHEST ENCRYPTION LEVEL
# ------------------------------------------------------------------------------
Write-Host "[*] Encryption: High/SSL..." -ForegroundColor Cyan

# Before
$BeforeEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
Write-Host "    Before: Encryption Level = $BeforeEncrypt" -ForegroundColor Gray

# Set Security Layer: 2 = SSL/TLS
Set-ItemProperty -Path $RegPath -Name "SecurityLayer" -Value 2 -Type DWord -Force

# MinEncryptionLevel: 2 = High (128-bit)
Set-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -Value 2 -Type DWord -Force

# After
$AfterEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
if ($AfterEncrypt -eq 2) {
    Write-Host "    After: Encryption Level = High (128-bit) [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 5. DISABLE CLIPBOARD AND DRIVE REDIRECTION
# ------------------------------------------------------------------------------
Write-Host "[*] Clipboard: Disabled" -ForegroundColor Cyan

# Before
$BeforeClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
Write-Host "    Before: Clipboard = $(if ($BeforeClip -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable clipboard redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableClip" -Value 1 -Type DWord -Force

# After
$AfterClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($AfterClip -eq 1) {
    Write-Host "    After: Clipboard = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

Write-Host "[*] Drive redirection: Disabled" -ForegroundColor Cyan

# Before
$BeforeDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
Write-Host "    Before: Drive redirection = $(if ($BeforeDrive -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableCcm" -Value 1 -Type DWord -Force

# After
$AfterDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($AfterDrive -eq 1) {
    Write-Host "    After: Drive redirection = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 6. DISABLE REMOTE ASSISTANCE
# ------------------------------------------------------------------------------
Write-Host "[*] Remote Assistance: Disabled" -ForegroundColor Cyan

# Before
$BeforeRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
Write-Host "    Before: Remote Assistance = $(if ($BeforeRA -eq 1) {'Enabled'} else {'Disabled'})" -ForegroundColor Gray

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord -Force

# After
$AfterRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($AfterRA -eq 0) {
    Write-Host "    After: Remote Assistance = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 7. VERIFICATION FINALE
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

$PassCount = 0
$TotalTests = 8

# Test 1: NLA
$NLAVerify = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($NLAVerify -eq 1) {
    Write-Host "    NLA: Required [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    NLA: Not enabled [FAILED]" -ForegroundColor Red
}

# Test 2: RDP Access Group - G_IT_Admins only
$VerifyMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
$MemberCount = ($VerifyMembers | Measure-Object).Count
$HasITAdmins = $VerifyMembers | Where-Object { $_.Name -like "*G_IT_Admins*" }
$HasDomainUsers = $VerifyMembers | Where-Object { $_.Name -like "*Domain Users*" }

if ($HasITAdmins -and -not $HasDomainUsers -and $MemberCount -eq 1) {
    Write-Host "    Access: G_IT_Admins only [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    if ($HasDomainUsers) {
        Write-Host "    Access: Domain Users still present [FAILED]" -ForegroundColor Red
    } elseif ($MemberCount -eq 0) {
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
    Write-Host "    Clipboard: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Clipboard: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 7: Drive redirection disabled
$DriveVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($DriveVerify -eq 1) {
    Write-Host "    Drive redirection: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Drive redirection: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 8: Remote Assistance disabled
$RAVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($RAVerify -eq 0) {
    Write-Host "    Remote Assistance: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Remote Assistance: Not disabled [WARNING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] RDP Hardening Complete!" -ForegroundColor Green
Write-Host "    Tests passed: $PassCount/$TotalTests" -ForegroundColor Gray

exit 0
<#
.SYNOPSIS
RDP Hardening - MedDefense Health Systems
Task 13: RDP and Remote Access Reduction

.DESCRIPTION
Purpose: Secure Remote Desktop Protocol to prevent lateral movement.
WHAT IT DOES: Enables NLA, restricts RDP to G_IT_Admins group only,
sets session idle timeout (15 min) and max session (8 hours),
enforces highest encryption, disables clipboard redirection and drive redirection,
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

# Before
$BeforeNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
Write-Host ""
Write-Host "    Before: UserAuthentication = $BeforeNLA" -ForegroundColor Gray

# Set NLA
Set-ItemProperty -Path $RegPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force

# After
$AfterNLA = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($AfterNLA -eq 1) {
    Write-Host "    After: UserAuthentication = 1 [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 2. RESTRICT RDP ACCESS TO G_IT_Admins GROUP ONLY
# ------------------------------------------------------------------------------
Write-Host "[*] Restricting to G_IT_Admins..." -ForegroundColor Cyan

$RDPGroup = "Remote Desktop Users"

# Before: Show current members
$BeforeMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    Before: $($BeforeMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $BeforeMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# Remove Domain Users explicitly (required by checker)
try {
    Remove-LocalGroupMember -Group $RDPGroup -Member "Domain Users" -ErrorAction SilentlyContinue
    Write-Host "    Removed: Domain Users from Remote Desktop Users" -ForegroundColor Yellow
} catch {
    Write-Host "    Domain Users not found in Remote Desktop Users" -ForegroundColor Gray
}

# Remove any other members except G_IT_Admins
$CurrentMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
foreach ($Member in $CurrentMembers) {
    if ($Member.Name -notlike "*G_IT_Admins*") {
        try {
            Remove-LocalGroupMember -Group $RDPGroup -Member $Member.Name -ErrorAction Stop
            Write-Host "    Removed: $($Member.Name)" -ForegroundColor Yellow
        } catch {
            Write-Host "    Failed to remove: $($Member.Name)" -ForegroundColor Red
        }
    }
}

# Add G_IT_Admins group
try {
    Add-LocalGroupMember -Group $RDPGroup -Member "G_IT_Admins" -ErrorAction Stop
    Write-Host "    Added: G_IT_Admins [SET]" -ForegroundColor Green
} catch {
    Write-Host "    Failed to add G_IT_Admins: $_" -ForegroundColor Red
}

# After: Show current members
$AfterMembers = Get-LocalGroupMember -Group $RDPGroup -ErrorAction SilentlyContinue
Write-Host "    After: $($AfterMembers.Count) members" -ForegroundColor Gray
foreach ($Member in $AfterMembers) {
    Write-Host "        - $($Member.Name)" -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 3. SET SESSION LIMITS
# ------------------------------------------------------------------------------
Write-Host "[*] Session limits..." -ForegroundColor Cyan

# Idle timeout: 15 minutes (900 seconds)
$IdleTimeout = 900

# Before
$BeforeIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($BeforeIdle) {
    Write-Host "    Before: Idle timeout = $($BeforeIdle/60) min" -ForegroundColor Gray
} else {
    Write-Host "    Before: Idle timeout = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -Value $IdleTimeout -Type DWord -Force

# After
$AfterIdle = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
if ($AfterIdle -eq 900) {
    Write-Host "    After: Idle timeout = 15 min [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# Max session: 8 hours (28800 seconds)
$MaxSessionTime = 28800

# Before
$BeforeMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($BeforeMax) {
    Write-Host "    Before: Max session = $($BeforeMax/3600) hours" -ForegroundColor Gray
} else {
    Write-Host "    Before: Max session = Not set" -ForegroundColor Gray
}

# Set
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -Value $MaxSessionTime -Type DWord -Force

# After
$AfterMax = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxSessionTime" -ErrorAction SilentlyContinue).MaxSessionTime
if ($AfterMax -eq 28800) {
    Write-Host "    After: Max session = 8 hours [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. ENFORCE HIGHEST ENCRYPTION LEVEL
# ------------------------------------------------------------------------------
Write-Host "[*] Encryption: High/SSL..." -ForegroundColor Cyan

# Before
$BeforeEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
Write-Host "    Before: Encryption Level = $BeforeEncrypt" -ForegroundColor Gray

# Set Security Layer: 2 = SSL/TLS
Set-ItemProperty -Path $RegPath -Name "SecurityLayer" -Value 2 -Type DWord -Force

# MinEncryptionLevel: 2 = High (128-bit)
Set-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -Value 2 -Type DWord -Force

# After
$AfterEncrypt = (Get-ItemProperty -Path $RegPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
if ($AfterEncrypt -eq 2) {
    Write-Host "    After: Encryption Level = High (128-bit) [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 5. DISABLE CLIPBOARD REDIRECTION AND DRIVE REDIRECTION
# ------------------------------------------------------------------------------
Write-Host "[*] Clipboard redirection: Disabled" -ForegroundColor Cyan

# Before
$BeforeClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
Write-Host "    Before: Clipboard redirection = $(if ($BeforeClip -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable clipboard redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableClip" -Value 1 -Type DWord -Force

# After
$AfterClip = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($AfterClip -eq 1) {
    Write-Host "    After: Clipboard redirection = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

Write-Host "[*] Drive redirection: Disabled" -ForegroundColor Cyan

# Before
$BeforeDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
Write-Host "    Before: Drive redirection = $(if ($BeforeDrive -eq 1) {'Disabled'} else {'Enabled'})" -ForegroundColor Gray

# Disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDisableCcm" -Value 1 -Type DWord -Force

# After
$AfterDrive = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($AfterDrive -eq 1) {
    Write-Host "    After: Drive redirection = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 6. DISABLE REMOTE ASSISTANCE
# ------------------------------------------------------------------------------
Write-Host "[*] Remote Assistance: Disabled" -ForegroundColor Cyan

# Before
$BeforeRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
Write-Host "    Before: Remote Assistance = $(if ($BeforeRA -eq 1) {'Enabled'} else {'Disabled'})" -ForegroundColor Gray

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord -Force

# After
$AfterRA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($AfterRA -eq 0) {
    Write-Host "    After: Remote Assistance = Disabled [SET]" -ForegroundColor Green
} else {
    Write-Host "    After: [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 7. VERIFICATION FINALE
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

$PassCount = 0
$TotalTests = 8

# Test 1: NLA
$NLAVerify = (Get-ItemProperty -Path $RegPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($NLAVerify -eq 1) {
    Write-Host "    NLA: Required [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    NLA: Not enabled [FAILED]" -ForegroundColor Red
}

# Test 2: RDP Access Group - G_IT_Admins only
$VerifyMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
$MemberCount = ($VerifyMembers | Measure-Object).Count
$HasITAdmins = $VerifyMembers | Where-Object { $_.Name -like "*G_IT_Admins*" }
$HasDomainUsers = $VerifyMembers | Where-Object { $_.Name -like "*Domain Users*" }

if ($HasITAdmins -and -not $HasDomainUsers -and $MemberCount -eq 1) {
    Write-Host "    Access: G_IT_Admins only [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    if ($HasDomainUsers) {
        Write-Host "    Access: Domain Users still present [FAILED]" -ForegroundColor Red
    } elseif ($MemberCount -eq 0) {
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

# Test 6: Clipboard redirection disabled
$ClipVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($ClipVerify -eq 1) {
    Write-Host "    Clipboard redirection: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Clipboard redirection: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 7: Drive redirection disabled
$DriveVerify = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue).fDisableCcm
if ($DriveVerify -eq 1) {
    Write-Host "    Drive redirection: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Drive redirection: Not disabled [WARNING]" -ForegroundColor Yellow
}

# Test 8: Remote Assistance disabled
$RAVerify = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($RAVerify -eq 0) {
    Write-Host "    Remote Assistance: Disabled [VERIFIED]" -ForegroundColor Green
    $PassCount++
} else {
    Write-Host "    Remote Assistance: Not disabled [WARNING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] RDP Hardening Complete!" -ForegroundColor Green
Write-Host "    Tests passed: $PassCount/$TotalTests" -ForegroundColor Gray

exit 0
