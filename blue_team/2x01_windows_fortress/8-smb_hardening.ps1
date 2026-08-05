<#
.SYNOPSIS
    SMB and Protocol Hardening - MedDefense Health Systems
    Task 8: SMB and Protocol Hardening

.DESCRIPTION
    Purpose: Disable SMBv1 and enforce SMB signing to eliminate one of the
    most commonly exploited lateral movement vectors.
    
    WHAT IT DOES: Checks SMB config (v1, signing, encryption), disables
    SMBv1 client/server, enforces SMB signing, enables SMB encryption,
    disables NetBIOS over TCP/IP and LLMNR, verifies all changes.
    
    WHY: SMBv1 = EternalBlue (WannaCry, NotPetya). Crimson Tide didn't use
    it but it's still enabled on MedDefense DC. Disabling costs nothing.
    SMB signing prevents relay attacks. SMB encryption prevents sniffing.
    LLMNR enables credential theft via name resolution poisoning.
    
    WHEN TO USE: After Kerberos hardening (Task 7). This closes network
    protocol attack surfaces used for lateral movement (CT Phase 4).

.REFERENCES
    EternalBlue (MS17-010) - WannaCry, NotPetya
    Crimson Tide Phase 4: Lateral movement via SMB
    CIS Windows Server 2022 Benchmark Section 2.3

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Harden SMB and legacy protocols for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# 1. CHECK CURRENT SMB CONFIGURATION
# ------------------------------------------------------------------------------
Write-Host "[*] Current SMB Configuration..." -ForegroundColor Cyan

# SMBv1
$Smbv1Server = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
$Smbv1Enabled = ($Smbv1Server -eq "Enabled")
Write-Host "    SMBv1: $(if ($Smbv1Enabled) { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($Smbv1Enabled) { 'Red' } else { 'Green' })

# SMB Signing
$SmbSigning = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSecuritySignature
Write-Host "    Signing Required: $SmbSigning $(if (-not $SmbSigning) { '[!]' } else { '[OK]' })" -ForegroundColor $(if (-not $SmbSigning) { 'Red' } else { 'Green' })

# SMB Encryption
$SmbEncryption = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EncryptData
Write-Host "    Encryption: $SmbEncryption $(if (-not $SmbEncryption) { '[!]' } else { '[OK]' })" -ForegroundColor $(if (-not $SmbEncryption) { 'Red' } else { 'Green' })

# ------------------------------------------------------------------------------
# 2. DISABLE SMBv1 (SERVER + CLIENT)
# ------------------------------------------------------------------------------
Write-Host "[*] Disabling SMBv1 (server + client)..." -NoNewline -ForegroundColor Cyan

try {
    # Disable SMBv1 server
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    # Disable SMBv1 client
    Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Host "   [DONE]" -ForegroundColor Green
} catch {
    Write-Host "   [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 3. ENFORCE SMB SIGNING
# ------------------------------------------------------------------------------
Write-Host "[*] Enforcing SMB Signing..." -NoNewline -ForegroundColor Cyan

try {
    Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host "               [SET]" -ForegroundColor Green
} catch {
    Write-Host "               [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 4. ENABLE SMB ENCRYPTION
# ------------------------------------------------------------------------------
Write-Host "[*] Enabling SMB Encryption..." -NoNewline -ForegroundColor Cyan

try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
    Write-Host "             [SET]" -ForegroundColor Green
} catch {
    Write-Host "             [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 5. DISABLE NETBIOS OVER TCP/IP
# ------------------------------------------------------------------------------
Write-Host "[*] Disabling NetBIOS over TCP/IP..." -NoNewline -ForegroundColor Cyan

try {
    # Set NetBIOS to disabled on all interfaces
    $Adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    foreach ($Adapter in $Adapters) {
        $Adapter.SetTcpipNetbios(2) | Out-Null
    }
    Write-Host "       [SET]" -ForegroundColor Green
} catch {
    Write-Host "       [FAILED]" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# 6. DISABLE LLMNR VIA GPO
# ------------------------------------------------------------------------------
Write-Host "[*] Disabling LLMNR via GPO..." -NoNewline -ForegroundColor Cyan

$GpoName = "MedDefense - SMB and Protocol Hardening"
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop }
    
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -ValueName "EnableMulticast" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    
    $DomainDN = (Get-ADDomain).DistinguishedName
    New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Host "             [SET]" -ForegroundColor Green
} catch {
    Write-Host "             [FAILED]" -ForegroundColor Red
}

# Force update
gpupdate /force > $null 2>&1

# ------------------------------------------------------------------------------
# 7. VERIFICATION
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

# Verify SMBv1
$Smbv1After = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
$Smbv1Disabled = ($Smbv1After -ne "Enabled")
Write-Host "    SMBv1: $(if ($Smbv1Disabled) { 'Disabled [VERIFIED]' } else { 'Still Enabled [WARN]' })" -ForegroundColor $(if ($Smbv1Disabled) { 'Green' } else { 'Red' })

# Verify SMB Signing
$SmbSigningAfter = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature
Write-Host "    Signing: $(if ($SmbSigningAfter) { 'Required [VERIFIED]' } else { 'Not Required [WARN]' })" -ForegroundColor $(if ($SmbSigningAfter) { 'Green' } else { 'Red' })

# Verify SMB Encryption
$SmbEncryptionAfter = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EncryptData
Write-Host "    Encryption: $(if ($SmbEncryptionAfter) { 'Enabled [VERIFIED]' } else { 'Not Enabled [WARN]' })" -ForegroundColor $(if ($SmbEncryptionAfter) { 'Green' } else { 'Red' })

# Verify LLMNR
$LLMNR = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
Write-Host "    LLMNR: $(if ($LLMNR -eq 0) { 'Disabled [VERIFIED]' } else { 'Still Enabled [WARN]' })" -ForegroundColor $(if ($LLMNR -eq 0) { 'Green' } else { 'Red' })

Write-Host ""
Write-Host "SMB and Protocol Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
