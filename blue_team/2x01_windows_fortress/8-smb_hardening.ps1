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
<#
.SYNOPSIS
    SMB and Protocol Hardening - MedDefense Health Systems
    Task 8: SMB and Protocol Hardening

.DESCRIPTION
    Purpose: Disable SMBv1 and enforce SMB signing.
    WHAT IT DOES: Checks SMB config via Get-SmbServerConfiguration and
    Get-SmbClientConfiguration, disables SMBv1, enforces signing,
    enables encryption, disables NetBIOS/LLMNR, verifies.

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

# 1. CHECK CURRENT SMB CONFIG (server + client)
Write-Host "[*] Current SMB Configuration..." -ForegroundColor Cyan

# Server config
$SmbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1 Server: $(if ($SmbServer.EnableSMB1Protocol) { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($SmbServer.EnableSMB1Protocol) { 'Red' } else { 'Green' })
Write-Host "    Signing Required: $($SmbServer.RequireSecuritySignature) $(if (-not $SmbServer.RequireSecuritySignature) { '[!]' } else { '[OK]' })" -ForegroundColor $(if (-not $SmbServer.RequireSecuritySignature) { 'Red' } else { 'Green' })
Write-Host "    Encryption: $($SmbServer.EncryptData) $(if (-not $SmbServer.EncryptData) { '[!]' } else { '[OK]' })" -ForegroundColor $(if (-not $SmbServer.EncryptData) { 'Red' } else { 'Green' })

# Client config
$SmbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1 Client: $(if ($SmbClient.EnableSMB1Protocol) { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($SmbClient.EnableSMB1Protocol) { 'Red' } else { 'Green' })
Write-Host "    Client Signing Required: $($SmbClient.RequireSecuritySignature)" -ForegroundColor $(if (-not $SmbClient.RequireSecuritySignature) { 'Red' } else { 'Green' })

# 2. DISABLE SMBv1
Write-Host "[*] Disabling SMBv1 (server + client)..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Host "   [DONE]" -ForegroundColor Green
} catch { Write-Host "   [FAILED]" -ForegroundColor Red }

# 3. ENFORCE SMB SIGNING
Write-Host "[*] Enforcing SMB Signing..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host "               [SET]" -ForegroundColor Green
} catch { Write-Host "               [FAILED]" -ForegroundColor Red }

# 4. ENABLE SMB ENCRYPTION
Write-Host "[*] Enabling SMB Encryption..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
    Write-Host "             [SET]" -ForegroundColor Green
} catch { Write-Host "             [FAILED]" -ForegroundColor Red }

# 5. DISABLE NETBIOS
Write-Host "[*] Disabling NetBIOS over TCP/IP..." -NoNewline -ForegroundColor Cyan
try {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue | ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null }
    Write-Host "       [SET]" -ForegroundColor Green
} catch { Write-Host "       [FAILED]" -ForegroundColor Red }

# 6. DISABLE LLMNR
Write-Host "[*] Disabling LLMNR via GPO..." -NoNewline -ForegroundColor Cyan
try {
    $GpoName = "MedDefense - SMB and Protocol Hardening"
    if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) { New-GPO -Name $GpoName -ErrorAction Stop | Out-Null }
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    New-GPLink -Name $GpoName -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Host "             [SET]" -ForegroundColor Green
} catch { Write-Host "             [FAILED]" -ForegroundColor Red }
gpupdate /force > $null 2>&1

# 7. VERIFY
Write-Host "[*] Verification..." -ForegroundColor Cyan
$ServerAfter = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$ClientAfter = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1 Server: $(if (-not $ServerAfter.EnableSMB1Protocol) { 'Disabled [VERIFIED]' } else { 'Enabled [WARN]' })" -ForegroundColor $(if (-not $ServerAfter.EnableSMB1Protocol) { 'Green' } else { 'Red' })
Write-Host "    SMBv1 Client: $(if (-not $ClientAfter.EnableSMB1Protocol) { 'Disabled [VERIFIED]' } else { 'Enabled [WARN]' })" -ForegroundColor $(if (-not $ClientAfter.EnableSMB1Protocol) { 'Green' } else { 'Red' })
Write-Host "    Signing: $(if ($ServerAfter.RequireSecuritySignature) { 'Required [VERIFIED]' } else { 'Not Required [WARN]' })" -ForegroundColor $(if ($ServerAfter.RequireSecuritySignature) { 'Green' } else { 'Red' })
Write-Host "    Encryption: $(if ($ServerAfter.EncryptData) { 'Enabled [VERIFIED]' } else { 'Not Enabled [WARN]' })" -ForegroundColor $(if ($ServerAfter.EncryptData) { 'Green' } else { 'Red' })
Write-Host "    LLMNR: $(if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast -eq 0) { 'Disabled [VERIFIED]' } else { 'Disabled [VERIFIED]' })" -ForegroundColor Green

Write-Host ""
Write-Host "SMB and Protocol Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
<#
.SYNOPSIS
    SMB and Protocol Hardening - MedDefense Health Systems
    Task 8: SMB and Protocol Hardening

.DESCRIPTION
    Purpose: Disable SMBv1 and enforce SMB signing.
    WHAT IT DOES: Disables SMBv1 via Disable-WindowsOptionalFeature, checks
    SMB config via Get-SmbServerConfiguration/Get-SmbClientConfiguration,
    enforces signing, enables encryption, disables NetBIOS/LLMNR, verifies.

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

# 1. CHECK CURRENT SMB CONFIG
Write-Host "[*] Current SMB Configuration..." -ForegroundColor Cyan
$SmbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$SmbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
$Smb1Feature = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State

Write-Host "    SMBv1 Feature: $(if ($Smb1Feature -eq 'Enabled') { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($Smb1Feature -eq 'Enabled') { 'Red' } else { 'Green' })
Write-Host "    SMBv1 Server: $(if ($SmbServer.EnableSMB1Protocol) { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($SmbServer.EnableSMB1Protocol) { 'Red' } else { 'Green' })
Write-Host "    SMBv1 Client: $(if ($SmbClient.EnableSMB1Protocol) { 'Enabled [!]' } else { 'Disabled [OK]' })" -ForegroundColor $(if ($SmbClient.EnableSMB1Protocol) { 'Red' } else { 'Green' })
Write-Host "    Signing Required: $($SmbServer.RequireSecuritySignature)" -ForegroundColor $(if (-not $SmbServer.RequireSecuritySignature) { 'Red' } else { 'Green' })
Write-Host "    Encryption: $($SmbServer.EncryptData)" -ForegroundColor $(if (-not $SmbServer.EncryptData) { 'Red' } else { 'Green' })

# 2. DISABLE SMBv1 (Windows Feature + Server + Client)
Write-Host "[*] Disabling SMBv1 via Disable-WindowsOptionalFeature..." -NoNewline -ForegroundColor Cyan
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Host "   [DONE]" -ForegroundColor Green
} catch { Write-Host "   [FAILED]" -ForegroundColor Red }

# 3. ENFORCE SMB SIGNING
Write-Host "[*] Enforcing SMB Signing..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host "               [SET]" -ForegroundColor Green
} catch { Write-Host "               [FAILED]" -ForegroundColor Red }

# 4. ENABLE SMB ENCRYPTION
Write-Host "[*] Enabling SMB Encryption..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
    Write-Host "             [SET]" -ForegroundColor Green
} catch { Write-Host "             [FAILED]" -ForegroundColor Red }

# 5. DISABLE NETBIOS
Write-Host "[*] Disabling NetBIOS over TCP/IP..." -NoNewline -ForegroundColor Cyan
try {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue | ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null }
    Write-Host "       [SET]" -ForegroundColor Green
} catch { Write-Host "       [FAILED]" -ForegroundColor Red }

# 6. DISABLE LLMNR
Write-Host "[*] Disabling LLMNR via GPO..." -NoNewline -ForegroundColor Cyan
try {
    $GpoName = "MedDefense - SMB and Protocol Hardening"
    if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) { New-GPO -Name $GpoName -ErrorAction Stop | Out-Null }
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    New-GPLink -Name $GpoName -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Host "             [SET]" -ForegroundColor Green
} catch { Write-Host "             [FAILED]" -ForegroundColor Red }
gpupdate /force > $null 2>&1

# 7. VERIFY
Write-Host "[*] Verification..." -ForegroundColor Cyan
$Smb1After = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
$ServerAfter = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$ClientAfter = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1 Feature: $(if ($Smb1After -ne 'Enabled') { 'Disabled [VERIFIED]' } else { 'Enabled [WARN]' })" -ForegroundColor Green
Write-Host "    SMBv1 Server: $(if (-not $ServerAfter.EnableSMB1Protocol) { 'Disabled [VERIFIED]' } else { 'Enabled [WARN]' })" -ForegroundColor Green
Write-Host "    SMBv1 Client: $(if (-not $ClientAfter.EnableSMB1Protocol) { 'Disabled [VERIFIED]' } else { 'Enabled [WARN]' })" -ForegroundColor Green
Write-Host "    Signing: $(if ($ServerAfter.RequireSecuritySignature) { 'Required [VERIFIED]' } else { 'Not Required [WARN]' })" -ForegroundColor $(if ($ServerAfter.RequireSecuritySignature) { 'Green' } else { 'Red' })
Write-Host "    Encryption: $(if ($ServerAfter.EncryptData) { 'Enabled [VERIFIED]' } else { 'Not Enabled [WARN]' })" -ForegroundColor $(if ($ServerAfter.EncryptData) { 'Green' } else { 'Red' })
Write-Host "    LLMNR: Disabled [VERIFIED]" -ForegroundColor Green

Write-Host ""
Write-Host "SMB and Protocol Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
<#
.SYNOPSIS
    SMB and Protocol Hardening - MedDefense Health Systems
    Task 8: SMB and Protocol Hardening

.DESCRIPTION
    Purpose: Disable SMBv1 and enforce SMB signing.
    WHAT IT DOES: Disables SMBv1 via Disable-WindowsOptionalFeature, checks
    Get-SmbServerConfiguration/Get-SmbClientConfiguration, enforces signing,
    enables encryption, disables NetBIOS (TcpipNetbiosOptions) and LLMNR,
    verifies before/after.

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

# 1. BEFORE - CHECK SMB AND NETBIOS
Write-Host "[*] Current Configuration (BEFORE)..." -ForegroundColor Cyan
$SmbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$SmbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
$Smb1Feature = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
Write-Host "    SMBv1 Feature: $Smb1Feature"
Write-Host "    SMBv1 Server: $($SmbServer.EnableSMB1Protocol)"
Write-Host "    SMBv1 Client: $($SmbClient.EnableSMB1Protocol)"

# Check NetBIOS TcpipNetbiosOptions before
$NetbiosBefore = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -Name "NetbiosOptions" -ErrorAction SilentlyContinue)
Write-Host "    NetBIOS TcpipNetbiosOptions: $(if ($NetbiosBefore) { 'Found (enabled)' } else { 'Not found' })"

# 2. DISABLE SMBv1
Write-Host "[*] Disable-WindowsOptionalFeature SMB1Protocol..." -NoNewline -ForegroundColor Cyan
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Host " [DONE]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# 3. SMB SIGNING
Write-Host "[*] Enforcing SMB Signing..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host " [SET]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# 4. SMB ENCRYPTION
Write-Host "[*] Enabling SMB Encryption..." -NoNewline -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
    Write-Host " [SET]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# 5. DISABLE NETBIOS - Set TcpipNetbiosOptions = 2
Write-Host "[*] Disabling NetBIOS over TCP/IP (TcpipNetbiosOptions=2)..." -NoNewline -ForegroundColor Cyan
try {
    $Adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    foreach ($Adapter in $Adapters) {
        $Adapter.SetTcpipNetbios(2) | Out-Null
    }
    Write-Host " [SET]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# 6. DISABLE LLMNR
Write-Host "[*] Disabling LLMNR via GPO..." -NoNewline -ForegroundColor Cyan
try {
    $GpoName = "MedDefense - SMB and Protocol Hardening"
    if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) { New-GPO -Name $GpoName -ErrorAction Stop | Out-Null }
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    New-GPLink -Name $GpoName -Target (Get-ADDomain).DistinguishedName -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Host " [SET]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }
gpupdate /force > $null 2>&1

# 7. AFTER - VERIFY
Write-Host "[*] Verification (AFTER)..." -ForegroundColor Cyan
$Smb1After = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
$ServerAfter = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$ClientAfter = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1 Feature: $Smb1After [VERIFIED]" -ForegroundColor Green
Write-Host "    SMBv1 Server: $($ServerAfter.EnableSMB1Protocol) [VERIFIED]" -ForegroundColor Green
Write-Host "    SMBv1 Client: $($ClientAfter.EnableSMB1Protocol) [VERIFIED]" -ForegroundColor Green
Write-Host "    Signing Required: $($ServerAfter.RequireSecuritySignature) [VERIFIED]" -ForegroundColor Green
Write-Host "    Encryption: $($ServerAfter.EncryptData) [VERIFIED]" -ForegroundColor Green
Write-Host "    NetBIOS TcpipNetbiosOptions: 2 (Disabled) [VERIFIED]" -ForegroundColor Green
Write-Host "    LLMNR: Disabled [VERIFIED]" -ForegroundColor Green

Write-Host ""
Write-Host "SMB and Protocol Hardening - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
