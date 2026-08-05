<#
.SYNOPSIS
    Windows Firewall Hardening - MedDefense Health Systems
    Task 11: Firewall Lockdown

.DESCRIPTION
    Purpose: Enforce least-privilege network access on DC01 by setting 
    default-deny inbound policy with service-specific allow rules.
    
    WHAT IT DOES: Captures current state, enables all profiles with 
    default-deny inbound, creates 6 allow rules for required services,
    enables logging, and removes conflicting legacy rules.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "[*] Current Firewall State..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. CAPTURE CURRENT STATE
# ------------------------------------------------------------------------------
$Profiles = @{
    "Domain" = Get-NetFirewallProfile -Name Domain
    "Private" = Get-NetFirewallProfile -Name Private
    "Public" = Get-NetFirewallProfile -Name Public
}

$StateLines = @()
foreach ($ProfileName in $Profiles.Keys) {
    $Profile = $Profiles[$ProfileName]
    $Status = if ($Profile.Enabled) { "ON" } else { "OFF" }
    $Inbound = if ($Profile.DefaultInboundAction -eq "Allow") { "Allow" } else { "Block" }
    $Indicator = if ($Profile.DefaultInboundAction -eq "Allow") { "[!]" } else { "" }
    $Line = "    $ProfileName`: $Status, DefaultInbound: $Inbound $Indicator"
    $StateLines += $Line
}
$StateLines | ForEach-Object { Write-Host $_ }

# Capture legacy rules count for later
$LegacyRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
               Where-Object { $_.Name -notlike "MedDef-*" -and $_.Name -notlike "*-CUSTOM-*" }

# ------------------------------------------------------------------------------
# 2. SET DEFAULT-DENY ON ALL PROFILES
# ------------------------------------------------------------------------------
Write-Host "[*] Setting default-deny on all profiles..." -NoNewline -ForegroundColor Cyan
Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 3. CREATE ALLOW RULES FOR REQUIRED SERVICES
# ------------------------------------------------------------------------------
Write-Host "[*] Creating allow rules..." -ForegroundColor Cyan

# Helper function to create rules with error handling
function New-FirewallRuleSafe {
    param(
        [string]$DisplayName,
        [string]$Direction = "Inbound",
        [string]$Action = "Allow",
        [string]$Protocol,
        [string]$LocalPort,
        [string]$RemoteAddress,
        [string]$Description = ""
    )
    
    try {
        $Params = @{
            DisplayName = $DisplayName
            Direction = $Direction
            Action = $Action
            Protocol = $Protocol
            Enabled = $True
        }
        if ($LocalPort) { $Params.LocalPort = $LocalPort }
        if ($RemoteAddress) { $Params.RemoteAddress = $RemoteAddress }
        if ($Description) { $Params.Description = $Description }
        
        # Check if rule already exists
        $Existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if ($Existing) {
            Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        }
        
        New-NetFirewallRule @Params -ErrorAction Stop
        Write-Host "    $DisplayName : $Protocol $($LocalPort -replace ',','-')" -NoNewline -ForegroundColor White
        if ($RemoteAddress) { Write-Host " from $RemoteAddress" -NoNewline -ForegroundColor Gray }
        Write-Host " [CREATED]" -ForegroundColor Green
    }
    catch {
        Write-Host "    $DisplayName : [FAILED] - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Rule 1: RDP from management subnet
New-FirewallRuleSafe -DisplayName "MedDef-RDP-Mgmt" -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "10.10.3.0/24" -Description "RDP access from management subnet"

# Rule 2: DNS (TCP/UDP 53)
New-FirewallRuleSafe -DisplayName "MedDef-DNS-TCP" -Protocol TCP -LocalPort 53 `
    -Description "DNS TCP for domain controller operation"
New-FirewallRuleSafe -DisplayName "MedDef-DNS-UDP" -Protocol UDP -LocalPort 53 `
    -Description "DNS UDP for domain controller operation"

# Rule 3: LDAP (TCP 389)
New-FirewallRuleSafe -DisplayName "MedDef-LDAP" -Protocol TCP -LocalPort 389 `
    -Description "LDAP for AD authentication"

# Rule 4: Kerberos (TCP/UDP 88)
New-FirewallRuleSafe -DisplayName "MedDef-Kerberos-TCP" -Protocol TCP -LocalPort 88 `
    -Description "Kerberos TCP for AD authentication"
New-FirewallRuleSafe -DisplayName "MedDef-Kerberos-UDP" -Protocol UDP -LocalPort 88 `
    -Description "Kerberos UDP for AD authentication"

# Rule 5: SMB from server subnet
New-FirewallRuleSafe -DisplayName "MedDef-SMB" -Protocol TCP -LocalPort 445 `
    -RemoteAddress "10.10.1.0/24" -Description "SMB from server subnet"

# Rule 6: WinRM from management subnet (5985 HTTP, 5986 HTTPS)
New-FirewallRuleSafe -DisplayName "MedDef-WinRM" -Protocol TCP -LocalPort "5985,5986" `
    -RemoteAddress "10.10.3.0/24" -Description "WinRM from management subnet"

# ------------------------------------------------------------------------------
# 4. ENABLE LOGGING FOR DROPPED PACKETS
# ------------------------------------------------------------------------------
Write-Host "[*] Enabling dropped packet logging..." -NoNewline -ForegroundColor Cyan
$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
if (!(Test-Path "C:\Windows\System32\LogFiles\Firewall")) {
    New-Item -Path "C:\Windows\System32\LogFiles\Firewall" -ItemType Directory -Force | Out-Null
}
Set-NetFirewallProfile -All -LogAllowed False -LogBlocked True -LogFileName $LogPath -LogMaxSizeKilobytes 16384
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 5. DISABLE LEGACY ALLOW RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Disabling legacy allow rules..." -NoNewline -ForegroundColor Cyan
$LegacyCount = ($LegacyRules | Measure-Object).Count
$LegacyRules | ForEach-Object {
    Disable-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
}
Write-Host " [$LegacyCount disabled]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 6. VERIFICATION
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

# Verify profiles
$AllBlocked = $true
foreach ($ProfileName in @("Domain", "Private", "Public")) {
    $Profile = Get-NetFirewallProfile -Name $ProfileName
    if ($Profile.DefaultInboundAction -ne "Block" -or $Profile.Enabled -ne $True) {
        $AllBlocked = $false
        Write-Host "    $ProfileName`: ON, DefaultInbound: $($Profile.DefaultInboundAction) [FAILED]" -ForegroundColor Red
    } else {
        Write-Host "    $ProfileName`: ON, DefaultInbound: Block [VERIFIED]" -ForegroundColor Green
    }
}

# Verify custom rules
$CustomRules = Get-NetFirewallRule -DisplayName "MedDef-*" -Enabled True | Measure-Object
$RuleCount = $CustomRules.Count
$ExpectedCount = 6 # MedDef-RDP-Mgmt, MedDef-DNS-TCP, MedDef-DNS-UDP, MedDef-LDAP, MedDef-Kerberos-TCP, MedDef-Kerberos-UDP, MedDef-SMB, MedDef-WinRM = 7 actually
$ExpectedCount = 7 # Correct count: 7 rules (RDP, DNS-TCP, DNS-UDP, LDAP, Kerberos-TCP, Kerberos-UDP, SMB, WinRM) 
$ExpectedCount = 8 # Actually: RDP + DNS(TCP/UDP) + LDAP + Kerberos(TCP/UDP) + SMB + WinRM = 1+2+1+2+1+1 = 8

if ($RuleCount -ge 8) {
    Write-Host "    Custom rules: $RuleCount active [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Custom rules: $RuleCount/8 active [WARNING] - Some rules may be missing" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] Windows Firewall Lockdown Complete!" -ForegroundColor Green
Write-Host "    Logs: $LogPath" -ForegroundColor Gray
Write-Host "    To view logs: Get-Content '$LogPath' -Tail 50" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# 7. OPTIONAL: TEST CONNECTIVITY (SKIP IF NOT ON MANAGEMENT SUBNET)
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Quick connectivity test (from this host)..." -ForegroundColor Cyan
$TestPorts = @(389, 88, 53, 445)
foreach ($Port in $TestPorts) {
    $Test = Test-NetConnection -ComputerName "localhost" -Port $Port -WarningAction SilentlyContinue
    if ($Test.TcpTestSucceeded) {
        Write-Host "    TCP $Port : [OPEN]" -ForegroundColor Green
    } else {
        Write-Host "    TCP $Port : [CLOSED]" -ForegroundColor Yellow
    }
}

exit 0
<#
.SYNOPSIS
    Windows Firewall Hardening - MedDefense Health Systems
    Task 11: Firewall Lockdown

.DESCRIPTION
    Purpose: Enforce least-privilege network access on DC01 by setting
    default-deny inbound policy with service-specific allow rules.
    
    WHAT IT DOES: Captures current state, enables all profiles with
    default-deny inbound, creates 6 allow rules for required services,
    enables logging, and removes conflicting legacy rules.

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "[*] Current Firewall State..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. CAPTURE CURRENT STATE
# ------------------------------------------------------------------------------
$Profiles = @{
    "Domain" = Get-NetFirewallProfile -Name Domain
    "Private" = Get-NetFirewallProfile -Name Private
    "Public" = Get-NetFirewallProfile -Name Public
}

$StateLines = @()
foreach ($ProfileName in $Profiles.Keys) {
    $Profile = $Profiles[$ProfileName]
    $Status = if ($Profile.Enabled) { "ON" } else { "OFF" }
    $Inbound = if ($Profile.DefaultInboundAction -eq "Allow") { "Allow" } else { "Block" }
    $Indicator = if ($Profile.DefaultInboundAction -eq "Allow") { "[!]" } else { "" }
    $Line = "    $ProfileName`: $Status, DefaultInbound: $Inbound $Indicator"
    $StateLines += $Line
}
$StateLines | ForEach-Object { Write-Host $_ }

# Capture legacy rules count for later
$LegacyRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | 
               Where-Object { $_.Name -notlike "MedDef-*" -and $_.Name -notlike "*-CUSTOM-*" }

# ------------------------------------------------------------------------------
# 2. SET DEFAULT-DENY ON ALL PROFILES
# ------------------------------------------------------------------------------
Write-Host "[*] Setting default-deny on all profiles..." -NoNewline -ForegroundColor Cyan
Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 3. CREATE ALLOW RULES FOR REQUIRED SERVICES
# ------------------------------------------------------------------------------
Write-Host "[*] Creating allow rules..." -ForegroundColor Cyan

function New-FirewallRuleSafe {
    param(
        [string]$DisplayName,
        [string]$Direction = "Inbound",
        [string]$Action = "Allow",
        [string]$Protocol,
        [string]$LocalPort,
        [string]$RemoteAddress,
        [string]$Description = ""
    )
    
    try {
        $Params = @{
            DisplayName = $DisplayName
            Direction = $Direction
            Action = $Action
            Protocol = $Protocol
            Enabled = $True
        }
        if ($LocalPort) { $Params.LocalPort = $LocalPort }
        if ($RemoteAddress) { $Params.RemoteAddress = $RemoteAddress }
        if ($Description) { $Params.Description = $Description }
        
        $Existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if ($Existing) {
            Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        }
        
        New-NetFirewallRule @Params -ErrorAction Stop
        Write-Host "    $DisplayName : $Protocol $($LocalPort -replace ',','-')" -NoNewline -ForegroundColor White
        if ($RemoteAddress) { Write-Host " from $RemoteAddress" -NoNewline -ForegroundColor Gray }
        Write-Host " [CREATED]" -ForegroundColor Green
    }
    catch {
        Write-Host "    $DisplayName : [FAILED] - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Rule 1: RDP from management subnet
New-FirewallRuleSafe -DisplayName "MedDef-RDP-Mgmt" -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "10.10.3.0/24" -Description "RDP access from management subnet"

# Rule 2: DNS (TCP/UDP 53)
New-FirewallRuleSafe -DisplayName "MedDef-DNS-TCP" -Protocol TCP -LocalPort 53 `
    -Description "DNS TCP for domain controller operation"
New-FirewallRuleSafe -DisplayName "MedDef-DNS-UDP" -Protocol UDP -LocalPort 53 `
    -Description "DNS UDP for domain controller operation"

# Rule 3: LDAP (TCP 389)
New-FirewallRuleSafe -DisplayName "MedDef-LDAP" -Protocol TCP -LocalPort 389 `
    -Description "LDAP for AD authentication"

# Rule 4: Kerberos (TCP/UDP 88)
New-FirewallRuleSafe -DisplayName "MedDef-Kerberos-TCP" -Protocol TCP -LocalPort 88 `
    -Description "Kerberos TCP for AD authentication"
New-FirewallRuleSafe -DisplayName "MedDef-Kerberos-UDP" -Protocol UDP -LocalPort 88 `
    -Description "Kerberos UDP for AD authentication"

# Rule 5: SMB from server subnet
New-FirewallRuleSafe -DisplayName "MedDef-SMB" -Protocol TCP -LocalPort 445 `
    -RemoteAddress "10.10.1.0/24" -Description "SMB from server subnet"

# Rule 6: WinRM from management subnet
New-FirewallRuleSafe -DisplayName "MedDef-WinRM" -Protocol TCP -LocalPort "5985,5986" `
    -RemoteAddress "10.10.3.0/24" -Description "WinRM from management subnet"

# ------------------------------------------------------------------------------
# 4. ENABLE LOGGING FOR DROPPED PACKETS
# ------------------------------------------------------------------------------
Write-Host "[*] Enabling dropped packet logging..." -NoNewline -ForegroundColor Cyan
$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
if (!(Test-Path "C:\Windows\System32\LogFiles\Firewall")) {
    New-Item -Path "C:\Windows\System32\LogFiles\Firewall" -ItemType Directory -Force | Out-Null
}
Set-NetFirewallProfile -All -LogAllowed False -LogBlocked True -LogFileName $LogPath -LogMaxSizeKilobytes 16384
Write-Host " [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 5. DISABLE LEGACY ALLOW RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Disabling legacy allow rules..." -NoNewline -ForegroundColor Cyan
$LegacyCount = ($LegacyRules | Measure-Object).Count
$LegacyRules | ForEach-Object {
    Disable-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
}
Write-Host " [$LegacyCount disabled]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 6. VERIFICATION
# ------------------------------------------------------------------------------
Write-Host "[*] Verification..." -ForegroundColor Cyan

$AllBlocked = $true
foreach ($ProfileName in @("Domain", "Private", "Public")) {
    $Profile = Get-NetFirewallProfile -Name $ProfileName
    if ($Profile.DefaultInboundAction -ne "Block" -or $Profile.Enabled -ne $True) {
        $AllBlocked = $false
        Write-Host "    $ProfileName`: ON, DefaultInbound: $($Profile.DefaultInboundAction) [FAILED]" -ForegroundColor Red
    } else {
        Write-Host "    $ProfileName`: ON, DefaultInbound: Block [VERIFIED]" -ForegroundColor Green
    }
}

$CustomRules = Get-NetFirewallRule -DisplayName "MedDef-*" -Enabled True | Measure-Object
$RuleCount = $CustomRules.Count
if ($RuleCount -ge 8) {
    Write-Host "    Custom rules: $RuleCount active [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Custom rules: $RuleCount/8 active [WARNING]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] Windows Firewall Lockdown Complete!" -ForegroundColor Green
Write-Host "    Logs: $LogPath" -ForegroundColor Gray
Write-Host "    To view logs: Get-Content '$LogPath' -Tail 50" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# 7. OPTIONAL: TEST CONNECTIVITY
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Quick connectivity test (from this host)..." -ForegroundColor Cyan
$TestPorts = @(389, 88, 53, 445)
foreach ($Port in $TestPorts) {
    $Test = Test-NetConnection -ComputerName "localhost" -Port $Port -WarningAction SilentlyContinue
    if ($Test.TcpTestSucceeded) {
        Write-Host "    TCP $Port : [OPEN]" -ForegroundColor Green
    } else {
        Write-Host "    TCP $Port : [CLOSED]" -ForegroundColor Yellow
    }
}

exit 0
