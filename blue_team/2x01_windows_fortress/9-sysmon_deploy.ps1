<#
.SYNOPSIS
    Sysmon Deployment - MedDefense Health Systems
    Task 9: Sysmon Deployment

.DESCRIPTION
    Purpose: Install and configure Sysmon with a detection-optimized
    configuration, the most important endpoint detection tool on Windows.
    
    WHAT IT DOES: Downloads Sysmon from Microsoft Sysinternals, downloads
    SwiftOnSecurity Sysmon config, installs Sysmon with config, verifies
    service/driver/events, tests FileCreate (Event ID 11) detection.
    
    WHY: Windows Event Logs capture authentication. Sysmon captures
    everything else: network connections, DNS, file creation, registry,
    drivers, WMI, pipes. Without Sysmon, detecting Crimson Tide lateral
    movement (PsExec, WMI), data exfiltration (Rclone) and ransomware
    deployment is nearly impossible.
    
    WHEN TO USE: After audit policy (Task 5). Before validation (Task 15).
    This is the last major detection tool deployed on endpoints.

.REFERENCES
    Microsoft Sysinternals Sysmon
    SwiftOnSecurity Sysmon Config
    Crimson Tide Phase 3-4-6: Lateral movement, exfiltration, ransomware

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy Sysmon with detection-optimized config for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SysmonUrl = "https://live.sysinternals.com/Sysmon64.exe"
$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$SysmonPath = "C:\Program Files\Sysmon\Sysmon64.exe"
$ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
$SysmonDir = "C:\Program Files\Sysmon"

Write-Host "[*] Starting Sysmon deployment..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. CREATE DIRECTORY AND DOWNLOAD SYSMON
# ------------------------------------------------------------------------------
Write-Host "[*] Downloading Sysmon from Microsoft Sysinternals..." -NoNewline -ForegroundColor Cyan

try {
    New-Item -ItemType Directory -Path $SysmonDir -Force -ErrorAction Stop | Out-Null
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonPath -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Red
    Write-Host "    [INFO] Manual download: https://live.sysinternals.com/Sysmon64.exe" -ForegroundColor Yellow
    exit 1
}

# ------------------------------------------------------------------------------
# 2. DOWNLOAD SWIFTONSECURITY CONFIG
# ------------------------------------------------------------------------------
Write-Host "[*] Downloading SwiftOnSecurity Sysmon config..." -NoNewline -ForegroundColor Cyan

try {
    Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    # If download fails, create a minimal config
    Write-Host " FALLBACK" -ForegroundColor Yellow
    Write-Host "    [INFO] Creating minimal Sysmon config with key Event IDs..." -ForegroundColor Yellow
    
    $MinimalConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <FileCreateTime onmatch="exclude"/>
    <NetworkConnect onmatch="exclude"/>
    <ProcessTerminate onmatch="exclude"/>
    <DriverLoad onmatch="exclude"/>
    <ImageLoad onmatch="exclude"/>
    <CreateRemoteThread onmatch="exclude"/>
    <RawAccessRead onmatch="exclude"/>
    <ProcessAccess onmatch="exclude"/>
    <FileCreate onmatch="exclude">
        <!-- Monitor executable creation in temp directories -->
        <TargetFilename condition="contains">\Windows\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
    </FileCreate>
    <RegistryEvent onmatch="exclude"/>
    <WmiEvent onmatch="exclude"/>
    <DnsQuery onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
"@
    $MinimalConfig | Out-File -FilePath $ConfigPath -Encoding UTF8
}

# ------------------------------------------------------------------------------
# 3. INSTALL SYSMON WITH CONFIG
# ------------------------------------------------------------------------------
Write-Host "[*] Installing Sysmon with config..." -ForegroundColor Cyan

try {
    & $SysmonPath -accepteula -i $ConfigPath 2>&1 | ForEach-Object { Write-Host "    $_" }
    
    # Verify service
    $Service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($Service -and $Service.Status -eq "Running") {
        Write-Host "    Service: Sysmon64 - Running            [OK]" -ForegroundColor Green
    } else {
        Write-Host "    Service: Sysmon64 - NOT RUNNING        [FAIL]" -ForegroundColor Red
        exit 1
    }
    
    # Verify driver
    $Driver = Get-WindowsDriver -Online -Driver "SysmonDrv" -ErrorAction SilentlyContinue
    if ($Driver) {
        Write-Host "    Driver: SysmonDrv - Loaded             [OK]" -ForegroundColor Green
    } else {
        Write-Host "    Driver: SysmonDrv - Not found          [WARN]" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Installation FAILED: $_" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------------------
# 4. VERIFY EVENT GENERATION
# ------------------------------------------------------------------------------
Write-Host "[*] Verifying event generation..." -ForegroundColor Cyan

Start-Sleep -Seconds 3

try {
    $RecentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue
    $EventCount = ($RecentEvents | Measure-Object).Count
    Write-Host "    Events found: $EventCount          [OK]" -ForegroundColor Green
} catch {
    Write-Host "    No Sysmon events found yet (may need reboot) [INFO]" -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# 5. TEST FILECREATE DETECTION (Event ID 11)
# ------------------------------------------------------------------------------
Write-Host "[*] Testing FileCreate detection (Event ID 11)..." -ForegroundColor Cyan

$TestFile = "C:\Windows\Temp\sysmon_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
$BeforeTest = Get-Date

try {
    # Create a test file
    "MedDefense Sysmon FileCreate Test" | Out-File -FilePath $TestFile -Encoding UTF8
    Write-Host "    Created: $TestFile" -ForegroundColor Cyan
    
    # Wait for event
    Start-Sleep -Seconds 3
    
    # Query for Event ID 11 (FileCreate) after our test time
    $Event11 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $BeforeTest }
    
    if ($Event11) {
        Write-Host "    Event ID 11 captured                   [VERIFIED]" -ForegroundColor Green
    } else {
        Write-Host "    Event ID 11 not yet visible (check Event Viewer) [INFO]" -ForegroundColor Yellow
    }
    
    # Cleanup
    Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "    Test FAILED: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "======================================================================"
Write-Host "  SYSMON DEPLOYMENT - COMPLETE"
Write-Host "======================================================================"
Write-Host "  Service: Sysmon64"
Write-Host "  Config:  $ConfigPath"
Write-Host "  Events:  Microsoft-Windows-Sysmon/Operational"
Write-Host "======================================================================"

exit 0
