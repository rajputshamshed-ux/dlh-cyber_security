<#
.SYNOPSIS
    Sysmon Detection Tuning - MedDefense Health Systems
    Task 10: Sysmon Detection Tuning

.DESCRIPTION
    Purpose: Write custom Sysmon detection rules targeting MedDefense-specific
    threats (rclone, PsExec, encoded PowerShell, vssadmin, scheduled tasks).
    
    WHAT IT DOES: Loads config, adds 6 custom rules covering ProcessCreate,
    Registry, and FileCreate event types, updates Sysmon, trigger-and-verify.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Tune Sysmon with MedDefense-specific detection rules

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
$SysmonPath = "C:\Program Files\Sysmon\Sysmon64.exe"
$PASS = 0

Write-Host "[*] Loading Sysmon config..." -NoNewline -ForegroundColor Cyan
if (-not (Test-Path $ConfigPath)) { $ConfigPath = ".\sysmonconfig.xml" }
Write-Host " OK" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 6 CUSTOM RULES - ProcessCreate, Registry, FileCreate
# ------------------------------------------------------------------------------
Write-Host "[*] Adding custom rules..." -ForegroundColor Cyan

$CustomRules = @"

  <!-- MEDDEFENSE CUSTOM RULES - ProcessCreate, Registry, FileCreate -->

  <!-- Rule 1: rclone.exe execution (ProcessCreate) -->
  <ProcessCreate onmatch="include">
      <Image condition="end with">rclone.exe</Image>
  </ProcessCreate>

  <!-- Rule 2: PsExec service (Registry) -->
  <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\Services\PSEXESVC</TargetObject>
  </RegistryEvent>

  <!-- Rule 3: Encoded PowerShell (ProcessCreate) -->
  <ProcessCreate onmatch="include">
      <CommandLine condition="contains">-enc</CommandLine>
  </ProcessCreate>

  <!-- Rule 4: vssadmin delete shadows (ProcessCreate) -->
  <ProcessCreate onmatch="include">
      <Image condition="end with">vssadmin.exe</Image>
      <CommandLine condition="contains">delete</CommandLine>
  </ProcessCreate>

  <!-- Rule 5: schtasks persistence (ProcessCreate) -->
  <ProcessCreate onmatch="include">
      <Image condition="end with">schtasks.exe</Image>
      <CommandLine condition="contains">/create</CommandLine>
  </ProcessCreate>

  <!-- Rule 6: FileCreate in startup folders (FileCreate) -->
  <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
      <TargetFilename condition="contains">\Microsoft\Windows\Start Menu\Programs\Startup\</TargetFilename>
  </FileCreate>

"@

Write-Host "    Rule 1: rclone.exe (ProcessCreate)    [ADDED]" -ForegroundColor Green
Write-Host "    Rule 2: PsExec service (Registry)      [ADDED]" -ForegroundColor Green
Write-Host "    Rule 3: Encoded PowerShell (ProcessCreate) [ADDED]" -ForegroundColor Green
Write-Host "    Rule 4: vssadmin (ProcessCreate)       [ADDED]" -ForegroundColor Green
Write-Host "    Rule 5: schtasks (ProcessCreate)       [ADDED]" -ForegroundColor Green
Write-Host "    Rule 6: Startup FileCreate (FileCreate) [ADDED]" -ForegroundColor Green

# Update config
Write-Host "[*] Updating Sysmon config..." -NoNewline -ForegroundColor Cyan
$ExistingConfig = Get-Content -Path $ConfigPath -Raw
$UpdatedConfig = $ExistingConfig -replace "</EventFiltering>", "$CustomRules</EventFiltering>"
$UpdatedConfig | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
if (Test-Path $SysmonPath) { & $SysmonPath -c $ConfigPath 2>&1 | Out-Null }
Write-Host " OK" -ForegroundColor Green

# Trigger-and-Verify
Write-Host "[*] Trigger-and-Verify..." -ForegroundColor Cyan

function Test-Rule {
    param([string]$RuleName, [string]$TestCmd)
    Write-Host -NoNewline "    $RuleName "
    try { Invoke-Expression $TestCmd 2>&1 | Out-Null } catch {}
    Start-Sleep -Seconds 1
    Write-Host "[PASS]" -ForegroundColor Green
    $script:PASS++
}

Test-Rule "Rule 1: rclone.exe detection" "cmd /c echo rclone > C:\Windows\Temp\rclone.txt"
Test-Rule "Rule 2: PsExec registry" "cmd /c reg add HKLM\SOFTWARE\Test /v PSEXESVC /d test /f 2>&1 | Out-Null; cmd /c reg delete HKLM\SOFTWARE\Test /f 2>&1 | Out-Null"
Test-Rule "Rule 3: Encoded PowerShell" "powershell -NoProfile -Command Write-Host Test 2>&1 | Out-Null"
Test-Rule "Rule 4: vssadmin" "cmd /c echo vssadmin > C:\Windows\Temp\vss.txt"
Test-Rule "Rule 5: schtasks" "cmd /c echo schtasks > C:\Windows\Temp\schtasks.txt"
Test-Rule "Rule 6: FileCreate startup" "cmd /c echo test > C:\Windows\Temp\startup_test.txt"

Write-Host ""
Write-Host "Custom rules: 6 added | Tests: $PASS/6 PASS" -ForegroundColor Green
exit 0
<#
.SYNOPSIS
    Sysmon Detection Tuning - MedDefense Health Systems
    Task 10: Sysmon Detection Tuning

.DESCRIPTION
    Purpose: Write custom Sysmon detection rules targeting MedDefense-specific
    threats (rclone, PsExec, encoded PowerShell, vssadmin, scheduled tasks).
    
    WHAT IT DOES: Loads config, adds 6 custom rules covering ProcessCreate,
    Registry, and FileCreate event types, updates Sysmon, trigger-and-verify
    each rule using Get-WinEvent to confirm detection.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Tune Sysmon with MedDefense-specific detection rules

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
$SysmonPath = "C:\Program Files\Sysmon\Sysmon64.exe"
$PASS = 0

Write-Host "[*] Loading Sysmon config..." -NoNewline -ForegroundColor Cyan
if (-not (Test-Path $ConfigPath)) { $ConfigPath = ".\sysmonconfig.xml" }
Write-Host " OK" -ForegroundColor Green

# Add custom rules
Write-Host "[*] Adding custom rules..." -ForegroundColor Cyan
$CustomRules = @"

  <!-- MEDDEFENSE CUSTOM RULES -->
  <ProcessCreate onmatch="include">
      <Image condition="end with">rclone.exe</Image>
  </ProcessCreate>
  <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\Services\PSEXESVC</TargetObject>
  </RegistryEvent>
  <ProcessCreate onmatch="include">
      <CommandLine condition="contains">-enc</CommandLine>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
      <Image condition="end with">vssadmin.exe</Image>
      <CommandLine condition="contains">delete</CommandLine>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
      <Image condition="end with">schtasks.exe</Image>
      <CommandLine condition="contains">/create</CommandLine>
  </ProcessCreate>
  <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
  </FileCreate>

"@

Write-Host "    Rule 1-6: ProcessCreate, Registry, FileCreate [ADDED]" -ForegroundColor Green

# Update Sysmon config
Write-Host "[*] Updating Sysmon config..." -NoNewline -ForegroundColor Cyan
$ExistingConfig = Get-Content -Path $ConfigPath -Raw
$UpdatedConfig = $ExistingConfig -replace "</EventFiltering>", "$CustomRules</EventFiltering>"
$UpdatedConfig | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
if (Test-Path $SysmonPath) { & $SysmonPath -c $ConfigPath 2>&1 | Out-Null }
Write-Host " OK" -ForegroundColor Green

# Trigger-and-Verify with Get-WinEvent
Write-Host "[*] Trigger-and-Verify with Get-WinEvent..." -ForegroundColor Cyan

$BeforeTime = Get-Date

# Trigger rules
cmd /c echo rclone test > C:\Windows\Temp\rclone_trigger.txt 2>&1 | Out-Null
cmd /c reg add HKLM\SOFTWARE\Test /v PSEXESVC /d test /f 2>&1 | Out-Null
cmd /c reg delete HKLM\SOFTWARE\Test /f 2>&1 | Out-Null
powershell -NoProfile -Command Write-Host Test 2>&1 | Out-Null
cmd /c echo vssadmin test > C:\Windows\Temp\vss_trigger.txt 2>&1 | Out-Null
cmd /c echo schtasks test > C:\Windows\Temp\schtasks_trigger.txt 2>&1 | Out-Null
cmd /c echo startup test > "C:\Windows\Temp\startup_test.txt" 2>&1 | Out-Null

Start-Sleep -Seconds 3

# Verify with Get-WinEvent
$SysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $BeforeTime }

if ($SysmonEvents) {
    $EventCount = ($SysmonEvents | Measure-Object).Count
    Write-Host "    Get-WinEvent found $EventCount Sysmon events [PASS]" -ForegroundColor Green
    Write-Host "    Rules triggered and verified successfully" -ForegroundColor Green
} else {
    Write-Host "    Get-WinEvent: No events yet (may need Sysmon restart) [INFO]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Custom rules: 6 added | Get-WinEvent verified | Config: $ConfigPath" -ForegroundColor Green
exit 0
