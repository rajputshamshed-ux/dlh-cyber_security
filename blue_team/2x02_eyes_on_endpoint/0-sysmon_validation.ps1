# Name: 0-sysmon_validation.ps1
# Author: shamshed rajput
# Date: 30/07/2026
# Purpose: Validate Sysmon telemetry coverage for MedDefense Health Systems

<#
.SYNOPSIS
    Sysmon Telemetry Validation - MedDefense Health Systems
    Task 0: Sysmon Telemetry Validation

.DESCRIPTION
    Purpose: Validate Sysmon captures security events by triggering actions
    and verifying Event IDs 1,3,11,13,22.
    
    WHAT IT DOES: Triggers 5 controlled attacker-like actions and checks
    Sysmon logs with Get-WinEvent. Reports PASS/MISSED for each.
    
    WHY: Deployment does not equal coverage. Silent blind spots must be found.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PASS = 0; $FAIL = 0
Write-Host "[*] Running Sysmon telemetry validation..." -ForegroundColor Cyan

# TEST 1
Write-Host "    [1/5] Process creation (Event ID 1)..." -ForegroundColor Cyan
$Before = Get-Date; cmd /c whoami 2>&1 | Out-Null; Start-Sleep -Seconds 2
$EID1 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $Before } | Select-Object -First 1
if ($EID1) { Write-Host "          Sysmon EID 1 captured   [PASS]" -ForegroundColor Green; $PASS++ } else { Write-Host "          [MISSED]" -ForegroundColor Red; $FAIL++ }

# TEST 2
Write-Host "    [2/5] Network connection (Event ID 3)..." -ForegroundColor Cyan
$Before = Get-Date; Invoke-WebRequest -Uri "http://localhost" -ErrorAction SilentlyContinue 2>&1 | Out-Null; Start-Sleep -Seconds 2
$EID3 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $Before } | Select-Object -First 1
if ($EID3) { Write-Host "          Sysmon EID 3 captured   [PASS]" -ForegroundColor Green; $PASS++ } else { Write-Host "          [MISSED]" -ForegroundColor Red; $FAIL++ }

# TEST 3
Write-Host "    [3/5] File creation (Event ID 11)..." -ForegroundColor Cyan
$Before = Get-Date; $TestFile = "C:\Windows\Temp\sysmon_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
"MedDefense Test" | Out-File -FilePath $TestFile -Encoding UTF8; Start-Sleep -Seconds 2
$EID11 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $Before } | Select-Object -First 1
if ($EID11) { Write-Host "          Sysmon EID 11 captured   [PASS]" -ForegroundColor Green; $PASS++ } else { Write-Host "          [MISSED]" -ForegroundColor Red; $FAIL++ }

# TEST 4
Write-Host "    [4/5] Registry modification (Event ID 13)..." -ForegroundColor Cyan
$Before = Get-Date; New-Item -Path "HKCU:\Software\MedDefense" -Force 2>&1 | Out-Null
New-ItemProperty -Path "HKCU:\Software\MedDefense" -Name "SysmonTest" -Value "test" -Force 2>&1 | Out-Null; Start-Sleep -Seconds 2
$EID13 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=13]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $Before } | Select-Object -First 1
if ($EID13) { Write-Host "          Sysmon EID 13 captured   [PASS]" -ForegroundColor Green; $PASS++ } else { Write-Host "          [MISSED]" -ForegroundColor Red; $FAIL++ }

# TEST 5
Write-Host "    [5/5] DNS query (Event ID 22)..." -ForegroundColor Cyan
$Before = Get-Date; nslookup localhost 2>&1 | Out-Null; Start-Sleep -Seconds 2
$EID22 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=22]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $Before } | Select-Object -First 1
if ($EID22) { Write-Host "          Sysmon EID 22 captured   [PASS]" -ForegroundColor Green; $PASS++ } else { Write-Host "          [MISSED]" -ForegroundColor Red; $FAIL++ }

# CLEANUP
Write-Host "[*] Cleanup: removing test artifacts..." -ForegroundColor Cyan
Remove-Item -Path "C:\Windows\Temp\sysmon_test_*.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\MedDefense" -Recurse -Force -ErrorAction SilentlyContinue

# SUMMARY
$Total = $PASS + $FAIL
Write-Host "Actions tested: $Total | Captured: $PASS | Missed: $FAIL"
exit 0
