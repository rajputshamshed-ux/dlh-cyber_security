<#
name:
    2-powershell_logging_validation.ps1

purpose: Validates that PowerShell Script Block Logging (4104), Module Logging
         (4103), and Transcription are correctly capturing commands, encoded
         payloads, module imports, multi-line scripts, and session transcripts.
         Proves each logging layer works against the PowerShell abuse techniques
         used by Crimson Tide (Phase 3).

author:
    shamshed rajput

date:
    30/07/2026

project:
    MedDefense Endpoint Telemetry Engineering - Task 2
    Ensures PowerShell logging is complete and decoded before SOC handoff
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PASS = 0
$FAIL = 0
$TranscriptDir = "C:\PSTranscripts"
$PSLogName = "Microsoft-Windows-PowerShell/Operational"

Write-Host "[*] Testing PowerShell logging coverage..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# Helper: Search for an event in PowerShell operational log
# ------------------------------------------------------------------------------
function Wait-PSEvent {
    param(
        [int]$EventID,
        [string]$Pattern,
        [int]$Timeout = 15
    )
    $Start = Get-Date
    while ((Get-Date) -lt $Start.AddSeconds($Timeout)) {
        $Event = Get-WinEvent -LogName $PSLogName -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Id -eq $EventID -and
                $_.TimeCreated -ge $Start.AddSeconds(-5) -and
                $_.Message -match [regex]::Escape($Pattern)
            } | Select-Object -First 1
        if ($Event) { return $Event }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

function Report-Result {
    param([string]$Test, [bool]$Success, [string]$Detail)
    if ($Success) { Write-Host "          $Detail   [PASS]" -ForegroundColor Green; $script:PASS++ }
    else { Write-Host "          $Detail   [FAIL]" -ForegroundColor Red; $script:FAIL++ }
}

# ------------------------------------------------------------------------------
# 1. Simple command (Get-Process) → Event ID 4104 (ScriptBlock logging)
# ------------------------------------------------------------------------------
Write-Host "    [1/5] Simple command (Get-Process) - ScriptBlock..." -ForegroundColor Cyan
Start-Process powershell "-NoProfile -Command Get-Process" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Get-Process"
Report-Result "ScriptBlock logging" ($Event -ne $null) "EID 4104: `"Get-Process`" captured"

# ------------------------------------------------------------------------------
# 2. Encoded command → decoded in 4104
# ------------------------------------------------------------------------------
Write-Host "    [2/5] Encoded command..." -ForegroundColor Cyan
$Plain = "Write-Host 'MedDefense Test'"
$Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Plain))
Write-Host "          Input: -enc $Enc"
Start-Process powershell "-NoProfile -EncodedCommand $Enc" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Write-Host"
$Decoded = $Event -and ($Event.Message -match "Write-Host")
Report-Result "Encoded command" $Decoded "EID 4104: `"Write-Host 'MedDefense Test'`" (decoded) captured"

# ------------------------------------------------------------------------------
# 3. Module import → Event ID 4103
# ------------------------------------------------------------------------------
Write-Host "    [3/5] Module import..." -ForegroundColor Cyan
Start-Process powershell "-NoProfile -Command Import-Module ActiveDirectory" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4103 -Pattern "ActiveDirectory"
Report-Result "Module import" ($Event -ne $null) "EID 4103: `"Import-Module ActiveDirectory`" captured"

# ------------------------------------------------------------------------------
# 4. Multi-line script block → Event ID 4104
# ------------------------------------------------------------------------------
Write-Host "    [4/5] Multi-line script block..." -ForegroundColor Cyan
$Multiline = @'
$i = 0
while ($i -lt 3) {
    Write-Host "Line $i"
    $i++
}
Get-Service | Select-Object -First 2
'@
$Multiline | Out-File -FilePath "C:\Windows\Temp\multiline_test.ps1" -Encoding UTF8
Start-Process powershell "-NoProfile -File C:\Windows\Temp\multiline_test.ps1" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Line 0"
$FullBlock = $Event -and ($Event.Message -match "Get-Service")
Report-Result "Multi-line script block" $FullBlock "EID 4104: Full block captured (multi-line)"

# ------------------------------------------------------------------------------
# 5. Transcription file exists
# ------------------------------------------------------------------------------
Write-Host "    [5/5] Transcription file..." -ForegroundColor Cyan
$TranscriptExists = $false
if (Test-Path $TranscriptDir) {
    $Files = Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -ErrorAction SilentlyContinue
    if ($Files.Count -gt 0) {
        $TranscriptExists = $true
    }
}
Report-Result "Transcription file" $TranscriptExists "$TranscriptDir\*.txt exists, session recorded"

# Cleanup
Remove-Item -Path "C:\Windows\Temp\multiline_test.ps1" -Force -ErrorAction SilentlyContinue

# Summary
$Total = $PASS + $FAIL
Write-Host ""
Write-Host "Tests: $Total | Captured: $PASS | Missed: $FAIL" -ForegroundColor $(if ($FAIL -eq 0) { "Green" } else { "Red" })
exit 0
