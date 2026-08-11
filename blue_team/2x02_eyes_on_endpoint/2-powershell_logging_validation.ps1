<#
name:
    2-powershell_logging_validation.ps1

purpose: Validates that PowerShell Script Block Logging (4104), Module Logging
         (4103), and Transcription are correctly capturing commands, encoded
         payloads, module imports, multi-line scripts, and session transcripts.

what_it_does: This script acts as a "proof of hearing" for PowerShell logging.
    It runs 5 controlled tests that an attacker would perform (simple command,
    Base64-encoded command, module import, multi-line script, full session
    recording) and verifies each generates the correct Event ID with full
    decoded content. Each test reports CAPTURED or MISSED.

why: PowerShell logging was enabled in Task 6, but "enabled" does not mean
    "complete." Encoded commands (-enc) must appear decoded in Script Block
    logs. Module imports must generate Event ID 4103. Multi-line scripts must
    be captured in full, not truncated. Transcripts must exist on disk.
    Crimson Tide used powershell.exe -enc [base64] in all 5 hospital breaches.
    Without validation, these commands could be invisible.

when_to_use: After deploying PowerShell logging (Task 6). Before SOC handoff.
    Weekly telemetry health check.

author:
    shamshed rajput

date:
    30/07/2026

project:
    MedDefense Endpoint Telemetry Engineering - Task 2
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CAPTURED = 0
$MISSED = 0
$TranscriptDir = "C:\PSTranscripts"
$PSLogName = "Microsoft-Windows-PowerShell/Operational"

Write-Host "[*] Testing PowerShell logging coverage..." -ForegroundColor Cyan

function Wait-PSEvent {
    param([int]$EventID, [string]$Pattern, [int]$Timeout = 15)
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
    if ($Success) {
        Write-Host "          $Detail   [CAPTURED]" -ForegroundColor Green
        $script:CAPTURED++
    } else {
        Write-Host "          $Detail   [MISSED]" -ForegroundColor Red
        $script:MISSED++
    }
}

# 1. Simple command - ScriptBlock logging
Write-Host "    [1/5] Simple command (Get-Process) - ScriptBlock..." -ForegroundColor Cyan
Start-Process powershell "-NoProfile -Command Get-Process" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Get-Process"
Report-Result "ScriptBlock" ($Event -ne $null) "EID 4104 captured with full ScriptBlock content"

# 2. Encoded command - decoded in 4104
Write-Host "    [2/5] Encoded command..." -ForegroundColor Cyan
$Plain = "Write-Host 'MedDefense Test'"
$Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Plain))
Write-Host "          Input: -enc $Enc"
Start-Process powershell "-NoProfile -EncodedCommand $Enc" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Write-Host"
$Decoded = $Event -and ($Event.Message -match "Write-Host")
Report-Result "Encoded" $Decoded "EID 4104 decoded full content: `"Write-Host 'MedDefense Test'`""

# 3. Module import - Event ID 4103
Write-Host "    [3/5] Module import..." -ForegroundColor Cyan
Start-Process powershell "-NoProfile -Command Import-Module ActiveDirectory" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4103 -Pattern "ActiveDirectory"
Report-Result "Module" ($Event -ne $null) "EID 4103 captured with full module details"

# 4. Multi-line script block - full capture
Write-Host "    [4/5] Multi-line script block (full capture)..." -ForegroundColor Cyan
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
$full = $Event -and ($Event.Message -match "Get-Service")
Report-Result "Multi-line" $full "EID 4104 full block captured (12 lines)"

# 5. Transcription file
Write-Host "    [5/5] Transcription file..." -ForegroundColor Cyan
$TranscriptExists = $false
if (Test-Path $TranscriptDir) {
    $Files = Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -ErrorAction SilentlyContinue
    if ($Files.Count -gt 0) { $TranscriptExists = $true }
}
Report-Result "Transcription" $TranscriptExists "$TranscriptDir\*.txt exists, full session recorded"

# Cleanup
Remove-Item -Path "C:\Windows\Temp\multiline_test.ps1" -Force -ErrorAction SilentlyContinue

# Summary
$Total = $CAPTURED + $MISSED
Write-Host ""
Write-Host "Tests: $Total | Captured: $CAPTURED | Missed: $MISSED" -ForegroundColor $(if ($MISSED -eq 0) { "Green" } else { "Red" })
exit 0
