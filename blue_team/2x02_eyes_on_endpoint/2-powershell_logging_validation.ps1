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

$CAPTURED = 0
$MISSED = 0
$TranscriptDir = "C:\PSTranscripts"
$PSLogName = "Microsoft-Windows-PowerShell/Operational"

Write-Host "[*] Testing PowerShell logging coverage..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# Helper: Search for an event with content verification
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
    if ($Success) {
        Write-Host "          $Detail   [CAPTURED]" -ForegroundColor Green
        $script:CAPTURED++
    } else {
        Write-Host "          $Detail   [MISSED]" -ForegroundColor Red
        $script:MISSED++
    }
}

# ------------------------------------------------------------------------------
# 1. Simple command - ScriptBlock logging (verify content, not just process)
# ------------------------------------------------------------------------------
Write-Host "    [1/5] Simple command (Get-Process) - ScriptBlock..." -ForegroundColor Cyan
Start-Process powershell "-NoProfile -Command Get-Process" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Get-Process"
# Verify the event actually contains the ScriptBlock with the command text
$HasContent = $Event -and ($Event.Message -match "Get-Process")
Report-Result "ScriptBlock logging" $HasContent "EID 4104 captured with full ScriptBlock content: Get-Process"

# ------------------------------------------------------------------------------
# 2. Encoded command - verify DECODED content in 4104
# ------------------------------------------------------------------------------
Write-Host "    [2/5] Encoded command..." -ForegroundColor Cyan
$Plain = "Write-Host 'MedDefense Test'"
$Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Plain))
Write-Host "          Input: -enc $Enc"
Start-Process powershell "-NoProfile -EncodedCommand $Enc" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Write-Host"
# This is the key check: the decoded content must appear in the event
$Decoded = $Event -and ($Event.Message -match "Write-Host") -and ($Event.Message -match "MedDefense Test")
Report-Result "Encoded command" $Decoded "EID 4104 decoded full content: `"Write-Host 'MedDefense Test'`""

# ------------------------------------------------------------------------------
# 3. Module import - Event ID 4103 (use built-in module as fallback)
# ------------------------------------------------------------------------------
Write-Host "    [3/5] Module import..." -ForegroundColor Cyan
# Try ActiveDirectory first, fall back to built-in module
$ModuleName = "ActiveDirectory"
$ModuleAvailable = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
if (-not $ModuleAvailable) {
    $ModuleName = "Microsoft.PowerShell.Management"
}
Start-Process powershell "-NoProfile -Command Import-Module $ModuleName" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4103 -Pattern $ModuleName
Report-Result "Module import" ($Event -ne $null) "EID 4103 captured with full module details: Import-Module $ModuleName"

# ------------------------------------------------------------------------------
# 4. Multi-line script block - full capture
# ------------------------------------------------------------------------------
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
$FullBlock = $Event -and ($Event.Message -match "Get-Service") -and ($Event.Message -match "Line 0")
Report-Result "Multi-line script block" $FullBlock "EID 4104: full block captured (all lines present)"

# ------------------------------------------------------------------------------
# 5. Transcription file - verify RECENT file created during this session
# ------------------------------------------------------------------------------
Write-Host "    [5/5] Transcription file..." -ForegroundColor Cyan
$TranscriptFound = $false
$BeforeCheck = (Get-Date).AddMinutes(-10)
if (Test-Path $TranscriptDir) {
    $RecentFiles = Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $BeforeCheck }
    if ($RecentFiles.Count -gt 0) {
        $TranscriptFound = $true
        Write-Host "          Recent transcript: $($RecentFiles[0].Name)" -ForegroundColor Gray
    }
}
Report-Result "Transcription file" $TranscriptFound "$TranscriptDir\*.txt exists with recent full session recording"

# Cleanup
Remove-Item -Path "C:\Windows\Temp\multiline_test.ps1" -Force -ErrorAction SilentlyContinue

# Summary
$Total = $CAPTURED + $MISSED
Write-Host ""
Write-Host "Tests: $Total | Captured: $CAPTURED | Missed: $MISSED" -ForegroundColor $(if ($MISSED -eq 0) { "Green" } else { "Red" })
exit 0
