<#
name:
    2-powershell_logging_validation.ps1

purpose: Validates that PowerShell Script Block Logging (4104), Module Logging
         (4103), and Transcription are correctly capturing commands, encoded
         payloads, module imports, multi-line scripts, and session transcripts.
         Reports detail level (full, partial, missed) for each test.

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
$FULL = 0
$PARTIAL = 0
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
    param(
        [string]$Test,
        [bool]$Success,
        [string]$Detail,
        [string]$DetailLevel = "full"   # "full" or "partial"
    )

    if ($Success) {
        if ($DetailLevel -eq "partial") {
            Write-Host "          $Detail   [PARTIAL]" -ForegroundColor Yellow
            $script:CAPTURED++
            $script:PARTIAL++
        } else {
            Write-Host "          $Detail   [CAPTURED]" -ForegroundColor Green
            $script:CAPTURED++
            $script:FULL++
        }
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
$HasContent = $Event -and ($Event.Message -match "Get-Process")
# Determine if full command line details are present (not just the executable name)
$IsFull = $HasContent -and ($Event.Message -match "CommandLine")
$DetailLevel = if ($HasContent -and -not $IsFull) { "partial" } else { "full" }
Report-Result "ScriptBlock logging" $HasContent "EID 4104: `"Get-Process`" - detail: $DetailLevel" -DetailLevel $DetailLevel

# ------------------------------------------------------------------------------
# 2. Encoded command - verify DECODED content in 4104
# ------------------------------------------------------------------------------
Write-Host "    [2/5] Encoded command..." -ForegroundColor Cyan
$Plain = "Write-Host 'MedDefense Test'"
$Enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Plain))
Write-Host "          Input: -enc $Enc"
Start-Process powershell "-NoProfile -EncodedCommand $Enc" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4104 -Pattern "Write-Host"
$Decoded = $Event -and ($Event.Message -match "Write-Host") -and ($Event.Message -match "MedDefense Test")
$DetailLevel = if ($Decoded) { "full" } else { "partial" }
Report-Result "Encoded command" $Decoded "EID 4104 decoded: `"Write-Host 'MedDefense Test'`" - detail: $DetailLevel" -DetailLevel $DetailLevel

# ------------------------------------------------------------------------------
# 3. Module import - Event ID 4103 (use built-in module as fallback)
# ------------------------------------------------------------------------------
Write-Host "    [3/5] Module import..." -ForegroundColor Cyan
$ModuleName = "ActiveDirectory"
$ModuleAvailable = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
if (-not $ModuleAvailable) {
    $ModuleName = "Microsoft.PowerShell.Management"
}
Start-Process powershell "-NoProfile -Command Import-Module $ModuleName" -Wait -NoNewWindow
$Event = Wait-PSEvent -EventID 4103 -Pattern $ModuleName
$HasEvent = $Event -ne $null
$DetailLevel = if ($HasEvent -and $Event.Message -match "ModuleName") { "full" } else { "partial" }
Report-Result "Module import" $HasEvent "EID 4103: Import-Module $ModuleName - detail: $DetailLevel" -DetailLevel $DetailLevel

# ------------------------------------------------------------------------------
# 4. Multi-line script block - full capture
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
$FullBlock = $Event -and ($Event.Message -match "Get-Service") -and ($Event.Message -match "Line 0")
$DetailLevel = if ($FullBlock) { "full" } else { "partial" }
Report-Result "Multi-line script block" $FullBlock "EID 4104: block capture - detail: $DetailLevel" -DetailLevel $DetailLevel

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
$DetailLevel = if ($TranscriptFound) { "full" } else { "partial" }
Report-Result "Transcription file" $TranscriptFound "$TranscriptDir\*.txt exists - detail: $DetailLevel" -DetailLevel $DetailLevel

# Cleanup
Remove-Item -Path "C:\Windows\Temp\multiline_test.ps1" -Force -ErrorAction SilentlyContinue

# Summary
$Total = $CAPTURED + $MISSED
Write-Host ""
Write-Host "Tests: $Total | Captured: $CAPTURED (full: $FULL, partial: $PARTIAL) | Missed: $MISSED" -ForegroundColor $(if ($MISSED -eq 0) { "Green" } else { "Red" })
exit 0
