<#
name:
    3-windows_telemetry_export.ps1

purpose: Exports Windows telemetry (Security, Sysmon, PowerShell) into analyst-
         ready JSON with normalized timestamps, consistent field names, and
         event-specific enrichment for key Event IDs (4624, 4625, 4672, 4688,
         4104, Sysmon 1/3/11/13/22). This script is the Windows half of the
         final telemetry handoff package for the MedDefense SOC.

why: Raw EVTX data is not enough. The SOC analyst needs consistent JSON records
     with standard fields across all log sources. Without normalization, the
     analyst spends time parsing instead of detecting. This script transforms
     raw Windows events into the same structured format the Linux telemetry
     export produces.

what_it_does:
     - Reads from Windows Security, Sysmon Operational, and PowerShell
       Operational logs (default: last 24 hours)
     - Normalizes common fields: timestamp, hostname, platform, source_type,
       channel, event_id, event_category, provider, raw_message
     - Enriches specific Event IDs with parsed fields (target user, logon type,
       command line, destination IP, etc.)
     - Generates windows_events_export.json
     - Prints counts per channel and top Event IDs

author:
    shamshed rajput

date:
    30/07/2026

project:
    MedDefense Endpoint Telemetry Engineering - Task 3
    Produces the Windows half of the analyst telemetry handoff package
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
    [int]$Hours = 24
)

$StartTime = (Get-Date).AddHours(-$Hours)
$OutputFile = "windows_events_export.json"
$Hostname = $env:COMPUTERNAME

Write-Host "[*] Exporting Windows telemetry from last $Hours hours..." -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# Log sources to query
# ------------------------------------------------------------------------------
$LogSources = @(
    @{ Name = "Security"; Channel = "Security" }
    @{ Name = "Sysmon"; Channel = "Microsoft-Windows-Sysmon/Operational" }
    @{ Name = "PowerShell"; Channel = "Microsoft-Windows-PowerShell/Operational" }
)

$AllEvents = @()
$ChannelCounts = @{}

foreach ($Source in $LogSources) {
    Write-Host "    Querying $($Source.Name) log..." -ForegroundColor Gray
    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = $Source.Channel
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
    } catch {
        $Events = $null
    }

    if ($Events) {
        $Count = ($Events | Measure-Object).Count
        $ChannelCounts[$Source.Name] = $Count
        Write-Host "        $Count events found" -ForegroundColor Gray

        foreach ($Event in $Events) {
            $Normalized = [PSCustomObject]@{
                timestamp      = $Event.TimeCreated.ToString("o")
                hostname       = $Hostname
                platform       = "windows"
                source_type    = $Source.Name
                channel        = $Source.Channel
                event_id       = $Event.Id
                event_category = ""
                provider       = $Event.ProviderName
                raw_message    = $Event.Message
                enrichment     = @{}
            }

            # Enrich specific Event IDs
            switch ($Event.Id) {
                4624 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.target_user = $Matches[1].Trim() }
                    if ($Event.Message -match "Logon Type:\s+(\d+)") { $Normalized.enrichment.logon_type = $Matches[1].Trim() }
                    if ($Event.Message -match "Source Network Address:\s+(.*)") { $Normalized.enrichment.source_ip = $Matches[1].Trim() }
                    if ($Event.Message -match "Workstation Name:\s+(.*)") { $Normalized.enrichment.workstation = $Matches[1].Trim() }
                    $Normalized.event_category = "Logon"
                }
                4625 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.target_user = $Matches[1].Trim() }
                    if ($Event.Message -match "Failure Reason:\s+(.*)") { $Normalized.enrichment.failure_reason = $Matches[1].Trim() }
                    if ($Event.Message -match "Source Network Address:\s+(.*)") { $Normalized.enrichment.source_ip = $Matches[1].Trim() }
                    $Normalized.event_category = "Failed Logon"
                }
                4672 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.privileged_account = $Matches[1].Trim() }
                    $Normalized.event_category = "Special Logon"
                }
                4688 {
                    if ($Event.Message -match "New Process Name:\s+(.*)") { $Normalized.enrichment.process_name = $Matches[1].Trim() }
                    if ($Event.Message -match "Process Command Line:\s+(.*)") { $Normalized.enrichment.command_line = $Matches[1].Trim() }
                    if ($Event.Message -match "Creator Process ID:\s+(.*)") { $Normalized.enrichment.parent_process_id = $Matches[1].Trim() }
                    $Normalized.event_category = "Process Creation"
                }
                4104 {
                    if ($Event.Message -match "ScriptBlockText:\s+(.*)") { $Normalized.enrichment.script_block_text = $Matches[1].Trim() }
                    $Normalized.event_category = "PowerShell Script Block"
                }
                1 {  # Sysmon Process Creation
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.image = $Matches[1].Trim() }
                    if ($Event.Message -match "CommandLine:\s+(.*)") { $Normalized.enrichment.command_line = $Matches[1].Trim() }
                    if ($Event.Message -match "ParentImage:\s+(.*)") { $Normalized.enrichment.parent_image = $Matches[1].Trim() }
                    if ($Event.Message -match "Hashes:\s+(.*)") { $Normalized.enrichment.hashes = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Process Creation"
                }
                3 {  # Sysmon Network Connection
                    if ($Event.Message -match "DestinationIp:\s+(.*)") { $Normalized.enrichment.destination_ip = $Matches[1].Trim() }
                    if ($Event.Message -match "DestinationPort:\s+(.*)") { $Normalized.enrichment.destination_port = $Matches[1].Trim() }
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.process = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Network Connection"
                }
                11 { # Sysmon File Creation
                    if ($Event.Message -match "TargetFilename:\s+(.*)") { $Normalized.enrichment.target_filename = $Matches[1].Trim() }
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.creating_process = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "File Creation"
                }
                13 { # Sysmon Registry Event
                    if ($Event.Message -match "TargetObject:\s+(.*)") { $Normalized.enrichment.registry_key = $Matches[1].Trim() }
                    if ($Event.Message -match "Details:\s+(.*)") { $Normalized.enrichment.value_name = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Registry Modification"
                }
                22 { # Sysmon DNS Query
                    if ($Event.Message -match "QueryName:\s+(.*)") { $Normalized.enrichment.query_name = $Matches[1].Trim() }
                    if ($Event.Message -match "QueryResults:\s+(.*)") { $Normalized.enrichment.query_results = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "DNS Query"
                }
            }

            $AllEvents += $Normalized
        }
    } else {
        $ChannelCounts[$Source.Name] = 0
        Write-Host "        0 events found" -ForegroundColor Gray
    }
}

# ------------------------------------------------------------------------------
# Export JSON
# ------------------------------------------------------------------------------
$TotalEvents = ($AllEvents | Measure-Object).Count
$AllEvents | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputFile -Encoding UTF8

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
$SecurityCount  = if ($ChannelCounts.ContainsKey("Security"))   { $ChannelCounts["Security"] }   else { 0 }
$SysmonCount    = if ($ChannelCounts.ContainsKey("Sysmon"))     { $ChannelCounts["Sysmon"] }     else { 0 }
$PSCount        = if ($ChannelCounts.ContainsKey("PowerShell")) { $ChannelCounts["PowerShell"] } else { 0 }

# Top Event IDs
$TopIDs = $AllEvents | Group-Object -Property event_id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { $_.Name }
$TopIDsStr = $TopIDs -join ", "

Write-Host ""
Write-Host "Security events: $SecurityCount"
Write-Host "Sysmon events: $SysmonCount"
Write-Host "PowerShell events: $PSCount"
Write-Host "Total events: $TotalEvents"
Write-Host "Top Event IDs: $TopIDsStr"
Write-Host "Output: $OutputFile" -ForegroundColor Green

exit 0
