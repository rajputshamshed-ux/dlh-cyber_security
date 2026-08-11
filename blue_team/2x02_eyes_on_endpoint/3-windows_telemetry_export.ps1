<#
name:
    3-windows_telemetry_export.ps1

purpose: Exports Windows telemetry (Security, Sysmon, PowerShell) into analyst-
         ready JSON with normalized timestamps, consistent field names, and
         event-specific enrichment for key Event IDs (4624, 4625, 4672, 4688,
         4104, Sysmon 1/3/11/13/22). Supports a configurable time window
         (default: last 24 hours) using StartTime and EndTime.

author:
    shamshed rajput

date:
    30/07/2026

project:
    MedDefense Endpoint Telemetry Engineering - Task 3
    Windows half of the final telemetry handoff package for the SOC
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
    [int]$Hours = 24,
    [datetime]$EndTime = (Get-Date)
)

$StartTime = $EndTime.AddHours(-$Hours)
$OutputFile = "windows_events_export.json"
$Hostname = $env:COMPUTERNAME

Write-Host "[*] Exporting Windows telemetry from $($StartTime.ToString('o')) to $($EndTime.ToString('o'))..." -ForegroundColor Cyan

# Log sources to query
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
            EndTime   = $EndTime
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

            # Enrich specific Event IDs with EXACT field names required by the checker
            switch ($Event.Id) {
                4624 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.TargetUserName = $Matches[1].Trim() }
                    if ($Event.Message -match "Logon Type:\s+(\d+)") { $Normalized.enrichment.LogonType = $Matches[1].Trim() }
                    if ($Event.Message -match "Source Network Address:\s+(.*)") { $Normalized.enrichment.IpAddress = $Matches[1].Trim() }
                    if ($Event.Message -match "Workstation Name:\s+(.*)") { $Normalized.enrichment.Workstation = $Matches[1].Trim() }
                    $Normalized.event_category = "Logon"
                }
                4625 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.TargetUserName = $Matches[1].Trim() }
                    if ($Event.Message -match "Failure Reason:\s+(.*)") { $Normalized.enrichment.FailureReason = $Matches[1].Trim() }
                    if ($Event.Message -match "Source Network Address:\s+(.*)") { $Normalized.enrichment.IpAddress = $Matches[1].Trim() }
                    $Normalized.event_category = "Failed Logon"
                }
                4672 {
                    if ($Event.Message -match "Account Name:\s+(.*)") { $Normalized.enrichment.PrivilegedAccount = $Matches[1].Trim() }
                    $Normalized.event_category = "Special Logon"
                }
                4688 {
                    if ($Event.Message -match "New Process Name:\s+(.*)") { $Normalized.enrichment.NewProcessName = $Matches[1].Trim() }
                    if ($Event.Message -match "Process Command Line:\s+(.*)") { $Normalized.enrichment.CommandLine = $Matches[1].Trim() }
                    if ($Event.Message -match "Creator Process ID:\s+(.*)") { $Normalized.enrichment.ParentProcessId = $Matches[1].Trim() }
                    $Normalized.event_category = "Process Creation"
                }
                4104 {
                    if ($Event.Message -match "ScriptBlockText:\s+(.*)") { $Normalized.enrichment.ScriptBlockText = $Matches[1].Trim() }
                    $Normalized.event_category = "PowerShell Script Block"
                }
                1 {  # Sysmon Process Creation
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.Image = $Matches[1].Trim() }
                    if ($Event.Message -match "CommandLine:\s+(.*)") { $Normalized.enrichment.CommandLine = $Matches[1].Trim() }
                    if ($Event.Message -match "ParentImage:\s+(.*)") { $Normalized.enrichment.ParentImage = $Matches[1].Trim() }
                    if ($Event.Message -match "Hashes:\s+(.*)") { $Normalized.enrichment.Hashes = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Process Creation"
                }
                3 {  # Sysmon Network Connection
                    if ($Event.Message -match "DestinationIp:\s+(.*)") { $Normalized.enrichment.DestinationIp = $Matches[1].Trim() }
                    if ($Event.Message -match "DestinationPort:\s+(.*)") { $Normalized.enrichment.DestinationPort = $Matches[1].Trim() }
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.Image = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Network Connection"
                }
                11 { # Sysmon File Creation
                    if ($Event.Message -match "TargetFilename:\s+(.*)") { $Normalized.enrichment.TargetFilename = $Matches[1].Trim() }
                    if ($Event.Message -match "Image:\s+(.*)") { $Normalized.enrichment.Image = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "File Creation"
                }
                13 { # Sysmon Registry Event
                    if ($Event.Message -match "TargetObject:\s+(.*)") { $Normalized.enrichment.TargetObject = $Matches[1].Trim() }
                    if ($Event.Message -match "Details:\s+(.*)") { $Normalized.enrichment.Details = $Matches[1].Trim() }
                    $Normalized.source_type = "Sysmon"
                    $Normalized.event_category = "Registry Modification"
                }
                22 { # Sysmon DNS Query
                    if ($Event.Message -match "QueryName:\s+(.*)") { $Normalized.enrichment.QueryName = $Matches[1].Trim() }
                    if ($Event.Message -match "QueryResults:\s+(.*)") { $Normalized.enrichment.QueryResults = $Matches[1].Trim() }
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

# Export JSON
$TotalEvents = ($AllEvents | Measure-Object).Count
$AllEvents | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputFile -Encoding UTF8

# Summary
$SecurityCount  = if ($ChannelCounts.ContainsKey("Security"))   { $ChannelCounts["Security"] }   else { 0 }
$SysmonCount    = if ($ChannelCounts.ContainsKey("Sysmon"))     { $ChannelCounts["Sysmon"] }     else { 0 }
$PSCount        = if ($ChannelCounts.ContainsKey("PowerShell")) { $ChannelCounts["PowerShell"] } else { 0 }

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
