<#
name:
    1-sysmon_coverage_matrix.ps1

purpose: Produces a structured ATT&CK coverage matrix from the Sysmon XML
         configuration. Maps Sysmon Event IDs to MITRE ATT&CK techniques,
         evaluates coverage (covered/partial/blind), and identifies filter
         conflicts and tuning recommendations.

author:
    shamshed rajput

date:
    30/07/2026

project:
    MedDefense Endpoint Telemetry Engineering - Task 1
    Proves which attacker techniques are visible through current Sysmon config
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ConfigPath = "C:\Program Files\Sysmon\sysmonconfig.xml"
if (-not (Test-Path $ConfigPath)) {
    $ConfigPath = ".\sysmonconfig.xml"
}
if (-not (Test-Path $ConfigPath)) {
    Write-Host "[ERROR] sysmonconfig.xml not found" -ForegroundColor Red
    exit 1
}

$OutputFile = "sysmon_coverage_matrix.json"

Write-Host "[*] Parsing Sysmon config: $ConfigPath" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# Parse enabled Event IDs from XML
# ------------------------------------------------------------------------------
[xml]$SysmonXml = Get-Content -Path $ConfigPath -Raw

$EnabledEventIDs = @()
$FilterConflicts = @()

# Map event names to IDs
$EventNameToID = @{
    "ProcessCreate"      = 1
    "FileCreateTime"     = 2
    "NetworkConnect"     = 3
    "ProcessTerminate"   = 5
    "DriverLoad"         = 6
    "ImageLoad"          = 7
    "CreateRemoteThread" = 8
    "RawAccessRead"      = 9
    "ProcessAccess"      = 10
    "FileCreate"         = 11
    "RegistryEvent"      = 13
    "FileCreateStreamHash" = 15
    "WmiEvent"           = 19
    "DnsQuery"           = 22
}

foreach ($Rule in $SysmonXml.Sysmon.EventFiltering.ChildNodes) {
    $EventName = $Rule.Name
    $OnMatch = $Rule.onmatch
    $EventID = $EventNameToID[$EventName]
    
    if ($EventID) {
        $EnabledEventIDs += $EventID
        
        # Check for exclude rules that could suppress events
        if ($OnMatch -eq "exclude") {
            $FilterConflicts += [PSCustomObject]@{
                EventName = $EventName
                EventID   = $EventID
                Issue     = "Default exclude - events only logged if include rule matches"
            }
        }
        
        # Check for include rules with conditions
        $IncludeRules = $Rule.ChildNodes | Where-Object { $_.onmatch -eq "include" }
        if (-not $IncludeRules -and $OnMatch -eq "include") {
            # No conditions, catches all
        } elseif ($IncludeRules) {
            $FilterConflicts += [PSCustomObject]@{
                EventName = $EventName
                EventID   = $EventID
                Issue     = "Filtered - only specific conditions trigger events"
            }
        }
    }
}

$EnabledEventIDs = $EnabledEventIDs | Sort-Object -Unique
Write-Host "Enabled Event IDs: $($EnabledEventIDs -join ', ')" -ForegroundColor Green

# ------------------------------------------------------------------------------
# ATT&CK Technique Mappings
# ------------------------------------------------------------------------------
$Techniques = @(
    [PSCustomObject]@{
        TechniqueID   = "T1059"
        TechniqueName = "Command and Scripting Interpreter"
        RequiredEIDs  = @(1)
        EvidenceFields = "Image, CommandLine, ParentImage, User"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1053"
        TechniqueName = "Scheduled Task/Job"
        RequiredEIDs  = @(1)
        EvidenceFields = "Image, CommandLine (schtasks.exe, at.exe), ParentImage"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1547"
        TechniqueName = "Boot or Logon Autostart Execution"
        RequiredEIDs  = @(13)
        EvidenceFields = "TargetObject (Run/RunOnce keys), Details, Image"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1055"
        TechniqueName = "Process Injection"
        RequiredEIDs  = @(8, 10)
        EvidenceFields = "SourceImage, TargetImage, GrantedAccess, CallTrace"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1071"
        TechniqueName = "Application Layer Protocol"
        RequiredEIDs  = @(3, 22)
        EvidenceFields = "DestinationIp, DestinationPort, Image, QueryName"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1574.002"
        TechniqueName = "DLL Side-Loading"
        RequiredEIDs  = @(7)
        EvidenceFields = "ImageLoaded, Signature, Signed, Image"
    },
    [PSCustomObject]@{
        TechniqueID   = "T1027"
        TechniqueName = "Obfuscated or Compressed Files"
        RequiredEIDs  = @(11, 15)
        EvidenceFields = "TargetFilename, CreationUtcTime, Image"
    }
)

# ------------------------------------------------------------------------------
# Evaluate Coverage
# ------------------------------------------------------------------------------
$CoverageResults = @()
$Covered = 0
$Partial = 0
$Blind = 0

foreach ($Tech in $Techniques) {
    $MatchedEIDs = $Tech.RequiredEIDs | Where-Object { $_ -in $EnabledEventIDs }
    $MissingEIDs = $Tech.RequiredEIDs | Where-Object { $_ -notin $EnabledEventIDs }
    
    $Conflicts = $FilterConflicts | Where-Object { $_.EventID -in $Tech.RequiredEIDs }
    
    # Determine status
    if ($MatchedEIDs.Count -eq $Tech.RequiredEIDs.Count -and $Conflicts.Count -eq 0) {
        $Status = "covered"
        $Covered++
        $Recommendation = "No action required - full visibility"
    } elseif ($MatchedEIDs.Count -gt 0) {
        $Status = "partial"
        $Partial++
        $MissingList = if ($MissingEIDs.Count -gt 0) { "Missing EIDs: $($MissingEIDs -join ',')" } else { "" }
        $ConflictList = if ($Conflicts.Count -gt 0) { "Filter conflicts: $($Conflicts.Issue -join '; ')" } else { "" }
        $Recommendation = "Tune config: $MissingList $ConflictList"
    } else {
        $Status = "blind"
        $Blind++
        $Recommendation = "Enable Event IDs: $($Tech.RequiredEIDs -join ',')"
    }
    
    $CoverageResults += [PSCustomObject]@{
        technique_id           = $Tech.TechniqueID
        technique_name         = $Tech.TechniqueName
        required_event_ids     = $Tech.RequiredEIDs -join ","
        enabled_event_ids      = $MatchedEIDs -join ","
        missing_event_ids      = $MissingEIDs -join ","
        filter_conflicts       = if ($Conflicts) { ($Conflicts.Issue -join "; ") } else { "None" }
        coverage_status        = $Status
        evidence_fields_expected = $Tech.EvidenceFields
        recommendation         = $Recommendation
    }
}

Write-Host "Techniques assessed: $($Techniques.Count)" -ForegroundColor Cyan
Write-Host "Covered: $Covered" -ForegroundColor Green
Write-Host "Partial: $Partial" -ForegroundColor Yellow
Write-Host "Blind: $Blind" -ForegroundColor $(if ($Blind -gt 0) { "Red" } else { "Green" })

# ------------------------------------------------------------------------------
# Export JSON
# ------------------------------------------------------------------------------
$Report = [PSCustomObject]@{
    metadata = [PSCustomObject]@{
        script     = "1-sysmon_coverage_matrix.ps1"
        author     = "shamshed rajput"
        purpose    = "Sysmon ATT&CK coverage matrix for MedDefense"
        date       = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        config_file = $ConfigPath
    }
    summary = [PSCustomObject]@{
        techniques_assessed = $Techniques.Count
        covered             = $Covered
        partial             = $Partial
        blind               = $Blind
        enabled_event_ids   = $EnabledEventIDs -join ","
    }
    techniques = $CoverageResults
}

$Report | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
exit 0
