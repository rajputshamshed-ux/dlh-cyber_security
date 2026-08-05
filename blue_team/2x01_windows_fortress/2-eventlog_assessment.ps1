<#
.SYNOPSIS
    Windows Event Log Assessment - MedDefense Health Systems
    Task 2: Windows Event Log Assessment

.DESCRIPTION
    Purpose: Assess current event logging capability by checking which
    critical Event IDs the domain is actually generating and identifying
    visibility gaps.
    
    WHAT IT DOES: Checks audit policy configuration via auditpol, verifies
    if critical Event IDs (4624, 4625, 4648, 4688, 4720, 4726, 4732, 4672,
    1102) are being generated, and reports visibility gaps.
    
    WHY: If Event ID 4688 is not generated, every attacker process is
    invisible. If 4672 is not logged, admin privilege use is undetectable.
    Crimson Tide operated undetected for 5 days due to missing audit logs.
    
    WHEN TO USE: Before deploying audit policy (Task 6). Weekly security
    assessment. Gap analysis before SIEM deployment.

.REFERENCES
    Crimson Tide Phase 5: Attacker cleared logs
    CISA Advisory: Missing audit visibility in all 5 hospital breaches
    CIS Windows Server 2022 Benchmark Section 17

.AUTHOR
    shamshed rajput

.DATE
    30/07/2026

.TARGET
    DC01.meddefense.local - Windows Server 2022 Domain Controller
#>

# Author: shamshed rajput
# Script Purpose: Assess Windows event logging capability for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Starting Windows Event Log Assessment..." -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# CRITICAL EVENT IDS AND THEIR REQUIRED AUDIT SUBCATEGORIES
# ------------------------------------------------------------------------------
$CriticalEvents = @(
    [PSCustomObject]@{ EventID = 4624; Description = "Successful Logon"; Subcategory = "Logon" }
    [PSCustomObject]@{ EventID = 4625; Description = "Failed Logon"; Subcategory = "Logon" }
    [PSCustomObject]@{ EventID = 4648; Description = "Explicit Credentials"; Subcategory = "Logon" }
    [PSCustomObject]@{ EventID = 4688; Description = "Process Creation"; Subcategory = "Process Tracking" }
    [PSCustomObject]@{ EventID = 4720; Description = "Account Created"; Subcategory = "Account Management" }
    [PSCustomObject]@{ EventID = 4726; Description = "Account Deleted"; Subcategory = "Account Management" }
    [PSCustomObject]@{ EventID = 4732; Description = "Member Added to Group"; Subcategory = "Account Management" }
    [PSCustomObject]@{ EventID = 4672; Description = "Special Logon"; Subcategory = "Special Logon" }
    [PSCustomObject]@{ EventID = 1102; Description = "Audit Log Cleared"; Subcategory = "System Integrity" }
)

# ------------------------------------------------------------------------------
# GET AUDIT POLICY CONFIGURATION
# ------------------------------------------------------------------------------
Write-Host "[*] Checking audit policy configuration with auditpol..." -ForegroundColor Cyan
$AuditPolOutput = auditpol /get /category:* 2>/dev/null | Out-String

# ------------------------------------------------------------------------------
# GET SECURITY LOG EVENTS FROM LAST 24 HOURS
# ------------------------------------------------------------------------------
Write-Host "[*] Querying Security log for last 24 hours..." -ForegroundColor Cyan
$StartTime = (Get-Date).AddHours(-24)

try {
    $RecentEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Select-Object Id
} catch {
    $RecentEvents = $null
}

$GeneratingIDs = @()
if ($RecentEvents) {
    $GeneratingIDs = ($RecentEvents | Group-Object Id | Select-Object Name).Name
}

# ------------------------------------------------------------------------------
# CHECK EACH CRITICAL EVENT ID
# ------------------------------------------------------------------------------
Write-Host "Event ID  Description               Audit Subcategory     Status"
Write-Host "--------  -----------               -----------------     ------"

foreach ($Event in $CriticalEvents) {
    $EventID = $Event.EventID
    $Description = $Event.Description
    $Subcategory = $Event.Subcategory
    
    $Status = "[NOT CONFIGURED]"
    
    if ($AuditPolOutput -match $Subcategory) {
        if ($GeneratingIDs -contains $EventID.ToString()) {
            $Status = "[GENERATING]"
        } else {
            $Status = "[ENABLED - No Events]"
        }
    }
    
    Write-Host "$EventID      $($Description.PadRight(27)) $($Subcategory.PadRight(22)) $Status"
}

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
$ConfiguredCount = 0
$GeneratingCount = 0
$NotConfiguredCount = 0

foreach ($Event in $CriticalEvents) {
    if ($AuditPolOutput -match $Event.Subcategory) {
        $ConfiguredCount++
        if ($GeneratingIDs -contains $Event.EventID.ToString()) {
            $GeneratingCount++
        }
    } else {
        $NotConfiguredCount++
    }
}

Write-Host ""
Write-Host "======================================================================"
Write-Host "  EVENT LOG ASSESSMENT - COMPLETE"
Write-Host "======================================================================"
Write-Host "  Critical Event IDs checked: 9"
Write-Host "  Subcategories configured:   $ConfiguredCount"
Write-Host "  Actually generating events: $GeneratingCount"
Write-Host "  Not configured:             $NotConfiguredCount"
Write-Host "  Visibility gap:             $($NotConfiguredCount) critical Event IDs missing"
Write-Host "======================================================================"

exit 0
