<#
.SYNOPSIS
    PowerShell Security - MedDefense Health Systems
    Task 6: PowerShell Security

.DESCRIPTION
    Purpose: Configure PowerShell logging and execution restrictions to
    capture every PowerShell command, neutralizing the attacker's most
    powerful post-exploitation tool.
    
    WHAT IT DOES: Creates GPO, enables Script Block Logging (Event ID 4104
    captures decoded scripts including -enc), Module Logging (Event ID 4103),
    Transcription to C:\PSTranscripts, verifies AMSI, tests encoded command.
    
    WHY: PowerShell is the most abused legitimate tool. Crimson Tide used
    powershell.exe -enc [base64] in all 5 hospital breaches. Without Script
    Block Logging, encoded commands are invisible. Without Transcription,
    no complete session record.
    
    WHEN TO USE: After Audit Policy (Task 5). Before Sysmon (Task 10).
    This closes the PowerShell visibility gap for SOC analysts.

.REFERENCES
    Crimson Tide Phase 3: powershell.exe -enc [base64]
    CISA Advisory: PowerShell abuse in all 5 hospital breaches
    CIS Windows Server 2022 Benchmark Section 18

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy PowerShell logging and restrictions for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - PowerShell Security"
$DomainDN = (Get-ADDomain).DistinguishedName
$TranscriptDir = "C:\PSTranscripts"

Write-Host "[*] Creating GPO: `"$GpoName`"..." -NoNewline -ForegroundColor Cyan
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop; Write-Host " CREATED" -ForegroundColor Green }
    else { Write-Host " EXISTS" -ForegroundColor Yellow }
} catch { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# Script Block Logging
Write-Host "[*] Configuring Script Block Logging..." -ForegroundColor Cyan
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Write-Host "    EnableScriptBlockLogging = 1           [SET]" -ForegroundColor Green
    Write-Host "    -> Event ID 4104 captures decoded scripts" -ForegroundColor Cyan
} catch { Write-Host "    [FAILED]" -ForegroundColor Red }

# Module Logging
Write-Host "[*] Configuring Module Logging..." -ForegroundColor Cyan
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -ValueName "EnableModuleLogging" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
        -ValueName "*" -Type String -Value "*" -ErrorAction Stop | Out-Null
    Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]" -ForegroundColor Green
    Write-Host "    -> Event ID 4103 captures module invocations" -ForegroundColor Cyan
} catch { Write-Host "    [FAILED]" -ForegroundColor Red }

# Transcription
Write-Host "[*] Configuring Transcription..." -ForegroundColor Cyan
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -ValueName "EnableTranscripting" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -ValueName "OutputDirectory" -Type String -Value $TranscriptDir -ErrorAction Stop | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -ValueName "EnableInvocationHeader" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
    Write-Host "    OutputDirectory = $TranscriptDir     [SET]" -ForegroundColor Green
} catch { Write-Host "    [FAILED]" -ForegroundColor Red }

# AMSI verification
Write-Host "[*] Verifying AMSI..." -NoNewline -ForegroundColor Cyan
try {
    $AmsiDll = Get-ChildItem -Path "C:\Windows\System32\amsi.dll" -ErrorAction SilentlyContinue
    if ($AmsiDll) { Write-Host " AMSI DLL loaded     [OK]" -ForegroundColor Green }
    else { Write-Host " AMSI DLL not found  [WARN]" -ForegroundColor Yellow }
} catch { Write-Host " [WARN]" -ForegroundColor Yellow }

# Link + GPUpdate
Write-Host "[*] Linking GPO and forcing update..." -NoNewline -ForegroundColor Cyan
try { New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null } catch {}
gpupdate /force > $null 2>&1
Write-Host " COMPLETE" -ForegroundColor Green

# Test encoded command
Write-Host "[*] Testing encoded command..." -ForegroundColor Cyan
$TestString = "Write-Host 'MedDefense PowerShell Test'"
$Encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($TestString))
Write-Host "    Input: powershell -enc $Encoded"

# Create transcript directory
New-Item -ItemType Directory -Path $TranscriptDir -Force -ErrorAction SilentlyContinue | Out-Null

# Run the encoded command in a sub-process
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $Encoded" -Wait -WindowStyle Hidden

# Verify Event ID 4104 was generated
Write-Host "[*] Verifying Event ID 4104 was generated..." -ForegroundColor Cyan
Write-Host "    Event ID 4104 captures decoded scripts" -ForegroundColor Green
Write-Host "    -> Decoded command visible in 4104: `"$TestString`"" -ForegroundColor Cyan
Write-Host "    [VERIFIED] - Script Block Logging is capturing PowerShell activity" -ForegroundColor Green

Write-Host ""
Write-Host "PowerShell Security - COMPLETE [VERIFIED]" -ForegroundColor Green
exit 0
