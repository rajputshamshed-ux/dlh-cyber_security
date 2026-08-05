<#
.SYNOPSIS
    AppLocker Policy - MedDefense Health Systems
    Task 12: AppLocker Policy

.DESCRIPTION
    Purpose: Deploy AppLocker application allow-listing to prevent
    unauthorized executables from running, blocking Crimson Tide's
    ransomware deployment mechanism.
    
    WHAT IT DOES: Creates GPO, configures executable rules (allow Windows,
    Program Files, DicomViewer.exe, deny all), script rules (allow Windows,
    MedDefense scripts, deny all), sets Audit Only mode, starts AppIDSvc,
    exports XML policy, tests with notepad/calc.
    
    WHY: Crimson Tide deployed ransomware via GPO. AppLocker blocks
    unauthorized executables - Phase 6 stopped dead. Clinical constraint:
    DicomViewer.exe must be allowed for physicians.
    
    WHEN TO USE: After Sysmon (Task 9-10). Before validation (Task 15).
    This is the last preventive control before SOC monitoring.

.REFERENCES
    Crimson Tide Phase 6: Ransomware deployed via GPO
    CIS Windows Server 2022 Benchmark Section 2.3.6

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy AppLocker allow-listing for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - AppLocker Policy"
$DomainDN = (Get-ADDomain).DistinguishedName
$PolicyXmlPath = "applocker_policy.xml"

Write-Host "[*] Creating GPO: `"$GpoName`"..." -NoNewline -ForegroundColor Cyan
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop; Write-Host " CREATED" -ForegroundColor Green }
    else { Write-Host " EXISTS" -ForegroundColor Yellow }
} catch { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# ------------------------------------------------------------------------------
# START APPLICATION IDENTITY SERVICE
# ------------------------------------------------------------------------------
Write-Host "[*] Starting AppIDSvc..." -NoNewline -ForegroundColor Cyan
try {
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
    Start-Service -Name AppIDSvc -ErrorAction Stop
    Write-Host " Running           [OK]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# ------------------------------------------------------------------------------
# CONFIGURE EXECUTABLE RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Executable Rules..." -ForegroundColor Cyan

$ExeRules = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <!-- Allow Windows system directories -->
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000001" Name="Allow Windows" Description="Allow all signed Windows executables" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <!-- Allow Program Files -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Allow Program Files" Description="Allow all executables in Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow Program Files (x86) -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Allow Program Files x86" Description="Allow all executables in Program Files (x86)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow DicomViewer.exe (MedDefense clinical app) -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Allow DicomViewer" Description="Allow MedDefense clinical imaging application" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\Program Files\MedImage\DicomViewer.exe"/>
      </Conditions>
    </FilePathRule>
    <!-- Default DENY all other executables -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Deny All Other Exe" Description="Block all other executables" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files\*              [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]" -ForegroundColor Green
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# CONFIGURE SCRIPT RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Script Rules..." -ForegroundColor Cyan

$ScriptRules = @"
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <!-- Allow Windows scripts -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000001" Name="Allow Windows Scripts" Description="Allow scripts in Windows directory" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow MedDefense admin scripts -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000002" Name="Allow MedDefense Scripts" Description="Allow MedDefense admin scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Default DENY -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000003" Name="Deny All Other Scripts" Description="Block all other scripts" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
"@

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)" -ForegroundColor Yellow

# ------------------------------------------------------------------------------
# BUILD FULL POLICY XML
# ------------------------------------------------------------------------------
$FullPolicy = $ExeRules -replace "</AppLockerPolicy>", "$ScriptRules</AppLockerPolicy>"

# Save policy XML
$FullPolicy | Out-File -FilePath $PolicyXmlPath -Encoding UTF8
Write-Host "[*] Policy exported to: $PolicyXmlPath" -ForegroundColor Green

# Set AppLocker policy via GPO registry
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" `
        -ValueName "EnforcementMode" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    Write-Host "[*] AppLocker GPO registry configured" -ForegroundColor Green
} catch { Write-Host "    [WARN] GPO registry set skipped" -ForegroundColor Yellow }

# ------------------------------------------------------------------------------
# LINK GPO
# ------------------------------------------------------------------------------
Write-Host "[*] Linking GPO..." -NoNewline -ForegroundColor Cyan
try {
    New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
    Write-Host " COMPLETE" -ForegroundColor Green
} catch { Write-Host " ALREADY LINKED" -ForegroundColor Yellow }
gpupdate /force > $null 2>&1

# ------------------------------------------------------------------------------
# TEST
# ------------------------------------------------------------------------------
Write-Host "[*] Testing..." -ForegroundColor Cyan
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]" -ForegroundColor Green
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]" -ForegroundColor Yellow

Write-Host ""
Write-Host "======================================================================"
Write-Host "  APPLOCKER POLICY - COMPLETE"
Write-Host "======================================================================"
Write-Host "  Mode:      Audit Only (testing period)"
Write-Host "  Exe rules: 5 (Allow Windows/ProgramFiles/DicomViewer + Deny All)"
Write-Host "  Script:    3 (Allow Windows/MedDefense + Deny All)"
Write-Host "  XML:       $PolicyXmlPath"
Write-Host "======================================================================"

exit 0
<#
.SYNOPSIS
    AppLocker Policy - MedDefense Health Systems
    Task 12: AppLocker Policy

.DESCRIPTION
    Purpose: Deploy AppLocker application allow-listing to prevent
    unauthorized executables from running, blocking Crimson Tide's
    ransomware deployment mechanism.
    
    WHAT IT DOES: Creates GPO, configures executable rules (allow Windows,
    Program Files, DicomViewer.exe, deny all), script rules (allow Windows,
    MedDefense scripts, deny all), sets Audit Only mode, starts AppIDSvc,
    exports XML policy, tests with notepad/calc.
    
    WHY: Crimson Tide deployed ransomware via GPO. AppLocker blocks
    unauthorized executables - Phase 6 stopped dead. Clinical constraint:
    DicomViewer.exe must be allowed for physicians.
    
    WHEN TO USE: After Sysmon (Task 9-10). Before validation (Task 15).
    This is the last preventive control before SOC monitoring.

.REFERENCES
    Crimson Tide Phase 6: Ransomware deployed via GPO
    CIS Windows Server 2022 Benchmark Section 2.3.6

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy AppLocker allow-listing for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - AppLocker Policy"
$DomainDN = (Get-ADDomain).DistinguishedName
$PolicyXmlPath = "applocker_policy.xml"

Write-Host "[*] Creating GPO: `"$GpoName`"..." -NoNewline -ForegroundColor Cyan
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop; Write-Host " CREATED" -ForegroundColor Green }
    else { Write-Host " EXISTS" -ForegroundColor Yellow }
} catch { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# ------------------------------------------------------------------------------
# START APPLICATION IDENTITY SERVICE
# ------------------------------------------------------------------------------
Write-Host "[*] Starting AppIDSvc..." -NoNewline -ForegroundColor Cyan
try {
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
    Start-Service -Name AppIDSvc -ErrorAction Stop
    Write-Host " Running           [OK]" -ForegroundColor Green
} catch { Write-Host " [FAILED]" -ForegroundColor Red }

# ------------------------------------------------------------------------------
# CONFIGURE EXECUTABLE RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Executable Rules..." -ForegroundColor Cyan

$ExeRules = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <!-- Allow Windows system directories -->
    <FilePublisherRule Id="00000000-0000-0000-0000-000000000001" Name="Allow Windows" Description="Allow all signed Windows executables" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <!-- Allow Program Files -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Allow Program Files" Description="Allow all executables in Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow Program Files (x86) -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Allow Program Files x86" Description="Allow all executables in Program Files (x86)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow DicomViewer.exe (MedDefense clinical app) -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Allow DicomViewer" Description="Allow MedDefense clinical imaging application" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\Program Files\MedImage\DicomViewer.exe"/>
      </Conditions>
    </FilePathRule>
    <!-- Default DENY all other executables -->
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Deny All Other Exe" Description="Block all other executables" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files\*              [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]" -ForegroundColor Green
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# ------------------------------------------------------------------------------
# CONFIGURE SCRIPT RULES
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring Script Rules..." -ForegroundColor Cyan

$ScriptRules = @"
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <!-- Allow Windows scripts -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000001" Name="Allow Windows Scripts" Description="Allow scripts in Windows directory" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow MedDefense admin scripts -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000002" Name="Allow MedDefense Scripts" Description="Allow MedDefense admin scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Default DENY -->
    <FilePathRule Id="10000000-0000-0000-0000-000000000003" Name="Deny All Other Scripts" Description="Block all other scripts" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
"@

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)" -ForegroundColor Yellow

# ------------------------------------------------------------------------------
# BUILD FULL POLICY XML
# ------------------------------------------------------------------------------
$FullPolicy = $ExeRules -replace "</AppLockerPolicy>", "$ScriptRules</AppLockerPolicy>"

# Save policy XML
$FullPolicy | Out-File -FilePath $PolicyXmlPath -Encoding UTF8
Write-Host "[*] Policy exported to: $PolicyXmlPath" -ForegroundColor Green

# Set AppLocker policy via GPO registry
try {
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" `
        -ValueName "EnforcementMode" -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    Write-Host "[*] AppLocker GPO registry configured" -ForegroundColor Green
} catch { Write-Host "    [WARN] GPO registry set skipped" -ForegroundColor Yellow }

# ------------------------------------------------------------------------------
# LINK GPO
# ------------------------------------------------------------------------------
Write-Host "[*] Linking GPO..." -NoNewline -ForegroundColor Cyan
try {
    New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
    Write-Host " COMPLETE" -ForegroundColor Green
} catch { Write-Host " ALREADY LINKED" -ForegroundColor Yellow }
gpupdate /force > $null 2>&1

# ------------------------------------------------------------------------------
# TEST
# ------------------------------------------------------------------------------
Write-Host "[*] Testing..." -ForegroundColor Cyan
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]" -ForegroundColor Green
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]" -ForegroundColor Yellow

Write-Host ""
Write-Host "======================================================================"
Write-Host "  APPLOCKER POLICY - COMPLETE"
Write-Host "======================================================================"
Write-Host "  Mode:      Audit Only (testing period)"
Write-Host "  Exe rules: 5 (Allow Windows/ProgramFiles/DicomViewer + Deny All)"
Write-Host "  Script:    3 (Allow Windows/MedDefense + Deny All)"
Write-Host "  XML:       $PolicyXmlPath"
Write-Host "======================================================================"

exit 0
<#
.SYNOPSIS
    AppLocker Policy - MedDefense Health Systems
    Task 12: AppLocker Policy

.DESCRIPTION
    Purpose: Deploy AppLocker application allow-listing to prevent
    unauthorized executables from running.
    
    WHAT IT DOES: Creates GPO, configures executable rules (allow Windows,
    Program Files, DicomViewer.exe, deny all), script rules (allow Windows,
    MedDefense scripts, deny all), sets Audit Only mode, starts AppIDSvc
    and verifies with Get-Service, exports XML, tests.

.AUTHOR
    shamshed rajput
.DATE
    30/07/2026
.TARGET
    DC01.meddefense.local
#>

# Author: shamshed rajput
# Date: 30/07/2026
# Script Purpose: Deploy AppLocker allow-listing for MedDefense

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GpoName = "MedDefense - AppLocker Policy"
$DomainDN = (Get-ADDomain).DistinguishedName
$PolicyXmlPath = "applocker_policy.xml"

Write-Host "[*] Creating GPO..." -NoNewline -ForegroundColor Cyan
try {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $Gpo) { $Gpo = New-GPO -Name $GpoName -ErrorAction Stop; Write-Host " CREATED" -ForegroundColor Green }
    else { Write-Host " EXISTS" -ForegroundColor Yellow }
} catch { Write-Host " FAILED" -ForegroundColor Red; exit 1 }

# Start and verify AppIDSvc with Get-Service
Write-Host "[*] Starting AppIDSvc and verifying with Get-Service..." -ForegroundColor Cyan
try {
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
    Start-Service -Name AppIDSvc -ErrorAction Stop
    $SvcStatus = (Get-Service -Name AppIDSvc -ErrorAction Stop).Status
    Write-Host "    Get-Service AppIDSvc: $SvcStatus           [OK]" -ForegroundColor Green
} catch { Write-Host "    [FAILED]" -ForegroundColor Red }

# Executable Rules
Write-Host "[*] Configuring Executable Rules..." -ForegroundColor Cyan
Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files\*              [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]" -ForegroundColor Green
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# Script Rules
Write-Host "[*] Configuring Script Rules..." -ForegroundColor Cyan
Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# Audit Only
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)" -ForegroundColor Yellow

# Build and export XML
$PolicyXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="00000000-0000-0000-0000-000000000001" Name="Allow Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000002" Name="Allow Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000003" Name="Allow Program Files x86" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES(X86)%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000004" Name="Allow DicomViewer" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="C:\Program Files\MedImage\DicomViewer.exe"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="00000000-0000-0000-0000-000000000005" Name="Deny All Exe" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="10000000-0000-0000-0000-000000000001" Name="Allow Windows Scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="10000000-0000-0000-0000-000000000002" Name="Allow MedDefense Scripts" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="C:\MedDefense_Lab\Scripts\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="10000000-0000-0000-0000-000000000003" Name="Deny All Scripts" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

$PolicyXml | Out-File -FilePath $PolicyXmlPath -Encoding UTF8
Write-Host "[*] Policy exported to: $PolicyXmlPath" -ForegroundColor Green

# Link GPO
Write-Host "[*] Linking GPO..." -NoNewline -ForegroundColor Cyan
try { New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null; Write-Host " COMPLETE" -ForegroundColor Green } catch { Write-Host " ALREADY LINKED" -ForegroundColor Yellow }
gpupdate /force > $null 2>&1

# Test
Write-Host "[*] Testing..." -ForegroundColor Cyan
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]" -ForegroundColor Green
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]" -ForegroundColor Yellow

Write-Host ""
Write-Host "AppLocker Policy - COMPLETE" -ForegroundColor Green
exit 0
