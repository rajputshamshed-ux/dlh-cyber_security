================================================================================
                    LEGACY SYSTEMS - MEDDEFENSE HEALTH SYSTEMS
                    Task 12: The Legacy Systems
================================================================================

Exercise: Task 12 - The Legacy Systems
Analyst: shamshed rajput
Date: 21/07/2026
Objective: Assess the unique risk profile of end-of-life systems that will
          never receive another security patch.

Source: meddefense-vulnerability-scan.txt
NVD: https://nvd.nist.gov
Cross-References: 1x00 Task 6 (Legacy Dilemma), 1x01 Kill Chains


================================================================================
SYSTEM 1: WINDOWS XP SP3 (MRI WORKSTATION)
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Host             | 10.10.1.70 (WS-RAD-01)                           |
+------------------+--------------------------------------------------+
| OS               | Windows XP SP3                                   |
+------------------+--------------------------------------------------+
| EOL Date         | April 8, 2014 (Extended Support)                 |
|                  | April 8, 2014 (Extended Security Updates)        |
+------------------+--------------------------------------------------+
| Asset Role       | Siemens MAGNETOM MRI Scanner Control             |
|                  | Workstation (from 1x00 Asset Registry SRV-013)  |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - Patient safety, diagnostic imaging    |
|                  | 45 MRI studies/day, $2.1M device                |
+------------------+--------------------------------------------------+

EOL RESEARCH
------------
+----------------------------------------------------------------------------+
| Critical CVEs affecting Windows XP in the last 2 years:                    |
|                                                                             |
| COUNT: Over 40 critical CVEs published since EOL date                    |
|                                                                             |
| Most Critical (Last 2 Years):                                              |
|                                                                             |
| 1. CVE-2023-23415 (CVSS 9.8)                                              |
|    Windows Internet Key Exchange (IKE) Extension Remote Code Execution    |
|    Vulnerability. Unauthenticated remote attacker can execute code on     |
|    affected systems. No patch for Windows XP.                            |
|                                                                             |
| 2. CVE-2023-23525 (CVSS 8.1)                                              |
|    Remote Desktop Protocol Remote Code Execution Vulnerability.           |
|    No patch for Windows XP.                                               |
|                                                                             |
| Note: These are IN ADDITION to the already weaponized exploits present    |
| on the system (CVE-2017-0144 EternalBlue, CVE-2019-0708 BlueKeep,         |
| CVE-2008-4250 MS08-067).                                                 |
+----------------------------------------------------------------------------+

PERMANENT EXPOSURE
------------------
+----------------------------------------------------------------------------+
| EOL is categorically different from "unpatched" because it is             |
| PERMANENT. An unpatched system can be fixed by applying the available     |
| patch. An EOL system has NO patches available and NEVER WILL.             |
|                                                                             |
| Every future CVE affecting this OS version will remain unpatched          |
| indefinitely. The vulnerability count grows every year. The only way     |
| to close this risk is to REPLACE or RETIRE the system. The MRI           |
| cannot be upgraded due to manufacturer certification requirements,        |
| so the risk is PERMANENT unless compensating controls are implemented.   |
+----------------------------------------------------------------------------+

SCAN FINDINGS
-------------
+------------------+--------------------------------------------------+
| Finding 004      | Windows XP EOL with multiple weaponized          |
|                  | exploits (EternalBlue, BlueKeep, MS08-067)      |
+------------------+--------------------------------------------------+
| Finding 024      | DICOM Service Without Encryption (PACS images   |
|                  | transmitted in cleartext)                        |
+------------------+--------------------------------------------------+
| **Exploitable**  | **YES. CVE-2017-0144, CVE-2019-0708, and       |
| **Because EOL**  | **CVE-2008-4250 are ALL weaponized and acti-    |
|                  | **vely exploited. They remain unpatched BECAUSE**|
|                  | **the OS is EOL. There is no way to patch them.**|
+------------------+--------------------------------------------------+

COMPENSATING CONTROLS
---------------------
+----------------------------------------------------------------------------+
| PROPOSED IN 1x00 (Task 6 - Legacy Dilemma):                                |
|                                                                             |
| 1. Network Segmentation (Isolated VLAN) - Technical / Compensating        |
| 2. Application Whitelisting - Technical / Compensating                    |
| 3. Host-Based Firewall - Technical / Compensating                        |
|                                                                             |
| ADEQUACY:                                                                  |
|                                                                             |
| These controls are ONLY PARTIALLY adequate. They address the network     |
| access risk (segmentation) and execution risk (whitelisting), but they   |
| do NOT address:                                                            |
| - The risk of an attacker exploiting known vulnerabilities directly     |
| - The risk of malware that bypasses whitelisting                         |
| - The risk of physical access to the MRI                               |
|                                                                             |
| ADDITIONAL CONTROLS RECOMMENDED:                                           |
|                                                                             |
| 1. Immutable OS image - Read-only system that resets on reboot           |
| 2. Application Allow-List ONLY (Windows XP AppLocker)                   |
| 3. Network Monitoring - IDS/IPS on the MRI VLAN                         |
| 4. Periodic Vulnerability Scanning for Configuration Drift               |
| 5. Aggressive Endpoint Detection and Response (EDR) - if compatible     |
+----------------------------------------------------------------------------+


================================================================================
SYSTEM 2: WINDOWS SERVER 2012 R2 (PRINT SERVER)
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Host             | 10.10.2.31 (print-srv-01)                         |
+------------------+--------------------------------------------------+
| OS               | Windows Server 2012 R2                            |
+------------------+--------------------------------------------------+
| EOL Date         | October 10, 2023                                 |
+------------------+--------------------------------------------------+
| Asset Role       | Print Server (from 1x00 Asset Registry SRV-008)  |
+------------------+--------------------------------------------------+
| Asset Criticality| LOW - Printing services, no patient data         |
|                  | CIA: Availability (printing services)            |
+------------------+--------------------------------------------------+

EOL RESEARCH
------------
+----------------------------------------------------------------------------+
| Critical CVEs affecting Windows Server 2012 R2 in the last 2 years:       |
|                                                                             |
| COUNT: Over 50 critical CVEs published since EOL date                    |
|                                                                             |
| Most Critical (Last 2 Years):                                              |
|                                                                             |
| 1. CVE-2024-30080 (CVSS 8.8)                                              |
|    Windows Print Spooler Remote Code Execution Vulnerability.             |
|    Affects Windows Server 2012 R2. No patches for EOL systems.           |
|                                                                             |
| 2. CVE-2023-21768 (CVSS 9.8)                                              |
|    Windows Ancillary Function Driver Elevation of Privilege.             |
|    No patches for Windows Server 2012 R2.                                |
+----------------------------------------------------------------------------+

PERMANENT EXPOSURE
------------------
+----------------------------------------------------------------------------+
| Windows Server 2012 R2 reached EOL on October 10, 2023. Every new CVE    |
| discovered after this date that affects this OS version will NEVER be    |
| patched. Unlike Windows XP, the print server is not a critical medical  |
| device - it can be replaced or migrated to a newer OS.                   |
+----------------------------------------------------------------------------+

SCAN FINDINGS
-------------
+------------------+--------------------------------------------------+
| Finding 008      | Windows Server 2012 R2 EOL with PrintNightmare   |
|                  | (CVE-2021-34527, CVSS 8.8) - Weaponized         |
+------------------+--------------------------------------------------+
| **Exploitable**  | **YES. Print spooler vulnerabilities are        |
| **Because EOL**  | **actively exploited. The OS is EOL, so no**     |
|                  | **patches are available for any future print**   |
|                  | **spooler vulnerabilities.**                      |
+------------------+--------------------------------------------------+

COMPENSATING CONTROLS
---------------------
+----------------------------------------------------------------------------+
| CURRENT CONTROLS: None documented.                                        |
|                                                                             |
| RECOMMENDED CONTROLS:                                                      |
|                                                                             |
| Since this is NOT a critical medical device, the best compensating        |
| control is MIGRATION to a supported OS.                                   |
|                                                                             |
| If migration is not immediate:                                             |
| 1. Disable Print Spooler service if not needed                            |
| 2. Restrict network access to print server only                          |
| 3. Apply Windows Server 2012 R2 Extended Security Updates (ESU)          |
|    (paid support from Microsoft)                                          |
+----------------------------------------------------------------------------+


================================================================================
SYSTEM 3: UBUNTU 18.04 LTS (BILLING SERVER)
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Host             | 10.10.2.15 (billing-srv-01)                       |
+------------------+--------------------------------------------------+
| OS               | Ubuntu 18.04 LTS (Bionic Beaver)                  |
+------------------+--------------------------------------------------+
| EOL Date         | April 2023 (Standard Support)                    |
|                  | April 2028 (Extended Security Maintenance)       |
+------------------+--------------------------------------------------+
| Asset Role       | Billing/Claims Processing Server (SRV-004)       |
+------------------+--------------------------------------------------+
| Asset Criticality| HIGH - Financial data, revenue cycle             |
|                  | CIA: Confidentiality, Integrity, Availability    |
+------------------+--------------------------------------------------+

EOL RESEARCH
------------
+----------------------------------------------------------------------------+
| Critical CVEs affecting Ubuntu 18.04 in the last 2 years:                 |
|                                                                             |
| COUNT: Over 100 critical CVEs published since EOL date                   |
|                                                                             |
| Most Critical (Last 2 Years):                                              |
|                                                                             |
| 1. CVE-2024-2961 (CVSS 9.8)                                               |
|    glibc iconv() buffer overflow - Remote Code Execution.                |
|    Ubuntu 18.04 is affected. No patches without ESM.                    |
|                                                                             |
| 2. CVE-2023-4911 (CVSS 7.8)                                               |
|    GNU C Library (glibc) privilege escalation.                           |
|    Ubuntu 18.04 is affected. No patches without ESM.                    |
+----------------------------------------------------------------------------+

PERMANENT EXPOSURE
------------------
+----------------------------------------------------------------------------+
| Ubuntu 18.04 LTS reached standard EOL in April 2023. However, Extended    |
| Security Maintenance (ESM) is available through Ubuntu Pro. Unlike       |
| Windows XP, this system CAN BE PATCHED if ESM is activated. The          |
| problem is that ESM is NOT currently active (Finding 011).               |
+----------------------------------------------------------------------------+

SCAN FINDINGS
-------------
+------------------+--------------------------------------------------+
| Finding 001      | Apache mod_lua RCE (CVE-2021-44790, CVSS 9.8)    |
+------------------+--------------------------------------------------+
| Finding 002      | Apache Privilege Escalation (CVE-2019-0211,      |
|                  | CVSS 7.8) - CISA KEV                            |
+------------------+--------------------------------------------------+
| Finding 006      | MySQL Unrestricted Network Binding               |
+------------------+--------------------------------------------------+
| Finding 009      | SSH Password Authentication Enabled              |
+------------------+--------------------------------------------------+
| Finding 011      | Ubuntu 18.04 EOL without ESM                     |
+------------------+--------------------------------------------------+
| Finding 026      | Kernel Version Outdated (4.15.0-213)             |
+------------------+--------------------------------------------------+
| **Exploitable**  | **PARTIALLY. The Apache CVEs are exploitable     |
| **Because EOL**  | **regardless of ESM. However, the kernel and    |
|                  | **glibc vulnerabilities can ONLY be patched via  |
|                  | **ESM. Without ESM, these remain unpatched.**    |
+------------------+--------------------------------------------------+

COMPENSATING CONTROLS
---------------------
+----------------------------------------------------------------------------+
| RECOMMENDED CONTROLS:                                                      |
|                                                                             |
| 1. ACTIVATE ESM via Ubuntu Pro - IMMEDIATE PRIORITY                      |
|    (This is the most cost-effective solution)                            |
|                                                                             |
| 2. If ESM cannot be activated:                                             |
|    - Network Segmentation (move to isolated VLAN)                        |
|    - Harden SSH (disable password auth)                                  |
|    - Apply host-based firewall                                            |
|    - Increase logging and monitoring                                     |
|                                                                             |
| 3. Long-term: Migrate to Ubuntu 22.04 LTS or 24.04 LTS                  |
+----------------------------------------------------------------------------+


================================================================================
BUSINESS DECISION
================================================================================

+----------------------------------------------------------------------------+
| BUSINESS DECISION: Which ONE system should be migrated next quarter ?    |
|                                                                             |
| PRIORITY #1: MRI WINDOWS XP (System 1)                                    |
|                                                                             |
| JUSTIFICATION:                                                             |
|                                                                             |
| 1. ASSET CRITICALITY (from 1x00):                                          |
|    - The MRI is a CRITICAL asset (patient safety, 45 studies/day)        |
|    - $2.1M device value, 12-year expected lifespan                       |
|    - Direct patient safety impact                                         |
|                                                                             |
| 2. THREAT EXPOSURE (from 1x01):                                            |
|    - Kill Chain #4 (MRI → EHR) - weaponized exploits (EternalBlue)      |
|    - Breach 3 (Task 13) validated the exact scenario with $40M+         |
|      recovery costs                                                        |
|    - CISA KEV listed (EternalBlue, BlueKeep)                             |
|                                                                             |
| 3. PERMANENT VULNERABILITY:                                                |
|    - Windows XP has NO patches and NEVER WILL                            |
|    - Cannot be upgraded (manufacturer certification)                     |
|    - Compensating controls are ONLY PARTIAL mitigations                  |
|                                                                             |
| 4. WHY NOT THE OTHERS:                                                    |
|    - Windows Server 2012 R2: LOW criticality (print server)             |
|    - Ubuntu 18.04: Can be patched via ESM (quick win, low cost)        |
|                                                                             |
| 5. IMMEDIATE ACTION:                                                      |
|    - Phase 1 (1 week): Isolate MRI on dedicated VLAN (compensating       |
|      controls)                                                             |
|    - Phase 2 (3 months): Evaluate MRI replacement or virtualizing       |
|      the control workstation                                             |
|                                                                             |
| BOTTOM LINE:                                                              |
| The MRI Windows XP is the SINGLE MOST DANGEROUS legacy system.           |
| It has weaponized exploits, is on the flat network, and directly         |
| impacts patient safety. It must be the #1 priority for remediation.      |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+-----------------+-----------------+------------------+
| System   | OS               | EOL Date        | Critical CVEs   | Priority         |
|          |                  |                 | (Last 2 Years)  |                  |
+----------+------------------+-----------------+-----------------+------------------+
| MRI      | Windows XP SP3   | Apr 2014        | 40+             | #1 - CRITICAL    |
| Workst.  |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| Print    | Windows          | Oct 2023        | 50+             | #3 - LOW         |
| Server   | Server 2012 R2   |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| Billing  | Ubuntu 18.04 LTS | Apr 2023        | 100+            | #2 - HIGH        |
| Server   |                  |                 | (without ESM)   |                  |
+----------+------------------+-----------------+-----------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The MRI Windows XP is the SINGLE MOST CRITICAL legacy system.
   - Permanent vulnerabilities, no patches, weaponized exploits
   - #1 priority for migration/compensating controls

2. Windows Server 2012 R2 is the LEAST critical legacy system.
   - LOW criticality (print server)
   - Can be migrated easily
   - #3 priority

3. Ubuntu 18.04 is the EASIEST to fix.
   - ESM is available and relatively low cost
   - Activation immediately provides patches
   - #2 priority

4. EOL is categorically different from "unpatched":
   - Unpatched = can be fixed
   - EOL = CANNOT be fixed (for that OS)

5. Compensating controls are ONLY PARTIAL solutions:
   - They reduce risk but do NOT eliminate it
   - Only migration/replacement eliminates the risk


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt (Findings 001, 002, 004, 006, 008, 009,
  011, 024, 026)
- NVD: https://nvd.nist.gov
- Asset Registry (1x00 Task 7): SRV-001, SRV-004, SRV-008, SRV-013
- Criticality Assessment (1x00 Task 8)
- Legacy Dilemma (1x00 Task 6)
- Kill Chains (1x01 Task 10): KC #4
- Reality Check (1x00 Task 13): Breach 3


================================================================================
END OF LEGACY SYSTEMS REPORT
================================================================================
