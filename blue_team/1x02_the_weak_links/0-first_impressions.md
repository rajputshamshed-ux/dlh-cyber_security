================================================================================
                    FIRST IMPRESSIONS - MEDDEFENSE HEALTH SYSTEMS
                    Task 0: The Scan Report
================================================================================

Exercise: Task 0 - The Scan Report
Analyst: shamshed rajput
Date: 19/07/2026
Objective: Develop the professional reflex of reading a scan report for
          structure and context before diving into individual findings.

Source: meddefense-vulnerability-scan.txt
Scanner: OpenVAS 22.x (Greenbone Community Edition)
Scan Date: 19/07/2026 - 5 days
Scan Target: 10.10.0.0/16 (all internal subnets)
Scan Policy: Full and Deep (authenticated where credentials available)
Requested by: James Chen, Deputy CISO
Executed by: SecurePoint Consulting (third-party)

Cross-References to Project 1x00:
- Asset Registry (Task 7): All assets
- Gap Analysis (Task 12): GAP-001, GAP-003, GAP-004, GAP-007, GAP-014, GAP-016


================================================================================
1. SCAN METADATA
================================================================================

+------------------+--------------------------------------------------+
| Scanner          | OpenVAS 22.x (Greenbone Community Edition)       |
+------------------+--------------------------------------------------+
| Scan Date        | 19/07/2026 - 5 days                               |
+------------------+--------------------------------------------------+
| Scan Target      | 10.10.0.0/16 (all internal subnets)              |
+------------------+--------------------------------------------------+
| Scan Policy      | Full and Deep (authenticated where credentials   |
|                  | available)                                        |
+------------------+--------------------------------------------------+
| Executed By      | SecurePoint Consulting (third-party)             |
+------------------+--------------------------------------------------+
| Requested By     | James Chen, Deputy CISO                          |
+------------------+--------------------------------------------------+
| Hosts Scanned    | 47 (responsive during scan window)               |
+------------------+--------------------------------------------------+
| Findings         | 31 total                                          |
+------------------+--------------------------------------------------+
| Authentication   | Authenticated: Linux servers (SSH), Windows     |
|                  | (domain credentials)                             |
|                  | Unauthenticated: Medical devices (no credentials)|
+------------------+--------------------------------------------------+
| Scan Timing      | Off-peak hours (02:00-06:00) - minimized         |
|                  | clinical impact                                   |
+------------------+--------------------------------------------------+
| NOT SCANNED      | - Cloud services (O365)                          |
|                  | - Mobile devices (iPads)                         |
|                  | - Assets offline during scan window              |
|                  | - No active exploitation attempted               |
+------------------+--------------------------------------------------+
| False Positives  | OpenVAS typical false positive rate: 5-10%      |
+------------------+--------------------------------------------------+


================================================================================
2. FINDING DISTRIBUTION
================================================================================

+------------------+---------------------+------------------------------------------+
| Severity         | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| CRITICAL         | 4                   | 12.9%                                    |
| HIGH             | 7                   | 22.6%                                    |
| MEDIUM           | 11                  | 35.5%                                    |
| LOW              | 5                   | 16.1%                                    |
| INFORMATIONAL    | 4                   | 12.9%                                    |
+------------------+---------------------+------------------------------------------+
| TOTAL            | 31                  | 100%                                     |
+------------------+---------------------+------------------------------------------+

MOST FINDINGS BY SEVERITY: MEDIUM (11 findings - 35.5%)


================================================================================
3. ASSET HEAT MAP
================================================================================

TOP 5 HOSTS BY FINDING COUNT
----------------------------

+----------+------------------+-----------------+------------------------------------------+
| Rank     | Host             | Finding Count   | Asset Role (from 1x00 T7)                |
+----------+------------------+-----------------+------------------------------------------+
| #1       | 10.10.2.15       | 6 (C-2, H-3,    | billing-srv-01 - Billing/Claims          |
|          | (billing-srv-01) | L-1)            | Processing (CRITICAL - Financial Data)   |
+----------+------------------+-----------------+------------------------------------------+
| #2       | 10.10.2.50       | 4 (H-1, M-3)    | web-srv-01 - Public Website + Patient    |
|          | (web-srv-01)     |                 | Portal (HIGH)                            |
+----------+------------------+-----------------+------------------------------------------+
| #3       | 10.10.2.10       | 2 (M-1,         | ehr-srv-01 - EHR Application Server      |
|          | (ehr-srv-01)     | Info-1)         | (CRITICAL - Patient Care)                |
+----------+------------------+-----------------+------------------------------------------+
| #4       | 10.10.2.20       | 2 (H-1, M-1,    | ad-dc-01 - Primary Domain Controller     |
|          | (ad-dc-01)       | L-1)            | (CRITICAL - Authentication)              |
+----------+------------------+-----------------+------------------------------------------+
| #5       | Multiple (IoT)   | 2 (H-1, M-1)    | BD Alaris Pumps + Philips Monitors      |
|          | (10.10.3.40-46,  |                 | (CRITICAL - Life-Safety)                 |
|          | 10.10.3.10-32)   |                 |                                          |
+----------+------------------+-----------------+------------------------------------------+

OBSERVATION: billing-srv-01 has the MOST findings (6). This is the same
server that had the crypto-miner (Task 2) and was hit by ransomware in
January. It is clearly MedDefense's most exposed critical asset.


================================================================================
4. FIRST OBSERVATIONS
================================================================================

CRITICAL FINDINGS CONCENTRATION
-------------------------------
+----------------------------------------------------------------------------+
| The 4 CRITICAL findings are spread across 3 distinct systems:              |
|                                                                             |
| 1. FINDING 001 + 002 (billing-srv-01) - Apache vulnerabilities             |
|    - CVE-2021-44790 (CVSS 9.8) - Remote Code Execution via mod_lua        |
|    - CVE-2019-0211 (CVSS 7.8) - Local Privilege Escalation                |
|    - These TWO vulnerabilities chain together for FULL SERVER CONTROL     |
|                                                                             |
| 2. FINDING 003 (ehr-db-01) - PostgreSQL unrestricted network access        |
|    - No CVE - Misconfiguration                                            |
|    - Database accessible from the ENTIRE flat network                     |
|                                                                             |
| 3. FINDING 004 (MRI Workstation - WS-RAD-01) - Windows XP EOL             |
|    - Multiple weaponized exploits (EternalBlue, BlueKeep, MS08-067)       |
|    - Ports 445 and 3389 are OPEN on an EOL system                         |
+----------------------------------------------------------------------------+

RELATED FINDINGS
----------------
+----------------------------------------------------------------------------+
| MULTIPLE FINDINGS FORM CHAINS:                                             |
|                                                                             |
| CHAIN #1: billing-srv-01 Full Compromise                                   |
|  - Finding 001 (Remote Code Execution via Apache)                         |
|  - Finding 002 (Privilege Escalation to root)                             |
|  - Finding 009 (SSH password auth, brute-force potential)                 |
|  - Finding 006 (MySQL accessible network-wide)                            |
|  - Finding 011 (Ubuntu 18.04 EOL - no patches)                            |
|                                                                             |
| CHAIN #2: MRI → Pivot to Network                                           |
|  - Finding 004 (Windows XP - multiple exploits)                           |
|  - Finding 024 (PACS DICOM unencrypted)                                   |
|  - Finding 003 (PostgreSQL accessible) - MRI can reach EHR database       |
|                                                                             |
| CHAIN #3: Internal Network Discovery                                       |
|  - Finding 007 (LDAP signing not required)                                |
|  - Finding 018 (Kerberos weak encryption)                                 |
|  - Finding 025 (DNS zone transfer) - Full network map                     |
+----------------------------------------------------------------------------+

SURPRISES
---------
+----------------------------------------------------------------------------+
| 1. UNIDENTIFIED SHADOW IT DEVICES:                                         |
|    - Finding 028: Unknown Linux device on server subnet (port 8888,       |
|      9090) - Jupyter Notebook + Cockpit                                  |
|    - Finding 029: Unknown Linux device at Westside (port 3000 - Grafana) |
|    - These were NOT in the Asset Registry (Task 7)                       |
|                                                                             |
| 2. DEFAULT CREDENTIALS ON MEDICAL DEVICES:                                 |
|    - BD Alaris pumps (7 of 7) have unchanged admin/admin credentials     |
|    - This was identified as GAP-007 in 1x00                              |
|                                                                             |
| 3. OPEN PORTS ON Windows XP MRI:                                           |
|    - Port 445 (SMB) and 3389 (RDP) are OPEN on a Windows XP system      |
|    - EternalBlue, BlueKeep, and MS08-067 are ALL present                 |
|    - This is a PERMANENT backdoor (GAP-007 from 1x00)                   |
+----------------------------------------------------------------------------+

PATTERN OBSERVATION
-------------------
+----------------------------------------------------------------------------+
| The flat network (GAP-003) is a COMMON ENABLER across multiple findings:  |
|                                                                             |
| - Finding 003: PostgreSQL accessible network-wide                         |
| - Finding 006: MySQL accessible network-wide                              |
| - Finding 007: LDAP accessible network-wide                               |
| - Finding 015: NAS management accessible network-wide                     |
| - Finding 016: Philips monitors accessible network-wide                   |
| - Finding 010: BD Alaris pumps accessible network-wide                    |
|                                                                             |
| Without network segmentation, a compromise of ANY system provides access  |
| to ALL other systems. This confirms the kill chain analysis from 1x01.   |
+----------------------------------------------------------------------------+


================================================================================
5. SCAN LIMITATIONS
================================================================================

+----------------------------------------------------------------------------+
| WHAT THIS SCAN DOES NOT TELL YOU:                                          |
|                                                                             |
| 1. MISSING ASSETS:                                                         |
|    - Cloud services (O365) - not scanned                                 |
|    - Mobile devices (iPads) - not scanned                                |
|    - Assets offline during scan window - not scanned                     |
|    - Westside unknown server (ws-srv-02) - suspected but not confirmed  |
|                                                                             |
| 2. VULNERABILITY TYPES OUTSIDE SCOPE:                                      |
|    - Zero-day vulnerabilities (not in CVE databases)                     |
|    - Vulnerabilities disclosed after the scan date                       |
|    - Social engineering vulnerabilities (human factor)                   |
|    - Physical security vulnerabilities                                   |
|    - Supply chain vulnerabilities (vendor security)                      |
|    - Misconfigurations without CVE numbers (some are covered, but not    |
|      all)                                                                 |
|                                                                             |
| 3. OPERATIONAL CONTEXT:                                                    |
|    - Does NOT tell you which vulnerabilities are actually being          |
|      exploited by threat actors (requires CISA KEV cross-reference)      |
|    - Does NOT tell you which assets are most critical (requires 1x00     |
|      Asset Registry)                                                      |
|    - Does NOT tell you how to prioritize (requires 1x01 Threat Report)   |
|    - Does NOT verify if findings are false positives (requires manual    |
|      verification)                                                        |
|                                                                             |
| 4. EXPLOIT AVAILABILITY:                                                   |
|    - Does NOT tell you if public exploit code exists (requires Exploit-DB)|
|                                                                             |
| 5. BUSINESS IMPACT:                                                        |
|    - Does NOT tell you the business impact of a compromise (requires     |
|      Asset Criticality from 1x00 T8)                                      |
+----------------------------------------------------------------------------+


================================================================================
6. KEY TAKEAWAYS
================================================================================

1. billing-srv-01 has the MOST findings (6) - this is the server with the
   crypto-miner history. It remains the most exposed critical asset.

2. The 4 CRITICAL findings are not noise. They represent:
   - Remote code execution on billing-srv-01 (FINDING 001)
   - Database exposure on ehr-db-01 (FINDING 003)
   - Windows XP MRI with weaponized exploits (FINDING 004)

3. The flat network (GAP-003) is the PRIMARY ENABLER. Multiple findings
   are made worse by the lack of segmentation.

4. 2 UNKNOWN SHADOW IT devices were discovered. These need immediate
   investigation (GAP-009 from 1x00).

5. The scan confirms the Kill Chains from 1x01:
   - Kill Chain #1 (VPN Ransomware) can use the Apache vulnerabilities
   - Kill Chain #2 (Phishing → EHR) can use PostgreSQL exposure
   - Kill Chain #4 (MRI → EHR) can use Windows XP exploits

6. The scan does NOT cover O365, iPads, or offline assets. These remain
   blind spots.

7. Finding 020 (OpenSSH) is flagged as a potential FALSE POSITIVE by the
   scanner itself. This will need manual verification.

8. This is a DATASET, not an ANALYSIS. The next step is to research each
   finding and connect it to the threat landscape and asset criticality.


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt
- Asset Registry (1x00 Task 7)
- Gap Analysis (1x00 Task 12)
- Threat Actor Matrix (1x01 Task 6)
- Kill Chains (1x01 Task 10)


================================================================================
END OF FIRST IMPRESSIONS REPORT
================================================================================
