================================================================================
                    RISK REGISTER - MEDDEFENSE HEALTH SYSTEMS
                    Task 10: The Risk Register
================================================================================

Exercise: Task 10 - The Risk Register
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Build the formal Risk Register that will serve as the operational
          backbone of MedDefense's security program.

Sources: 1x00 Gap Analysis, 1x01 Threat Landscape, 1x02 Vulnerability Scan,
         1x03 ALE Workshop (T6), 1x03 Cost-Benefit Analysis (T7)


================================================================================
RISK SCORING SCALE
================================================================================

LIKELIHOOD SCALE (1-5)
+----------+------------------------------------------+
| Score    | Definition                               |
+----------+------------------------------------------+
| 1        | Highly unlikely (once in 10+ years)      |
| 2        | Unlikely (once in 5-10 years)            |
| 3        | Possible (once in 2-5 years)             |
| 4        | Likely (once in 1-2 years)               |
| 5        | Highly likely (more than once per year)  |
+----------+------------------------------------------+

IMPACT SCALE (1-5)
+----------+------------------------------------------+
| Score    | Definition                               |
+----------+------------------------------------------+
| 1        | Negligible (<$10K, no patient impact)    |
| 2        | Minor ($10K-$50K, minimal patient impact)|
| 3        | Moderate ($50K-$250K, some patient impact)|
| 4        | Major ($250K-$1M, significant patient    |
|          | impact)                                  |
| 5        | Catastrophic (>$1M, patient safety risk, |
|          | regulatory fines, reputational damage)   |
+----------+------------------------------------------+

RISK SCORE MATRIX
+----------+----------+----------+----------+----------+----------+
|          | Impact 1 | Impact 2 | Impact 3 | Impact 4 | Impact 5 |
+----------+----------+----------+----------+----------+----------+
| Likely 5 | 5        | 10       | 15       | 20       | 25       |
| Likely 4 | 4        | 8        | 12       | 16       | 20       |
| Likely 3 | 3        | 6        | 9        | 12       | 15       |
| Likely 2 | 2        | 4        | 6        | 8        | 10       |
| Likely 1 | 1        | 2        | 3        | 4        | 5        |
+----------+----------+----------+----------+----------+----------+

RISK LEVELS:
- Critical: 20-25 (Immediate action required)
- High: 12-19 (Action within 30 days)
- Medium: 6-11 (Action within 90 days)
- Low: 1-5 (Monitor)


================================================================================
RISK REGISTER
================================================================================

RISK-001: DATA BREACH VIA EHR DATABASE EXPOSURE
-----------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-001                                         |
+------------------+--------------------------------------------------+
| Risk Description | Unauthorized access to the EHR database via      |
|                  | unrestricted network access (PostgreSQL 5432)   |
|                  | leading to exfiltration of 50,000+ patient      |
|                  | records.                                         |
+------------------+--------------------------------------------------+
| Risk Category    | COMPLIANCE + FINANCIAL                           |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), Insider Malicious (#4)   |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 003 (PostgreSQL Unrestricted Access),    |
|                  | Finding 031 (Ghostcat)                           |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ehr-db-01 (SRV-002 - CRITICAL), ehr-srv-01       |
|                  | (SRV-001 - CRITICAL)                             |
+------------------+--------------------------------------------------+
| Likelihood       | 5 (Highly likely - PostgreSQL accessible         |
|                  | network-wide, no SIEM)                           |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - PHI exposure, HIPAA fines,     |
|                  | litigation, reputational damage, $9M+ cost)     |
+------------------+--------------------------------------------------+
| Inherent Risk    | 25 (CRITICAL)                                     |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $4,310,625                                        |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO)                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Highest ALE in the organization. Direct          |
| Justification    | path to patient data. Must be addressed          |
|                  | immediately.                                      |
+------------------+--------------------------------------------------+
| Planned          | 1. PostgreSQL restriction (Finding 003)          |
| Control(s)       | 2. Ghostcat patch (Finding 031)                  |
|                  | 3. SIEM deployment (GAP-001)                     |
|                  | 4. Network segmentation (GAP-003)                |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - PostgreSQL will be restricted,     |
|                  | Ghostcat patched, SIEM provides detection,      |
|                  | segmentation limits lateral movement.           |
+------------------+--------------------------------------------------+
| KRI              | Number of failed connection attempts to          |
|                  | PostgreSQL 5432 from unauthorized IPs            |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-002: VPN COMPROMISE LEADING TO FULL NETWORK ACCESS
-------------------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-002                                         |
+------------------+--------------------------------------------------+
| Risk Description | Unpatched FortiGate VPN vulnerability exploited   |
|                  | allowing external attacker to gain full network  |
|                  | access and deploy ransomware.                    |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL + FINANCIAL                          |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), Opportunistic (#6)      |
+------------------+--------------------------------------------------+
| Vulnerability    | OSINT - CVE-2024-21762 (FortiGate), GAP-014      |
|                  | (No Patch Management)                            |
+------------------+--------------------------------------------------+
| Affected Asset(s)| FortiGate 100F (NET-001 - CRITICAL), ALL         |
|                  | internal assets                                  |
+------------------+--------------------------------------------------+
| Likelihood       | 4 (Likely - VPN is #1 initial access vector at   |
|                  | 38%, no patch management)                        |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - Full network access, all       |
|                  | systems compromised, $5M+ cost)                 |
+------------------+--------------------------------------------------+
| Inherent Risk    | 20 (CRITICAL)                                     |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $1,334,945                                        |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO) + Sarah Park (IT        |
|                  | Director)                                        |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | VPN is the single point of entry. Compromise     |
| Justification    | bypasses ALL perimeter controls.                 |
+------------------+--------------------------------------------------+
| Planned          | 1. VPN Patch Management (GAP-014)                |
| Control(s)       | 2. MFA on VPN (GAP-004)                          |
|                  | 3. Network Segmentation (GAP-003)                |
|                  | 4. SIEM alerting on VPN access (GAP-001)        |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (8) - MFA and segmentation significantly  |
|                  | reduce risk, but VPN remains an entry point.    |
+------------------+--------------------------------------------------+
| KRI              | Unusual VPN login attempts from new IP          |
|                  | addresses or off-hours                          |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-003: RANSOMWARE ENCRYPTS EHR SYSTEM
-----------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-003                                         |
+------------------+--------------------------------------------------+
| Risk Description | Ransomware deployment on EHR system causing      |
|                  | extended downtime, data loss, and patient        |
|                  | care disruption.                                  |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL + COMPLIANCE                         |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1)                           |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 001/002 (Apache chain), Finding 031      |
|                  | (Ghostcat), GAP-003 (Flat Network)              |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ehr-srv-01 (SRV-001 - CRITICAL), ehr-db-01       |
|                  | (SRV-002 - CRITICAL), all clinical systems      |
+------------------+--------------------------------------------------+
| Likelihood       | 4 (Likely - Healthcare is most-targeted sector,  |
|                  | MedDefense matches target profile)              |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - 11+ days downtime, $5M+       |
|                  | recovery, patient safety risk)                  |
+------------------+--------------------------------------------------+
| Inherent Risk    | 20 (CRITICAL)                                     |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $273,615                                          |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO) + Sarah Park (IT        |
|                  | Director)                                        |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Ransomware is the #1 threat to healthcare.       |
| Justification    | Multiple vulnerabilities enable this attack.    |
+------------------+--------------------------------------------------+
| Planned          | 1. Patch Apache (Finding 001/002)                |
| Control(s)       | 2. Patch Ghostcat (Finding 031)                  |
|                  | 3. Network Segmentation (GAP-003)                |
|                  | 4. MFA (GAP-004)                                 |
|                  | 5. Offsite Backup (Control 5 from T7)           |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - Multiple controls reduce            |
|                  | likelihood and impact, but ransomware remains   |
|                  | a persistent threat.                             |
+------------------+--------------------------------------------------+
| KRI              | Ransomware threat intelligence alerts, unusual   |
|                  | file encryption activity                         |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-004: INSIDER DATA THEFT (NEGLIGENT)
-----------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-004                                         |
+------------------+--------------------------------------------------+
| Risk Description | Negligent insider (employee) inadvertently       |
|                  | exposes PHI via USB drive, misdirected email,   |
|                  | or lost device.                                   |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL + COMPLIANCE                         |
+------------------+--------------------------------------------------+
| Threat Source    | Insider Negligent (#2)                           |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 023 (USB not restricted), GAP-013 (Low   |
|                  | Training), GAP-011 (No Enforcement)             |
+------------------+--------------------------------------------------+
| Affected Asset(s)| Clinical workstations (END-001, END-002,         |
|                  | END-003), patient data                           |
+------------------+--------------------------------------------------+
| Likelihood       | 5 (Highly likely - 2,000 staff, no DLP, no      |
|                  | USB restriction, low training completion)       |
+------------------+--------------------------------------------------+
| Impact           | 3 (Moderate - $120K average cost per incident)   |
+------------------+--------------------------------------------------+
| Inherent Risk    | 15 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $360,000                                          |
+------------------+--------------------------------------------------+
| Risk Owner       | Sarah Park (IT Director) + HR Director           |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Highest frequency risk. Low cost controls can    |
| Justification    | significantly reduce risk.                       |
+------------------+--------------------------------------------------+
| Planned          | 1. USB Restriction GPO (Finding 023)             |
| Control(s)       | 2. Security Awareness Training (GAP-013)         |
|                  | 3. DLP solution                                   |
|                  | 4. Enforcement policy (GAP-011)                  |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - Training and USB restrictions       |
|                  | reduce risk, but human error cannot be fully    |
|                  | eliminated.                                      |
+------------------+--------------------------------------------------+
| KRI              | Number of USB devices connected to workstations, |
|                  | phishing simulation click rate                  |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-005: MEDICAL IOT COMPROMISE (PATIENT SAFETY)
--------------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-005                                         |
+------------------+--------------------------------------------------+
| Risk Description | BD Alaris infusion pumps or MRI workstation      |
|                  | compromised via default credentials or Windows   |
|                  | XP exploit, leading to patient safety incident. |
+------------------+--------------------------------------------------+
| Risk Category    | STRATEGIC + OPERATIONAL                          |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), Opportunistic (#6)      |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 010 (BD Alaris default credentials),     |
|                  | Finding 004 (MRI Windows XP), GAP-003 (Flat     |
|                  | Network), GAP-007 (No Compensating)             |
+------------------+--------------------------------------------------+
| Affected Asset(s)| BD Alaris Pumps (IOT-002 - CRITICAL), MRI        |
|                  | Workstation (SRV-013 - CRITICAL)                |
+------------------+--------------------------------------------------+
| Likelihood       | 3 (Possible - Flat network and default           |
|                  | credentials make compromise plausible)          |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - Patient injury or death, FDA   |
|                  | investigation, massive liability)               |
+------------------+--------------------------------------------------+
| Inherent Risk    | 15 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $45,000 (DoS) + $43,000 (Patient Safety) =       |
|                  | $88,000 total                                    |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO) + Biomedical            |
|                  | Engineering Director                              |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Patient safety is paramount. Direct risk to      |
| Justification    | human life.                                       |
+------------------+--------------------------------------------------+
| Planned          | 1. Change default credentials (Finding 010)      |
| Control(s)       | 2. IoT Network Segmentation (GAP-003)            |
|                  | 3. Compensating Controls for MRI (GAP-007)      |
|                  | 4. Network Monitoring (C-020)                    |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (8) - Default credentials changed and     |
|                  | IoT isolated. MRI remains EOL but compensated.  |
+------------------+--------------------------------------------------+
| KRI              | Unusual traffic to IoT devices, failed login     |
|                  | attempts on pump management interfaces          |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-006: SUPPLY CHAIN COMPROMISE (VENDOR ACCESS)
--------------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-006                                         |
+------------------+--------------------------------------------------+
| Risk Description | MedTech Solutions vendor account compromised     |
|                  | leading to direct access to the EHR system.     |
+------------------+--------------------------------------------------+
| Risk Category    | STRATEGIC + COMPLIANCE                           |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), APT (#2)                |
+------------------+--------------------------------------------------+
| Vulnerability    | GAP-012 (No Vendor Account Management), GAP-004 |
|                  | (No MFA for vendors)                             |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ehr-srv-01 (SRV-001 - CRITICAL), ehr-db-01       |
|                  | (SRV-002 - CRITICAL)                             |
+------------------+--------------------------------------------------+
| Likelihood       | 3 (Possible - Change Healthcare breach proved   |
|                  | this vector is real, but requires vendor        |
|                  | compromise)                                      |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - Direct access to PHI, $2.5M+  |
|                  | ransom, $5M+ recovery)                          |
+------------------+--------------------------------------------------+
| Inherent Risk    | 15 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | Not directly calculated - included in Risk-002  |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO) + Sarah Park (IT        |
|                  | Director)                                        |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Vendor accounts bypass ALL perimeter controls.  |
| Justification    | MedTech has direct server access.               |
+------------------+--------------------------------------------------+
| Planned          | 1. Vendor Account MFA (GAP-012)                  |
| Control(s)       | 2. Vendor Access Review (quarterly)              |
|                  | 3. Least Privilege for vendor accounts          |
|                  | 4. Vendor activity monitoring (SIEM)            |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - MFA and monitoring reduce risk,    |
|                  | but vendor compromise risk remains.             |
+------------------+--------------------------------------------------+
| KRI              | Vendor account login activity from unusual      |
|                  | locations, vendor access requests               |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-007: NO INCIDENT RESPONSE CAPABILITY
------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-007                                         |
+------------------+--------------------------------------------------+
| Risk Description | No formal incident response plan leading to      |
|                  | extended recovery time, higher costs, and        |
|                  | regulatory penalties when an incident occurs.   |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL + COMPLIANCE                         |
+------------------+--------------------------------------------------+
| Threat Source    | ALL actors (post-incident impact)                |
+------------------+--------------------------------------------------+
| Vulnerability    | GAP-002 (No IR Plan), GAP-001 (No SIEM)         |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL assets                                        |
+------------------+--------------------------------------------------+
| Likelihood       | 5 (Highly likely - an incident WILL happen,      |
|                  | no plan to respond)                              |
+------------------+--------------------------------------------------+
| Impact           | 4 (Major - Extended recovery, higher costs,      |
|                  | regulatory penalties)                            |
+------------------+--------------------------------------------------+
| Inherent Risk    | 20 (CRITICAL)                                     |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | Not directly calculated (part of all ALEs)      |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO)                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Without a plan, every incident is more costly    |
| Justification    | and takes longer to recover.                     |
+------------------+--------------------------------------------------+
| Planned          | 1. IR Plan Development (GAP-002)                 |
| Control(s)       | 2. Tabletop exercises                             |
|                  | 3. BCP/DR Plan Development                        |
|                  | 4. Designated response roles (RACI)             |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (8) - A plan will reduce recovery time,   |
|                  | but execution still depends on people.          |
+------------------+--------------------------------------------------+
| KRI              | Number of IR plan updates, tabletop exercise     |
|                  | completion, incident response time              |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-008: WESTSIDE CLINIC PERIMETER BREACH
-------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-008                                         |
+------------------+--------------------------------------------------+
| Risk Description | Consumer-grade Netgear router at Westside        |
|                  | compromised allowing attacker to pivot to        |
|                  | MedDefense Central via VPN tunnel.              |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL                                       |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), Opportunistic (#6)      |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 014 (Consumer-grade router), GAP-003    |
|                  | (Flat Network)                                   |
+------------------+--------------------------------------------------+
| Affected Asset(s)| Westside Router (NET-004), VPN tunnel, Central   |
|                  | network                                          |
+------------------+--------------------------------------------------+
| Likelihood       | 3 (Possible - Consumer router has known          |
|                  | vulnerabilities, no enterprise security)        |
+------------------+--------------------------------------------------+
| Impact           | 4 (Major - Pivot to Central network, potential  |
|                  | ransomware)                                      |
+------------------+--------------------------------------------------+
| Inherent Risk    | 12 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | $58,723 (from T6 - Westside Firewall deferral)   |
+------------------+--------------------------------------------------+
| Risk Owner       | Sarah Park (IT Director)                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Westside is a medical facility with no           |
| Justification    | enterprise security. This is unacceptable.      |
+------------------+--------------------------------------------------+
| Planned          | 1. Replace Netgear with enterprise firewall      |
| Control(s)       |    (Control 6 from T7)                           |
|                  | 2. Network segmentation for Westside            |
+------------------+--------------------------------------------------+
| Residual Risk    | Low (4) - Enterprise firewall significantly      |
|                  | reduces the risk.                                |
+------------------+--------------------------------------------------+
| KRI              | Unusual traffic patterns from Westside to        |
|                  | Central, router firmware updates missed          |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-009: SHADOW IT ON THE NETWORK
-----------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-009                                         |
+------------------+--------------------------------------------------+
| Risk Description | Unmanaged shadow IT devices (unknown Linux       |
|                  | servers, Raspberry Pi) providing undetected      |
|                  | entry points for attackers.                      |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL                                       |
+------------------+--------------------------------------------------+
| Threat Source    | Opportunistic (#6), Insider Negligent (#2)      |
+------------------+--------------------------------------------------+
| Vulnerability    | Findings 028/029 (Unknown Linux devices),        |
|                  | GAP-009 (Shadow IT)                              |
+------------------+--------------------------------------------------+
| Affected Asset(s)| Unknown Linux devices (END-007, END-008),        |
|                  | Raspberry Pi                                     |
+------------------+--------------------------------------------------+
| Likelihood       | 4 (Likely - Devices discovered, no process to    |
|                  | identify shadow IT)                              |
+------------------+--------------------------------------------------+
| Impact           | 4 (Major - Undetected entry point, pivot to      |
|                  | internal systems)                                |
+------------------+--------------------------------------------------+
| Inherent Risk    | 16 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | Not directly calculated                           |
+------------------+--------------------------------------------------+
| Risk Owner       | James Chen (Deputy CISO) + IT Asset Management   |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | Shadow IT is invisible to all security controls. |
| Justification    | Must be discovered and managed.                  |
+------------------+--------------------------------------------------+
| Planned          | 1. Investigate and document shadow IT devices    |
| Control(s)       | 2. Implement asset inventory maintenance         |
|                  |    (CIS Control 1)                               |
|                  | 3. Network scanning for unknown devices          |
|                  | 4. Decommission or migrate shadow IT             |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - Once discovered, devices can be     |
|                  | managed or removed.                              |
+------------------+--------------------------------------------------+
| KRI              | Number of unknown devices on network scans,      |
|                  | unregistered IP addresses                        |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


RISK-010: PACS DATA LOSS (NO BACKUPS)
--------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | RISK-010                                         |
+------------------+--------------------------------------------------+
| Risk Description | PACS imaging server compromised or fails, with   |
|                  | no backups available, resulting in permanent     |
|                  | loss of medical images.                          |
+------------------+--------------------------------------------------+
| Risk Category    | OPERATIONAL + FINANCIAL                          |
+------------------+--------------------------------------------------+
| Threat Source    | Ransomware Groups (#1), Insider (#4)            |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 024 (DICOM unencrypted), Artifact 5      |
|                  | (PACS NOT backed up)                             |
+------------------+--------------------------------------------------+
| Affected Asset(s)| pacs-srv-01 (SRV-003 - CRITICAL), MRI, CT        |
+------------------+--------------------------------------------------+
| Likelihood       | 3 (Possible - Ransomware could encrypt PACS      |
|                  | like other systems)                              |
+------------------+--------------------------------------------------+
| Impact           | 5 (Catastrophic - Permanent loss of medical      |
|                  | images, 45 MRI studies/day, diagnostic           |
|                  | capability compromised)                          |
+------------------+--------------------------------------------------+
| Inherent Risk    | 15 (HIGH)                                         |
| Score            |                                                   |
+------------------+--------------------------------------------------+
| ALE              | Not directly calculated                           |
+------------------+--------------------------------------------------+
| Risk Owner       | Sarah Park (IT Director) + Radiology Director    |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                          |
| Decision         |                                                   |
+------------------+--------------------------------------------------+
| Treatment        | PACS is NOT backed up. Recovery impossible if   |
| Justification    | encrypted or corrupted.                          |
+------------------+--------------------------------------------------+
| Planned          | 1. Implement PACS backup (GAP-006)              |
| Control(s)       | 2. Offsite/immutable backup (Control 5 from T7)  |
|                  | 3. DICOM encryption (Finding 024)                |
|                  | 4. Network segmentation (GAP-003)                |
+------------------+--------------------------------------------------+
| Residual Risk    | Medium (6) - Backups will allow recovery, but    |
|                  | restoration takes time.                          |
+------------------+--------------------------------------------------+
| KRI              | Backup success/failure rate, PACS storage usage  |
+------------------+--------------------------------------------------+
| Review Date      | 22/08/2026                                        |
+------------------+--------------------------------------------------+


================================================================================
RISK REGISTER SUMMARY
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Risk ID  | Risk Description | Inherent Risk    | Treatment        | Risk Owner       |
|          |                  | Score            | Decision         |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-001 | Data Breach EHR  | 25 (CRITICAL)    | MITIGATE         | James Chen       |
+----------+------------------+------------------+------------------+------------------+
| RISK-002 | VPN Compromise   | 20 (CRITICAL)    | MITIGATE         | James + Sarah    |
+----------+------------------+------------------+------------------+------------------+
| RISK-003 | Ransomware EHR   | 20 (CRITICAL)    | MITIGATE         | James + Sarah    |
+----------+------------------+------------------+------------------+------------------+
| RISK-004 | Insider Data     | 15 (HIGH)        | MITIGATE         | Sarah + HR       |
|          | Theft            |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-005 | Medical IoT      | 15 (HIGH)        | MITIGATE         | James + Biomed   |
+----------+------------------+------------------+------------------+------------------+
| RISK-006 | Supply Chain     | 15 (HIGH)        | MITIGATE         | James + Sarah    |
+----------+------------------+------------------+------------------+------------------+
| RISK-007 | No IR Capability | 20 (CRITICAL)    | MITIGATE         | James Chen       |
+----------+------------------+------------------+------------------+------------------+
| RISK-008 | Westside Breach  | 12 (HIGH)        | MITIGATE         | Sarah Park       |
+----------+------------------+------------------+------------------+------------------+
| RISK-009 | Shadow IT        | 16 (HIGH)        | MITIGATE         | James + IT Asset |
|          |                  |                  |                  | Mgt              |
+----------+------------------+------------------+------------------+------------------+
| RISK-010 | PACS Data Loss   | 15 (HIGH)        | MITIGATE         | Sarah +          |
|          |                  |                  |                  | Radiology        |
+----------+------------------+------------------+------------------+------------------+

TOTAL CRITICAL RISKS: 3 (RISK-001, RISK-002, RISK-003, RISK-007)
TOTAL HIGH RISKS: 6 (RISK-004, RISK-005, RISK-006, RISK-008, RISK-009, RISK-010)
TOTAL MEDIUM RISKS: 0
TOTAL LOW RISKS: 0


================================================================================
RISK REGISTER GOVERNANCE NOTE
================================================================================

+----------------------------------------------------------------------------+
| RISK REGISTER GOVERNANCE                                                   |
|                                                                             |
| The Risk Register is maintained by the Deputy CISO (James Chen) with       |
| support from the Security Analyst (you). It is reviewed monthly at the     |
| security governance meeting attended by James Chen, Sarah Park, and        |
| department heads. Out-of-cycle reviews are triggered by:                   |
| - CISA KEV additions affecting MedDefense assets                         |
| - New critical vulnerabilities disclosed in MedDefense technology stack   |
| - Changes in the threat landscape (new ransomware groups targeting       |
|   healthcare)                                                             |
| - Changes to MedDefense infrastructure (new systems, cloud migration)     |
| - Security incidents or near-misses                                       |
| When a KRI threshold is breached, the Security Analyst escalates to the   |
| Deputy CISO within 24 hours, who determines if the risk requires          |
| immediate action or can be addressed in the next monthly review.          |
| The Risk Register is presented quarterly to the Board of Directors.       |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Gap Analysis (1x00 Task 12)
- Threat Actor Matrix (1x01 Task 6)
- Kill Chains (1x01 Task 10)
- Vulnerability Scan (1x02)
- ALE Workshop (1x03 T6)
- Cost-Benefit Analysis (1x03 T7)
- Budget Allocation (1x03 T8)


================================================================================
END OF RISK REGISTER REPORT
================================================================================
