================================================================================
                    CIS CONTROLS AUDIT - MEDDEFENSE HEALTH SYSTEMS
                    Task 2: The CIS Controls Audit
================================================================================

Exercise: Task 2 - The CIS Controls Audit
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Score MedDefense against the CIS Top 18 Controls to produce a
          concrete, actionable security maturity assessment.

Source: cis-controls-summary.txt, Projects 1x00, 1x01, 1x02
Scoring: Implemented / Partial / Not Implemented


================================================================================
CIS CONTROLS SCORECARD
================================================================================


CIS CONTROL 1: INVENTORY AND CONTROL OF ENTERPRISE ASSETS
----------------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Asset inventory was built in 1x00 Task 7, but it was            |
| incomplete (shadow IT discovered in 1x00 T11 and 1x02 T28/29). No         |
| ongoing maintenance process exists.                                       |
+----------------------------------------------------------------------------+


CIS CONTROL 2: INVENTORY AND CONTROL OF SOFTWARE ASSETS
--------------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Vulnerability scan identified software versions on most          |
| systems, but no comprehensive software inventory exists. Apache 2.4.29,   |
| Ubuntu 18.04, and Windows XP were discovered - no central tracking.       |
+----------------------------------------------------------------------------+


CIS CONTROL 3: DATA PROTECTION
-------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No data classification policy exists (1x00 T9). No encryption   |
| for data at rest (EHR database, backups). No encryption for data in       |
| transit (DICOM, internal network). No DLP controls.                       |
+----------------------------------------------------------------------------+


CIS CONTROL 4: SECURE CONFIGURATION OF ENTERPRISE ASSETS
---------------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Some systems are hardened (ehr-srv-01 SSH key-only) but most    |
| are not (billing-srv-01 SSH password auth, PostgreSQL unrestricted,       |
| MySQL unrestricted). No formal configuration baselines exist.             |
+----------------------------------------------------------------------------+


CIS CONTROL 5: ACCESS CONTROL MANAGEMENT
-----------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Password policy exists (1x00 Artifact 3), but NO MFA anywhere   |
| (GAP-004), shared accounts exist (radiology), and no privileged access   |
| management (PAM).                                                        |
+----------------------------------------------------------------------------+


CIS CONTROL 6: CONTINUOUS VULNERABILITY MANAGEMENT
---------------------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: One-time vulnerability scan was performed (1x02), but no        |
| continuous scanning, no vulnerability management process, no patch       |
| management program (GAP-014).                                             |
+----------------------------------------------------------------------------+


CIS CONTROL 7: AUDIT LOG MANAGEMENT
------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No centralized logging, no SIEM (GAP-001). Logs exist on       |
| individual systems but are not collected, reviewed, or protected.         |
+----------------------------------------------------------------------------+


CIS CONTROL 8: EMAIL AND WEB BROWSER PROTECTIONS
-------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Sophos endpoint protection exists on workstations, but no       |
| email filtering (GAP-013), no phishing simulations (GAP-013), no web     |
| filtering. TLS 1.0 on patient portal (1x02 Finding 005).                 |
+----------------------------------------------------------------------------+


CIS CONTROL 9: MALWARE DEFENSES
--------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Sophos is deployed on Windows workstations (1x00 Artifact 4),  |
| but servers are NOT covered, 31 devices have outdated signatures, and    |
| 15 devices are not reporting. No EDR.                                     |
+----------------------------------------------------------------------------+


CIS CONTROL 10: DATA RECOVERY
------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Veeam backups exist for critical VMs (1x00 Artifact 5), but    |
| PACS is NOT backed up, backups are co-located, and recovery has never    |
| been tested. No offsite/cloud backups.                                    |
+----------------------------------------------------------------------------+


CIS CONTROL 11: NETWORK INFRASTRUCTURE MANAGEMENT
--------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Firewall exists (FortiGate 100F) but is misconfigured (no      |
| egress filtering, rules allow ALL services). No network segmentation     |
| (GAP-003). Westside uses consumer-grade router (1x00 T3).                |
+----------------------------------------------------------------------------+


CIS CONTROL 12: NETWORK MONITORING AND DEFENSE
-----------------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No IDS/IPS, no network traffic monitoring, no SIEM (GAP-001).  |
| The crypto-miner on billing-srv-01 ran for weeks undetected.             |
+----------------------------------------------------------------------------+


CIS CONTROL 13: SECURITY AWARENESS AND SKILLS TRAINING
-------------------------------------------------------
+----------------------------------------------------------------------------+
| Score: PARTIAL                                                              |
+----------------------------------------------------------------------------+
| Evidence: Annual security awareness training exists (1x00 Artifact 7),   |
| but completion rates are low (58-71% at some sites), no phishing        |
| simulations, and no role-specific training.                              |
+----------------------------------------------------------------------------+


CIS CONTROL 14: SERVICE PROVIDER MANAGEMENT
--------------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No vendor account management (GAP-012). MedTech has direct     |
| access to EHR with NO MFA. No vendor security assessments. No            |
| contractual security requirements.                                        |
+----------------------------------------------------------------------------+


CIS CONTROL 15: APPLICATION SOFTWARE SECURITY
----------------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No web application security testing (GAP-016). Ghostcat        |
| (CVE-2020-1938) on ehr-srv-01 discovered via manual investigation. No   |
| SAST/DAST, no code review.                                               |
+----------------------------------------------------------------------------+


CIS CONTROL 16: INCIDENT RESPONSE MANAGEMENT
---------------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No formal IR plan (GAP-002). January ransomware was handled    |
| ad-hoc. No designated response team, no communication plan.              |
+----------------------------------------------------------------------------+


CIS CONTROL 17: PENETRATION TESTING
------------------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No penetration testing performed. Vulnerability scan was       |
| conducted but no active exploitation testing.                            |
+----------------------------------------------------------------------------+


CIS CONTROL 18: GOVERNANCE
---------------------------
+----------------------------------------------------------------------------+
| Score: NOT IMPLEMENTED                                                     |
+----------------------------------------------------------------------------+
| Evidence: No formal CISO, no security strategy, no risk register, no     |
| Board reporting (1x03 T1). Security is not a formal governance function. |
+----------------------------------------------------------------------------+


================================================================================
SCORECARD SUMMARY
================================================================================

+------------------+---------------------+------------------------------------------+
| Score             | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| IMPLEMENTED       | 0                   | 0%                                       |
+------------------+---------------------+------------------------------------------+
| PARTIAL           | 8                   | 44.4%                                    |
|                   | (Controls 1, 2, 4,  |                                          |
|                   | 5, 8, 9, 10, 11,   |                                          |
|                   | 13)                 |                                          |
+------------------+---------------------+------------------------------------------+
| NOT IMPLEMENTED   | 10                  | 55.6%                                    |
|                   | (Controls 3, 6, 7,  |                                          |
|                   | 12, 14, 15, 16,    |                                          |
|                   | 17, 18)             |                                          |
+------------------+---------------------+------------------------------------------+

IMPLEMENTED: 0 (0%)
PARTIAL: 8 (44.4%)
NOT IMPLEMENTED: 10 (55.6%)


================================================================================
TOP 5 PRIORITY CONTROLS
================================================================================

+----------+------------------+----------------------------------------+
| Priority | CIS Control      | Justification                          |
+----------+------------------+----------------------------------------+
| #1       | Control 5:       | No MFA means a single compromised      |
|          | Access Control   | credential provides access to ALL      |
|          | Management       | systems. This is the #1 entry vector   |
|          |                  | for ransomware (from 1x01).           |
+----------+------------------+----------------------------------------+
| #2       | Control 6:       | Without continuous scanning and        |
|          | Continuous       | patching, new vulnerabilities go       |
|          | Vulnerability    | undetected. The Apache RCE (1x02)     |
|          | Management       | would not have been discovered.        |
+----------+------------------+----------------------------------------+
| #3       | Control 11:      | The flat network (GAP-003) amplifies   |
|          | Network          | EVERY vulnerability. Segmentation      |
|          | Infrastructure   | would contain attacks and reduce       |
|          | Management       | blast radius.                          |
+----------+------------------+----------------------------------------+
| #4       | Control 7:       | Without logs and alerts, attacks go    |
|          | Audit Log        | undetected for weeks (crypto-miner,    |
|          | Management       | January ransomware).                   |
+----------+------------------+----------------------------------------+
| #5       | Control 16:      | Without an IR plan, the next incident  |
|          | Incident         | will be handled ad-hoc like the        |
|          | Response         | January ransomware (4 days improvising).|
+----------+------------------+----------------------------------------+


================================================================================
CIS IMPLEMENTATION GROUP ANALYSIS
================================================================================

+----------------------------------------------------------------------------+
| IMPLEMENTATION GROUP 1 (IG1): ESSENTIAL                                    |
|                                                                             |
| MedDefense has NOT fully implemented IG1. Key missing IG1 safeguards:      |
| - Control 5: MFA for all users                                            |
| - Control 6: Continuous vulnerability scanning                            |
| - Control 7: Centralized logging                                           |
| - Control 11: Network segmentation                                         |
| - Control 16: Incident response plan                                      |
|                                                                             |
| These are the absolute minimum for any organization. Without them,        |
| MedDefense is operating with BASIC HYGIENE gaps.                          |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| IMPLEMENTATION GROUP 2 (IG2): FOUNDATIONAL                                 |
|                                                                             |
| MedDefense has significant IG2 gaps:                                      |
| - Control 3: Data protection (encryption, DLP)                            |
| - Control 14: Service provider management                                 |
| - Control 15: Application security                                        |
|                                                                             |
| These should be addressed within 6-12 months.                             |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- cis-controls-summary.txt
- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment (1x02)

Cross-References:
- Control Matrix (1x00 Task 10)
- Gap Analysis (1x00 Task 12)
- NIST CSF Mapping (1x03 T1)


================================================================================
END OF CIS CONTROLS AUDIT REPORT
================================================================================
