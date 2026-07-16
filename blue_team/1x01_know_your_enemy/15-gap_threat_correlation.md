================================================================================
                    GAP-THREAT CORRELATION - MEDDEFENSE HEALTH SYSTEMS
                    Task 15: The Gap-Threat Correlation
================================================================================

Exercise: Task 15 - The Gap-Threat Correlation
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Cross-reference the gaps identified in 1x00 with the threats
          identified in 1x01 to produce an updated, threat-informed
          prioritization.

Methodology References:
- NIST SP 800-30: Risk assessment
- NIST SP 800-53: Security Controls
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

Cross-References:
- Gap Analysis (1x00 Task 12): All Gap IDs
- Kill Chains (1x01 Task 10): Attack sequences
- Threat Scenarios (1x01 Task 14): Complete scenarios
- Threat Actor Matrix (1x01 Task 6): Actor profiles
- Technical Vectors (1x01 Task 8): Attack vectors


================================================================================
1. INDIVIDUAL GAP CORRELATIONS
================================================================================

GAP-001: NO SIEM OR LOG MONITORING
----------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-001                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No centralized logging, no intrusion detection,  |
|                  | no automated security alerting.                  |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | ALL actors: Ransomware Groups (#1), Insider      |
|                  | (#3/#4), Opportunistic (#6), APT (#2)           |
+------------------+--------------------------------------------------+
| Kill Chains      | ALL 5 kill chains:                               |
|                  | - KC #1 (VPN Ransomware) - Step 3               |
|                  | - KC #2 (Phishing EHR) - Step 3                  |
|                  | - KC #3 (IoT Patient Safety) - Step 2, 4        |
|                  | - KC #4 (MRI to EHR) - Step 3, 4                |
|                  | - KC #5 (Supply Chain) - Step 3, 5              |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios:                                 |
|                  | - S1 (Ransomware) - Step 3, 4, 5, 7             |
|                  | - S2 (Insider) - Step 2, 4                      |
|                  | - S3 (Supply Chain) - Step 4, 5, 6              |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (UPGRADED - #1 priority)                |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | This gap is present in EVERY kill chain and      |
|                  | EVERY scenario. Without SIEM, ALL attacks go    |
|                  | undetected until impact. The crypto-miner       |
|                  | (Task 2) and January ransomware both proved     |
|                  | this. This is the single most critical gap.    |
+------------------+--------------------------------------------------+


GAP-003: MEDICAL IOT ON FLAT NETWORK - NO SEGMENTATION
------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-003                                          |
+------------------+--------------------------------------------------+
| Gap Description  | All devices on 10.10.0.0/16 with no VLANs or    |
|                  | segmentation. Medical IoT devices on same       |
|                  | network as workstations and servers.            |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Opportunistic (#6),     |
|                  | Insider (#3/#4), APT (#2)                       |
+------------------+--------------------------------------------------+
| Kill Chains      | ALL 5 kill chains:                               |
|                  | - KC #1 (VPN Ransomware) - Step 3              |
|                  | - KC #2 (Phishing EHR) - Step 3, 5             |
|                  | - KC #3 (IoT Patient Safety) - Step 1, 3       |
|                  | - KC #4 (MRI to EHR) - Step 1, 3               |
|                  | - KC #5 (Supply Chain) - Step 3                |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios:                                 |
|                  | - S1 (Ransomware) - Step 5                     |
|                  | - S2 (Insider) - N/A (insider uses own access) |
|                  | - S3 (Supply Chain) - Step 5                   |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#2 priority)                           |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | The flat network is the PRIMARY ENABLER of      |
|                  | lateral movement in 4 of 5 kill chains. Marcus  |
|                  | noted: "This is insane." This gap turns a      |
|                  | single compromised system into a network-wide   |
|                  | breach.                                          |
+------------------+--------------------------------------------------+


GAP-004: NO MFA ANYWHERE
------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-004                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No MFA for ANY system. Credential theft is       |
|                  | the #1 entry vector.                            |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | ALL actors: Ransomware Groups (#1), Insider     |
|                  | (#3/#4), Opportunistic (#6), APT (#2),          |
|                  | Hacktivist (#5)                                 |
+------------------+--------------------------------------------------+
| Kill Chains      | ALL 5 kill chains:                               |
|                  | - KC #1 (VPN Ransomware) - Step 1, 3, 4        |
|                  | - KC #2 (Phishing EHR) - Step 1, 2, 3          |
|                  | - KC #3 (IoT Patient Safety) - Step 2          |
|                  | - KC #4 (MRI to EHR) - Step 3                  |
|                  | - KC #5 (Supply Chain) - Step 1, 3             |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios:                                 |
|                  | - S1 (Ransomware) - Step 2, 4                  |
|                  | - S2 (Insider) - Step 1, 2                     |
|                  | - S3 (Supply Chain) - Step 4, 5                |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#3 priority)                           |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | No MFA appears in EVERY kill chain and scenario.|
|                  | Credential theft is the #1 entry vector across  |
|                  | all threat actor types. Breach 2 (Task 13)      |
|                  | validated this.                                  |
+------------------+--------------------------------------------------+


GAP-007: NO COMPENSATING CONTROLS FOR MRI (WINDOWS XP)
------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-007                                          |
+------------------+--------------------------------------------------+
| Gap Description  | MRI runs Windows XP (EOL 2014). No compensating  |
|                  | controls (segmentation, whitelisting, host       |
|                  | firewall) are in place.                          |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Opportunistic (#6)      |
+------------------+--------------------------------------------------+
| Kill Chains      | 2 kill chains:                                   |
|                  | - KC #3 (IoT Patient Safety) - Step 2           |
|                  | - KC #4 (MRI to EHR) - Step 1, 2, 3             |
+------------------+--------------------------------------------------+
| Scenarios        | 1 scenario:                                      |
|                  | - S1 (Ransomware) - Step 5 (uses MRI as pivot)  |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#4 priority - unchanged)               |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | While it appears in fewer kill chains, the MRI  |
|                  | is a PERMANENT, UNPATCHABLE backdoor. Breach 3  |
|                  | (Task 13) validated that this exact scenario    |
|                  | caused $40M recovery and delayed cancer         |
|                  | treatments. This remains CRITICAL.              |
+------------------+--------------------------------------------------+


GAP-014: NO PATCH MANAGEMENT FOR NETWORK DEVICES
------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-014                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No patch management program for VPN, firewall,   |
|                  | switches. Perimeter devices unpatched.           |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Opportunistic (#6),     |
|                  | APT (#2)                                         |
+------------------+--------------------------------------------------+
| Kill Chains      | 2 kill chains:                                   |
|                  | - KC #1 (VPN Ransomware) - Step 1              |
|                  | - KC #4 (MRI to EHR) - Step 1 (enables initial  |
|                  |   access)                                        |
+------------------+--------------------------------------------------+
| Scenarios        | 1 scenario:                                      |
|                  | - S1 (Ransomware) - Step 1, 2                   |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#5 priority - unchanged)               |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | This gap enables INITIAL ACCESS for the most     |
|                  | damaging attacks. Breach 1 (Task 13) validated   |
|                  | that unpatched VPN is the #1 entry vector (38%). |
+------------------+--------------------------------------------------+


GAP-008: EGRESS FILTERING - OUTBOUND TRAFFIC UNRESTRICTED
----------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-008                                          |
+------------------+--------------------------------------------------+
| Gap Description  | Firewall allows ALL outbound traffic. No        |
|                  | restriction on what data can leave.              |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Insider (#3/#4),        |
|                  | Opportunistic (#6)                              |
+------------------+--------------------------------------------------+
| Kill Chains      | 4 kill chains:                                   |
|                  | - KC #1 (VPN Ransomware) - Step 7               |
|                  | - KC #2 (Phishing EHR) - Step 6                 |
|                  | - KC #4 (MRI to EHR) - Step 4                   |
|                  | - KC #5 (Supply Chain) - Step 4                 |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios:                                 |
|                  | - S1 (Ransomware) - Step 7                     |
|                  | - S2 (Insider) - Step 4                        |
|                  | - S3 (Supply Chain) - Step 6                   |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#6 priority - unchanged)               |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | This gap enables DATA EXFILTRATION in all       |
|                  | scenarios. Without egress filtering, attackers  |
|                  | can steal PHI without restriction. The          |
|                  | crypto-miner on billing-srv-01 proved this gap  |
|                  | is actively being exploited.                    |
+------------------+--------------------------------------------------+


GAP-002: NO INCIDENT RESPONSE PLAN
----------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-002                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No formal IR plan, BCP, or DR plan. No tested   |
|                  | recovery procedures.                             |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00)                                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | ALL actors (applies to aftermath of ANY attack)  |
+------------------+--------------------------------------------------+
| Kill Chains      | ALL 5 kill chains (post-impact):                |
|                  | - KC #1 - Step 5 (post-impact)                  |
|                  | - KC #2 - Step 5 (post-impact)                  |
|                  | - KC #3 - Step 5 (post-impact)                  |
|                  | - KC #4 - Step 5 (post-impact)                  |
|                  | - KC #5 - Step 5 (post-impact)                  |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios:                                 |
|                  | - S1 - Post-impact                              |
|                  | - S2 - Post-impact                              |
|                  | - S3 - Post-impact                              |
+------------------+--------------------------------------------------+
| Updated Risk     | HIGH (DOWNGRADED from CRITICAL)                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | While important for recovery, this gap does not  |
|                  | ENABLE attacks - it affects how MedDefense     |
|                  | responds after one occurs. The January          |
|                  | ransomware proved that ad-hoc response is       |
|                  | inadequate. However, prevention and detection   |
|                  | gaps take priority.                             |
+------------------+--------------------------------------------------+


GAP-012: NO VENDOR ACCOUNT MANAGEMENT
-------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-012                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No oversight of vendor accounts. No MFA, no     |
|                  | access reviews, no monitoring of vendor         |
|                  | activity.                                        |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00 - added from Task 13)            |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), APT (#2), Opportunistic |
|                  | (#6)                                             |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain:                                    |
|                  | - KC #5 (Supply Chain) - Steps 1-5              |
+------------------+--------------------------------------------------+
| Scenarios        | 1 scenario:                                      |
|                  | - S3 (Supply Chain) - Steps 1-6                 |
+------------------+--------------------------------------------------+
| Updated Risk     | CRITICAL (#7 priority - unchanged)               |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | This gap enables supply chain attacks that      |
|                  | bypass ALL perimeter controls. Change           |
|                  | Healthcare breach (2024) showed this is a real  |
|                  | and devastating attack vector. While it appears  |
|                  | in fewer kill chains, the impact is CATASTROPHIC.|
+------------------+--------------------------------------------------+


GAP-015: NO AUTOMATED USER OFFBOARDING
--------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-015                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No automated process to deactivate user         |
|                  | accounts upon termination. Manual manager       |
|                  | action required.                                 |
+------------------+--------------------------------------------------+
| Original Risk    | CRITICAL (1x00 - added from Task 13)            |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Insider (Malicious #4), Insider (Negligent #2)  |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain:                                    |
|                  | - KC #2 (Phishing EHR) - Step 2 (enables        |
|                  |   credential retention)                          |
+------------------+--------------------------------------------------+
| Scenarios        | 1 scenario:                                      |
|                  | - S2 (Insider) - Step 1                         |
+------------------+--------------------------------------------------+
| Updated Risk     | HIGH (DOWNGRADED from CRITICAL)                  |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | While important for insider threat prevention,  |
|                  | this gap enables a lower-likelihood attack       |
|                  | vector compared to ransomware or supply chain.  |
|                  | Breach 2 (Task 13) validated this but it is a   |
|                  | preventable administrative gap.                |
+------------------+--------------------------------------------------+


GAP-009: SHADOW IT SYSTEMS
--------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-009                                          |
+------------------+--------------------------------------------------+
| Gap Description  | 3 unmanaged devices (Dr. Patel's NAS, Marketing  |
|                  | Google Drive, Raspberry Pi). No controls.       |
+------------------+--------------------------------------------------+
| Original Risk    | HIGH (1x00)                                      |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Opportunistic (#6), Insider (Negligent #2)      |
+------------------+--------------------------------------------------+
| Kill Chains      | 2 kill chains:                                   |
|                  | - KC #2 (Phishing EHR) - Step 3 (pivot point)   |
|                  | - KC #3 (IoT Patient Safety) - Step 1 (pivot   |
|                  |   point)                                         |
+------------------+--------------------------------------------------+
| Scenarios        | 0 scenarios (used as pivot points, not primary)  |
+------------------+--------------------------------------------------+
| Updated Risk     | HIGH (UPGRADED from HIGH - remains HIGH)         |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Shadow IT devices are invisible to ALL security  |
|                  | controls. They provide perfect pivot points for  |
|                  | attackers. The Raspberry Pi with default         |
|                  | credentials is particularly dangerous.          |
+------------------+--------------------------------------------------+


GAP-013: NO EMAIL FILTERING OR MAIL RULE MONITORING
---------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-013                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No monitoring of O365 mail rules, no Conditional |
|                  | Access policies, no email filtering.             |
+------------------+--------------------------------------------------+
| Original Risk    | HIGH (1x00 - added from Task 13)                 |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Insider (#3/#4),        |
|                  | Opportunistic (#6)                              |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain:                                    |
|                  | - KC #2 (Phishing EHR) - Step 1                 |
+------------------+--------------------------------------------------+
| Scenarios        | 0 scenarios (enables phishing but not primary)  |
+------------------+--------------------------------------------------+
| Updated Risk     | HIGH (unchanged)                                 |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Email is the #1 vector for phishing. While this  |
|                  | gap enables credential theft, phishing itself   |
|                  | is addressed by GAP-004 (MFA) and GAP-001       |
|                  | (SIEM) as higher priorities.                    |
+------------------+--------------------------------------------------+


GAP-010: NO ADMINISTRATIVE DETECTIVE CONTROLS (AUDITS)
------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-010                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No security audits, compliance reviews, or      |
|                  | vulnerability assessments.                       |
+------------------+--------------------------------------------------+
| Original Risk    | HIGH (1x00)                                      |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | ALL actors (enables blind spots)                 |
+------------------+--------------------------------------------------+
| Kill Chains      | ALL 5 kill chains (indirectly):                 |
|                  | - Enables ALL because gaps are not identified   |
+------------------+--------------------------------------------------+
| Scenarios        | ALL 3 scenarios (indirectly):                   |
+------------------+--------------------------------------------------+
| Updated Risk     | MEDIUM (DOWNGRADED from HIGH)                    |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | While important for identifying gaps, this gap  |
|                  | does not directly ENABLE attacks. It is a       |
|                  | "gap discovery" gap. Other technical gaps       |
|                  | should be prioritized first.                    |
+------------------+--------------------------------------------------+


GAP-011: NO ADMINISTRATIVE DETERRENT CONTROLS (ENFORCEMENT)
-----------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-011                                          |
+------------------+--------------------------------------------------+
| Gap Description  | No disciplinary policies for security           |
|                  | violations. No consequences. Enforcement weak.  |
+------------------+--------------------------------------------------+
| Original Risk    | MEDIUM (1x00)                                    |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Insider (Negligent #2)                          |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain (indirectly):                      |
|                  | - KC #2 (Phishing EHR) - Step 1 (enables       |
|                  |   negligence)                                    |
+------------------+--------------------------------------------------+
| Scenarios        | 0 scenarios (indirect)                          |
+------------------+--------------------------------------------------+
| Updated Risk     | MEDIUM (UPGRADED from MEDIUM - unchanged)       |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | This is a cultural gap rather than a technical  |
|                  | one. It enables negligent insider behavior but  |
|                  | is not as urgent as technical gaps.             |
+------------------+--------------------------------------------------+


GAP-006: NO BACKUP FOR PACS
---------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-006                                          |
+------------------+--------------------------------------------------+
| Gap Description  | pacs-srv-01 is NOT backed up. "Too large"       |
|                  | for the NAS.                                     |
+------------------+--------------------------------------------------+
| Original Risk    | HIGH (1x00)                                      |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Threat Actors    | Ransomware Groups (#1), Insider (#3/#4)         |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain:                                    |
|                  | - KC #1 (VPN Ransomware) - Step 4 (PACS         |
|                  |   encrypted)                                     |
+------------------+--------------------------------------------------+
| Scenarios        | 1 scenario:                                      |
|                  | - S1 (Ransomware) - Step 8 (PACS not backed up) |
+------------------+--------------------------------------------------+
| Updated Risk     | HIGH (unchanged)                                 |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | If PACS is encrypted, all imaging data is lost  |
|                  | forever. This is a critical operational gap but  |
|                  | only affects PACS specifically.                 |
+------------------+--------------------------------------------------+


GAP-005: UNRESTRICTED PHYSICAL ACCESS TO SERVER ROOM
----------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-005                                          |
+------------------+--------------------------------------------------+
| Gap Description  | Server room uses generic badge. No camera. No   |
|                  | visitor log.                                     |
+------------------+--------------------------------------------------+
| Original Risk    | HIGH (1x00 - downgraded from CRITICAL in Task   |
| Level            | 13)                                              |
+------------------+--------------------------------------------------+
| Threat Actors    | Insider (#3/#4), Opportunistic (#6), APT (#2)  |
+------------------+--------------------------------------------------+
| Kill Chains      | 1 kill chain:                                    |
|                  | - KC #1 (VPN Ransomware) - Alternative entry    |
|                  |   path (bypasses technical controls)            |
+------------------+--------------------------------------------------+
| Scenarios        | 0 scenarios (not used in primary attack paths)  |
+------------------+--------------------------------------------------+
| Updated Risk     | MEDIUM (DOWNGRADED from HIGH)                    |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Physical access is important but none of the    |
|                  | primary attack paths use it. Technical controls  |
|                  | (MFA, SIEM, segmentation) take priority.       |
+------------------+--------------------------------------------------+


================================================================================
2. RE-PRIORITIZED GAP LIST (THREAT-INFORMED)
================================================================================

+----------+------------------+----------------------------------------+------------------------------------------+
| New      | Gap ID           | Gap Title                              | Updated Risk Level                       |
| Rank     |                  |                                        |                                          |
+----------+------------------+----------------------------------------+------------------------------------------+
| #1       | GAP-001          | No SIEM or Log Monitoring              | CRITICAL (UPGRADED - now #1)             |
+----------+------------------+----------------------------------------+------------------------------------------+
| #2       | GAP-003          | Medical IoT on Flat Network            | CRITICAL (#2)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #3       | GAP-004          | No MFA Anywhere                        | CRITICAL (#3)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #4       | GAP-007          | No Compensating Controls for MRI       | CRITICAL (#4)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #5       | GAP-014          | No Patch Management                    | CRITICAL (#5)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #6       | GAP-008          | No Egress Filtering                    | CRITICAL (#6)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #7       | GAP-012          | No Vendor Account Management           | CRITICAL (#7)                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #8       | GAP-002          | No Incident Response Plan              | HIGH (DOWNGRADED from CRITICAL)          |
+----------+------------------+----------------------------------------+------------------------------------------+
| #9       | GAP-015          | No Automated Offboarding               | HIGH (DOWNGRADED from CRITICAL)          |
+----------+------------------+----------------------------------------+------------------------------------------+
| #10      | GAP-009          | Shadow IT Systems                      | HIGH (unchanged)                         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #11      | GAP-013          | No Email Security                      | HIGH (unchanged)                         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #12      | GAP-006          | No Backup for PACS                     | HIGH (unchanged)                         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #13      | GAP-010          | No Administrative Detective Controls   | MEDIUM (DOWNGRADED from HIGH)            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #14      | GAP-011          | No Administrative Deterrent Controls   | MEDIUM (unchanged)                       |
+----------+------------------+----------------------------------------+------------------------------------------+
| #15      | GAP-005          | Unrestricted Physical Access           | MEDIUM (DOWNGRADED from HIGH)            |
+----------+------------------+----------------------------------------+------------------------------------------+


================================================================================
3. THE CRITICAL THREE
================================================================================

+----------------------------------------------------------------------------+
| THE CRITICAL THREE                                                         |
|                                                                             |
| These are the 3 gaps that appear most frequently across kill chains and    |
| scenarios. Closing these gaps would disrupt the greatest number of         |
| attack paths.                                                               |
|                                                                             |
| RANK 1: GAP-001 - No SIEM or Log Monitoring                                |
|                                                                             |
| Appears in ALL 5 kill chains and ALL 3 scenarios. Without detection,       |
| every attack proceeds unseen until impact. This is the single most        |
| critical gap because it enables EVERY other vulnerability to be           |
| exploited without detection.                                               |
|                                                                             |
| RANK 2: GAP-003 - Medical IoT on Flat Network - No Segmentation           |
|                                                                             |
| Appears in 4 of 5 kill chains and 2 of 3 scenarios. The flat network      |
| is the PRIMARY ENABLER of lateral movement. It turns a single             |
| compromised system into a network-wide breach.                            |
|                                                                             |
| RANK 3: GAP-004 - No MFA Anywhere                                         |
|                                                                             |
| Appears in ALL 5 kill chains and ALL 3 scenarios. Credential theft is     |
| the #1 entry vector across ALL threat actor types. Without MFA,           |
| captured credentials provide immediate access to ALL systems.             |
+----------------------------------------------------------------------------+


================================================================================
4. THE SURPRISE
================================================================================

+----------------------------------------------------------------------------+
| THE SURPRISE                                                               |
|                                                                             |
| GAP ID: GAP-009 - Shadow IT Systems                                        |
|                                                                             |
| Original Rating: HIGH                                                      |
| New Rating: HIGH (unchanged)                                               |
|                                                                             |
| Why this is a surprise:                                                    |
|                                                                             |
| In 1x00, shadow IT was rated HIGH based on the existence of 3 unmanaged   |
| devices (Dr. Patel's NAS, Marketing Google Drive, Raspberry Pi). This     |
| seemed like a moderate risk compared to critical gaps like no MFA or      |
| no SIEM. However, threat analysis reveals a different picture:           |
|                                                                             |
| 1. The Raspberry Pi has DEFAULT CREDENTIALS and is connected to the       |
|    flat network. This is a PERFECT pivot point for attackers. The         |
|    threat analysis shows this gap appears in 2 kill chains (KC #2 and    |
|    KC #3) as a pivot point.                                               |
|                                                                             |
| 2. Shadow IT devices are INVISIBLE to all security controls. An attacker  |
|    on a shadow IT device can move to the EHR without detection.           |
|                                                                             |
| 3. The threat analysis shows that opportunistic attackers (#6) actively  |
|    scan for devices like the Raspberry Pi. The crypto-miner on           |
|    billing-srv-01 proves that MedDefense is already being scanned.       |
|                                                                             |
| What changed:                                                             |
|                                                                             |
| The threat context reveals that shadow IT is not just an "asset           |
| management" problem. It is an ACTIVE ATTACK SURFACE. An attacker who     |
| discovers the Raspberry Pi with default credentials is inside the        |
| network with no resistance. The Raspberry Pi is a device that NO ONE      |
| knows about, NO ONE monitors, and NO ONE patches.                        |
|                                                                             |
| While the rating remains HIGH (not CRITICAL), the justification has       |
| shifted from "unmanaged devices" to "unmanaged devices that provide       |
| undetectable network entry points."                                      |
+----------------------------------------------------------------------------+


================================================================================
5. KEY FINDINGS
================================================================================

1. GAP-001 (No SIEM) is the #1 priority. It appears in EVERY kill chain
   and EVERY scenario. Without detection, ALL other controls are blind.

2. GAP-003 (Flat Network) is the #2 priority. It is the PRIMARY ENABLER
   of lateral movement. It turns any compromise into a network-wide breach.

3. GAP-004 (No MFA) is the #3 priority. Credential theft is the #1 entry
   vector across ALL threat actor types.

4. GAP-002 (No IR Plan), GAP-015 (No Offboarding), and GAP-005 (Physical
   Access) have been DOWNGRADED. While important, they do not enable
   attacks as directly as technical gaps. They affect recovery and
   prevention rather than active exploitation.

5. GAP-009 (Shadow IT) remains HIGH and is a SURPRISE - the threat
   analysis reveals that unmanaged devices provide PERFECT pivot points
   for attackers. The Raspberry Pi with default credentials is particularly
   dangerous.

6. The Critical Three (GAP-001, GAP-003, GAP-004) are the gaps that
   appear most frequently across kill chains and scenarios. Closing these
   three gaps would disrupt the GREATEST NUMBER of attack paths.

7. The prioritization has shifted from "asset criticality" to "threat
   enablement." Gaps that enable attacks (SIEM, segmentation, MFA) are
   now prioritized over gaps that affect recovery (IR plan) or prevention
   of lower-likelihood vectors (physical access, offboarding).


================================================================================
6. REFERENCES
================================================================================

- NIST SP 800-30: Risk assessment
- NIST SP 800-53: Security Controls
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

Cross-References:
- Gap Analysis (1x00 Task 12): All Gap IDs
- Kill Chains (1x01 Task 10): Attack sequences
- Threat Scenarios (1x01 Task 14): Complete scenarios
- Threat Actor Matrix (1x01 Task 6): Actor profiles
- Technical Vectors (1x01 Task 8): Attack vectors


================================================================================
END OF GAP-THREAT CORRELATION REPORT
================================================================================
