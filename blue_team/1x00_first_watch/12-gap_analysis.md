================================================================================
                    GAP ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 12: The Gap Analysis
================================================================================

Exercise: Task 12 - The Gap Analysis
Analyst: shamshed rajput
Date: 14/07/2026

Objective: Perform a formal gap analysis by systematically cross-referencing
          asset criticality, control coverage and identified weaknesses to
          produce a prioritized list of security gaps.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Risk components
- NIST SP 800-53 Rev.5: CM-8 (Asset Inventory), RA-5 (Vulnerability)
- NIST CSF 2.0: Identify Function - ID.RA (Risk Assessment)
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare security practices

Sources: Task 8 (Criticality Assessment), Task 9 (Data Map),
         Task 10 (Control Matrix), Task 11 (Shadow Systems)


================================================================================
1. CROSS-REFERENCE FRAMEWORK
================================================================================

This gap analysis connects three dimensions:

+------------------+------------------+------------------+------------------+
| ASSET            | DATA             | CONTROL          | GAP              |
| CRITICALITY      | CLASSIFICATION   | COVERAGE         | PRIORITY         |
| (Task 8)         | (Task 9)         | (Task 10)        |                  |
+------------------+------------------+------------------+------------------+
| CRITICAL         | RESTRICTED       | ABSENT/WEAK      | CRITICAL         |
| CRITICAL         | RESTRICTED       | PARTIAL          | HIGH             |
| HIGH             | CONFIDENTIAL     | ABSENT/WEAK      | HIGH             |
| HIGH             | CONFIDENTIAL     | PARTIAL          | MEDIUM           |
| MEDIUM           | INTERNAL         | ABSENT/WEAK      | MEDIUM           |
| LOW              | PUBLIC           | ANY              | LOW              |
+------------------+------------------+------------------+------------------+

PRIORITIZATION RULES (applied throughout):
- CRITICAL: Gap affects a Critical-rated asset OR Restricted data AND
            has no detective or corrective control
- HIGH: Gap affects a High-rated asset OR Confidential data AND has
         incomplete control coverage
- MEDIUM: Gap affects a Medium-rated asset OR has partial controls that
           reduce but do not eliminate risk
- LOW: Gap affects a Low-rated asset AND has partial compensating measures


================================================================================
2. GAP ANALYSIS - IDENTIFIED GAPS
================================================================================

GAP-001: NO SIEM OR LOG MONITORING FOR CRITICAL SYSTEMS
-------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-001                                          |
+------------------+--------------------------------------------------+
| Title            | No SIEM or Log Monitoring for Critical Systems   |
+------------------+--------------------------------------------------+
| Affected Asset(s)| EHR System (CRITICAL), Active Directory (CRITICAL)|
|                  | PACS/Imaging (CRITICAL), Network Core (CRITICAL)  |
|                  | Medical IoT (CRITICAL)                           |
+------------------+--------------------------------------------------+
| Data at Risk     | Patient Medical Records (RESTRICTED),            |
|                  | Medical Imaging Data (RESTRICTED),               |
|                  | System Credentials (RESTRICTED), Audit Logs      |
|                  | (CONFIDENTIAL)                                   |
+------------------+--------------------------------------------------+
| Current Control  | C-004: Firewall Logging (local only, no SIEM)    |
| Status           | C-010: Sophos Detections (no auto-notification)  |
|                  | C-014: AD Logging (no alerting)                  |
+------------------+--------------------------------------------------+
| What is Missing  | DETECTIVE controls. No SIEM. No centralized log  |
|                  | aggregation. No automated alerting. No anomaly   |
|                  | detection. No log integrity protection.          |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects ALL 5 CRITICAL asset categories and      |
|                  | RESTRICTED data (PHI, PACS, credentials). The    |
|                  | crypto-miner on billing-srv-01 went undetected   |
|                  | for weeks due to NO detective controls. An       |
|                  | attacker can operate without detection.         |
+------------------+--------------------------------------------------+
| Potential Impact | A ransomware attack (like January) could encrypt |
|                  | the EHR and PACS without any alert. No one would |
|                  | know until clinicians cannot access patient      |
|                  | records. 50,000 patients affected. Regulatory    |
|                  | fines and reputational damage.                   |
+------------------+--------------------------------------------------+


GAP-002: NO INCIDENT RESPONSE PLAN
----------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-002                                          |
+------------------+--------------------------------------------------+
| Title            | No Incident Response Plan                         |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL assets (EHR, PACS, Medical IoT, AD, Network) |
+------------------+--------------------------------------------------+
| Data at Risk     | ALL data categories (Patient Records, Imaging,   |
|                  | Billing, HR, Credentials, Audit Logs)            |
+------------------+--------------------------------------------------+
| Current Control  | C-009: Veeam Backups (limited corrective)        |
| Status           | C-019: MRI IR Procedure (Proposed only)          |
+------------------+--------------------------------------------------+
| What is Missing  | CORRECTIVE controls. No formal IR plan. No BCP.  |
|                  | No DR plan. No tested recovery procedures.       |
|                  | No post-incident analysis process.               |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects ALL assets and ALL data categories.      |
|                  | The January ransomware incident was handled      |
|                  | "ad-hoc" over 4 days. Without a plan, the next   |
|                  | incident will be even more chaotic.              |
+------------------+--------------------------------------------------+
| Potential Impact | When (not if) another major incident occurs, the |
|                  | organization has no structured response.         |
|                  | Recovery time will be extended. Patient care     |
|                  | will be disrupted. Regulatory penalties for      |
|                  | lack of incident response capability.            |
+------------------+--------------------------------------------------+


GAP-003: MEDICAL IOT ON FLAT NETWORK - NO SEGMENTATION
------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-003                                          |
+------------------+--------------------------------------------------+
| Title            | Medical IoT on Flat Network - No Segmentation    |
+------------------+--------------------------------------------------+
| Affected Asset(s)| Medical IoT: Patient Monitors (CRITICAL),        |
|                  | Infusion Pumps (CRITICAL), MRI (CRITICAL)        |
+------------------+--------------------------------------------------+
| Data at Risk     | Patient vital signs, medication dosages,         |
|                  | diagnostic images (RESTRICTED)                   |
+------------------+--------------------------------------------------+
| Current Control  | NO preventive controls for IoT                   |
| Status           | C-015: Network Segmentation (Proposed only)      |
|                  | C-020: Network Monitoring (Proposed only)        |
+------------------+--------------------------------------------------+
| What is Missing  | PREVENTIVE and COMPENSATING controls. No network |
|                  | segmentation. IoT devices on same flat network   |
|                  | as workstations/servers. No isolation.           |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects CRITICAL life-safety devices. The MRI    |
|                  | runs Windows XP (EOL 2014). An attacker who      |
|                  | compromises a workstation can pivot to IoT       |
|                  | devices. Marcus note: "If someone gets on the    |
|                  | network they can reach the pumps." Direct        |
|                  | patient safety risk.                             |
+------------------+--------------------------------------------------+
| Potential Impact | An attacker could alter patient monitor readings |
|                  | or infusion pump dosages, directly harming       |
|                  | patients. The MRI could be disabled. This is     |
|                  | a life-safety risk.                              |
+------------------+--------------------------------------------------+


GAP-004: NO MFA ANYWHERE
------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-004                                          |
+------------------+--------------------------------------------------+
| Title            | No Multi-Factor Authentication (MFA) Anywhere    |
+------------------+--------------------------------------------------+
| Affected Asset(s)| EHR System (CRITICAL), Active Directory (CRITICAL)|
|                  | PACS/Imaging (CRITICAL), Billing (HIGH),         |
|                  | VPN Access (Network Core - CRITICAL)             |
+------------------+--------------------------------------------------+
| Data at Risk     | Patient Medical Records (RESTRICTED),            |
|                  | System Credentials (RESTRICTED), Medical Imaging |
|                  | (RESTRICTED), Billing Data (RESTRICTED)          |
+------------------+--------------------------------------------------+
| Current Control  | C-006: Password Policy (no MFA)                  |
| Status           | Note: "MFA is recommended but not currently      |
|                  | required" (Artifact 3)                           |
+------------------+--------------------------------------------------+
| What is Missing  | PREVENTIVE controls. No MFA for ANY system.      |
|                  | No MFA for VPN. No MFA for EHR. No MFA for AD.   |
|                  | No MFA for privileged accounts.                  |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects CRITICAL and HIGH assets with RESTRICTED |
|                  | data. A single compromised password gives an     |
|                  | attacker access to EHR, AD, VPN, and all other   |
|                  | systems. No second factor to stop credential     |
|                  | theft.                                           |
+------------------+--------------------------------------------------+
| Potential Impact | An attacker obtains a password (phishing,        |
|                  | credential reuse). They access the EHR and       |
|                  | exfiltrate PHI for 50,000 patients. Or they      |
|                  | compromise AD and take over the entire network.  |
+------------------+--------------------------------------------------+


GAP-005: UNRESTRICTED PHYSICAL ACCESS TO SERVER ROOM
----------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-005                                          |
+------------------+--------------------------------------------------+
| Title            | Unrestricted Physical Access to Server Room      |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL servers (EHR, PACS, Billing, AD, Backup)    |
|                  | Network Core equipment                           |
+------------------+--------------------------------------------------+
| Data at Risk     | ALL data (Patient Records, Imaging, Billing, HR, |
|                  | Credentials, Audit Logs)                         |
+------------------+--------------------------------------------------+
| Current Control  | C-011: Guard Service (M-F 7AM-7PM only, lobby    |
| Status           | only)                                            |
|                  | C-012: Camera System (no server room coverage)   |
|                  | C-018: Physical Access Restriction (Proposed)    |
+------------------+--------------------------------------------------+
| What is Missing  | PREVENTIVE physical controls. Server room door   |
|                  | uses same generic badge everyone gets. No camera |
|                  | in server room. No visitor log. No locked        |
|                  | network closets.                                  |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Physical access bypasses ALL technical controls. |
|                  | Observation 1: "Same generic badge every employee|
|                  | receives." No cameras. No logs. An attacker with |
|                  | physical access can steal servers, install       |
|                  | malicious hardware, or compromise any system.    |
+------------------+--------------------------------------------------+
| Potential Impact | An attacker or disgruntled employee enters the   |
|                  | server room and physically damages or steals     |
|                  | servers. EHR, PACS, billing, AD all go offline.  |
|                  | Patient care stops. No forensic evidence because |
|                  | no cameras.                                       |
+------------------+--------------------------------------------------+


GAP-006: NO BACKUP FOR PACS (MEDICAL IMAGING)
---------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-006                                          |
+------------------+--------------------------------------------------+
| Title            | No Backup for PACS (Medical Imaging)             |
+------------------+--------------------------------------------------+
| Affected Asset(s)| PACS/Imaging System (CRITICAL)                   |
+------------------+--------------------------------------------------+
| Data at Risk     | Medical Imaging Data (RESTRICTED)                |
+------------------+--------------------------------------------------+
| Current Control  | C-009: Veeam Backups (pacs-srv-01 NOT included)  |
| Status           | Artifact 5: "pacs-srv-01 - 'too large, would    |
|                  | fill the NAS'"                                    |
+------------------+--------------------------------------------------+
| What is Missing  | CORRECTIVE controls. No backup for PACS. No      |
|                  | recovery option if server fails or is            |
|                  | compromised.                                     |
+------------------+--------------------------------------------------+
| Risk Level       | HIGH                                             |
+------------------+--------------------------------------------------+
| Risk Justification| Affects CRITICAL asset (PACS/Imaging) with       |
|                  | RESTRICTED data. No recovery option. Loss of     |
|                  | imaging data is catastrophic for radiology       |
|                  | department and patient care.                     |
+------------------+--------------------------------------------------+
| Potential Impact | pacs-srv-01 fails or is encrypted by ransomware. |
|                  | No backup exists. Years of medical images are    |
|                  | lost forever. Radiology cannot function.         |
|                  | Physicians cannot access imaging for diagnosis.  |
+------------------+--------------------------------------------------+


GAP-007: NO COMPENSATING CONTROLS FOR MRI (WINDOWS XP)
------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-007                                          |
+------------------+--------------------------------------------------+
| Title            | No Compensating Controls for MRI (Windows XP)    |
+------------------+--------------------------------------------------+
| Affected Asset(s)| MRI Scanner (CRITICAL - part of PACS/Imaging)    |
+------------------+--------------------------------------------------+
| Data at Risk     | Medical Imaging Data (RESTRICTED)                |
+------------------+--------------------------------------------------+
| Current Control  | C-015: Network Segmentation (Proposed)           |
| Status           | C-016: Application Whitelisting (Proposed)       |
|                  | C-017: Host-Based Firewall (Proposed)            |
|                  | C-019: MRI IR Procedure (Proposed)               |
+------------------+--------------------------------------------------+
| What is Missing  | COMPENSATING controls. MRI runs Windows XP (EOL  |
|                  | 2014) with known vulnerabilities. No isolation.  |
|                  | No application whitelisting. No host firewall.   |
|                  | No alternative controls implemented.             |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects CRITICAL asset (MRI) with RESTRICTED     |
|                  | data. Windows XP is unpatched with publicly      |
|                  | available exploits. The MRI is on the flat       |
|                  | network. This is a permanent backdoor. Marcus    |
|                  | flagged it as "CRITICAL."                        |
+------------------+--------------------------------------------------+
| Potential Impact | An attacker exploits a known Windows XP          |
|                  | vulnerability (EternalBlue). The MRI is          |
|                  | compromised. The attacker pivots to the EHR,     |
|                  | billing, AD. The entire hospital network is      |
|                  | compromised via a 12-year-old OS.                |
+------------------+--------------------------------------------------+


GAP-008: EGRESS FILTERING - OUTBOUND TRAFFIC UNRESTRICTED
---------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-008                                          |
+------------------+--------------------------------------------------+
| Title            | Egress Filtering - Outbound Traffic Unrestricted  |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL systems (Network Core - CRITICAL)            |
+------------------+--------------------------------------------------+
| Data at Risk     | ALL data categories (data exfiltration risk)      |
+------------------+--------------------------------------------------+
| Current Control  | C-002: Firewall - Outbound NAT (ALLOW ALL)       |
| Status           | Artifact 1: Rule 4 "set service ALL"             |
|                  | Marcus: "The crypto-miner is happily talking to  |
|                  | mining pools because nothing stops outbound."    |
+------------------+--------------------------------------------------+
| What is Missing  | PREVENTIVE controls. No egress filtering. No     |
|                  | restriction on outbound traffic. Any system can  |
|                  | connect to any external IP on any port.          |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Risk Justification| Affects CRITICAL Network Core. ALL systems       |
|                  | affected. Data exfiltration is trivial. The      |
|                  | crypto-miner on billing-srv-01 successfully      |
|                  | connected to mining pools because no egress      |
|                  | filtering.                                       |
+------------------+--------------------------------------------------+
| Potential Impact | An attacker compromises a system. They can       |
|                  | exfiltrate PHI, billing data, or patient records |
|                  | without restriction. No firewall rules stop      |
|                  | outbound connections. Data theft is silent.      |
+------------------+--------------------------------------------------+


GAP-009: SHADOW IT SYSTEMS (3 UNMANAGED DEVICES)
------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-009                                          |
+------------------+--------------------------------------------------+
| Title            | Shadow IT Systems - 3 Unmanaged Devices          |
+------------------+--------------------------------------------------+
| Affected Asset(s)| Dr. Patel's Personal NAS, Marketing Google Drive,|
|                  | Raspberry Pi (ALL Shadow IT - HIGH risk)         |
+------------------+--------------------------------------------------+
| Data at Risk     | Research Data (potentially RESTRICTED),          |
|                  | Marketing/Press Materials (CONFIDENTIAL),        |
|                  | Network Traffic/Credentials (RESTRICTED)         |
+------------------+--------------------------------------------------+
| Current Control  | NO controls cover these systems                  |
| Status           | All 20 controls from Task 10 do NOT cover these  |
|                  | shadow systems.                                   |
+------------------+--------------------------------------------------+
| What is Missing  | ALL controls. No inventory. No monitoring. No    |
|                  | patching. No authentication. No backups.         |
+------------------+--------------------------------------------------+
| Risk Level       | HIGH                                             |
+------------------+--------------------------------------------------+
| Risk Justification| Shadow IT systems are invisible to all security  |
|                  | controls. The NAS and Pi are on the flat         |
|                  | network. A compromise of ANY shadow system       |
|                  | provides a pivot point to ALL MedDefense systems.|
+------------------+--------------------------------------------------+
| Potential Impact | The Raspberry Pi has default credentials. An     |
|                  | attacker discovers it, compromises it, and       |
|                  | sniffs network traffic. They capture AD          |
|                  | credentials and access the EHR. No one notices   |
|                  | because no one knows the Pi exists.              |
+------------------+--------------------------------------------------+


GAP-010: NO ADMINISTRATIVE DETECTIVE CONTROLS (AUDITS)
-------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-010                                          |
+------------------+--------------------------------------------------+
| Title            | No Administrative Detective Controls (Audits)    |
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL systems (organization-wide)                  |
+------------------+--------------------------------------------------+
| Data at Risk     | ALL data categories                              |
+------------------+--------------------------------------------------+
| Current Control  | No controls in this cell                         |
| Status           | Matrix - Administrative Detective cell EMPTY     |
+------------------+--------------------------------------------------+
| What is Missing  | DETECTIVE controls. No security audits. No       |
|                  | compliance reviews. No vulnerability assessments.|
|                  | No HIPAA compliance assessments. No penetration  |
|                  | testing. No policy reviews.                      |
+------------------+--------------------------------------------------+
| Risk Level       | HIGH                                             |
+------------------+--------------------------------------------------+
| Risk Justification| Affects ALL assets and ALL data. Without audits, |
|                  | systemic weaknesses go unidentified. HIPAA has   |
|                  | NEVER been assessed. Marcus notes: "Legal says   |
|                  | 'we're compliant' but has no evidence." The      |
|                  | organization has no way to measure its security  |
|                  | posture.                                         |
+------------------+--------------------------------------------------+
| Potential Impact | Existing vulnerabilities (e.g., MRI Windows XP)  |
|                  | are never discovered. HIPAA compliance gaps are  |
|                  | unknown until an audit reveals them - or a       |
|                  | breach reveals them. Regulatory fines.           |
+------------------+--------------------------------------------------+


GAP-011: NO ADMINISTRATIVE DETERRENT CONTROLS (ENFORCEMENT)
------------------------------------------------------------
+------------------+--------------------------------------------------+
| Gap ID           | GAP-011                                          |
+------------------+--------------------------------------------------+
| Title            | No Administrative Deterrent Controls (Enforcement)|
+------------------+--------------------------------------------------+
| Affected Asset(s)| ALL employees, contractors, vendors              |
+------------------+--------------------------------------------------+
| Data at Risk     | ALL data categories                              |
+------------------+--------------------------------------------------+
| Current Control  | No controls in this cell                         |
| Status           | Matrix - Administrative Deterrent cell EMPTY     |
+------------------+--------------------------------------------------+
| What is Missing  | DETERRENT controls. No disciplinary policies for |
|                  | security violations. No enforcement. No          |
|                  | consequences. Executive accountability absent.   |
+------------------+--------------------------------------------------+
| Risk Level       | MEDIUM                                           |
+------------------+--------------------------------------------------+
| Risk Justification| Affects organizational culture. Without          |
|                  | consequences, employees don't take security      |
|                  | seriously. Shared accounts continue. Staff stay  |
|                  | logged in. Propped fire doors go unreported.     |
|                  | Security awareness is weak.                      |
+------------------+--------------------------------------------------+
| Potential Impact| Employees continue to use shared accounts.       |
|                  | Radiology "raduser/radiology1" goes unreported.  |
|                  | Phishing training has low completion. Security   |
|                  | culture remains weak. Incidents continue.        |
+------------------+--------------------------------------------------+


================================================================================
3. GAP DISTRIBUTION SUMMARY
================================================================================

3.1 GAPS BY RISK LEVEL
----------------------
+------------------+---------------------+------------------------------------------+
| Risk Level       | Count               | Gap IDs                                  |
+------------------+---------------------+------------------------------------------+
| CRITICAL         | 7                   | GAP-001, GAP-002, GAP-003, GAP-004,      |
|                  |                     | GAP-005, GAP-007, GAP-008                |
+------------------+---------------------+------------------------------------------+
| HIGH             | 3                   | GAP-006, GAP-009, GAP-010                |
+------------------+---------------------+------------------------------------------+
| MEDIUM           | 1                   | GAP-011                                  |
+------------------+---------------------+------------------------------------------+
| LOW              | 0                   | None                                     |
+------------------+---------------------+------------------------------------------+

TOTAL GAPS IDENTIFIED: 11


3.2 GAPS BY AFFECTED ASSET CATEGORY
-----------------------------------
+------------------+---------------------+------------------------------------------+
| Asset Category   | Criticality Rating  | Gap Count                                |
+------------------+---------------------+------------------------------------------+
| EHR System       | CRITICAL            | 6 (GAP-001, GAP-002, GAP-004, GAP-005,   |
|                  |                     | GAP-008, GAP-010)                        |
+------------------+---------------------+------------------------------------------+
| Medical IoT      | CRITICAL            | 4 (GAP-001, GAP-002, GAP-003, GAP-005,   |
|                  |                     | GAP-007)                                 |
+------------------+---------------------+------------------------------------------+
| PACS/Imaging     | CRITICAL            | 5 (GAP-001, GAP-002, GAP-005, GAP-006,   |
|                  |                     | GAP-007, GAP-008)                        |
+------------------+---------------------+------------------------------------------+
| Active Directory | CRITICAL            | 5 (GAP-001, GAP-002, GAP-004, GAP-005,   |
|                  |                     | GAP-008)                                 |
+------------------+---------------------+------------------------------------------+
| Network Core     | CRITICAL            | 5 (GAP-001, GAP-002, GAP-005, GAP-008,   |
|                  |                     | GAP-010)                                 |
+------------------+---------------------+------------------------------------------+
| Shadow IT        | HIGH                | 1 (GAP-009)                              |
+------------------+---------------------+------------------------------------------+


3.3 GAPS BY CONTROL FUNCTION
----------------------------
+------------------+---------------------+------------------------------------------+
| Control Function | Gap Count           | Gap IDs                                  |
+------------------+---------------------+------------------------------------------+
| PREVENTIVE       | 5                   | GAP-003, GAP-004, GAP-005, GAP-008,      |
|                  |                     | GAP-011                                  |
+------------------+---------------------+------------------------------------------+
| DETECTIVE        | 3                   | GAP-001, GAP-010                         |
+------------------+---------------------+------------------------------------------+
| CORRECTIVE       | 2                   | GAP-002, GAP-006                         |
+------------------+---------------------+------------------------------------------+
| COMPENSATING     | 1                   | GAP-007                                  |
+------------------+---------------------+------------------------------------------+
| DETERRENT        | 1                   | GAP-011                                  |
+------------------+---------------------+------------------------------------------+


3.4 GAPS BY CONTROL CATEGORY
----------------------------
+------------------+---------------------+------------------------------------------+
| Control Category | Gap Count           | Gap IDs                                  |
+------------------+---------------------+------------------------------------------+
| TECHNICAL        | 6                   | GAP-001, GAP-003, GAP-004, GAP-007,      |
|                  |                     | GAP-008                                  |
+------------------+---------------------+------------------------------------------+
| ADMINISTRATIVE   | 4                   | GAP-002, GAP-010, GAP-011                |
+------------------+---------------------+------------------------------------------+
| PHYSICAL         | 2                   | GAP-005                                  |
+------------------+---------------------+------------------------------------------+
| SHADOW IT        | 1                   | GAP-009                                  |
+------------------+---------------------+------------------------------------------+


================================================================================
4. PATTERN ANALYSIS
================================================================================

+----------------------------------------------------------------------------+
| PATTERN OBSERVATIONS:                                                      |
|                                                                             |
| 1. DETECTIVE CONTROLS ARE THE WEAKEST FUNCTION                            |
|    - Only 1 detective control exists (Firewall Logging)                   |
|    - 2 gaps directly address missing detective controls (GAP-001, GAP-010)|
|    - All CRITICAL assets lack proper detective controls                   |
|                                                                             |
| 2. CRITICAL ASSETS CONCENTRATE MOST GAPS                                  |
|    - EHR System: 6 gaps                                                   |
|    - Medical IoT: 4 gaps                                                  |
|    - PACS/Imaging: 5 gaps                                                 |
|    - Active Directory: 5 gaps                                             |
|    - Network Core: 5 gaps                                                 |
|                                                                             |
| 3. PREVENTIVE CONTROLS HAVE THE MOST GAPS (5)                            |
|    - No MFA (GAP-004)                                                     |
|    - No segmentation (GAP-003)                                             |
|    - No physical access control (GAP-005)                                  |
|    - No egress filtering (GAP-008)                                         |
|    - No deterrent enforcement (GAP-011)                                   |
|                                                                             |
| 4. TECHNICAL GAPS DOMINATE (6 of 11)                                     |
|    - SIEM, Segmentation, MFA, Compensating, Egress Filtering             |
|                                                                             |
| 5. ADMINISTRATIVE GAPS ARE SYSTEMIC                                      |
|    - No IR Plan, No Audits, No Enforcement (3 gaps)                      |
|                                                                             |
| 6. PHYSICAL SECURITY IS UNDER-REPRESENTED IN GAPS (1)                   |
|    - Only 1 physical gap identified but physical security is a major     |
|      issue (Observation 1-2). This may indicate that physical security   |
|      gaps are not being adequately captured.                             |
|                                                                             |
| 7. THE FLAT NETWORK AMPLIFIES EVERY GAP                                 |
|    - All assets on same network means a gap in ANY asset affects ALL    |
|      assets. A compromise of the MRI (GAP-007) compromises the EHR.     |
+----------------------------------------------------------------------------+


================================================================================
5. PRIORITIZED ACTION PLAN
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap              | Recommended Action                    | Timeline         |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-007          | IMMEDIATELY isolate MRI (Windows XP)  | 24 hours         |
|          | (No Compensating)| on isolated VLAN. Implement           |                  |
|          | for MRI)         | application whitelisting.             |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-003          | Segment Medical IoT devices to        | 1 week           |
|          | (IoT Flat        | isolated VLAN. Implement network      |                  |
|          | Network)         | monitoring.                            |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-004          | Implement MFA for ALL critical        | 2 weeks          |
|          | (No MFA)         | systems (EHR, AD, VPN).               |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-001          | Deploy SIEM and centralized logging.  | 2 weeks          |
|          | (No SIEM)        | Implement alerting.                   |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-005          | Restrict server room access. Install  | 1 week           |
|          | (Physical Access)| cameras. Implement visitor log.       |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | GAP-008          | Implement egress filtering. Restrict  | 1 week           |
|          | (Egress)         | outbound traffic.                      |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | GAP-002          | Develop and test IR plan, BCP, DR     | 1 month          |
|          | (No IR Plan)     | plan.                                  |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | GAP-006          | Implement backup for PACS. Test       | 2 weeks          |
|          | (No PACS Backup) | recovery.                              |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | GAP-009          | Locate and decommission Pi. Migrate   | 1 week           |
|          | (Shadow IT)      | NAS and Google Drive data.            |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | GAP-010          | Conduct security audits and HIPAA     | 1 month          |
|          | (No Audits)      | compliance assessment.                |                  |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | GAP-011          | Implement disciplinary policy for     | 2 months         |
|          | (No Enforcement) | security violations. Enforce.         |                  |
+----------+------------------+----------------------------------------+------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. 11 gaps identified: 7 CRITICAL, 3 HIGH, 1 MEDIUM, 0 LOW.

2. EHR System has the most gaps (6) - the MOST CRITICAL asset is also
   the most vulnerable. This is the top priority.

3. Detective controls are the WEAKEST function (3 gaps). No SIEM means
   no visibility into attacks.

4. Medical IoT and MRI have CRITICAL gaps with NO implemented controls.
   This is a life-safety issue requiring immediate action.

5. Physical security is under-represented in this gap analysis.
   Additional physical gaps likely exist but were not captured.

6. The flat network AMPLIFIES every gap. A compromise of ANY system
   compromises ALL systems.

7. Shadow IT represents a HIGH risk. 3 unmanaged systems on the network
   with no controls.

8. The organization has NO way to detect attacks, NO plan to respond,
   and NO way to enforce security policies. This is a systemic failure.


================================================================================
7. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Risk components
- NIST SP 800-53 Rev.5: CM-8 (Asset Inventory), RA-5 (Vulnerability)
- NIST CSF 2.0: Identify Function - ID.RA (Risk Assessment)
- ISO 27001 Gap Analysis: Methodology
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF GAP ANALYSIS REPORT
================================================================================
