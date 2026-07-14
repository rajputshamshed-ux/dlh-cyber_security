================================================================================
                    SECURITY POSTURE ASSESSMENT
                    MEDDEFENSE HEALTH SYSTEMS
================================================================================

Document Title:  MedDefense Health Systems - Security Posture Assessment
Prepared For:    Board of Directors, MedDefense Health Systems
Prepared By:     shamshed rajput, Junior Security Analyst
Approved By:     James Chen, Deputy CISO
Date:            14/07/2026
Classification:  CONFIDENTIAL - Internal Use Only


================================================================================
1. EXECUTIVE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
|                                                                             |
| CURRENT POSTURE:                                                           |
| MedDefense Health Systems is operating with a security posture that is     |
| PREVENTION-HEAVY but DETECTION-AND-RESPONSE-LIGHT. The organization has   |
| invested in basic preventive controls (firewall, antivirus, password       |
| policies) but has CRITICAL GAPS in detection (no SIEM), response (no IR   |
| plan), and compensating controls (MRI Windows XP).                        |
|                                                                             |
| This means MedDefense has some ability to STOP attacks but almost no      |
| ability to KNOW when an attack succeeds or what to DO about it.           |
|                                                                             |
| SINGLE MOST CRITICAL FINDING:                                              |
| The MRI scanner running Windows XP (EOL 2014) on the same flat network    |
| as the EHR, billing, and Active Directory. This creates a PERMANENT       |
| backdoor into the entire hospital network. Real-world breaches show this  |
| exact scenario has led to $40M recovery costs and delayed cancer          |
| treatments.                                                                |
|                                                                             |
| TOP 3 RECOMMENDED ACTIONS:                                                 |
| 1. IMMEDIATELY isolate the MRI and all medical IoT devices on dedicated   |
|    VLANs. Estimated cost: $22,000. Timeline: Quick Win (< 1 week).       |
|                                                                             |
| 2. IMPLEMENT MFA for all remote access, vendor accounts, and critical     |
|    systems. Estimated cost: $8,000 - $10,000. Timeline: Short-term        |
|    (< 1 month).                                                            |
|                                                                             |
| 3. DEPLOY basic SIEM (Wazuh open-source) for centralized logging and      |
|    alerting. Estimated cost: $5,000. Timeline: Short-term (< 1 month).   |
|                                                                             |
| BUDGET IMPLICATION:                                                        |
| The top 7 priorities can be addressed within the $120,000 annual          |
| security budget, with $42,000 allocated to immediate actions.             |
|                                                                             |
| WITHOUT INVESTMENT:                                                        |
| MedDefense is at high risk of a catastrophic breach similar to the        |
| hospitals described in the breach summaries: 11-day EHR outages, $5M      |
| recovery costs, patient diversions, CEO resignation, and class action     |
| lawsuits.                                                                  |
+----------------------------------------------------------------------------+


================================================================================
2. SCOPE AND METHODOLOGY
================================================================================

2.1 SCOPE OF ASSESSMENT
-----------------------
+----------------------------------------------------------------------------+
| SITES ASSESSED:                                                            |
| - MedDefense Central (350-bed acute care hospital, downtown)              |
| - Westside Clinic (suburban outpatient facility)                          |
| - Corporate HQ (administrative offices, business park)                   |
|                                                                             |
| SYSTEMS ASSESSED:                                                          |
| - All servers (EHR, PACS, billing, AD, backup, web)                      |
| - Network infrastructure (firewall, switches, VPN)                       |
| - Endpoints (workstations, thin clients, laptops, iPads)                 |
| - Medical IoT devices (patient monitors, infusion pumps, MRI, CT)        |
| - Physical security (server room, network closets, cameras, guards)     |
| - Cloud services (O365)                                                  |
|                                                                             |
| DATA ASSESSED:                                                            |
| - Patient Medical Records (RESTRICTED)                                   |
| - Medical Imaging Data (RESTRICTED)                                      |
| - Billing/Financial Data (RESTRICTED)                                    |
| - Employee HR Records (CONFIDENTIAL)                                     |
| - System Credentials (RESTRICTED)                                        |
| - Audit Logs (CONFIDENTIAL)                                              |
| - Marketing/Public Data (PUBLIC)                                         |
+----------------------------------------------------------------------------+

2.2 SOURCES OF INFORMATION
--------------------------
+----------------------------------------------------------------------------+
| DOCUMENTATION REVIEWED:                                                    |
| - Onboarding Packet (Task 0) - Organizational context, asset list        |
| - Incident Log (Task 1) - 6 months of security incidents                 |
| - Diagnostics (Task 2) - billing-srv-01 crypto-miner                    |
| - Walk-through Observations (Task 3) - Physical security gaps            |
| - Control Artifacts (Task 4) - Firewall, SSH, password policy, Sophos,  |
|   backups, physical security, training, logging                         |
| - Network Scan Summary (Task 7) - Active devices on the network         |
| - Healthcare Breach Summaries (Task 13) - Real-world validation          |
| - Marcus Webb Draft Assessment (Task 15) - Predecessor's findings        |
|                                                                             |
| METHODOLOGY:                                                              |
| - NIST SP 800-12: CIA Triad framework                                   |
| - NIST SP 800-30: Risk assessment (Threat, Vulnerability, Impact)       |
| - NIST SP 800-53: Control categorization (Technical/Admin/Physical)    |
| - NIST CSF 2.0: Identify function                                       |
| - ISO 27001: Gap analysis methodology                                   |
| - CISA Healthcare Guide: Healthcare threat context                      |
| - HHS HICP: Healthcare security practices                               |
+----------------------------------------------------------------------------+

2.3 LIMITATIONS AND ASSUMPTIONS
-------------------------------
+----------------------------------------------------------------------------+
| LIMITATIONS:                                                              |
| 1. Some endpoint counts are based on 8-month-old AD reports              |
| 2. Westside unknown server (ws-srv-02) remains unconfirmed               |
| 3. Clinical trial/research data not fully inventoried                   |
| 4. No vulnerability scanning was performed                              |
| 5. No penetration testing was performed                                 |
|                                                                             |
| ASSUMPTIONS:                                                              |
| 1. All documented controls are operational as described                  |
| 2. All undocumented systems are represented in the network scan         |
| 3. The Board will approve the recommended budget                        |
| 4. IT and clinical staff will support implementation of controls        |
+----------------------------------------------------------------------------+


================================================================================
3. ASSET LANDSCAPE
================================================================================

3.1 ASSET INVENTORY SUMMARY
---------------------------
+------------------+---------------------+------------------------------------------+
| Asset Type       | Count               | Locations                                |
+------------------+---------------------+------------------------------------------+
| Servers          | 13                  | Central (10), Westside (1 known +        |
|                  |                     | 1 suspected), HQ (0)                    |
+------------------+---------------------+------------------------------------------+
| Endpoints        | ~600                | Central (~320 workstations + 60 thin    |
|                  |                     | clients), Westside (~45), HQ (~120      |
|                  |                     | workstations + 30 laptops), iPads (~25) |
+------------------+---------------------+------------------------------------------+
| Network Devices  | 7                   | FortiGate, Cisco core, access switches, |
|                  |                     | Westside router/switch, UniFi APs,      |
|                  |                     | HQ building network                      |
+------------------+---------------------+------------------------------------------+
| IoT Medical      | 6 categories        | Monitors (~80), Pumps (~120), MRI (1),  |
|                  |                     | CT (1), Nurse Call (1), Badge System (1)|
+------------------+---------------------+------------------------------------------+
| Data Stores      | 2                   | Synology NAS-01, O365 Tenant            |
+------------------+---------------------+------------------------------------------+
| Physical Assets  | 4                   | Server Room, Network Closet, Nurse      |
|                  |                     | Station, Fire Exit Door                  |
+------------------+---------------------+------------------------------------------+
| Shadow IT        | 3                   | Dr. Patel's NAS, Marketing Google Drive,|
|                  |                     | Raspberry Pi                             |
+------------------+---------------------+------------------------------------------+
| TOTAL            | 35+                 |                                          |
+------------------+---------------------+------------------------------------------+

3.2 TOP 5 CRITICAL ASSETS
-------------------------
+----------+------------------+------------------------------------------+
| Rank     | Asset Category   | Justification                            |
+----------+------------------+------------------------------------------+
| #1       | EHR System       | Single source of truth for patient care. |
|          |                  | 50,000+ patients. Outage halts clinical  |
|          |                  | operations. PHI exposure triggers HIPAA  |
|          |                  | fines.                                   |
+----------+------------------+------------------------------------------+
| #2       | Medical IoT      | Life-safety devices (monitors, pumps).   |
|          |                  | On same flat network as everything else. |
|          |                  | Direct patient safety risk.              |
+----------+------------------+------------------------------------------+
| #3       | PACS/Imaging     | MRI runs Windows XP (EOL 2014).          |
|          |                  | $2.1M asset. 45 studies/day.             |
|          |                  | Permanent backdoor into the network.    |
+----------+------------------+------------------------------------------+
| #4       | Active Directory | Authentication backbone for ALL Windows  |
|          |                  | systems. "Keys to the kingdom."          |
|          |                  | Compromise = all systems compromised.    |
+----------+------------------+------------------------------------------+
| #5       | Network Core     | FortiGate + core switch. Single point of |
|          |                  | failure. If down, ALL sites lose         |
|          |                  | connectivity.                            |
+----------+------------------+------------------------------------------+

3.3 DATA CLASSIFICATION SUMMARY
-------------------------------
+------------------+---------------------+------------------------------------------+
| Classification   | Data Categories     | Volume / Scope                           |
+------------------+---------------------+------------------------------------------+
| RESTRICTED       | Patient Records,    | 50,000+ patients, 3,211+ records at risk |
|                  | Medical Imaging,    | from insider breach, billing data for    |
|                  | Billing, Credentials| all patients, system credentials for     |
|                  |                     | all systems                              |
+------------------+---------------------+------------------------------------------+
| CONFIDENTIAL     | HR Records, Audit   | ~2,000 employees, logs for all systems   |
|                  | Logs                |                                          |
+------------------+---------------------+------------------------------------------+
| INTERNAL         | Internal Memos,     | Organization-wide                         |
|                  | Meeting Notes       |                                          |
+------------------+---------------------+------------------------------------------+
| PUBLIC           | Website Content     | Public-facing only                        |
+------------------+---------------------+------------------------------------------+


================================================================================
4. CURRENT SECURITY CONTROLS
================================================================================

4.1 CONTROL MATRIX SUMMARY
--------------------------
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
|                  | Preventive      | Detective       | Corrective      | Compensating     | Deterrent       |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| TECHNICAL        | 8 controls      | 5 controls      | 1 control       | 4 controls       | 0 controls      |
|                  | (C-001, C-002,  | (C-004, C-008,  | (C-009)         | (C-015, C-016,   |                 |
|                  | C-003, C-005,   | C-010, C-014,   |                 | C-017, C-020)    |                 |
|                  | C-008, C-015,   | C-020)          |                 |                  |                 |
|                  | C-016, C-017)   |                 |                 |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| ADMINISTRATIVE   | 3 controls      | 0 controls      | 1 control       | 0 controls       | 0 controls      |
|                  | (C-006, C-007,  |                 | (C-019)         |                  |                 |
|                  | C-013)          |                 |                 |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| PHYSICAL         | 1 control       | 2 controls      | 0 controls      | 1 control       | 2 controls      |
|                  | (C-018)         | (C-011, C-012)  |                 | (C-018)         | (C-011, C-012)  |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+

TOTAL CONTROLS: 20 (14 existing + 6 proposed)

4.2 OVERALL MATURITY ASSESSMENT
-------------------------------
+----------------------------------------------------------------------------+
| STRENGTHS:                                                                 |
| - Perimeter firewall is in place (FortiGate 100F)                         |
| - Basic password policy exists (8 chars, complexity, 90-day rotation)    |
| - Antivirus deployed on Windows workstations (88.1% current)             |
| - Daily backups for critical VMs                                          |
| - SSH hardening on one server (ehr-srv-01)                               |
|                                                                             |
| WEAKNESSES:                                                               |
| - ONLY 1 control rated STRONG (SSH hardening)                            |
| - 40% of controls are WEAK (exist on paper, poorly implemented)          |
| - 30% of controls are PROPOSED (not yet implemented)                     |
| - NO SIEM or centralized logging                                         |
| - NO MFA anywhere                                                         |
| - NO incident response plan                                              |
| - NO network segmentation (flat network)                                 |
| - NO compensating controls for MRI (Windows XP)                          |
| - NO egress filtering (ALL outbound allowed)                            |
| - Physical security controls are minimal                                 |
+----------------------------------------------------------------------------+

4.3 EFFECTIVENESS FINDINGS
--------------------------
+------------------+---------------------+------------------------------------------+
| Rating           | Count               | Controls                                 |
+------------------+---------------------+------------------------------------------+
| STRONG           | 1 (5%)              | C-005 (SSH Hardening - ehr-srv-01)       |
+------------------+---------------------+------------------------------------------+
| ADEQUATE         | 5 (25%)             | C-006 (Password Policy), C-008 (Sophos), |
|                  |                     | C-009 (Backups), C-010 (Sophos           |
|                  |                     | Detections), C-011 (Guard Service)       |
+------------------+---------------------+------------------------------------------+
| WEAK             | 8 (40%)             | C-001, C-002, C-003, C-004, C-007,       |
|                  |                     | C-012, C-013, C-014                      |
+------------------+---------------------+------------------------------------------+
| PROPOSED         | 6 (30%)             | C-015, C-016, C-017, C-018, C-019,       |
|                  |                     | C-020                                    |
+------------------+---------------------+------------------------------------------+

CRITICAL OBSERVATION: 70% of controls are either WEAK or PROPOSED.
Only 1 control out of 20 is STRONG.


================================================================================
5. GAP ANALYSIS
================================================================================

5.1 PRIORITIZED GAP FINDINGS
----------------------------
+----------+------------------+----------------------------------------+------------------+
| Priority | Gap ID           | Gap Title                              | Risk Level       |
+----------+------------------+----------------------------------------+------------------+
| #1       | GAP-007          | No Compensating Controls for MRI       | CRITICAL         |
|          |                  | (Windows XP)                           |                  |
+----------+------------------+----------------------------------------+------------------+
| #2       | GAP-003          | Medical IoT on Flat Network - No       | CRITICAL         |
|          |                  | Segmentation                           |                  |
+----------+------------------+----------------------------------------+------------------+
| #3       | GAP-014          | No Patch Management for Network        | CRITICAL         |
|          |                  | Devices                                |                  |
+----------+------------------+----------------------------------------+------------------+
| #4       | GAP-001          | No SIEM or Log Monitoring              | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #5       | GAP-004          | No MFA Anywhere                        | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #6       | GAP-015          | No Automated User Offboarding          | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #7       | GAP-002          | No Incident Response Plan              | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #8       | GAP-012          | No Vendor Account Management           | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #9       | GAP-008          | Egress Filtering - Outbound Traffic    | HIGH             |
|          |                  | Unrestricted                           |                  |
+----------+------------------+----------------------------------------+------------------+
| #10      | GAP-006          | No Backup for PACS                     | HIGH             |
+----------+------------------+----------------------------------------+------------------+
| #11      | GAP-009          | Shadow IT Systems (3 unmanaged         | HIGH             |
|          |                  | devices)                               |                  |
+----------+------------------+----------------------------------------+------------------+
| #12      | GAP-010          | No Administrative Detective Controls   | HIGH             |
|          |                  | (Audits)                               |                  |
+----------+------------------+----------------------------------------+------------------+
| #13      | GAP-013          | No Email Filtering or Mail Rule        | HIGH             |
|          |                  | Monitoring                             |                  |
+----------+------------------+----------------------------------------+------------------+
| #14      | GAP-016          | No Web Application Security Testing    | HIGH             |
|          |                  | (SAST/DAST)                            |                  |
+----------+------------------+----------------------------------------+------------------+
| #15      | GAP-005          | Unrestricted Physical Access to        | MEDIUM           |
|          |                  | Server Room                            |                  |
+----------+------------------+----------------------------------------+------------------+
| #16      | GAP-011          | No Administrative Deterrent Controls   | MEDIUM           |
|          |                  | (Enforcement)                          |                  |
+----------+------------------+----------------------------------------+------------------+

5.2 GAP DISTRIBUTION ANALYSIS
-----------------------------
+------------------+---------------------+------------------------------------------+
| Risk Level       | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| CRITICAL         | 8                   | 50%                                      |
| HIGH             | 6                   | 37.5%                                    |
| MEDIUM           | 2                   | 12.5%                                    |
| LOW              | 0                   | 0%                                       |
+------------------+---------------------+------------------------------------------+

MOST EXPOSED AREAS:
1. Medical IoT / Legacy Devices (MRI Windows XP) - 2 gaps
2. Network Architecture (Flat network, no segmentation) - 2 gaps
3. Detection (No SIEM, no monitoring) - 3 gaps
4. Response (No IR plan, no recovery) - 2 gaps
5. Access Control (No MFA, no offboarding) - 2 gaps

5.3 CRITICAL GAP DETAILS
------------------------
+----------------------------------------------------------------------------+
| GAP-007: No Compensating Controls for MRI (Windows XP)                    |
| Affected Asset: MRI Scanner (CRITICAL)                                   |
| Risk: Life-safety risk. Permanent backdoor into network.                 |
| Treatment: Implement compensating controls (Segmentation, App            |
|           Whitelisting, Host Firewall).                                  |
| Cost: $10,000. Timeline: Quick Win (< 1 week).                           |
+----------------------------------------------------------------------------+
| GAP-003: Medical IoT on Flat Network - No Segmentation                   |
| Affected Asset: Patient Monitors (CRITICAL), Infusion Pumps (CRITICAL)  |
| Risk: Attacker can pivot from workstation to life-safety devices.        |
| Treatment: Isolated IoT VLAN + strict firewall rules.                    |
| Cost: $12,000. Timeline: Short-term (< 1 month).                         |
+----------------------------------------------------------------------------+
| GAP-014: No Patch Management for Network Devices                         |
| Affected Asset: Network Core (CRITICAL)                                  |
| Risk: Unpatched VPN/perimeter devices = entry point for attackers.      |
| Treatment: Formal patch management program, monthly schedule.            |
| Cost: $2,000. Timeline: Quick Win (< 1 week).                            |
+----------------------------------------------------------------------------+
| GAP-001: No SIEM or Log Monitoring                                       |
| Affected Asset: ALL Critical Assets                                      |
| Risk: Attacks go undetected for weeks/months.                            |
| Treatment: Deploy Wazuh SIEM (open-source) + basic alerting.             |
| Cost: $5,000. Timeline: Short-term (< 1 month).                          |
+----------------------------------------------------------------------------+
| GAP-004: No MFA Anywhere                                                 |
| Affected Asset: EHR (CRITICAL), AD (CRITICAL), VPN (CRITICAL)           |
| Risk: Single password compromise = full network access.                 |
| Treatment: MFA for VPN, AD admin, EHR remote access.                     |
| Cost: $8,000 - $10,000. Timeline: Short-term (< 1 month).               |
+----------------------------------------------------------------------------+
| GAP-015: No Automated User Offboarding                                   |
| Affected Asset: ALL Systems (former employees)                          |
| Risk: Former employees retain access for weeks/months.                  |
| Treatment: HR → IT integration for automated deactivation.              |
| Cost: $3,000. Timeline: Short-term (< 1 month).                          |
+----------------------------------------------------------------------------+
| GAP-002: No Incident Response Plan                                       |
| Affected Asset: ALL Systems                                             |
| Risk: Ad-hoc response = extended recovery (11 days in Breach 1).        |
| Treatment: Formal IR plan + Tabletop exercises.                          |
| Cost: $2,000. Timeline: Short-term (< 1 month).                          |
+----------------------------------------------------------------------------+
| GAP-012: No Vendor Account Management                                    |
| Affected Asset: ALL Systems (vendor access)                             |
| Risk: Compromised vendor account = direct network access.               |
| Treatment: Vendor account inventory + MFA + monitoring.                 |
| Cost: $3,000. Timeline: Short-term (< 1 month).                          |
+----------------------------------------------------------------------------+


================================================================================
6. RISK TREATMENT RECOMMENDATIONS
================================================================================

6.1 TOP 7 PRIORITY RECOMMENDATIONS
----------------------------------
+----------+------------------+----------------------------------------+------------------+------------------+
| Priority | Gap ID           | Recommended Action                     | Estimated Cost   | Timeline         |
+----------+------------------+----------------------------------------+------------------+------------------+
| #1       | GAP-007          | MRI Compensating Controls (Segmentation| $10,000          | Quick Win        |
|          |                  | + Whitelisting + Host Firewall)        |                  | (< 1 week)       |
+----------+------------------+----------------------------------------+------------------+------------------+
| #2       | GAP-003          | IoT VLAN + Network Monitoring          | $12,000          | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #3       | GAP-014          | Patch Management Program               | $2,000           | Quick Win        |
|          |                  |                                        |                  | (< 1 week)       |
+----------+------------------+----------------------------------------+------------------+------------------+
| #4       | GAP-001          | Wazuh SIEM + Alerting                  | $5,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #5       | GAP-004          | MFA for VPN, AD Admin, EHR             | $8,000 - $10,000 | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #6       | GAP-015          | HR → IT Offboarding Integration        | $3,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #7       | GAP-002          | IR Plan + Tabletop Exercises           | $2,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+

TOTAL COST FOR TOP 7 PRIORITIES: $42,000 - $44,000

6.2 BUDGET ALLOCATION
---------------------
+----------------------------------------------------------------------------+
| BUDGET OVERVIEW                                                            |
|                                                                             |
| Total Annual Security Budget:               $120,000                       |
| Top 7 Priority Mitigations:                 $42,000 - $44,000              |
|                                                                             |
| Remaining Budget:                           $76,000 - $78,000              |
|                                                                             |
| ALLOCATION OF REMAINING BUDGET:                                             |
| - Emergency Contingency:                    $20,000                         |
| - Future Fiscal Year Initiatives:           $56,000 - $58,000              |
|   - Commercial SIEM (if Wazuh insufficient): $50,000                       |
|   - EDR for Servers:                        $30,000                         |
|   - Security Awareness Training Program:    $15,000                         |
|   - Web Application Security Testing:       $10,000                         |
+----------------------------------------------------------------------------+

6.3 QUICK WINS (< 1 WEEK)
-------------------------
+----------+------------------+----------------------------------------+------------------+
| #        | Gap ID           | Action                                 | Cost             |
+----------+------------------+----------------------------------------+------------------+
| 1        | GAP-007          | MRI Compensating Controls (Segmentation| $10,000          |
|          |                  | + Whitelisting + Host Firewall)        |                  |
+----------+------------------+----------------------------------------+------------------+
| 2        | GAP-014          | Patch Management Program               | $2,000           |
+----------+------------------+----------------------------------------+------------------+

TOTAL QUICK WINS COST: $12,000

6.4 SHORT-TERM PRIORITIES (< 1 MONTH)
-------------------------------------
+----------+------------------+----------------------------------------+------------------+
| #        | Gap ID           | Action                                 | Cost             |
+----------+------------------+----------------------------------------+------------------+
| 1        | GAP-003          | IoT VLAN + Monitoring                  | $12,000          |
+----------+------------------+----------------------------------------+------------------+
| 2        | GAP-001          | Wazuh SIEM + Alerting                  | $5,000           |
+----------+------------------+----------------------------------------+------------------+
| 3        | GAP-004          | MFA for VPN, AD Admin, EHR             | $8,000 - $10,000 |
+----------+------------------+----------------------------------------+------------------+
| 4        | GAP-015          | HR → IT Offboarding Integration        | $3,000           |
+----------+------------------+----------------------------------------+------------------+
| 5        | GAP-002          | IR Plan + Tabletop Exercises           | $2,000           |
+----------+------------------+----------------------------------------+------------------+
| 6        | GAP-012          | Vendor Account Management              | $3,000           |
+----------+------------------+----------------------------------------+------------------+

TOTAL SHORT-TERM COST: $33,000 - $35,000

6.5 LONG-TERM ROADMAP ITEMS (> 1 MONTH)
---------------------------------------
+----------+------------------+----------------------------------------+------------------+
| #        | Gap ID           | Action                                 | Estimated Cost   |
+----------+------------------+----------------------------------------+------------------+
| 1        | GAP-008          | Egress Filtering Implementation        | $2,000           |
+----------+------------------+----------------------------------------+------------------+
| 2        | GAP-006          | PACS Backup Implementation             | $10,000          |
+----------+------------------+----------------------------------------+------------------+
| 3        | GAP-009          | Shadow IT Investigation + Remediation  | $5,000           |
+----------+------------------+----------------------------------------+------------------+
| 4        | GAP-010          | Security Audits + Assessments          | $15,000          |
+----------+------------------+----------------------------------------+------------------+
| 5        | GAP-013          | Email Security + Mail Rule Monitoring  | $8,000           |
+----------+------------------+----------------------------------------+------------------+
| 6        | GAP-016          | Web Application Security Testing       | $10,000          |
+----------+------------------+----------------------------------------+------------------+
| 7        | GAP-005          | Physical Access Controls               | $5,000           |
+----------+------------------+----------------------------------------+------------------+
| 8        | GAP-011          | Enforcement + Deterrent Policies       | $3,000           |
+----------+------------------+----------------------------------------+------------------+

TOTAL LONG-TERM COST: $58,000


================================================================================
7. CONCLUSION AND NEXT STEPS
================================================================================

7.1 SUMMARY OF SECURITY POSTURE (BUSINESS TERMS)
------------------------------------------------
+----------------------------------------------------------------------------+
| MedDefense Health Systems is currently operating with a SECURITY POSTURE  |
| that is INSUFFICIENT for a healthcare organization of its size and scope. |
|                                                                             |
| The organization has invested in basic preventive measures (firewall,      |
| antivirus, passwords) but has CRITICAL GAPS in:                            |
| - DETECTION (no ability to know when an attack occurs)                    |
| - RESPONSE (no plan for what to do when an attack happens)                |
| - COMPENSATING CONTROLS (unpatchable medical devices on the network)      |
|                                                                             |
| This means MedDefense has SOME protection against attacks but almost      |
| NO ability to survive one that gets through.                              |
|                                                                             |
| Real-world breach data (Task 13) shows that hospitals with similar gaps   |
| have experienced:                                                          |
| - 11 days of EHR downtime                                                |
| - $5M+ recovery costs                                                    |
| - Patient diversions and delayed treatments                              |
| - CEO resignations                                                       |
| - Class action lawsuits                                                  |
|                                                                             |
| MedDefense has the SAME vulnerabilities.                                 |
+----------------------------------------------------------------------------+

7.2 WHAT HAPPENS IF RECOMMENDATIONS ARE NOT IMPLEMENTED
-------------------------------------------------------
+----------------------------------------------------------------------------+
| Without action on these recommendations:                                   |
|                                                                             |
| 1. MEDICAL DEVICE COMPROMISE:                                              |
|    The MRI (Windows XP) remains a permanent backdoor. An attacker will    |
|    eventually exploit it, pivot to the EHR, and deploy ransomware.        |
|    (Breach 3 scenario - $40M recovery, delayed treatments)               |
|                                                                             |
| 2. CREDENTIAL THEFT:                                                       |
|    Without MFA, a single phished password gives an attacker access to     |
|    the EHR, AD, and VPN. (Breach 2 scenario - $890K response, lawsuit)   |
|                                                                             |
| 3. UNPATCHED VPN/PERIMETER:                                                |
|    Without patch management, an unpatched VPN vulnerability will give     |
|    attackers network access. (Breach 1 scenario - $5M recovery, CEO       |
|    resignation)                                                           |
|                                                                             |
| 4. NO DETECTION:                                                           |
|    Without SIEM, attackers will operate undetected for weeks or months.  |
|                                                                             |
| 5. NO RESPONSE:                                                            |
|    Without IR plan, recovery will be chaotic, extended, and costly.       |
|                                                                             |
| The organization faces a HIGH probability of a catastrophic security     |
| incident within the next 12-24 months.                                    |
+----------------------------------------------------------------------------+

7.3 TRANSITION TO EXTERNAL THREAT LANDSCAPE ASSESSMENT
------------------------------------------------------
+----------------------------------------------------------------------------+
| NEXT PHASE: EXTERNAL THREAT LANDSCAPE ASSESSMENT                          |
|                                                                             |
| Marcus Webb's unfinished work (Task 15) identified the logical next      |
| step: understanding who is targeting MedDefense and how.                  |
|                                                                             |
| This internal posture assessment tells us WHAT we are vulnerable to.      |
| The External Threat Landscape Assessment will tell us WHO is likely to    |
| exploit those vulnerabilities and HOW.                                    |
|                                                                             |
| RECOMMENDED NEXT STEPS:                                                    |
| 1. Complete Marcus's threat actor profile for MedDefense                  |
| 2. Map specific TTPs to the 16 identified gaps                           |
| 3. Apply STRIDE threat modeling to MedDefense's architecture              |
| 4. Monitor CISA healthcare advisories and HHS threat briefs               |
| 5. Update priorities quarterly based on evolving threat landscape         |
|                                                                             |
| This will provide the full picture: what we are exposed to AND who is    |
| coming for us.                                                             |
+----------------------------------------------------------------------------+


================================================================================
8. EVIDENCE TRACEABILITY
================================================================================

+----------+------------------------------------------+------------------------------------------+
| Finding  | Evidence Source                          | Traceable To                            |
+----------+------------------------------------------+------------------------------------------+
| F-001    | Flat network                             | Task 0 (Network Diagram), Task 3 (Obs)  |
+----------+------------------------------------------+------------------------------------------+
| F-002    | MRI Windows XP                           | Task 6, Task 7 (SRV-013), Task 13       |
+----------+------------------------------------------+------------------------------------------+
| F-003    | No MFA                                   | Task 4 (Artifact 3), Task 13 (Breach 2) |
+----------+------------------------------------------+------------------------------------------+
| F-004    | No SIEM                                  | Task 4 (Artifact 8), Task 13 (All       |
|          |                                          | breaches)                                |
+----------+------------------------------------------+------------------------------------------+
| F-005    | No IR Plan                               | Task 4 (Artifact 8), Task 13 (Breach 1) |
+----------+------------------------------------------+------------------------------------------+
| F-006    | No Network Segmentation                  | Task 0 (Network Diagram), Task 13 (All  |
|          |                                          | breaches)                                |
+----------+------------------------------------------+------------------------------------------+
| F-007    | No Backup for PACS                       | Task 4 (Artifact 5)                      |
+----------+------------------------------------------+------------------------------------------+
| F-008    | No Egress Filtering                      | Task 4 (Artifact 1), Task 2 (crypto-    |
|          |                                          | miner)                                   |
+----------+------------------------------------------+------------------------------------------+
| F-009    | No Patch Management                      | Task 13 (Breach 1, 3)                    |
+----------+------------------------------------------+------------------------------------------+
| F-010    | No Offboarding                           | Task 13 (Breach 2)                       |
+----------+------------------------------------------+------------------------------------------+
| F-011    | Shadow IT                                | Task 11 (Mike Torres), Task 7            |
+----------+------------------------------------------+------------------------------------------+
| F-012    | Physical Security Gaps                   | Task 3 (Obs 1, 2, 5)                     |
+----------+------------------------------------------+------------------------------------------+


================================================================================
9. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Identify Function - ID.RA (Risk Assessment)
- CIS Controls v8: Critical Security Controls
- CISA Healthcare and Public Health Sector Guide
- ISO 27001: Gap Analysis Methodology
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF SECURITY POSTURE ASSESSMENT REPORT
================================================================================
