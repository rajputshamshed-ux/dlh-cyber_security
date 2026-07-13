================================================================================
                    COMPLETE CONTROL MATRIX - MEDDEFENSE HEALTH SYSTEMS
                    Task 10: The Complete Control Matrix
================================================================================

Exercise: Task 10 - The Complete Control Matrix
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Produce a consolidated, authoritative control inventory that
          integrates all controls identified throughout the project, mapped
          against the assets they protect.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Protect Function
- CIS Controls v8: Critical Security Controls
- ISO 27001: A.8.1 (Asset Inventory)

Sources: Tasks 4, 6, 7, 8, 9; Control Artifacts; Walk-through Observations


================================================================================
PART 1: CONTROL REGISTRY (UPDATED)
================================================================================

CONTROL ID LEGEND:
- C-001 to C-014: Original controls from Task 4
- C-015 to C-020: New controls identified in subsequent tasks

+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| Control | Control Name        | Category        | Function        | Asset(s) Protected        | Effectiveness| Evidence/Source           |
| ID      |                     |                 |                 |                           |              |                           |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-001   | Firewall -          | Technical       | Preventive      | Entire internal network,  | Weak         | Artifact 1: Rules allow   |
|         | Perimeter           |                 |                 | web-srv-01                |              | ALL outbound. VPN too     |
|         | Protection          |                 |                 |                           |              | permissive. No egress     |
|         |                     |                 |                 |                           |              | filtering.                |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-002   | Firewall - Outbound | Technical       | Preventive      | Internal network users    | Weak         | Artifact 1: Rule 4 allows |
|         | NAT (Egress)        |                 |                 |                           |              | ALL outbound. Crypto-     |
|         |                     |                 |                 |                           |              | miner connects freely.    |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-003   | Firewall - VPN      | Technical       | Preventive      | Westside/HQ VPN           | Weak         | Artifact 1: Rules 2, 3    |
|         | Access              |                 |                 | connectivity              |              | allow "ALL" services.     |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-004   | Firewall Logging    | Technical       | Detective       | Network perimeter         | Weak         | Artifact 1: Logs local    |
|         |                     |                 |                 |                           |              | only. No SIEM. No alerts.|
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-005   | SSH Hardening -     | Technical       | Preventive      | ehr-srv-01                | Strong       | Artifact 2: Key-only,     |
|         | ehr-srv-01          |                 |                 |                           |              | root disabled, limited    |
|         |                     |                 |                 |                           |              | attempts.                 |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-006   | Password Policy -   | Administrative  | Preventive      | AD-authenticated systems  | Adequate     | Artifact 3: 8 chars,      |
|         | Active Directory    |                 |                 | (Windows)                 |              | complexity, rotation,     |
|         |                     |                 |                 |                           |              | lockout. No MFA.          |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-007   | Password Policy -   | Administrative  | Preventive      | Systems with shared       | Weak         | Artifact 3: Policy        |
|         | Shared Accounts     |                 |                 | accounts                  |              | exists but NOT enforced.  |
|         |                     |                 |                 |                           |              | Radiology still shared.   |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-008   | Sophos Endpoint     | Technical       | Preventive/     | Windows workstations      | Adequate     | Artifact 4: 88.1% current |
|         | Protection          |                 | Detective       | (372 of 387)              |              | signatures. 31 outdated.  |
|         |                     |                 |                 |                           |              | Servers NOT covered.      |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-009   | Veeam Backups -     | Technical       | Corrective      | ehr-srv-01, ehr-db-01,    | Adequate     | Artifact 5: Daily full    |
|         | Nightly Full        |                 |                 | billing-srv-01, ad-dc-01, |              | backups. NAS co-located.  |
|         |                     |                 |                 | file-srv-01, web-srv-01   |              | No offsite. 14-day        |
|         |                     |                 |                 |                           |              | retention.                |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-010   | Sophos Detections - | Technical       | Detective       | Windows workstations      | Adequate     | Artifact 4: Recent        |
|         | Alerting             |                 |                 |                           |              | detections but no auto    |
|         |                     |                 |                 |                           |              | notifications.            |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-011   | Guard Service -     | Physical        | Deterrent/      | Central main entrance     | Adequate     | Artifact 6: M-F, 7AM-     |
|         | ClearView Security  |                 | Detective       |                           |              | 7PM only. No patrols.     |
|         |                     |                 |                 |                           |              | No Westside/HQ.           |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-012   | Camera System -     | Physical        | Detective/      | Central main entrance,    | Weak         | Artifact 6: 4 analog      |
|         | Central             |                 | Deterrent       | ER entrance, parking      |              | cameras. No server room   |
|         |                     |                 |                 | garage                    |              | coverage. Self-monitored. |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-013   | Security Awareness  | Administrative  | Preventive      | All employees             | Weak         | Artifact 7: 58-71%        |
|         | Training            |                 |                 |                           |              | completion. Generic       |
|         |                     |                 |                 |                           |              | content. No phishing      |
|         |                     |                 |                 |                           |              | simulations.              |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-014   | AD Event Logging    | Technical       | Detective       | AD authentication events  | Weak         | Artifact 8: Local only.   |
|         |                     |                 |                 |                           |              | No alerting. Manual       |
|         |                     |                 |                 |                           |              | review only.              |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-015   | Network              | Technical       | Preventive/     | MRI (Windows XP),         | Proposed     | Task 6: Isolate MRI on    |
|         | Segmentation -      |                 | Compensating    | Medical IoT devices       |              | dedicated VLAN. Block     |
|         | MRI Isolation VLAN  |                 |                 |                           |              | lateral movement.         |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-016   | Application          | Technical       | Preventive/     | MRI (Windows XP)          | Proposed     | Task 6: Whitelist ONLY    |
|         | Whitelisting - MRI  |                 | Compensating    |                           |              | approved apps. Block      |
|         |                     |                 |                 |                           |              | malware execution.        |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-017   | Host-Based Firewall | Technical       | Preventive/     | MRI (Windows XP)          | Proposed     | Task 6: Block inbound     |
|         | - MRI               |                 | Compensating    |                           |              | connections to vulnerable |
|         |                     |                 |                 |                           |              | services.                 |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-018   | Physical Access     | Physical        | Preventive/     | MRI room, Server room,    | Proposed     | Task 6 + Obs 1: Restrict  |
|         | Restriction - MRI   |                 | Compensating    | Network closets           |              | badge access. Install     |
|         | Room                |                 |                 |                           |              | cameras.                  |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-019   | MRI-Specific         | Administrative  | Corrective/     | MRI (Windows XP)          | Proposed     | Task 6: Documented IR     |
|         | Incident Response   |                 | Compensating    |                           |              | procedure for MRI         |
|         | Procedure           |                 |                 |                           |              | compromise.               |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+
| C-020   | Network Monitoring   | Technical       | Detective/      | MRI, Medical IoT devices  | Proposed     | Task 6: IDS/IPS or        |
|         | - IoT Traffic       |                 | Compensating    |                           |              | NetFlow monitoring.       |
|         |                     |                 |                 |                           |              | Alerts for anomalies.     |
+---------+---------------------+-----------------+-----------------+---------------------------+--------------+---------------------------+


================================================================================
PART 2: UPDATED CONTROL SUMMARY MATRIX
================================================================================

+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
|                  | Preventive      | Detective       | Corrective      | Compensating     | Deterrent       |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| TECHNICAL        | C-001, C-002,   | C-004, C-008,   | C-009            | C-015, C-016,    | [EMPTY]         |
|                  | C-003, C-005,   | C-010, C-014,   |                  | C-017, C-020     |                 |
|                  | C-008, C-015,   | C-020            |                  |                  |                 |
|                  | C-016, C-017    |                  |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Count            | 9               | 5               | 1               | 4                | 0               |
| Avg Effectiveness| Weak/Adequate   | Weak/Adequate   | Adequate        | Proposed         | N/A             |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| ADMINISTRATIVE   | C-006, C-007,   | [EMPTY]         | C-019            | [EMPTY]          | [EMPTY]         |
|                  | C-013            |                 |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Count            | 3               | 0               | 1               | 0                | 0               |
| Avg Effectiveness| Weak/Adequate   | N/A             | Proposed        | N/A              | N/A             |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| PHYSICAL         | C-018            | C-011, C-012    | [EMPTY]         | C-018            | C-011, C-012    |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Count            | 1               | 2               | 0               | 1                | 2               |
| Avg Effectiveness| Proposed        | Weak/Adequate   | N/A             | Proposed        | Weak/Adequate   |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+

TOTAL CONTROLS: 20 (14 existing + 6 new)

GAPS REMAINING (EMPTY CELLS):
- Technical Deterrent: No technical deterrent controls
- Administrative Detective: No administrative detective controls
- Administrative Compensating: No administrative compensating controls
- Administrative Deterrent: No administrative deterrent controls
- Physical Corrective: No physical corrective controls


================================================================================
PART 3: CONTROL COVERAGE MAP - TOP 5 CRITICAL ASSETS
================================================================================

CRITICAL ASSET #1: EHR SYSTEM (ehr-srv-01 + ehr-db-01)
-------------------------------------------------------
+------------------+------------------------------------------+---------------------------+
| Function         | Controls                                 | Coverage Assessment       |
+------------------+------------------------------------------+---------------------------+
| PREVENTIVE       | C-005 (SSH Hardening - ehr-srv-01)       | PARTIAL                   |
|                  | C-006 (Password Policy)                  | - SSH hardened only on    |
|                  | C-008 (Sophos - workstations)            |   ehr-srv-01              |
|                  |                                          | - No MFA                  |
|                  |                                          | - No network segmentation |
+------------------+------------------------------------------+---------------------------+
| DETECTIVE        | C-004 (Firewall Logging - limited)       | CRITICAL GAP              |
|                  | C-010 (Sophos Detections)                | - No SIEM                 |
|                  | C-014 (AD Logging - no alerts)           | - No log monitoring       |
|                  |                                          | - No intrusion detection  |
+------------------+------------------------------------------+---------------------------+
| CORRECTIVE       | C-009 (Veeam Backups)                    | LIMITED                  |
|                  |                                          | - Backups exist but       |
|                  |                                          | - Co-located NAS          |
|                  |                                          | - No offsite              |
|                  |                                          | - No tested recovery      |
+------------------+------------------------------------------+---------------------------+
| COMPENSATING     | NONE                                     | CRITICAL GAP              |
+------------------+------------------------------------------+---------------------------+

OVERALL COVERAGE ASSESSMENT: CRITICAL GAPS
The EHR system is PROTECTED but not SECURED. Preventive controls are
partial. Detective controls are nearly absent. Corrective controls exist
but are limited (co-located backups). Compensating controls are absent.
This is the #1 critical asset with significant protection gaps.


CRITICAL ASSET #2: MEDICAL IOT (Patient Monitors + Infusion Pumps)
------------------------------------------------------------------
+------------------+------------------------------------------+---------------------------+
| Function         | Controls                                 | Coverage Assessment       |
+------------------+------------------------------------------+---------------------------+
| PREVENTIVE       | C-015 (Network Segmentation - Proposed)  | CRITICAL GAP              |
|                  | C-016 (App Whitelisting - Proposed)      | - No segmentation         |
|                  | C-017 (Host Firewall - Proposed)         | - Flat network            |
|                  |                                          | - No device hardening     |
|                  |                                          | - No segmentation         |
+------------------+------------------------------------------+---------------------------+
| DETECTIVE        | C-020 (Network Monitoring - Proposed)    | CRITICAL GAP              |
|                  |                                          | - No IoT monitoring       |
|                  |                                          | - No traffic analysis     |
|                  |                                          | - No anomaly detection    |
+------------------+------------------------------------------+---------------------------+
| CORRECTIVE       | NONE                                     | CRITICAL GAP              |
+------------------+------------------------------------------+---------------------------+
| COMPENSATING     | C-015, C-016, C-017 (Proposed)          | PARTIAL (Proposed only)   |
|                  | C-020 (Proposed)                         |                          |
+------------------+------------------------------------------+---------------------------+

OVERALL COVERAGE ASSESSMENT: CRITICAL GAPS
Medical IoT devices have ALMOST NO controls. They are on the same flat
network as everything else. No segmentation. No monitoring. No hardening.
All proposed controls are not yet implemented. This represents a life-
safety risk.


CRITICAL ASSET #3: PACS/IMAGING SYSTEM (pacs-srv-01 + MRI + CT)
----------------------------------------------------------------
+------------------+------------------------------------------+---------------------------+
| Function         | Controls                                 | Coverage Assessment       |
+------------------+------------------------------------------+---------------------------+
| PREVENTIVE       | C-015 (Network Segmentation - Proposed)  | CRITICAL GAP              |
|                  | C-016 (App Whitelisting - Proposed)      | - MRI on flat network     |
|                  | C-017 (Host Firewall - Proposed)         | - Windows XP EOL 2014     |
|                  |                                          | - No segmentation         |
|                  |                                          | - No compensating controls|
+------------------+------------------------------------------+---------------------------+
| DETECTIVE        | C-004 (Firewall Logging - limited)       | CRITICAL GAP              |
|                  | C-020 (Network Monitoring - Proposed)    | - No monitoring for       |
|                  |                                          |   imaging traffic         |
|                  |                                          | - No anomaly detection    |
+------------------+------------------------------------------+---------------------------+
| CORRECTIVE       | NONE                                     | CRITICAL GAP              |
|                  |                                          | - PACS NOT backed up      |
|                  |                                          | - No recovery plan        |
+------------------+------------------------------------------+---------------------------+
| COMPENSATING     | C-015, C-016, C-017 (Proposed)          | PARTIAL (Proposed only)   |
|                  | C-018 (Physical Access - Proposed)      |                          |
|                  | C-019 (IR Procedure - Proposed)         |                          |
+------------------+------------------------------------------+---------------------------+

OVERALL COVERAGE ASSESSMENT: CRITICAL GAPS
The PACS system has NO backups. The MRI runs Windows XP (EOL 2014) with
NO compensating controls. This is a permanent backdoor into the network.
All proposed controls are not yet implemented.


CRITICAL ASSET #4: ACTIVE DIRECTORY (ad-dc-01 + ad-dc-02)
----------------------------------------------------------
+------------------+------------------------------------------+---------------------------+
| Function         | Controls                                 | Coverage Assessment       |
+------------------+------------------------------------------+---------------------------+
| PREVENTIVE       | C-006 (Password Policy)                  | PARTIAL                   |
|                  |                                          | - Password policy exists  |
|                  |                                          | - No MFA                  |
|                  |                                          | - No privileged access    |
|                  |                                          |   management              |
+------------------+------------------------------------------+---------------------------+
| DETECTIVE        | C-014 (AD Logging - no alerts)           | CRITICAL GAP              |
|                  |                                          | - Logs exist but not      |
|                  |                                          |   monitored               |
|                  |                                          | - No alerting             |
|                  |                                          | - No SIEM integration     |
+------------------+------------------------------------------+---------------------------+
| CORRECTIVE       | C-009 (Backups - ad-dc-01 only)          | LIMITED                  |
|                  |                                          | - ad-dc-01 backed up      |
|                  |                                          | - ad-dc-02 NOT backed up  |
|                  |                                          | - No tested restore       |
+------------------+------------------------------------------+---------------------------+
| COMPENSATING     | NONE                                     | CRITICAL GAP              |
+------------------+------------------------------------------+---------------------------+

OVERALL COVERAGE ASSESSMENT: CRITICAL GAPS
AD is the "keys to the kingdom" but has weak preventive controls (no MFA,
no PAM), no detective controls (no monitoring), and incomplete corrective
controls (ad-dc-02 not backed up). An AD compromise is a catastrophic event.


CRITICAL ASSET #5: NETWORK CORE & PERIMETER (FortiGate 100F + Core Switch)
---------------------------------------------------------------------------
+------------------+------------------------------------------+---------------------------+
| Function         | Controls                                 | Coverage Assessment       |
+------------------+------------------------------------------+---------------------------+
| PREVENTIVE       | C-001 (Firewall Perimeter)               | PARTIAL                   |
|                  | C-002 (Outbound NAT)                     | - Firewall exists but     |
|                  | C-003 (VPN Access)                       | - Permissive rules        |
|                  |                                          | - No egress filtering     |
|                  |                                          | - No redundancy           |
+------------------+------------------------------------------+---------------------------+
| DETECTIVE        | C-004 (Firewall Logging)                 | CRITICAL GAP              |
|                  |                                          | - Logs local only         |
|                  |                                          | - No SIEM                 |
|                  |                                          | - No alerting             |
+------------------+------------------------------------------+---------------------------+
| CORRECTIVE       | NONE                                     | CRITICAL GAP              |
|                  |                                          | - No backup firewall      |
|                  |                                          | - No DR for network       |
|                  |                                          | - No tested failover      |
+------------------+------------------------------------------+---------------------------+
| COMPENSATING     | NONE                                     | CRITICAL GAP              |
+------------------+------------------------------------------+---------------------------+

OVERALL COVERAGE ASSESSMENT: CRITICAL GAPS
The network core is a single point of failure. Firewall rules are
permissive (allows ALL outbound). No egress filtering. No SIEM. No
redundancy. No DR testing. Failure of this asset takes down ALL sites.


================================================================================
4. CONTROL COVERAGE SUMMARY - TOP 5 CRITICAL ASSETS
================================================================================

+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| Critical Asset   | Preventive      | Detective       | Corrective      | Compensating     | Overall Status   |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| EHR System       | PARTIAL         | CRITICAL GAP    | LIMITED         | CRITICAL GAP     | CRITICAL GAPS    |
|                  | (C-005, C-006,  | (No SIEM)       | (Backups only)  |                   |                  |
|                  | C-008)          |                 |                 |                   |                  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| Medical IoT      | CRITICAL GAP    | CRITICAL GAP    | CRITICAL GAP    | PROPOSED ONLY    | CRITICAL GAPS    |
|                  | (No controls)   | (No monitoring) | (No recovery)   | (C-015, C-016,   |                  |
|                  |                 |                 |                 | C-017, C-020)    |                  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| PACS/Imaging     | CRITICAL GAP    | CRITICAL GAP    | CRITICAL GAP    | PROPOSED ONLY    | CRITICAL GAPS    |
|                  | (Windows XP)    | (No monitoring) | (No backups)    | (C-015, C-016,   |                  |
|                  |                 |                 |                 | C-017, C-018,    |                  |
|                  |                 |                 |                 | C-019)           |                  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| Active Directory | PARTIAL         | CRITICAL GAP    | LIMITED         | CRITICAL GAP     | CRITICAL GAPS    |
|                  | (C-006)         | (No monitoring) | (ad-dc-01 only) |                   |                  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+
| Network Core     | PARTIAL         | CRITICAL GAP    | CRITICAL GAP    | CRITICAL GAP     | CRITICAL GAPS    |
|                  | (C-001, C-002,  | (No SIEM)       | (No redundancy) |                   |                  |
|                  | C-003)          |                 |                 |                   |                  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------+


================================================================================
5. EFFECTIVENESS SUMMARY
================================================================================

+------------------+-----------------+-----------------+------------------------------------------+
| Category         | Strong          | Adequate        | Weak / Proposed                          |
+------------------+-----------------+-----------------+------------------------------------------+
| Technical        | C-005 (SSH      | C-008 (Sophos   | C-001, C-002, C-003, C-004, C-014        |
|                  | Hardening)      | Endpoint)       | (Weak)                                   |
|                  |                 | C-009 (Backups) | C-015, C-016, C-017, C-020 (Proposed)    |
|                  |                 | C-010 (Sophos   |                                          |
|                  |                 | Detections)     |                                          |
+------------------+-----------------+-----------------+------------------------------------------+
| Administrative   | None            | C-006 (Password | C-007 (Shared Accounts - Weak)           |
|                  |                 | Policy)         | C-013 (Training - Weak)                  |
|                  |                 |                 | C-019 (IR Procedure - Proposed)          |
+------------------+-----------------+-----------------+------------------------------------------+
| Physical         | None            | C-011 (Guard    | C-012 (Camera System - Weak)             |
|                  |                 | Service)        | C-018 (Physical Access - Proposed)       |
+------------------+-----------------+-----------------+------------------------------------------+

STRONG CONTROLS: 1 (5%)
ADEQUATE CONTROLS: 5 (25%)
WEAK CONTROLS: 8 (40%)
PROPOSED CONTROLS: 6 (30%)

TOTAL: 20 controls identified


================================================================================
6. KEY FINDINGS
================================================================================

1. ONLY 1 control (C-005 - SSH Hardening on ehr-srv-01) is rated STRONG.
   This indicates widespread control implementation issues.

2. 40% of controls are WEAK. They exist on paper but are poorly implemented
   or easily bypassed.

3. 30% of controls are PROPOSED. They represent compensating controls
   designed for the MRI but NOT yet implemented.

4. 5 CRITICAL GAPS remain across the Top 5 Critical Assets:
   - All 5 assets have CRITICAL GAPS in Detective controls (No SIEM)
   - 4 of 5 assets have CRITICAL GAPS in Corrective controls
   - 4 of 5 assets have CRITICAL GAPS in Compensating controls

5. The EHR System (#1 critical asset) has only 1 STRONG control (SSH)
   and CRITICAL GAPS in Detective and Compensating controls.

6. Medical IoT (#2 critical asset) has ALMOST NO controls. All proposed
   controls are not yet implemented. Life-safety risk.

7. The flat network (10.10.0.0/16) means that any control weakness in
   ANY asset can be exploited to compromise ALL assets.

8. No technical deterrent controls exist. No administrative detective,
   compensating, or deterrent controls exist. No physical corrective
   controls exist.


================================================================================
7. RECOMMENDATIONS
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap              | Recommended Action                    | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | No SIEM/         | Deploy SIEM. Centralize logs.         | NIST SP 800-53   |
|          | Detective        | Implement alerting.                   | AU-6             |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | No MFA           | Implement MFA for ALL critical        | NIST SP 800-53   |
|          |                  | systems (EHR, AD, VPN).               | IA-2             |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Medical IoT      | IMMEDIATELY segment IoT devices       | NIST SP 800-53   |
|          | No Controls      | to isolated VLAN. Implement           | SC-7             |
|          |                  | monitoring.                           |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Network          | Implement egress filtering.           | NIST SP 800-53   |
|          | Permissive       | Restrict outbound traffic.            | SC-7             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | No Backup        | Implement offsite/cloud backups.      | NIST SP 800-53   |
|          | Offsite          | Test recovery procedures.             | CP-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | No IR Plan       | Develop formal IR plan. Test it.      | NIST SP 800-53   |
|          |                  |                                        | IR-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Training         | Improve completion rates. Add         | NIST SP 800-53   |
|          | Low Completion   | healthcare-specific content.          | AT-2             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Protect Function
- CIS Controls v8: Critical Security Controls
- CISA Healthcare and Public Health Sector Guide
- ISO 27001: A.8.1 (Asset Inventory)
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF COMPLETE CONTROL MATRIX REPORT
================================================================================
