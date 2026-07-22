================================================================================
                    GAP-TO-FRAMEWORK BRIDGE - MEDDEFENSE HEALTH SYSTEMS
                    Task 3: The Gap-to-Framework Bridge
================================================================================

Exercise: Task 3 - The Gap-to-Framework Bridge
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Connect every significant gap from prior projects to a specific
          framework control, transforming raw findings into structured,
          framework-aligned action items.

Sources: 1x00 Gap Analysis (T12), 1x01 Threat Actor Matrix (T6), 1x01 Kill Chains (T10),
         1x02 Vulnerability Scan, 1x03 NIST CSF Mapping (T1), 1x03 CIS Controls Audit (T2)


================================================================================
GAP 1: NO MFA ANYWHERE (GAP-004)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-004                                          |
+------------------+--------------------------------------------------+
| Description      | No Multi-Factor Authentication for ANY system    |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 009 (SSH password auth), Finding 031     |
| Evidence         | (Ghostcat - credential theft), Finding 001/002   |
|                  | (Apache chain)                                   |
+------------------+--------------------------------------------------+
| Threat Context   | Ransomware Groups (#1) + Opportunistic (#6)      |
|                  | Kill Chains: KC #1, KC #2, KC #4, KC #5         |
|                  | Credential theft is the #1 entry vector          |
+------------------+--------------------------------------------------+
| NIST CSF         | PROTECT - Access Control (PR.AC)                 |
| Function         |                                                  |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 5 - Access Control Management        |
|                  | (IG1: MFA for all administrative access)         |
+------------------+--------------------------------------------------+
| Recommended      | Implement MFA for ALL remote access (VPN),       |
| Action           | administrative accounts (AD), and critical       |
|                  | systems (EHR). Phased deployment: VPN first.    |
+------------------+--------------------------------------------------+


================================================================================
GAP 2: FLAT NETWORK / NO SEGMENTATION (GAP-003)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-003                                          |
+------------------+--------------------------------------------------+
| Description      | Medical IoT and all assets on flat network       |
|                  | (10.10.0.0/16) with NO segmentation             |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 003 (PostgreSQL unrestricted), Finding   |
| Evidence         | 006 (MySQL unrestricted), Finding 016 (IoT web   |
|                  | interfaces), Finding 015 (NAS accessible)        |
+------------------+--------------------------------------------------+
| Threat Context   | Ransomware Groups (#1) + Opportunistic (#6) +    |
|                  | Insider (#4)                                     |
|                  | Kill Chains: KC #1, KC #2, KC #3, KC #4, KC #5  |
|                  | The flat network amplifies EVERY vulnerability   |
+------------------+--------------------------------------------------+
| NIST CSF         | PROTECT - Identity and Access Management (PR.AC) |
| Function         | NETWORK SEGMENTATION (PR.AC-5)                   |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
|                  | Management (IG1: Segment internal networks)      |
+------------------+--------------------------------------------------+
| Recommended      | Implement network segmentation: isolate medical  |
| Action           | IoT devices on dedicated VLAN, critical servers  |
|                  | on separate segments, Westside with enterprise   |
|                  | firewall                                          |
+------------------+--------------------------------------------------+


================================================================================
GAP 3: NO SIEM OR LOG MONITORING (GAP-001)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-001                                          |
+------------------+--------------------------------------------------+
| Description      | No centralized logging, no intrusion detection,  |
|                  | no automated security alerting                   |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 020 (false positive - but proves no      |
| Evidence         | monitoring), crypto-miner went undetected,       |
|                  | ransomware discovered only when files were       |
|                  | inaccessible                                      |
+------------------+--------------------------------------------------+
| Threat Context   | ALL actors (Ransomware Groups #1, Insider #2,    |
|                  | Opportunistic #6) - attacks go undetected        |
|                  | Kill Chains: ALL 5 kill chains                   |
+------------------+--------------------------------------------------+
| NIST CSF         | DETECT - Continuous Monitoring (DE.CM)           |
| Function         |                                                  |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 7 - Audit Log Management             |
|                  | (IG1: Collect and review logs)                   |
+------------------+--------------------------------------------------+
| Recommended      | Deploy a SIEM (Wazuh open-source) for            |
| Action           | centralized logging and alerting. Start with     |
|                  | critical systems (EHR, AD, billing).            |
+------------------+--------------------------------------------------+


================================================================================
GAP 4: NO PATCH MANAGEMENT (GAP-014)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-014                                          |
+------------------+--------------------------------------------------+
| Description      | No patch management program for network devices  |
|                  | and servers                                       |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 001 (Apache RCE CVE-2021-44790),         |
| Evidence         | Finding 002 (Apache PrivEsc CVE-2019-0211 -      |
|                  | CISA KEV), Finding 031 (Ghostcat on ehr-srv-01)  |
+------------------+--------------------------------------------------+
| Threat Context   | Ransomware Groups (#1) + Opportunistic (#6)      |
|                  | Kill Chains: KC #1 (VPN exploitation), KC #5    |
|                  | (Supply Chain)                                   |
+------------------+--------------------------------------------------+
| NIST CSF         | PROTECT - Maintenance (PR.MA)                    |
| Function         | IDENTIFY - Vulnerability Management (ID.RA)      |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 6 - Continuous Vulnerability         |
|                  | Management (IG1: Regular vulnerability scanning  |
|                  | and patching)                                    |
+------------------+--------------------------------------------------+
| Recommended      | Establish a formal patch management program      |
| Action           | with monthly maintenance windows. Apply          |
|                  | critical patches within 48 hours of CVE release. |
+------------------+--------------------------------------------------+


================================================================================
GAP 5: NO COMPENSATING CONTROLS FOR MRI (GAP-007)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-007                                          |
+------------------+--------------------------------------------------+
| Description      | MRI runs Windows XP (EOL 2014) with NO           |
|                  | compensating controls (segmentation,             |
|                  | whitelisting, host firewall)                     |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 004 (Windows XP with EternalBlue,        |
| Evidence         | BlueKeep, MS08-067 - CISA KEV)                   |
+------------------+--------------------------------------------------+
| Threat Context   | Ransomware Groups (#1) + Opportunistic (#6)      |
|                  | Kill Chains: KC #4 (MRI → EHR)                  |
|                  | Breach 3 (Task 13) validated $40M+ recovery      |
+------------------+--------------------------------------------------+
| NIST CSF         | PROTECT - Maintenance (PR.MA)                    |
| Function         | PROTECT - Protective Technology (PR.PT)          |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 4 - Secure Configuration of          |
|                  | Enterprise Assets (IG1: Configure systems)       |
|                  | CIS Control 11 - Network Segmentation            |
+------------------+--------------------------------------------------+
| Recommended      | Implement compensating controls: isolate MRI     |
| Action           | on dedicated VLAN, apply application             |
|                  | whitelisting, deploy host-based firewall,        |
|                  | implement network monitoring.                    |
+------------------+--------------------------------------------------+


================================================================================
GAP 6: NO VENDOR ACCOUNT MANAGEMENT (GAP-012)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-012                                          |
+------------------+--------------------------------------------------+
| Description      | No oversight of vendor accounts. No MFA, no      |
|                  | access reviews, no monitoring of vendor          |
|                  | activity.                                         |
+------------------+--------------------------------------------------+
| Vulnerability    | MedTech has direct access to EHR server with     |
| Evidence         | NO MFA (from 1x00 T5). SecurePoint scan          |
|                  | could not verify vendor controls.                |
+------------------+--------------------------------------------------+
| Threat Context   | Ransomware Groups (#1) + APT (#2)                |
|                  | Kill Chains: KC #5 (Supply Chain)               |
|                  | Change Healthcare breach (2024) was vendor       |
|                  | compromise                                        |
+------------------+--------------------------------------------------+
| NIST CSF         | IDENTIFY - Supply Chain (ID.SC)                  |
| Function         | IDENTIFY - Risk Assessment (ID.RA)               |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 14 - Service Provider Management     |
|                  | (IG2: Manage vendor accounts and access)         |
+------------------+--------------------------------------------------+
| Recommended      | Inventory ALL vendor accounts, implement MFA    |
| Action           | for vendor access, review vendor access          |
|                  | quarterly, enforce least privilege.             |
+------------------+--------------------------------------------------+


================================================================================
GAP 7: NO INCIDENT RESPONSE PLAN (GAP-002)
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-002                                          |
+------------------+--------------------------------------------------+
| Description      | No formal incident response plan, BCP, or DR     |
|                  | plan. No tested recovery procedures.             |
+------------------+--------------------------------------------------+
| Vulnerability    | January ransomware handled ad-hoc over 4 days,   |
| Evidence         | PACS not backed up, backups not tested.          |
+------------------+--------------------------------------------------+
| Threat Context   | ALL actors (applies to aftermath of ANY attack)  |
|                  | Breach 1 (Task 13): 11-day recovery              |
+------------------+--------------------------------------------------+
| NIST CSF         | RESPOND - Incident Response Planning (RS.RP)     |
| Function         | RECOVER - Recovery Planning (RC.RP)              |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 16 - Incident Response Management    |
|                  | (IG1: Document and test IR plan)                 |
+------------------+--------------------------------------------------+
| Recommended      | Develop formal IR plan (adapted from NIST        |
| Action           | SP 800-61), designate response roles, conduct    |
|                  | tabletop exercises, document BCP/DR plans.       |
+------------------+--------------------------------------------------+


================================================================================
GAP 8: SHADOW IT / NO ASSET INVENTORY MAINTENANCE
================================================================================

+------------------+--------------------------------------------------+
| Gap Reference    | GAP-009 (Shadow IT) + Asset Inventory Gap        |
+------------------+--------------------------------------------------+
| Description      | Shadow IT devices (Dr. Patel's NAS, Marketing    |
|                  | Google Drive, Raspberry Pi) with NO controls.    |
|                  | Asset inventory was built but is not maintained. |
+------------------+--------------------------------------------------+
| Vulnerability    | Finding 028 (Unknown Linux with Jupyter),        |
| Evidence         | Finding 029 (Unknown Linux with Grafana 8.2.0 -  |
|                  | CVE-2021-43798)                                  |
+------------------+--------------------------------------------------+
| Threat Context   | Opportunistic (#6) + Insider (Negligent #2)      |
|                  | Shadow IT devices are invisible to ALL controls  |
|                  | and provide perfect pivot points.               |
+------------------+--------------------------------------------------+
| NIST CSF         | IDENTIFY - Asset Management (ID.AM)              |
| Function         | PROTECT - Protective Technology (PR.PT)          |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 1 - Inventory and Control of         |
|                  | Enterprise Assets (IG1: Maintain asset           |
|                  | inventory)                                        |
+------------------+--------------------------------------------------+
| Recommended      | Investigate and document ALL shadow IT devices,  |
| Action           | migrate/decommission unauthorized devices,       |
|                  | establish ongoing asset inventory maintenance    |
|                  | process.                                         |
+------------------+--------------------------------------------------+


================================================================================
TRACEABILITY SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+------------------+
| Priority | Gap              | Vulnerability    | Threat Context   | NIST CSF         | CIS Control      |
|          |                  | Evidence         | (Kill Chain)     | Function         |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| #1       | GAP-004          | 009, 031, 001/002 | Ransomware #1    | PROTECT          | CIS 5            |
|          | (No MFA)         |                  | KC #1, KC #2     | (PR.AC)          | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #2       | GAP-003          | 003, 006, 015,   | Ransomware #1    | PROTECT          | CIS 11           |
|          | (Flat Network)   | 016              | KC #1, KC #3     | (PR.AC-5)        | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #3       | GAP-001          | Crypto-miner,    | ALL Actors       | DETECT           | CIS 7            |
|          | (No SIEM)        | Ransomware       | ALL 5 KC         | (DE.CM)          | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #4       | GAP-014          | 001, 002, 031    | Ransomware #1    | PROTECT/IDENTIFY | CIS 6            |
|          | (Patch Mgt)      |                  | KC #1, KC #5     | (PR.MA/ID.RA)    | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #5       | GAP-007          | 004 (Windows XP) | Ransomware #1    | PROTECT          | CIS 4, CIS 11    |
|          | (MRI Compens.)   |                  | KC #4            | (PR.MA/PR.PT)    | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #6       | GAP-012          | MedTech access   | Ransomware #1    | IDENTIFY         | CIS 14           |
|          | (Vendor Mgt)     |                  | KC #5            | (ID.SC/ID.RA)    | (IG2)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #7       | GAP-002          | Jan ransomware,  | ALL Actors       | RESPOND/RECOVER  | CIS 16           |
|          | (No IR Plan)     | PACS no backup   | (Post-incident)  | (RS.RP/RC.RP)    | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+
| #8       | GAP-009 +        | 028, 029         | Opportunistic #6 | IDENTIFY         | CIS 1            |
|          | Asset Inventory  | (Shadow IT)      | Insider #2       | (ID.AM)          | (IG1)            |
+----------+------------------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- Gap Analysis (1x00 Task 12)
- Threat Actor Matrix (1x01 Task 6)
- Kill Chains (1x01 Task 10)
- Vulnerability Scan (1x02)
- NIST CSF Mapping (1x03 T1)
- CIS Controls Audit (1x03 T2)

Cross-References:
- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment (1x02)


================================================================================
END OF GAP-TO-FRAMEWORK BRIDGE REPORT
================================================================================

