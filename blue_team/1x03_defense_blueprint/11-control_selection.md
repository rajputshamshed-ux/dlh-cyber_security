================================================================================
                    CONTROL SELECTION - MEDDEFENSE HEALTH SYSTEMS
                    Task 11: The Control Selection
================================================================================

Exercise: Task 11 - The Control Selection
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Select and justify specific security controls for each risk in the
          register, mapping every choice to CIS Controls and NIST CSF.

Sources: 1x03 Risk Register (T10), 1x03 Cost-Benefit Analysis (T7),
         1x00 Gap Analysis, 1x01 Threat Landscape, 1x02 Vulnerability Scan


================================================================================
RISK-001: DATA BREACH VIA EHR DATABASE EXPOSURE
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-001                                         |
+------------------+--------------------------------------------------+
| Selected Control | PostgreSQL Database Access Restriction           |
+------------------+--------------------------------------------------+
| Description      | Modify pg_hba.conf to restrict PostgreSQL        |
|                  | connections to ONLY ehr-srv-01 (10.10.2.10).    |
|                  | Configure host-based firewall to drop all other  |
|                  | connections to port 5432.                       |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 4 - Secure Configuration of          |
| Mapping          | Enterprise Assets (IG1)                          |
|                  | CIS Control 11 - Network Infrastructure          |
|                  | Management (IG1)                                 |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.AC-5 (Network integrity - segmentation)       |
| Mapping          | PR.DS-1 (Data-at-rest protection)               |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE                                       |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL                                        |
+------------------+--------------------------------------------------+
| Implementation   | $500 (configuration only)                        |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $4,310,625 to approximately     |
| Reduction        | $431,063 (90% reduction) - PostgreSQL is no     |
|                  | longer accessible network-wide.                 |
+------------------+--------------------------------------------------+
| Dependencies     | None - can be implemented immediately.          |
+------------------+--------------------------------------------------+


================================================================================
RISK-002: VPN COMPROMISE LEADING TO FULL NETWORK ACCESS
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-002                                         |
+------------------+--------------------------------------------------+
| Selected Control | MFA on VPN Access + Patch Management for         |
|                  | Network Devices                                   |
+------------------+--------------------------------------------------+
| Description      | Implement MFA for ALL VPN access. Establish       |
|                  | monthly patch management schedule for FortiGate  |
|                  | firmware updates. Apply critical patches within  |
|                  | 48 hours of CVE release.                        |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 5 - Access Control Management (IG1)  |
| Mapping          | CIS Control 6 - Continuous Vulnerability         |
|                  | Management (IG1)                                 |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.AC-7 (MFA)                                    |
| Mapping          | PR.MA-1 (Maintenance)                            |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE                                       |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL                                        |
+------------------+--------------------------------------------------+
| Implementation   | $10,000 (MFA $8K + Patch Management $2K)        |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $1,334,945 to approximately     |
| Reduction        | $133,495 (90% reduction) - MFA blocks credential |
|                  | theft; patches close vulnerabilities.           |
+------------------+--------------------------------------------------+
| Dependencies     | Patch management requires asset inventory       |
|                  | (CIS Control 1) to be in place.                |
+------------------+--------------------------------------------------+


================================================================================
RISK-003: RANSOMWARE ENCRYPTS EHR SYSTEM
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-003                                         |
+------------------+--------------------------------------------------+
| Selected Control | Offsite Immutable Backups + Endpoint Detection   |
|                  | and Response (EDR) on EHR servers               |
+------------------+--------------------------------------------------+
| Description      | Implement AWS S3 Glacier immutable backups for   |
|                  | EHR. Deploy EDR on ALL servers (currently only   |
|                  | workstations have Sophos).                      |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 10 - Data Recovery (IG1)             |
| Mapping          | CIS Control 9 - Malware Defenses (IG1)           |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.DS-1 (Data-at-rest)                           |
| Mapping          | PR.IP-1 (Baseline configuration)                |
+------------------+--------------------------------------------------+
| Control Type     | CORRECTIVE + PREVENTIVE                          |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL + OPERATIONAL                          |
+------------------+--------------------------------------------------+
| Implementation   | $44,400 (Offsite $14,400 + EDR $30,000)         |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $273,615 to approximately      |
| Reduction        | $54,723 (80% reduction) - backups enable        |
|                  | recovery; EDR prevents/ detects attacks.       |
+------------------+--------------------------------------------------+
| Dependencies     | EDR requires existing endpoint protection       |
|                  | infrastructure. Offsite backups require network  |
|                  | connectivity to AWS.                            |
+------------------+--------------------------------------------------+


================================================================================
RISK-004: INSIDER DATA THEFT (NEGLIGENT)
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-004                                         |
+------------------+--------------------------------------------------+
| Selected Control | USB Restriction GPO + Security Awareness         |
|                  | Training + Data Loss Prevention (DLP)           |
+------------------+--------------------------------------------------+
| Description      | Enforce Group Policy to block USB mass storage   |
|                  | on all workstations. Implement annual security   |
|                  | awareness training with phishing simulations.   |
|                  | Deploy basic DLP for email and file sharing.    |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 3 - Data Protection (IG1)            |
| Mapping          | CIS Control 13 - Security Awareness and Skills  |
|                  | Training (IG1)                                   |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.DS-1 (Data protection)                        |
| Mapping          | PR.AT-1 (Security awareness)                     |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE + DETERRENT                           |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL + ADMINISTRATIVE                       |
+------------------+--------------------------------------------------+
| Implementation   | $8,000 (USB GPO $500 + Training $2,500 + DLP    |
| Cost             | $5,000)                                          |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $360,000 to $120,000 (67%      |
| Reduction        | reduction) - USB restriction and DLP prevent    |
|                  | data exfiltration; training raises awareness.   |
+------------------+--------------------------------------------------+
| Dependencies     | Training requires training platform (available  |
|                  | via O365). DLP requires email infrastructure.   |
+------------------+--------------------------------------------------+


================================================================================
RISK-005: MEDICAL IOT COMPROMISE (PATIENT SAFETY)
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-005                                         |
+------------------+--------------------------------------------------+
| Selected Control | IoT Network Segmentation + Default Credential   |
|                  | Change + Network Monitoring                      |
+------------------+--------------------------------------------------+
| Description      | Isolate ALL medical IoT devices on dedicated     |
|                  | VLAN. Change default credentials on all BD      |
|                  | Alaris pumps and Philips monitors. Deploy        |
|                  | network monitoring for IoT traffic.             |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
| Mapping          | Management (IG1)                                 |
|                  | CIS Control 5 - Access Control Management (IG1)  |
|                  | CIS Control 12 - Network Monitoring and Defense  |
|                  | (IG1)                                            |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.AC-5 (Network segmentation)                   |
| Mapping          | PR.AC-1 (Access control)                         |
|                  | DE.CM-1 (Network monitoring)                     |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE + DETECTIVE + COMPENSATING            |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL                                        |
+------------------+--------------------------------------------------+
| Implementation   | $18,000 (Segmentation $12K + Monitoring $5K +   |
| Cost             | Credential change $1K)                           |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $88,000 to $13,200 (85%        |
| Reduction        | reduction) - segmentation prevents lateral      |
|                  | movement; monitoring provides detection.        |
+------------------+--------------------------------------------------+
| Dependencies     | Network segmentation requires VLAN-capable       |
|                  | switches. Credential change requires vendor     |
|                  | coordination.                                    |
+------------------+--------------------------------------------------+


================================================================================
RISK-006: SUPPLY CHAIN COMPROMISE (VENDOR ACCESS)
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-006                                         |
+------------------+--------------------------------------------------+
| Selected Control | Vendor Account MFA + Vendor Access Review +      |
|                  | Vendor Activity Monitoring                       |
+------------------+--------------------------------------------------+
| Description      | Implement MFA for ALL vendor accounts. Conduct   |
|                  | quarterly reviews of vendor access. Monitor      |
|                  | vendor activity via SIEM for unusual behavior.  |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 14 - Service Provider Management     |
| Mapping          | (IG2)                                            |
|                  | CIS Control 5 - Access Control Management (IG1)  |
+------------------+--------------------------------------------------+
| NIST CSF         | ID.SC-2 (Supply chain risk)                      |
| Mapping          | PR.AC-7 (MFA)                                    |
|                  | DE.CM-7 (Monitoring for unauthorized activity)  |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE + DETECTIVE                           |
+------------------+--------------------------------------------------+
| Control Category | ADMINISTRATIVE + TECHNICAL                       |
+------------------+--------------------------------------------------+
| Implementation   | $5,000 (MFA for vendors + monitoring)           |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces risk by 80% - MFA blocks credential     |
| Reduction        | theft; monitoring detects unauthorized access.  |
+------------------+--------------------------------------------------+
| Dependencies     | Vendor MFA requires MFA infrastructure.          |
|                  | Monitoring requires SIEM (GAP-001).             |
+------------------+--------------------------------------------------+


================================================================================
RISK-007: NO INCIDENT RESPONSE CAPABILITY
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-007                                         |
+------------------+--------------------------------------------------+
| Selected Control | Incident Response Plan Development + Tabletop   |
|                  | Exercises + BCP/DR Plan Development              |
+------------------+--------------------------------------------------+
| Description      | Document formal IR plan (adapted from NIST      |
|                  | SP 800-61). Conduct tabletop exercises 2x/year. |
|                  | Develop and document BCP and DR plans.         |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 16 - Incident Response Management   |
| Mapping          | (IG1)                                            |
+------------------+--------------------------------------------------+
| NIST CSF         | RS.RP-1 (Response plan)                          |
| Mapping          | RC.RP-1 (Recovery plan)                          |
+------------------+--------------------------------------------------+
| Control Type     | CORRECTIVE + ADMINISTRATIVE                      |
+------------------+--------------------------------------------------+
| Control Category | ADMINISTRATIVE                                   |
+------------------+--------------------------------------------------+
| Implementation   | $5,000 (IR plan + tabletop exercises + BCP/DR) |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces recovery time from 11+ days to under    |
| Reduction        | 3 days. Reduces incident costs by 40%.          |
+------------------+--------------------------------------------------+
| Dependencies     | None - can be developed immediately. IR plan    |
|                  | requires stakeholder input from IT and clinical. |
+------------------+--------------------------------------------------+


================================================================================
RISK-008: WESTSIDE CLINIC PERIMETER BREACH
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-008                                         |
+------------------+--------------------------------------------------+
| Selected Control | Enterprise Firewall Replacement for Westside     |
+------------------+--------------------------------------------------+
| Description      | Replace the consumer-grade Netgear Nighthawk     |
|                  | with a FortiGate 40F enterprise firewall.       |
|                  | Configure with proper ACLs and logging.         |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
| Mapping          | Management (IG1)                                 |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.AC-5 (Network segmentation)                   |
| Mapping          | PR.DS-1 (Data protection)                        |
+------------------+--------------------------------------------------+
| Control Type     | PREVENTIVE                                       |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL + PHYSICAL                             |
+------------------+--------------------------------------------------+
| Implementation   | $5,000 (FortiGate 40F + installation + support) |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces ALE from $58,723 to $5,872 (90%         |
| Reduction        | reduction) - enterprise firewall provides       |
|                  | proper perimeter protection.                    |
+------------------+--------------------------------------------------+
| Dependencies     | None - can be deployed immediately.             |
+------------------+--------------------------------------------------+


================================================================================
RISK-009: SHADOW IT ON THE NETWORK
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-009                                         |
+------------------+--------------------------------------------------+
| Selected Control | Asset Inventory Maintenance + Network            |
|                  | Discovery + Shadow IT Remediation                |
+------------------+--------------------------------------------------+
| Description      | Implement ongoing asset inventory maintenance.  |
|                  | Conduct quarterly network scans to discover     |
|                  | unauthorized devices. Investigate and           |
|                  | decommission or migrate all shadow IT devices.  |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 1 - Inventory and Control of         |
| Mapping          | Enterprise Assets (IG1)                          |
+------------------+--------------------------------------------------+
| NIST CSF         | ID.AM-1 (Asset inventory)                        |
| Mapping          | ID.AM-2 (Asset management)                       |
+------------------+--------------------------------------------------+
| Control Type     | DETECTIVE + CORRECTIVE                           |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL + ADMINISTRATIVE                       |
+------------------+--------------------------------------------------+
| Implementation   | $5,000 (scanning + investigation + remediation) |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces risk by 80% - discovers unknown         |
| Reduction        | devices; prevents them from being used as      |
|                  | pivot points.                                    |
+------------------+--------------------------------------------------+
| Dependencies     | Requires network scan capability (nmap or       |
|                  | vulnerability scanner).                          |
+------------------+--------------------------------------------------+


================================================================================
RISK-010: PACS DATA LOSS (NO BACKUPS)
================================================================================

+------------------+--------------------------------------------------+
| Risk ID          | RISK-010                                         |
+------------------+--------------------------------------------------+
| Selected Control | PACS Backup Implementation + DICOM Encryption   |
+------------------+--------------------------------------------------+
| Description      | Implement backup for pacs-srv-01 (AWS S3 or     |
|                  | dedicated backup server). Enable TLS encryption |
|                  | for DICOM traffic between MRI and PACS server.  |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 10 - Data Recovery (IG1)             |
| Mapping          | CIS Control 3 - Data Protection (IG1)            |
+------------------+--------------------------------------------------+
| NIST CSF         | PR.DS-1 (Data protection)                        |
| Mapping          | PR.DS-2 (Data-at-rest encryption)               |
+------------------+--------------------------------------------------+
| Control Type     | CORRECTIVE + PREVENTIVE                          |
+------------------+--------------------------------------------------+
| Control Category | TECHNICAL                                        |
+------------------+--------------------------------------------------+
| Implementation   | $10,000 (Backup $8K + Encryption $2K)          |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | Reduces risk from catastrophic to manageable    |
| Reduction        | - backups enable recovery; encryption protects  |
|                  | data in transit.                                |
+------------------+--------------------------------------------------+
| Dependencies     | Offsite backup requires cloud vendor contract   |
|                  | (AWS). Encryption requires PACS vendor support. |
+------------------+--------------------------------------------------+


================================================================================
CONTROL DEPENDENCY MAP
================================================================================

+----------------------------------------------------------------------------+
| CONTROL DEPENDENCY MAP (TEXT DIAGRAM)                                      |
|                                                                             |
|                         ┌─────────────────────────────┐                   |
|                         │  CIS Control 1 - Asset      │                   |
|                         │  Inventory (CIS-001)        │                   |
|                         │  (Foundation for ALL        │                   |
|                         │   other controls)           │                   |
|                         └──────────────┬──────────────┘                   |
|                                        │                                  |
|                    ┌───────────────────┼───────────────────┐              |
|                    │                   │                   │              |
|                    ▼                   ▼                   ▼              |
|        ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐  |
|        │  CIS Control 6 -  │ │  CIS Control 11 - │ │  CIS Control 5 -  │  |
|        │  Patch Management │ │  Network          │ │  MFA              │  |
|        │  (CIS-006)        │ │  Segmentation     │ │  (CIS-005)        │  |
|        │  └───────┬────────┘ │  (CIS-011)        │ │  └───────┬────────┘  |
|        │          │          │  └───────┬────────┘ │          │           |
|        └──────────┼──────────┘          │          └──────────┼───────────┘
|                   │                     │                     │
|                   ▼                     ▼                     ▼
|        ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐  |
|        │  CIS Control 9 -  │ │  CIS Control 12 - │ │  CIS Control 14 - │  |
|        │  EDR (CIS-009)    │ │  Network          │ │  Vendor Mgt       │  |
|        │  └───────┬────────┘ │  Monitoring       │ │  (CIS-014)        │  |
|        │          │          │  (CIS-012)        │ │  └───────┬────────┘  |
|        └──────────┼──────────┘  └───────┬────────┘ │          │           |
|                   │                     │          └──────────┼───────────┘
|                   │                     │                     │
|                   ▼                     ▼                     ▼
|        ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐  |
|        │  CIS Control 10 - │ │  CIS Control 3 -  │ │  CIS Control 16 - │  |
|        │  Offsite Backup   │ │  DLP              │ │  IR Plan          │  |
|        │  (CIS-010)        │ │  (CIS-003)        │ │  (CIS-016)        │  |
|        └───────────────────┘ └───────────────────┘ └───────────────────┘  |
|                                                                             |
| DEPENDENCY RULES:                                                           |
|                                                                             |
| 1. CIS Control 1 (Asset Inventory) is the FOUNDATION for all controls.    |
|    Without knowing what assets exist, other controls cannot be properly   |
|    scoped.                                                                 |
|                                                                             |
| 2. CIS Control 6 (Patch Management) must precede CIS Control 9 (EDR)      |
|    because EDR requires baseline patching to be effective.                |
|                                                                             |
| 3. CIS Control 11 (Network Segmentation) must precede CIS Control 12      |
|    (Network Monitoring) because monitoring is more effective when it      |
|    can focus on specific segments.                                       |
|                                                                             |
| 4. CIS Control 5 (MFA) must precede CIS Control 14 (Vendor Management)    |
|    because vendor MFA relies on the MFA infrastructure.                   |
|                                                                             |
| 5. CIS Control 10 (Offsite Backup) and CIS Control 16 (IR Plan) can be   |
|    implemented in parallel once the foundation is in place.              |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Risk ID  | Selected Control | CIS Control      | NIST CSF         | Implementation   |
|          |                  | Mapping          | Mapping          | Cost             |
+----------+------------------+------------------+------------------+------------------+
| RISK-001 | PostgreSQL       | CIS 4, CIS 11    | PR.AC-5, PR.DS-1 | $500             |
|          | Restriction      |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-002 | MFA + Patch Mgt  | CIS 5, CIS 6     | PR.AC-7, PR.MA-1 | $10,000          |
+----------+------------------+------------------+------------------+------------------+
| RISK-003 | EDR + Offsite    | CIS 9, CIS 10    | PR.DS-1, PR.IP-1 | $44,400          |
|          | Backup           |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-004 | USB GPO +        | CIS 3, CIS 13    | PR.DS-1, PR.AT-1 | $8,000           |
|          | Training + DLP   |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-005 | IoT Segmentation | CIS 5, CIS 11,   | PR.AC-5, DE.CM-1 | $18,000          |
|          | + Credential     | CIS 12           |                  |                  |
|          | Change           |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-006 | Vendor MFA +     | CIS 5, CIS 14    | ID.SC-2, PR.AC-7 | $5,000           |
|          | Monitoring       |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-007 | IR Plan +        | CIS 16           | RS.RP-1, RC.RP-1 | $5,000           |
|          | Tabletop         |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-008 | Westside         | CIS 11           | PR.AC-5, PR.DS-1 | $5,000           |
|          | Firewall         |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-009 | Asset Inventory  | CIS 1            | ID.AM-1, ID.AM-2 | $5,000           |
|          | + Scanning       |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| RISK-010 | PACS Backup +    | CIS 3, CIS 10    | PR.DS-1, PR.DS-2 | $10,000          |
|          | Encryption       |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
|          | TOTAL            |                  |                  | $110,900         |
+----------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- Risk Register (1x03 T10)
- Cost-Benefit Analysis (1x03 T7)
- CIS Controls v8
- NIST CSF 2.0
- Gap Analysis (1x00 Task 12)


================================================================================
END OF CONTROL SELECTION REPORT
================================================================================
