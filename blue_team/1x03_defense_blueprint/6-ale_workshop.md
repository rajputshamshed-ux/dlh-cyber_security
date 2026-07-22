================================================================================
                    ALE WORKSHOP - MEDDEFENSE HEALTH SYSTEMS
                    Task 6: The ALE Workshop
================================================================================

Exercise: Task 6 - The ALE Workshop
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Calculate ALE for MedDefense's top 5 real risks and use the
          results to connect risk analysis to control investment.

Sources: 1x00 Asset Registry, 1x00 Gap Analysis, 1x01 Threat Landscape,
         1x02 Vulnerability Scan, 1x03 Risk Equation (T5)


================================================================================
RISK 1: RANSOMWARE ENCRYPTS EHR SYSTEM
================================================================================

+------------------+--------------------------------------------------+
| Risk             | Ransomware encrypts EHR system                    |
+------------------+--------------------------------------------------+
| Source           | GAP-003 (Flat Network), GAP-004 (No MFA),        |
|                  | GAP-014 (No Patch Management)                    |
|                  | Findings: 001/002/003/004/031                     |
|                  | Threat Actor: Ransomware Groups (#1)             |
|                  | Kill Chain: KC #1, KC #2, KC #4                  |
+------------------+--------------------------------------------------+

ASSET: EHR System (ehr-srv-01 + ehr-db-01) - 50,000 patient records

ASSET VALUE (AV)
+------------------+--------------------------------------------------+
| Component        | Amount                                           |
+------------------+--------------------------------------------------+
| Recovery/        | $85,000 (forensics, rebuild, vendor support)     |
| Replacement      |                                                  |
+------------------+--------------------------------------------------+
| Revenue Loss     | $16,000/day × 18 days = $288,000                 |
| (downtime)       |                                                  |
+------------------+--------------------------------------------------+
| Regulatory       | $100,000 (HIPAA mid-range penalty)               |
| Penalties        |                                                  |
+------------------+--------------------------------------------------+
| Reputation /     | $600,000 (5% patient attrition over 2 years)     |
| Trust Impact     |                                                  |
+------------------+--------------------------------------------------+
| TOTAL AV         | $1,073,000                                        |
+------------------+--------------------------------------------------+

EXPOSURE FACTOR (EF): 85%
+----------------------------------------------------------------------------+
| Reasoning: Not 100% because some operations may continue with paper        |
| backup, insurance may cover some costs, and some revenue may be recovered. |
| However, 85% represents the severe operational and financial impact of a   |
| ransomware event on the EHR.                                               |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $1,073,000 × 0.85 = $912,050                       |
+------------------+--------------------------------------------------+

ANNUALIZED RATE OF OCCURRENCE (ARO): 0.3 (once every ~3.3 years)
+----------------------------------------------------------------------------+
| Reasoning: Based on CISA data showing healthcare ransomware incidents     |
| at 25% of all sectors. Three regional hospitals within 200 miles hit in  |
| 8 months. MedDefense has NO MFA, NO segmentation, NO patch management.   |
| The crypto-miner proves MedDefense is already being scanned.             |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $912,050 × 0.3 = $273,615                          |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| PROPOSED CONTROL: Network Segmentation + MFA + Patch Management            |
| Control Annual Cost: $22,000 (Segmentation $12K + MFA $8K + Patch $2K)   |
| Estimated ALE After Control: $54,723 (ARO drops from 0.3 to 0.06)        |
| Net Benefit: $273,615 - $54,723 - $22,000 = $196,892                     |
+----------------------------------------------------------------------------+


================================================================================
RISK 2: DATA BREACH (PHI EXPOSURE) VIA EHR DATABASE
================================================================================

+------------------+--------------------------------------------------+
| Risk             | Data breach exposing PHI via EHR database         |
+------------------+--------------------------------------------------+
| Source           | GAP-003 (Flat Network), GAP-001 (No SIEM)        |
|                  | Findings: 003 (PostgreSQL unrestricted)           |
|                  | 031 (Ghostcat)                                    |
|                  | Threat Actor: Ransomware Groups (#1),            |
|                  | Insider Malicious (#4)                            |
|                  | Kill Chain: KC #2 (Phishing → EHR)               |
+------------------+--------------------------------------------------+

ASSET: EHR Database (ehr-db-01) - 50,000 patient records

ASSET VALUE (AV)
+------------------+--------------------------------------------------+
| Component        | Amount                                           |
+------------------+--------------------------------------------------+
| Breach Cost      | 50,000 × $165 = $8,250,000 (Ponemon 2024)        |
| (per record)     |                                                  |
+------------------+--------------------------------------------------+
| Notification     | $25,000                                          |
| Costs            |                                                  |
+------------------+--------------------------------------------------+
| Litigation       | $200,000                                         |
| Exposure         |                                                  |
+------------------+--------------------------------------------------+
| Reputation /     | $600,000 (5% patient attrition)                  |
| Trust Impact     |                                                  |
+------------------+--------------------------------------------------+
| TOTAL AV         | $9,075,000                                        |
+------------------+--------------------------------------------------+

EXPOSURE FACTOR (EF): 95%
+----------------------------------------------------------------------------+
| Reasoning: A breach triggers ALL associated costs. Breach notification    |
| is mandatory. Legal exposure is almost certain. Reputational damage is    |
| inevitable. 5% retained for insurance coverage or partial mitigation.     |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $9,075,000 × 0.95 = $8,621,250                     |
+------------------+--------------------------------------------------+

ANNUALIZED RATE OF OCCURRENCE (ARO): 0.5 (once every 2 years)
+----------------------------------------------------------------------------+
| Reasoning: HHS breach portal: 1,247 breaches in 24 months across ~6,000  |
| hospitals. MedDefense is HIGHER RISK than average due to:                |
| - PostgreSQL accessible from ANY system (Finding 003)                    |
| - Ghostcat on ehr-srv-01 (Finding 031)                                   |
| - No SIEM (GAP-001)                                                       |
| - Flat network (GAP-003)                                                  |
| PostgreSQL itself is a direct path to PHI.                              |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $8,621,250 × 0.5 = $4,310,625                      |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| PROPOSED CONTROL: PostgreSQL Restriction + Ghostcat Patch + SIEM          |
| Control Annual Cost: $7,500 (PostgreSQL $500 + Ghostcat $2,000 + SIEM    |
| $5,000)                                                                   |
| Estimated ALE After Control: $431,063 (ARO drops from 0.5 to 0.05)       |
| Net Benefit: $4,310,625 - $431,063 - $7,500 = $3,872,062                |
+----------------------------------------------------------------------------+


================================================================================
RISK 3: INSIDER DATA THEFT (NEGLIGENT)
================================================================================

+------------------+--------------------------------------------------+
| Risk             | Negligent insider exfiltrates PHI                 |
+------------------+--------------------------------------------------+
| Source           | GAP-009 (Shadow IT), GAP-011 (No Enforcement),   |
|                  | GAP-013 (Low Training)                           |
|                  | Findings: 023 (USB not restricted), 028/029      |
|                  | (Shadow IT)                                       |
|                  | Threat Actor: Insider Negligent (#2)              |
|                  | Kill Chain: KC #2                                |
+------------------+--------------------------------------------------+

ASSET: Clinical workstations (~320 with EHR access)

ASSET VALUE (AV)
+------------------+--------------------------------------------------+
| Component        | Amount                                           |
+------------------+--------------------------------------------------+
| Investigation    | $30,000                                          |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Containment      | $25,000                                          |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Remediation      | $40,000                                          |
| Cost             |                                                  |
+------------------+--------------------------------------------------+
| Regulatory       | $25,000                                          |
| Reporting        |                                                  |
+------------------+--------------------------------------------------+
| TOTAL AV         | $120,000 (Ponemon Insider Threat Report average)  |
+------------------+--------------------------------------------------+

EXPOSURE FACTOR (EF): 100%
+----------------------------------------------------------------------------+
| Reasoning: If a negligent incident occurs, the full cost is incurred.     |
| There is no partial loss of AV.                                            |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $120,000 × 1.0 = $120,000                          |
+------------------+--------------------------------------------------+

ANNUALIZED RATE OF OCCURRENCE (ARO): 3.0 (3 incidents per year)
+----------------------------------------------------------------------------+
| Reasoning: 2,000 staff in healthcare environment. No DLP or USB           |
| restrictions (Finding 023). Shared accounts (GAP-007). Low training       |
| completion (58-71%). Negligent incidents = 60% of healthcare insider      |
| events. MedDefense is HIGHER RISK than average.                          |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $120,000 × 3.0 = $360,000                          |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| PROPOSED CONTROL: USB Restriction GPO + Security Training + DLP           |
| Control Annual Cost: $8,000 (USB GPO $500 + Training $2,500 + DLP $5,000)|
| Estimated ALE After Control: $120,000 (ARO drops from 3.0 to 1.0)        |
| Net Benefit: $360,000 - $120,000 - $8,000 = $232,000                    |
+----------------------------------------------------------------------------+


================================================================================
RISK 4: MEDICAL IOT COMPROMISE (PATIENT SAFETY)
================================================================================

+------------------+--------------------------------------------------+
| Risk             | Medical IoT compromise affecting patient safety   |
+------------------+--------------------------------------------------+
| Source           | GAP-003 (Flat Network), GAP-007 (No Compensating) |
|                  | Findings: 010 (BD Alaris default credentials),   |
|                  | 004 (MRI Windows XP)                             |
|                  | Threat Actor: Ransomware Groups (#1),            |
|                  | Opportunistic (#6)                                |
|                  | Kill Chain: KC #3 (IoT Patient Safety)           |
+------------------+--------------------------------------------------+

ASSET: BD Alaris Infusion Pumps + MRI Workstation

ASSET VALUE (AV)
+------------------+--------------------------------------------------+
| Component        | Amount                                           |
+------------------+--------------------------------------------------+
| Patient Safety   | $2,000,000 (mid-range liability estimate)        |
| Liability        |                                                  |
+------------------+--------------------------------------------------+
| FDA / Regu-      | $150,000                                         |
| latory Costs     |                                                  |
+------------------+--------------------------------------------------+
| Operational      | $100,000 (5 days manual dosing)                  |
| Disruption       |                                                  |
+------------------+--------------------------------------------------+
| TOTAL AV         | $2,250,000                                        |
+------------------+--------------------------------------------------+

EXPOSURE FACTOR (EF): 100%
+----------------------------------------------------------------------------+
| Reasoning: A patient safety incident triggers ALL costs. Catastrophic     |
| impact with no partial recovery.                                          |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $2,250,000 × 1.0 = $2,250,000                      |
+------------------+--------------------------------------------------+

ANNUALIZED RATE OF OCCURRENCE (ARO): 0.02 (once every 50 years)
+----------------------------------------------------------------------------+
| Reasoning: Low probability for patient safety event. However, the flat    |
| network and default credentials make opportunistic compromise plausible.  |
| Sector data on IoT patient safety incidents is limited. Estimate          |
| conservative: 1 in 50 years for actual patient harm.                     |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $2,250,000 × 0.02 = $45,000                        |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| PROPOSED CONTROL: IoT Segmentation + Default Credential Change +          |
| Network Monitoring                                                         |
| Control Annual Cost: $18,000 (Segmentation $12K + Credential Change      |
| $1,000 + Monitoring $5,000)                                               |
| Estimated ALE After Control: $4,500 (ARO drops from 0.02 to 0.002)       |
| Net Benefit: $45,000 - $4,500 - $18,000 = $22,500                       |
+----------------------------------------------------------------------------+


================================================================================
RISK 5: VPN COMPROMISE LEADING TO FULL NETWORK ACCESS
================================================================================

+------------------+--------------------------------------------------+
| Risk             | VPN compromise leading to full network access     |
+------------------+--------------------------------------------------+
| Source           | GAP-014 (No Patch Management), GAP-003 (Flat     |
|                  | Network), GAP-004 (No MFA)                       |
|                  | Findings: OSINT CVE-2024-21762 (FortiGate)       |
|                  | Threat Actor: Ransomware Groups (#1)             |
|                  | Kill Chain: KC #1 (Ransomware via VPN)           |
+------------------+--------------------------------------------------+

ASSET: Entire MedDefense internal network (via FortiGate VPN)

ASSET VALUE (AV)
+------------------+--------------------------------------------------+
| Component        | Amount                                           |
+------------------+--------------------------------------------------+
| Aggregate of     | $273,615 + $4,310,625 + $360,000 = $4,944,240    |
| Risks 1-3        |                                                  |
+------------------+--------------------------------------------------+
| TOTAL AV         | $4,944,240                                        |
+------------------+--------------------------------------------------+

EXPOSURE FACTOR (EF): 90%
+----------------------------------------------------------------------------+
| Reasoning: VPN compromise gives access to the ENTIRE flat network.        |
| Not 100% because some scenarios may not all occur simultaneously.        |
| However, VPN is the SINGLE POINT OF FAILURE.                            |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $4,944,240 × 0.90 = $4,449,816                     |
+------------------+--------------------------------------------------+

ANNUALIZED RATE OF OCCURRENCE (ARO): 0.3 (once every ~3.3 years)
+----------------------------------------------------------------------------+
| Reasoning: VPN is the #1 initial access vector (38% from 1x01).          |
| FortiOS CVEs disclosed regularly. CISA emergency directives for           |
| FortiGate. MedDefense has NO patch management for VPN.                   |
+----------------------------------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $4,449,816 × 0.3 = $1,334,945                      |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| PROPOSED CONTROL: VPN Patch Management + MFA on VPN + Network             |
| Segmentation                                                                |
| Control Annual Cost: $22,000 (Patch Mgt $2K + MFA $8K + Segmentation     |
| $12K)                                                                      |
| Estimated ALE After Control: $133,495 (ARO drops from 0.3 to 0.03)       |
| Net Benefit: $1,334,945 - $133,495 - $22,000 = $1,179,450               |
+----------------------------------------------------------------------------+


================================================================================
RISK PRIORITIZATION BY ALE
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Rank     | Risk             | ALE              | Control Cost     | Net Benefit      |
+----------+------------------+------------------+------------------+------------------+
| #1       | Data Breach      | $4,310,625       | $7,500           | $3,872,062       |
|          | (PHI Exposure)   |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #2       | VPN Compromise   | $1,334,945       | $22,000          | $1,179,450       |
|          | (Full Network)   |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #3       | Insider Data     | $360,000         | $8,000           | $232,000         |
|          | Theft            |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #4       | Ransomware       | $273,615         | $22,000          | $196,892         |
|          | (EHR)            |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #5       | Medical IoT      | $45,000          | $18,000          | $22,500          |
|          | (Patient Safety) |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The DATA BREACH risk has the HIGHEST ALE ($4.3M) and the HIGHEST net
   benefit ($3.87M). This should be the #1 priority.

2. The VPN COMPROMISE risk is #2 ($1.33M ALE). Addressing this requires
   patch management, MFA, and segmentation - which also address other risks.

3. The INSIDER DATA THEFT risk has the HIGHEST ARO (3.0 incidents/year)
   and is the most frequent risk. It requires DLP, USB restrictions, and
   training.

4. The RANSOMWARE risk has significant ALE ($273K) and high net benefit
   ($196K). It shares controls with VPN compromise (MFA, segmentation,
   patch management).

5. The MEDICAL IOT risk has the LOWEST ALE ($45K) due to the extremely low
   ARO (0.02). However, the CATASTROPHIC impact (patient safety) justifies
   the control investment.

6. Total ALE across all 5 risks: $6.3M
7. Total control cost across all 5 risks: $77,500
8. Total net benefit: $5.5M


================================================================================
REFERENCES
================================================================================

- CISA Advisory AA24-131A (1x01 File 1)
- Ponemon 2024 Cost of a Data Breach Report
- Ponemon Insider Threat Report
- Verizon DBIR Healthcare Supplement
- HHS Breach Portal Statistics (1x01 File 3)
- Asset Registry (1x00 Task 7)
- Gap Analysis (1x00 Task 12)
- Vulnerability Scan (1x02)

Cross-References:
- Risk Equation (1x03 T5)
- NIST CSF Mapping (1x03 T1)
- CIS Controls Audit (1x03 T2)


================================================================================
END OF ALE WORKSHOP REPORT
================================================================================

