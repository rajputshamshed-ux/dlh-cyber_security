================================================================================
                    RISK EQUATION - MEDDEFENSE HEALTH SYSTEMS
                    Task 5: The Risk Equation
================================================================================

Exercise: Task 5 - The Risk Equation
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Master quantitative risk analysis by calculating SLE, ARO and ALE
          for concrete MedDefense scenarios.

Sources: risk-scenarios.txt, 1x00 Asset Registry, 1x01 Threat Landscape,
         1x02 Vulnerability Scan, CISA Advisory, Ponemon Reports


================================================================================
SCENARIO 1: RANSOMWARE ATTACK ON BILLING SERVER
================================================================================

ASSET: billing-srv-01 (Ubuntu 18.04, Apache 2.4.29, MySQL)
THREAT: BlackReef-style ransomware group

CALCULATIONS
------------
+------------------+--------------------------------------------------+
| Asset Value (AV) |                                                    |
+------------------+--------------------------------------------------+
| Revenue Loss     | 18 days downtime × $16,000/day = $288,000        |
| Recovery Cost    | $85,000 (forensics, rebuild, vendor support)      |
| HIPAA Penalty    | $100,000 (mid-range estimate)                     |
| TOTAL AV         | $473,000                                          |
+------------------+--------------------------------------------------+
| Reasoning        | The asset value is NOT the server's replacement   |
|                  | cost (~$10,000). It is the TOTAL FINANCIAL IMPACT |
|                  | of a ransomware incident: downtime + recovery +   |
|                  | penalties. The server itself can be rebuilt;      |
|                  | the business impact is what matters.              |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Exposure Factor  | 75%                                               |
| (EF)             |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Not 100% because:                                  |
|                  | - Some revenue may be recovered retroactively     |
|                  | - Not all fines are always applied                |
|                  | - Insurance may cover some costs                  |
|                  | However, 75% represents the severe operational    |
|                  | and financial impact of a ransomware event.       |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $473,000 × 0.75 = $354,750                         |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Annualized Rate  | 0.3 (once every ~3.3 years)                        |
| of Occurrence    |                                                    |
| (ARO)            |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Based on:                                           |
|                  | - Healthcare ransomware rate: 1 attack every      |
|                  |   3-4 years for similar-profile hospitals         |
|                  | - MedDefense is HIGHER RISK than average due to:  |
|                  |   - No MFA (GAP-004)                             |
|                  |   - No patch management (GAP-014)                |
|                  |   - Flat network (GAP-003)                       |
|                  |   - Previously compromised (crypto-miner)        |
|                  | ARO = 0.3 (once every 3.3 years)                  |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $354,750 × 0.3 = $106,425                          |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| CONFIDENCE LEVEL: MEDIUM                                                    |
|                                                                             |
| The ALE is most sensitive to the ARO assumption. If ransomware attacks     |
| occur every 2 years (ARO = 0.5), ALE = $177,375. If every 5 years         |
| (ARO = 0.2), ALE = $70,950. The ARO is the most uncertain variable in     |
| this calculation.                                                          |
+----------------------------------------------------------------------------+


================================================================================
SCENARIO 2: PATIENT DATA BREACH VIA EHR SYSTEM
================================================================================

ASSET: EHR System (ehr-srv-01 + ehr-db-01, 50,000 patient records)
THREAT: Data exfiltration (external attacker or malicious insider)

CALCULATIONS
------------
+------------------+--------------------------------------------------+
| Asset Value (AV) |                                                    |
+------------------+--------------------------------------------------+
| Breach Cost      | 50,000 records × $165 = $8,250,000                |
| Notification     | $25,000 (fixed)                                   |
| Litigation       | $200,000                                          |
| Reputational     | $600,000 (5% patient attrition over 2 years)      |
| TOTAL AV         | $9,075,000                                        |
+------------------+--------------------------------------------------+
| Reasoning        | The AV is the TOTAL COST OF THE BREACH. Ponemon   |
|                  | reports $165 per breached healthcare record.      |
|                  | MedDefense has 50,000 records in the EHR.         |
|                  | This includes detection, notification, legal,     |
|                  | and lost business costs.                          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Exposure Factor  | 95%                                               |
| (EF)             |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | A breach triggers ALL associated costs. The EF   |
|                  | is nearly 100% because once a breach occurs,      |
|                  | MedDefense cannot avoid:                          |
|                  | - Breach notification (mandatory)                 |
|                  | - Legal exposure                                  |
|                  | - Reputational damage (patient attrition)         |
|                  | - Regulatory investigation                        |
|                  | 5% retained for insurance coverage/partial        |
|                  | mitigation.                                       |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $9,075,000 × 0.95 = $8,621,250                     |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Annualized Rate  | 0.5 (once every 2 years)                           |
| of Occurrence    |                                                    |
| (ARO)            |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Based on:                                           |
|                  | - HHS breach portal: 1,247 breaches in 24 months  |
|                  |   across ~6,000 hospitals                          |
|                  | - MedDefense is HIGHER RISK than average:         |
|                  |   - No SIEM (GAP-001)                             |
|                  |   - Flat network (GAP-003)                        |
|                  |   - No MFA (GAP-004)                              |
|                  |   - PostgreSQL unrestricted (Finding 003)         |
|                  |   - Ghostcat on ehr-srv-01 (Finding 031)         |
|                  | Average hospital: ~0.1 (1 in 10 years)           |
|                  | MedDefense: ~0.5 (1 in 2 years)                  |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $8,621,250 × 0.5 = $4,310,625                      |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| CONFIDENCE LEVEL: MEDIUM                                                    |
|                                                                             |
| The ALE is most sensitive to the per-record breach cost ($165) and the     |
| ARO. If the breach cost is $250 (from other estimates), the ALE doubles.   |
| If the ARO is 0.3 (once every 3.3 years), the ALE drops to $2.6M.         |
| The per-record cost is the most critical assumption.                      |
+----------------------------------------------------------------------------+


================================================================================
SCENARIO 3: INSIDER DATA THEFT (NEGLIGENT)
================================================================================

ASSET: Patient data accessible via clinical workstations
THREAT: Negligent insider

CALCULATIONS
------------
+------------------+--------------------------------------------------+
| Asset Value (AV) | $120,000 (average negligent insider incident)     |
+------------------+--------------------------------------------------+
| Reasoning        | Ponemon Insider Threat Report average cost for    |
|                  | healthcare: $120,000 per incident.                |
|                  | This includes investigation ($30,000),            |
|                  | containment ($25,000), remediation ($40,000),     |
|                  | and regulatory reporting ($25,000).               |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Exposure Factor  | 100%                                              |
| (EF)             |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | If a negligent incident occurs, the full cost is  |
|                  | incurred. There is no partial loss of AV.        |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $120,000 × 1.0 = $120,000                          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Annualized Rate  | 3.0 (3 incidents per year)                         |
| of Occurrence    |                                                    |
| (ARO)            |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Based on:                                           |
|                  | - 2,000 staff in a healthcare environment         |
|                  | - No DLP or USB restrictions (Finding 023)        |
|                  | - Shared accounts (GAP-007)                       |
|                  | - Low training completion (58-71%)                |
|                  | - Negligent incidents = 60% of healthcare        |
|                  |   insider events                                   |
|                  | - Sector average: 1-2 per year for similar size  |
|                  | - MedDefense is HIGHER RISK: 3 per year          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $120,000 × 3.0 = $360,000                          |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| CONFIDENCE LEVEL: MEDIUM                                                    |
|                                                                             |
| The ALE is most sensitive to the ARO assumption. If incidents occur        |
| 2 per year instead of 3, ALE = $240,000. If 5 per year, ALE = $600,000.  |
| The per-incident cost ($120,000) is well-researched but the ARO is        |
| based on MedDefense-specific factors (no DLP, no USB restriction).        |
+----------------------------------------------------------------------------+


================================================================================
SCENARIO 4: MEDICAL DEVICE COMPROMISE
================================================================================

ASSET: BD Alaris infusion pumps (7 units) + network
THREAT: Opportunistic attacker exploiting default credentials

CALCULATIONS - DOS SCENARIO
---------------------------
+------------------+--------------------------------------------------+
| Asset Value (AV) |                                                    |
| (DoS Scenario)   |                                                    |
+------------------+--------------------------------------------------+
| Device          | $15,000 × 7 = $105,000                            |
| Replacement     |                                                    |
| Operational     | $20,000/day × 5 days = $100,000                   |
| Disruption      |                                                    |
| TOTAL AV        | $205,000                                          |
+------------------+--------------------------------------------------+
| Reasoning        | The primary risk is operational disruption, not   |
|                  | device destruction. Switching to manual dosing   |
|                  | for 5 days while devices are quarantined.        |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| EF               | 100%                                              |
+------------------+--------------------------------------------------+
| SLE              | $205,000                                          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ARO              | 0.1 (once every 10 years)                          |
+------------------+--------------------------------------------------+
| ALE              | $205,000 × 0.1 = $20,500                           |
+------------------+--------------------------------------------------+

CALCULATIONS - PATIENT SAFETY SCENARIO
--------------------------------------
+------------------+--------------------------------------------------+
| Asset Value (AV) |                                                    |
| (Patient Safety) |                                                    |
+------------------+--------------------------------------------------+
| Liability       | $500,000 - $5,000,000 (mid-range $2,000,000)      |
| FDA Investi-    | $150,000                                          |
| gation          |                                                    |
| TOTAL AV        | $2,150,000                                        |
+------------------+--------------------------------------------------+
| Reasoning        | Patient safety incident liability is              |
|                  | catastrophic. Mid-range estimate $2M.             |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| EF               | 100%                                              |
+------------------+--------------------------------------------------+
| SLE              | $2,150,000                                        |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ARO              | 0.02 (once every 50 years)                         |
+------------------+--------------------------------------------------+
| ALE              | $2,150,000 × 0.02 = $43,000                        |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| COMBINED ALE (DoS + Patient Safety): $20,500 + $43,000 = $63,500          |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| CONFIDENCE LEVEL: LOW                                                       |
|                                                                             |
| The patient safety ARO (1 in 50 years) is highly uncertain. There is no   |
| good data on how often medical devices are compromised with patient       |
| safety impact. The ALE is most sensitive to the liability estimate         |
| ($500K-$5M) and the ARO. A single patient safety event would be          |
| catastrophic regardless of the probability.                              |
+----------------------------------------------------------------------------+


================================================================================
SCENARIO 5: VPN COMPROMISE LEADING TO FULL NETWORK ACCESS
================================================================================

ASSET: Entire MedDefense internal network (via FortiGate VPN)
THREAT: External attacker exploiting VPN vulnerability

CALCULATIONS
------------
+------------------+--------------------------------------------------+
| Asset Value (AV) |                                                    |
+------------------+--------------------------------------------------+
| Scenario 1 ALE   | $106,425                                          |
| Scenario 2 ALE   | $4,310,625                                        |
| Scenario 3 ALE   | $360,000                                          |
| TOTAL            | $4,777,050                                        |
+------------------+--------------------------------------------------+
| Reasoning        | The AV is the AGGREGATE of Scenarios 1, 2, and 3. |
|                  | The VPN is the gateway to ALL systems. If the    |
|                  | VPN is compromised, the attacker can execute      |
|                  | ransomware (S1), data exfiltration (S2), and     |
|                  | insider-like damage (S3).                        |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Exposure Factor  | 90%                                               |
| (EF)             |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Not 100% because:                                  |
|                  | - Some scenarios may not all occur simultaneously |
|                  | - Detection may stop the attack before completion |
|                  | - Some systems may be protected                  |
|                  | However, the VPN is the SINGLE POINT OF ENTRY.   |
|                  | A compromise gives access to the FLAT network.   |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| SLE = AV × EF    | $4,777,050 × 0.90 = $4,299,345                     |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| Annualized Rate  | 0.3 (once every ~3.3 years)                        |
| of Occurrence    |                                                    |
| (ARO)            |                                                    |
+------------------+--------------------------------------------------+
| Reasoning        | Based on:                                           |
|                  | - VPN is the #1 initial access vector (38%)       |
|                  |   (from 1x01 intelligence dossier)                |
|                  | - FortiOS CVEs disclosed regularly                |
|                  | - CISA emergency directives for FortiGate        |
|                  | - MedDefense has NO patch management for VPN     |
|                  | - OSINT found multiple FortiGate CVEs            |
|                  | (CVE-2024-21762 is weaponized)                   |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| ALE = SLE × ARO  | $4,299,345 × 0.3 = $1,289,804                      |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| CONFIDENCE LEVEL: LOW                                                       |
|                                                                             |
| This is the most uncertain calculation. The AV aggregates three scenarios  |
| that may not all occur. The ARO depends on unknown patching status of the  |
| FortiGate. The EF is subjective. However, this calculation demonstrates    |
| the HIGHEST RISK of all scenarios.                                        |
|                                                                             |
| The VPN is the SINGLE POINT OF FAILURE. A compromise bypasses ALL         |
| perimeter controls and provides access to the ENTIRE flat network.        |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+------------------+
| Scenario | Asset            | SLE              | ARO              | ALE              | Confidence       |
+----------+------------------+------------------+------------------+------------------+------------------+
| 1        | billing-srv-01   | $354,750         | 0.3              | $106,425         | MEDIUM           |
|          | (Ransomware)     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| 2        | EHR System       | $8,621,250       | 0.5              | $4,310,625       | MEDIUM           |
|          | (Data Breach)    |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| 3        | Clinical        | $120,000         | 3.0              | $360,000         | MEDIUM           |
|          | Workstations     |                  |                  |                  |                  |
|          | (Insider)        |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| 4        | BD Alaris Pumps  | DoS: $205,000    | 0.1              | $20,500          | LOW              |
|          | (IoT)            | Patient:         | 0.02             | $43,000          |                  |
|          |                  | $2,150,000       |                  | $63,500 (Total)  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| 5        | VPN + Network    | $4,299,345       | 0.3              | $1,289,804       | LOW              |
|          | (Full Network)   |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- CISA Advisory AA24-131A (1x01 File 1)
- Ponemon 2024 Cost of a Data Breach Report
- Ponemon Insider Threat Report
- HC3 Threat Actor Categories (1x01 File 2)
- Verizon DBIR Healthcare Supplement
- HHS Breach Portal Statistics (1x01 File 3)
- BlackReef Ransomware Profile (1x01 File 7)

Cross-References:
- Asset Registry (1x00 Task 7)
- Gap Analysis (1x00 Task 12)
- Threat Actor Matrix (1x01 Task 6)
- Kill Chains (1x01 Task 10)
- Vulnerability Scan (1x02)


================================================================================
END OF RISK EQUATION REPORT
================================================================================

