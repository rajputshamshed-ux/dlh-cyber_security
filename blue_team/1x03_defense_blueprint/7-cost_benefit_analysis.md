================================================================================
                    COST-BENEFIT ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 7: The Cost-Benefit Analysis
================================================================================

Exercise: Task 7 - The Cost-Benefit Analysis
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Evaluate 8 proposed security controls using formal cost-benefit
          analysis to determine which investments are financially justified.

Sources: 1x03 ALE Workshop (T6), 1x00 Gap Analysis, 1x02 Vulnerability Scan
Formula: Net Value = ALE Reduction - Annual Cost


================================================================================
CONTROL 1: NETWORK SEGMENTATION
================================================================================

+------------------+--------------------------------------------------+
| Control          | Network Segmentation                             |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
| Reference        | Management (IG1)                                 |
+------------------+--------------------------------------------------+
| Annual Cost      | $12,000 (firewall reconfiguration + VLAN setup + |
|                  | testing)                                         |
+------------------+--------------------------------------------------+
| Risk(s)          | Ransomware (T6), VPN Compromise (T6), Data       |
| Addressed        | Breach (T6), IoT Safety (T6)                    |
+------------------+--------------------------------------------------+
| ALE Reduction    | $4,310,625 (from Data Breach) + $273,615         |
| (Estimate)       | (from Ransomware) + $45,000 (from IoT)           |
|                  | = $4,629,240 × 40% = $1,851,696                  |
+------------------+--------------------------------------------------+
| Reasoning        | Segmentation reduces lateral movement. It would  |
|                  | prevent the flat network from enabling attacks. |
|                  | Estimate 40% reduction across all risks.        |
+------------------+--------------------------------------------------+
| NET VALUE        | $1,851,696 - $12,000 = $1,839,696                |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - Highest net value. This is the       |
|                  | single most effective control MedDefense can     |
|                  | implement.                                       |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 2: MFA DEPLOYMENT
================================================================================

+------------------+--------------------------------------------------+
| Control          | MFA on VPN and Administrative Accounts           |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 5 - Access Control Management (IG1)  |
| Reference        |                                                  |
+------------------+--------------------------------------------------+
| Annual Cost      | $8,000 (Azure AD Premium P1 licenses +           |
|                  | configuration + training)                        |
+------------------+--------------------------------------------------+
| Risk(s)          | All risks (credential theft is #1 entry vector)  |
| Addressed        |                                                  |
+------------------+--------------------------------------------------+
| ALE Reduction    | $4,310,625 (Data Breach) + $1,334,945 (VPN) +   |
| (Estimate)       | $273,615 (Ransomware) = $5,919,185 × 30%         |
|                  | = $1,775,756                                     |
+------------------+--------------------------------------------------+
| Reasoning        | MFA stops credential theft attacks. Credential   |
|                  | theft is the #1 entry vector across all threats. |
|                  | Estimate 30% reduction across all risks.        |
+------------------+--------------------------------------------------+
| NET VALUE        | $1,775,756 - $8,000 = $1,767,756                 |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - #2 priority. Credential theft is the |
|                  | most common entry vector.                       |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 3: ENTERPRISE SIEM DEPLOYMENT (WAZUH)
================================================================================

+------------------+--------------------------------------------------+
| Control          | Enterprise SIEM (Wazuh open-source)              |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 7 - Audit Log Management (IG1)       |
| Reference        |                                                  |
+------------------+--------------------------------------------------+
| Annual Cost      | $5,000 (labor + server + configuration)          |
+------------------+--------------------------------------------------+
| Risk(s)          | All risks (detection is the #1 missing          |
| Addressed        | capability)                                      |
+------------------+--------------------------------------------------+
| ALE Reduction    | $4,310,625 (Data Breach) + $1,334,945 (VPN) +   |
| (Estimate)       | $273,615 (Ransomware) = $5,919,185 × 25%         |
|                  | = $1,479,796                                     |
+------------------+--------------------------------------------------+
| Reasoning        | SIEM provides detection capability where NONE    |
|                  | currently exists. Attacks go undetected for      |
|                  | weeks. Early detection reduces impact. Estimate |
|                  | 25% reduction across all risks.                 |
+------------------+--------------------------------------------------+
| NET VALUE        | $1,479,796 - $5,000 = $1,474,796                 |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - #3 priority. Detection is essential. |
|                  | Open-source keeps cost low.                      |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 4: OFFSITE BACKUP REPLICATION
================================================================================

+------------------+--------------------------------------------------+
| Control          | Offsite Backup Replication (AWS S3 Glacier)      |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 10 - Data Recovery (IG1)             |
| Reference        |                                                  |
+------------------+--------------------------------------------------+
| Annual Cost      | $14,400 (from 1x00 Artifact 5 - quote for AWS    |
|                  | S3 replication)                                  |
+------------------+--------------------------------------------------+
| Risk(s)          | Ransomware, Data Breach, VPN Compromise (all     |
| Addressed        | involve backup encryption/deletion)              |
+------------------+--------------------------------------------------+
| ALE Reduction    | $273,615 (Ransomware) + $1,334,945 (VPN) =       |
| (Estimate)       | $1,608,560 × 40% = $643,424                      |
+------------------+--------------------------------------------------+
| Reasoning        | Offsite backups prevent ransomware from          |
|                  | encrypting ALL copies. Co-located backups are    |
|                  | a critical weakness (C-009). Estimate 40%       |
|                  | reduction for ransomware-related risks.          |
+------------------+--------------------------------------------------+
| NET VALUE        | $643,424 - $14,400 = $629,024                    |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - Essential for recovery. This was     |
|                  | previously denied but is now justified.          |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 5: ENDPOINT DETECTION AND RESPONSE (EDR) UPGRADE
================================================================================

+------------------+--------------------------------------------------+
| Control          | EDR Upgrade (Sophos Intercept X for all          |
|                  | endpoints including servers)                     |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 9 - Malware Defenses (IG1)           |
| Reference        |                                                  |
+------------------+--------------------------------------------------+
| Annual Cost      | $30,000 (existing Sophos license upgrade: $18K   |
|                  | → $48K, includes server protection previously    |
|                  | not covered)                                     |
+------------------+--------------------------------------------------+
| Risk(s)          | All risks (malware is a primary vector)          |
| Addressed        |                                                  |
+------------------+--------------------------------------------------+
| ALE Reduction    | $4,310,625 (Data Breach) + $273,615 (Ransomware) |
| (Estimate)       | + $360,000 (Insider) = $4,944,240 × 15%          |
|                  | = $741,636                                       |
+------------------+--------------------------------------------------+
| Reasoning        | EDR provides visibility into endpoint threats.   |
|                  | The current Sophos only covers workstations.     |
|                  | Estimate 15% reduction across major risks.      |
+------------------+--------------------------------------------------+
| NET VALUE        | $741,636 - $30,000 = $711,636                    |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - Provides server protection which     |
|                  | is currently missing. High value per dollar.     |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 6: DEDICATED FIREWALL FOR WESTSIDE CLINIC
================================================================================

+------------------+--------------------------------------------------+
| Control          | Dedicated Firewall for Westside Clinic           |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
| Reference        | Management (IG1)                                 |
+------------------+--------------------------------------------------+
| Annual Cost      | $5,000 (FortiGate 40F + installation + annual    |
|                  | support)                                         |
+------------------+--------------------------------------------------+
| Risk(s)          | Westside Clinic compromise (consumer router      |
| Addressed        | is a known vulnerability, Finding 014)          |
+------------------+--------------------------------------------------+
| ALE Reduction    | $45,000 (IoT Safety) + $273,615 (Ransomware) =   |
| (Estimate)       | $318,615 × 20% = $63,723                         |
+------------------+--------------------------------------------------+
| Reasoning        | Westside has a consumer-grade router (Netgear    |
|                  | Nighthawk). An enterprise firewall would         |
|                  | prevent the clinic from being used as a pivot    |
|                  | point. Estimate 20% reduction for Westside-      |
|                  | related risks.                                   |
+------------------+--------------------------------------------------+
| NET VALUE        | $63,723 - $5,000 = $58,723                       |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - Quick win. Low cost, immediate       |
|                  | impact for Westside.                             |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 7: 24/7 MANAGED SOC
================================================================================

+------------------+--------------------------------------------------+
| Control          | 24/7 Managed Security Operations Center (SOC)    |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 16 - Incident Response Management   |
| Reference        | (IG2) + CIS Control 7 - Audit Log Management     |
+------------------+--------------------------------------------------+
| Annual Cost      | $60,000 - $80,000 (outsourced managed SOC,        |
|                  | 24/7 monitoring)                                 |
+------------------+--------------------------------------------------+
| Risk(s)          | All risks (detection and response)               |
| Addressed        |                                                  |
+------------------+--------------------------------------------------+
| ALE Reduction    | $4,310,625 (Data Breach) + $1,334,945 (VPN) +   |
| (Estimate)       | $273,615 (Ransomware) = $5,919,185 × 20%         |
|                  | = $1,183,837                                     |
+------------------+--------------------------------------------------+
| Reasoning        | 24/7 SOC provides continuous monitoring and      |
|                  | response. However, MedDefense has NO current     |
|                  | detection. A full 24/7 SOC is expensive.       |
|                  | Estimate 20% reduction with 24/7 monitoring.    |
+------------------+--------------------------------------------------+
| NET VALUE        | $1,183,837 - $80,000 = $1,103,837                |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | DEFER - Justified but too expensive for the      |
|                  | current budget. Consider a daytime-only SOC      |
|                  | ($30K-$40K) or co-managed model.                |
+------------------+--------------------------------------------------+


================================================================================
CONTROL 8: FULL MEDICAL DEVICE NETWORK ISOLATION
================================================================================

+------------------+--------------------------------------------------+
| Control          | Full Medical Device Network Isolation with       |
|                  | Dedicated Monitoring                             |
+------------------+--------------------------------------------------+
| CIS Control      | CIS Control 11 - Network Infrastructure          |
| Reference        | Management (IG1) + CIS Control 12 - Network      |
|                  | Monitoring and Defense (IG1)                     |
+------------------+--------------------------------------------------+
| Annual Cost      | $18,000 (VLAN setup, firewall rules, monitoring) |
+------------------+--------------------------------------------------+
| Risk(s)          | IoT Safety, Patient Safety, Ransomware           |
| Addressed        |                                                  |
+------------------+--------------------------------------------------+
| ALE Reduction    | $45,000 (IoT Safety) + $273,615 (Ransomware) =   |
| (Estimate)       | $318,615 × 30% = $95,585                         |
+------------------+--------------------------------------------------+
| Reasoning        | IoT devices are on the flat network. Isolation    |
|                  | would prevent lateral movement to life-safety    |
|                  | devices. Estimate 30% reduction for IoT-related |
|                  | risks.                                          |
+------------------+--------------------------------------------------+
| NET VALUE        | $95,585 - $18,000 = $77,585                       |
+------------------+--------------------------------------------------+
| Verdict          | JUSTIFIED                                        |
+------------------+--------------------------------------------------+
| Recommendation   | IMPLEMENT - Important for patient safety.        |
|                  | Not the highest net value but essential for      |
|                  | protecting life-safety devices.                  |
+------------------+--------------------------------------------------+


================================================================================
COST-BENEFIT SUMMARY TABLE (RANKED BY NET VALUE)
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Rank     | Control          | Annual Cost      | Net Value        | Verdict          |
+----------+------------------+------------------+------------------+------------------+
| #1       | Network          | $12,000          | $1,839,696       | IMPLEMENT        |
|          | Segmentation     |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #2       | MFA Deployment   | $8,000           | $1,767,756       | IMPLEMENT        |
+----------+------------------+------------------+------------------+------------------+
| #3       | SIEM (Wazuh)     | $5,000           | $1,474,796       | IMPLEMENT        |
+----------+------------------+------------------+------------------+------------------+
| #4       | 24/7 SOC         | $80,000          | $1,103,837       | DEFER            |
+----------+------------------+------------------+------------------+------------------+
| #5       | EDR Upgrade      | $30,000          | $711,636         | IMPLEMENT        |
+----------+------------------+------------------+------------------+------------------+
| #6       | Offsite Backup   | $14,400          | $629,024         | IMPLEMENT        |
+----------+------------------+------------------+------------------+------------------+
| #7       | Medical IoT      | $18,000          | $77,585          | IMPLEMENT        |
|          | Isolation        |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| #8       | Westside         | $5,000           | $58,723          | IMPLEMENT        |
|          | Firewall         |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+


================================================================================
BUDGET ALLOCATION
================================================================================

+----------------------------------------------------------------------------+
| BUDGET ALLOCATION ($120,000 ANNUAL)                                        |
|                                                                             |
| CONTROLS TO IMPLEMENT (TOP 7 - excluding 24/7 SOC):                       |
|                                                                             |
| 1. Network Segmentation:                      $12,000                      |
| 2. MFA Deployment:                           $8,000                       |
| 3. SIEM (Wazuh):                             $5,000                       |
| 4. EDR Upgrade:                              $30,000                      |
| 5. Offsite Backup:                           $14,400                      |
| 6. Medical IoT Isolation:                    $18,000                      |
| 7. Westside Firewall:                        $5,000                       |
|                                                                             |
| TOTAL:                                       $92,400                      |
|                                                                             |
| REMAINING BUDGET:                            $27,600                      |
|                                                                             |
| DEFERRED (BUDGET CONSTRAINT):                                              |
| 24/7 Managed SOC:                            $80,000 (not in budget)      |
|                                                                             |
| ALTERNATIVE: A daytime-only SOC ($30K-$40K) could be considered with       |
| remaining budget + additional $3K-$13K.                                    |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- ALE Workshop (1x03 T6)
- CIS Controls v8
- Gap Analysis (1x00 Task 12)
- Vulnerability Scan (1x02)


================================================================================
END OF COST-BENEFIT ANALYSIS REPORT
================================================================================
