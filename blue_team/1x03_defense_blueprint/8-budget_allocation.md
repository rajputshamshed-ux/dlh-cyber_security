================================================================================
                    BUDGET ALLOCATION - MEDDEFENSE HEALTH SYSTEMS
                    Task 8: The Budget Game
================================================================================

Exercise: Task 8 - The Budget Game
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Make binding resource allocation decisions under realistic budget
          constraints, demonstrating that every dollar has a reason behind it.

Sources: 1x03 Cost-Benefit Analysis (T7), 1x03 ALE Workshop (T6)
Budget: $120,000


================================================================================
PART 1: THE SELECTION
================================================================================

CONTROLS FUNDED
---------------
+----------+------------------+------------------+------------------+
| Priority | Control          | Annual Cost      | Net Value        |
+----------+------------------+------------------+------------------+
| #1       | Network          | $12,000          | $1,839,696       |
|          | Segmentation     |                  |                  |
+----------+------------------+------------------+------------------+
| #2       | MFA Deployment   | $8,000           | $1,767,756       |
+----------+------------------+------------------+------------------+
| #3       | SIEM (Wazuh)     | $5,000           | $1,474,796       |
+----------+------------------+------------------+------------------+
| #4       | EDR Upgrade      | $30,000          | $711,636         |
+----------+------------------+------------------+------------------+
| #5       | Offsite Backup   | $14,400          | $629,024         |
+----------+------------------+------------------+------------------+
| #6       | Medical IoT      | $18,000          | $77,585          |
|          | Isolation        |                  |                  |
+----------+------------------+------------------+------------------+
| #7       | Westside         | $5,000           | $58,723          |
|          | Firewall         |                  |                  |
+----------+------------------+------------------+------------------+
|          | TOTAL SPEND      | $92,400          | $6,559,216       |
+----------+------------------+------------------+------------------+

TOTAL SPEND: $92,400
BUDGET REMAINING: $120,000 - $92,400 = $27,600

RATIONALE FOR FUNDED CONTROLS:
The top 7 controls are funded because they have the highest net value and
address the most critical risks (Data Breach, VPN Compromise, Ransomware,
IoT Safety). These controls represent the best return on investment.

CONTROLS DEFERRED
-----------------
+----------+------------------+------------------+------------------+
| Priority | Control          | Annual Cost      | Net Value        |
+----------+------------------+------------------+------------------+
| #8       | 24/7 Managed SOC | $80,000          | $1,103,837       |
+----------+------------------+------------------+------------------+

REASONING FOR DEFERRAL: The 24/7 SOC is financially justified (net value
$1.1M), but it costs $80,000 - more than the remaining budget ($27,600).
A daytime-only SOC ($30K-$40K) could be considered as an alternative in
the next fiscal year. The 24/7 SOC cannot be funded within the current
$120,000 budget while also funding the top 7 controls.

CONTROLS REJECTED
-----------------
None. All 8 controls are justified (net value > 0). The only reason a
control is not implemented is budget constraint, not lack of justification.

REJECTED DECISION: No controls are rejected entirely. All have positive net
value. The choice is between funding 7 controls now and deferring 1 control,
or funding fewer controls to include the more expensive SOC.

BUDGET REMAINING: $27,600 (unallocated for contingency or future use)


================================================================================
PART 2: THE OPPORTUNITY COST
================================================================================

OPPORTUNITY COST ANALYSIS
-------------------------
+----------------------------------------------------------------------------+
| DEFERRED CONTROL: 24/7 Managed SOC                                         |
| Cost: $80,000                                                             |
| Net Value: $1,103,837                                                     |
| ALE Reduction Foregone: $1,183,837                                        |
+----------------------------------------------------------------------------+

By deferring 24/7 Managed SOC, MedDefense accepts an estimated $1,183,837
in annual risk exposure that would have been reduced through continuous
24/7 monitoring and response capabilities.

This is a SIGNIFICANT opportunity cost. The SOC would have provided:
- Continuous monitoring of the SIEM (which MedDefense is deploying)
- Alert triage and initial response
- 24/7 coverage (currently no security monitoring exists)

However, the $80,000 cost would consume 67% of the entire budget,
preventing the implementation of multiple foundational controls.

ALTERNATIVE OPPORTUNITY COST: DAYTIME-ONLY SOC ($35,000)
+----------------------------------------------------------------------------+
| If MedDefense instead funded a daytime-only SOC ($35,000) and deferred   |
| the Westside Firewall ($5,000) and IoT Isolation ($18,000):              |
|                                                                             |
| Controls deferred: Westside Firewall + IoT Isolation                      |
| Opportunity Cost: $58,723 + $77,585 = $136,308                           |
| SOC Reduction: $1,183,837 × 60% (daytime only) = $710,302               |
| Net Benefit of Daytime SOC: $710,302 - $35,000 = $675,302               |
|                                                                             |
| This is less than the full 24/7 SOC but more than the two controls       |
| that would be deferred. This is discussed further in Part 3.            |
+----------------------------------------------------------------------------+


================================================================================
PART 3: THE ALTERNATIVE
================================================================================

PRIMARY RECOMMENDATION (7 controls)
-----------------------------------
+----------------------------------------------------------------------------+
| Controls: Segmentation, MFA, SIEM, EDR, Offsite Backup, IoT Isolation,   |
|           Westside Firewall                                                |
| Total Cost: $92,400                                                       |
| Total ALE Reduction: $6,559,216                                          |
| Budget Remaining: $27,600                                                |
+----------------------------------------------------------------------------+

ALTERNATIVE ALLOCATION (Daytime-Only SOC)
-----------------------------------------
+----------------------------------------------------------------------------+
| Replace IoT Isolation + Westside Firewall with Daytime-Only SOC ($35K):  |
|                                                                             |
| Controls:                                                                  |
| 1. Network Segmentation:                    $12,000                      |
| 2. MFA Deployment:                          $8,000                       |
| 3. SIEM (Wazuh):                            $5,000                       |
| 4. EDR Upgrade:                             $30,000                      |
| 5. Offsite Backup:                          $14,400                      |
| 6. Daytime-Only SOC (8am-6pm):              $35,000                      |
|                                                                             |
| TOTAL COST:                                 $104,400                     |
|                                                                             |
| ALE REDUCTION COMPARISON:                                                 |
|                                                                             |
| Removed: IoT Isolation ($77,585) + Westside Firewall ($58,723)          |
| Total Removed ALE Reduction: $136,308                                    |
|                                                                             |
| Added: Daytime-Only SOC ($710,302)                                        |
|                                                                             |
| ALTERNATIVE ALE REDUCTION = Primary ALE Reduction - Removed + Added      |
| = $6,559,216 - $136,308 + $710,302 = $7,133,210                        |
|                                                                             |
| ALTERNATIVE TOTAL ALE REDUCTION: $7,133,210                               |
|                                                                             |
| PRIMARY ALE REDUCTION: $6,559,216                                         |
|                                                                             |
| DIFFERENCE: $574,004 BETTER                                                |
+----------------------------------------------------------------------------+

COMPARISON
----------
+----------------------------------------------------------------------------+
| PRIMARY:                                    ALTERNATIVE:                  |
| - 7 controls                                - 6 controls                  |
| - $92,400 cost                              - $104,400 cost               |
| - $6.56M reduction                          - $7.13M reduction            |
| - $27,600 remaining                         - $15,600 remaining           |
|                                                                             |
| VERDICT: The Alternative Allocation (with Daytime-Only SOC) provides      |
| $574,004 MORE risk reduction for only $12,000 additional cost.           |
|                                                                             |
| RECOMMENDATION:                                                             |
| MedDefense should adopt the Alternative Allocation:                        |
|                                                                             |
| 1. Fund the Daytime-Only SOC ($35,000)                                   |
| 2. Defer IoT Isolation and Westside Firewall to the next fiscal year    |
| 3. Defer the Full 24/7 SOC to the next fiscal year                      |
|                                                                             |
| RATIONALE:                                                                 |
| A Daytime-Only SOC provides continuous monitoring during business hours   |
| when most attacks are detected (80% of incidents are detected during     |
| business hours). It also provides:                                        |
| - Alert triage for the SIEM                                               |
| - Initial incident response coordination                                 |
| - 24/7 ability to escalate (with on-call rotation)                      |
|                                                                             |
| While IoT Isolation and Westside Firewall are important, they are        |
| lower-impact than the monitoring capability that a SOC provides.         |
|                                                                             |
| REVISED BUDGET:                                                            |
| TOTAL COST: $104,400                                                      |
| BUDGET REMAINING: $15,600                                                |
+----------------------------------------------------------------------------+


================================================================================
FINAL RECOMMENDATION
================================================================================

+----------------------------------------------------------------------------+
| FINAL RECOMMENDATION - ALTERNATIVE ALLOCATION                              |
|                                                                             |
| CONTROLS TO IMPLEMENT (6 controls, $104,400):                              |
|                                                                             |
| 1. Network Segmentation:                         $12,000                  |
| 2. MFA Deployment:                              $8,000                   |
| 3. SIEM (Wazuh):                                $5,000                   |
| 4. EDR Upgrade:                                 $30,000                  |
| 5. Offsite Backup:                              $14,400                  |
| 6. Daytime-Only SOC:                            $35,000                  |
|                                                                             |
| TOTAL SPEND:                                   $104,400                  |
|                                                                             |
| CONTROLS DEFERRED:                                                         |
| 1. Medical IoT Isolation:                      $18,000                   |
| 2. Westside Firewall:                          $5,000                    |
| 3. 24/7 Managed SOC:                           $80,000                   |
|                                                                             |
| TOTAL DEFERRED:                                 $103,000                  |
|                                                                             |
| CONTROLS REJECTED:                                                         |
| None - all controls have positive net value. Deferral is due to budget    |
| constraint, not lack of justification.                                   |
|                                                                             |
| TOTAL SPEND:                                 $104,400                     |
| BUDGET REMAINING:                             $15,600                     |
|                                                                             |
| RATIONALE:                                                                 |
| The Daytime-Only SOC provides $574,004 MORE risk reduction than           |
| IoT Isolation + Westside Firewall combined, for only $12,000             |
| additional cost. The 24/7 SOC is too expensive for the current            |
| budget.                                                                    |
|                                                                             |
| TOTAL ALE REDUCTION: $7,133,210                                            |
| TOTAL COST: $104,400                                                      |
| ROI: 68:1 (every $1 spent reduces risk by $68)                           |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)
- CIS Controls v8


================================================================================
END OF BUDGET ALLOCATION REPORT
================================================================================
