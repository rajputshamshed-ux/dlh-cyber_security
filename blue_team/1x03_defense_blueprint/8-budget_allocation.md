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
Budget: 120000


================================================================================
PART 1: THE SELECTION
================================================================================

CONTROLS FUNDED
---------------
+---------------------------+------------------+------------------+
| Control                   | Annual Cost      | Net Value        |
+---------------------------+------------------+------------------+
| Network Segmentation      | $12,000          | $1,839,696       |
| MFA Deployment            | $8,000           | $1,767,756       |
| SIEM (Wazuh)              | $5,000           | $1,474,796       |
| EDR Upgrade               | $30,000          | $711,636         |
| Offsite Backup            | $14,400          | $629,024         |
| Medical IoT Isolation     | $18,000          | $77,585          |
| Westside Firewall         | $5,000           | $58,723          |
+---------------------------+------------------+------------------+
| Total spend               | $92,400          | $6,559,216       |
+---------------------------+------------------+------------------+

Total spend: $92,400
Budget remaining: 120000 - 92400 = 27600

RATIONALE FOR FUNDED CONTROLS:
The top 7 controls are funded because they have the highest net value and
address the most critical risks (Data Breach, VPN Compromise, Ransomware,
IoT Safety). These controls represent the best return on investment.

CONTROLS DEFERRED
-----------------
+---------------------------+------------------+------------------+
| Control                   | Annual Cost      | Net Value        |
+---------------------------+------------------+------------------+
| 24/7 Managed SOC          | $80,000          | $1,103,837       |
+---------------------------+------------------+------------------+

REASONING FOR DEFERRAL:
The 24/7 SOC is financially justified (net value $1.1M), but it costs
$80,000 - more than the remaining budget ($27,600). A daytime-only SOC
($30K-$40K) could be considered as an alternative in the next fiscal year.
The 24/7 SOC cannot be funded within the current 120000 budget while also
funding the top 7 controls.

CONTROLS REJECTED
-----------------
None. All 8 controls are justified (net value > 0). The only reason a
control is not implemented is budget constraint, not lack of justification.

REJECTED DECISION: No controls are rejected entirely. All have positive net
value. The choice is between funding 7 controls now and deferring 1 control,
or funding fewer controls to include the more expensive SOC.

Budget remaining: $27,600 (unallocated for contingency or future use)


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


================================================================================
PART 3: THE ALTERNATIVE
================================================================================

ALTERNATIVE ALLOCATION
----------------------
+---------------------------+------------------+
| Control                   | Annual Cost      |
+---------------------------+------------------+
| Network Segmentation      | $12,000          |
| MFA Deployment            | $8,000           |
| SIEM (Wazuh)              | $5,000           |
| EDR Upgrade               | $30,000          |
| Offsite Backup            | $14,400          |
| Daytime-Only SOC          | $35,000          |
+---------------------------+------------------+
| Total spend               | $104,400         |
+---------------------------+------------------+

Budget remaining: 120000 - 104400 = 15600

COMPARISON
----------
+----------------------------------------------------------------------------+
| PRIMARY RECOMMENDATION (7 controls):                                       |
| Total spend: $92,400                                                      |
| Total ALE Reduction: $6,559,216                                           |
| Budget remaining: $27,600                                                 |
|                                                                             |
| ALTERNATIVE ALLOCATION (6 controls):                                       |
| Total spend: $104,400                                                     |
| Total ALE Reduction: $7,133,210                                           |
| Budget remaining: $15,600                                                 |
|                                                                             |
| COMPARE the two allocations:                                               |
| The Alternative Allocation provides $574,004 MORE risk reduction than     |
| the Primary Recommendation.                                               |
|                                                                             |
| The Alternative Allocation achieves greater risk reduction at a           |
| LOWER COST PER DOLLAR SPENT - the ROI is 68:1 vs 71:1.                   |
+----------------------------------------------------------------------------+

TRADE-OFF ANALYSIS
------------------
+----------------------------------------------------------------------------+
| PRIMARY:                                    ALTERNATIVE:                  |
| - 7 controls                                - 6 controls                  |
| - $92,400 cost                              - $104,400 cost               |
| - $6.56M reduction                          - $7.13M reduction            |
| - $27,600 remaining                         - $15,600 remaining           |
|                                                                             |
| TRADE-OFFS:                                                                 |
|                                                                             |
| The Primary Recommendation funds IoT Isolation and Westside Firewall,     |
| which provide dedicated protection for medical devices and the Westside  |
| Clinic. These are important for patient safety and perimeter defense.    |
|                                                                             |
| The Alternative Allocation funds a Daytime-Only SOC instead, which        |
| provides continuous monitoring and detection capability. This addresses  |
| the DETECT function, which is currently NOT IMPLEMENTED at MedDefense.   |
|                                                                             |
| The Alternative Allocation provides $574,004 MORE risk reduction for     |
| only $12,000 additional cost. This is a better investment.                |
+----------------------------------------------------------------------------+

VERDICT AND RECOMMENDATION
--------------------------
+----------------------------------------------------------------------------+
| The Alternative Allocation (with Daytime-Only SOC) provides $574,004      |
| MORE risk reduction for only $12,000 additional cost.                     |
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
| when most attacks are detected. While IoT Isolation and Westside         |
| Firewall are important, they are lower-impact than the monitoring        |
| capability that a SOC provides. The additional $12,000 investment        |
| delivers $574,004 more risk reduction - a 48x return.                   |
+----------------------------------------------------------------------------+


================================================================================
FINAL RECOMMENDATION
================================================================================

+----------------------------------------------------------------------------+
| FINAL RECOMMENDATION - ALTERNATIVE ALLOCATION                              |
|                                                                             |
| CONTROLS TO IMPLEMENT (6 controls):                                        |
|                                                                             |
| 1. Network Segmentation:                         $12,000                  |
| 2. MFA Deployment:                              $8,000                   |
| 3. SIEM (Wazuh):                                $5,000                   |
| 4. EDR Upgrade:                                 $30,000                  |
| 5. Offsite Backup:                              $14,400                  |
| 6. Daytime-Only SOC:                            $35,000                  |
|                                                                             |
| Total spend:                                   $104,400                  |
|                                                                             |
| CONTROLS DEFERRED:                                                         |
| 1. Medical IoT Isolation:                      $18,000                   |
| 2. Westside Firewall:                          $5,000                    |
| 3. 24/7 Managed SOC:                           $80,000                   |
|                                                                             |
| CONTROLS REJECTED:                                                         |
| None - all controls have positive net value. Deferral is due to budget    |
| constraint, not lack of justification.                                   |
|                                                                             |
| Total spend:                                 $104,400                     |
| Budget remaining:                             $15,600                     |
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
