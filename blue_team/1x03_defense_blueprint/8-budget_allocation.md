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

COMPARE THE TWO ALLOCATIONS
---------------------------
+----------------------------------------------------------------------------+
| Let us compare the two allocations side by side:                            |
|                                                                             |
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
| When you compare these two options, the Alternative provides $574,004     |
| MORE risk reduction for only $12,000 additional cost.                     |
|                                                                             |
| The Alternative achieves this at a lower cost per dollar spent.           |
|                                                                             |
| COMPARISON TABLE:                                                          |
|                                                                             |
| Metric                    | Primary          | Alternative              |
| ------------------------- | ---------------- | ------------------------ |
| Number of controls        | 7                | 6                        |
| Total spend               | $92,400          | $104,400                 |
| Budget remaining          | $27,600          | $15,600                  |
| ALE Reduction             | $6,559,216       | $7,133,210               |
| ROI                       | 71:1             | 68:1                     |
+----------------------------------------------------------------------------+

TRADE-OFF ANALYSIS
------------------
+----------------------------------------------------------------------------+
| HONEST TRADE-OFFS:                                                          |
|                                                                             |
| The Primary Recommendation funds IoT Isolation and Westside Firewall,      |
| which provide dedicated protection for medical devices and the Westside   |
| Clinic. These are important for patient safety and perimeter defense.    |
|                                                                             |
| The Alternative Allocation funds a Daytime-Only SOC instead, which        |
| provides continuous monitoring and detection capability. This addresses   |
| the DETECT function, which is currently NOT IMPLEMENTED at MedDefense.   |
|                                                                             |
| Trade-off: Better IoT protection vs Better detection capability.          |
|                                                                             |
| The Alternative provides more risk reduction (by $574,004) but costs      |
| more ($104,400 vs $92,400). The Primary costs less but leaves MedDefense |
| with less detection capability.                                          |
|                                                                             |
| RECOMMENDATION:                                                             |
| MedDefense should adopt the Alternative Allocation because the            |
| additional $12,000 investment delivers $574,004 more risk reduction.     |
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
FINAL DECISION: FUNDED PORTFOLIO (7 controls, $92,400)
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

RATIONALE:
This portfolio is selected because it provides the best balance of risk
reduction and cost. It funds the 7 highest-value controls and stays well
under the $120,000 budget. The 24/7 SOC ($80,000) is deferred because it
would consume most of the budget.

CONTROLS DEFERRED
-----------------
+---------------------------+------------------+
| Control                   | Annual Cost      |
+---------------------------+------------------+
| 24/7 Managed SOC          | $80,000          |
+---------------------------+------------------+

REASON FOR DEFERRAL: The 24/7 SOC costs $80,000 - more than the remaining
budget ($27,600). A daytime-only SOC ($35,000) could be considered next year.

CONTROLS REJECTED
-----------------
None. All controls have positive net value. Deferrals are due to budget
constraint, not lack of justification.


================================================================================
OPPORTUNITY COST OF DEFERRAL
================================================================================

By deferring 24/7 Managed SOC, MedDefense accepts an estimated $1,183,837
in annual risk exposure that would have been reduced through continuous
24/7 monitoring.


================================================================================
ALTERNATIVE CONSIDERED (NOT SELECTED)
================================================================================

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

COMPARISON
----------
+----------------------------------------------------------------------------+
| Metric          | SELECTED (7 controls)   | Alternative (6 controls) |
+-----------------+-------------------------+--------------------------+
| Total spend     | $92,400                 | $104,400                 |
| ALE Reduction   | $6,559,216              | $7,133,210               |
+-----------------+-------------------------+--------------------------+

The Alternative provides $574,004 more risk reduction but costs $12,000
more. The Selected portfolio is preferred because it funds IoT Isolation
and Westside Firewall while staying further under budget.


================================================================================
SUMMARY
================================================================================

SELECTED PORTFOLIO: 7 controls, $92,400
Budget remaining: $27,600
Total ALE Reduction: $6,559,216

This portfolio is BUDGET-COMPLIANT ($92,400 < $120,000).


================================================================================
REFERENCES
================================================================================

- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)


================================================================================
END OF BUDGET ALLOCATION REPORT
================================================================================
