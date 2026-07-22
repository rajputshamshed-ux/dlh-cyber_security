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
FINAL DECISION: FUNDED PORTFOLIO
================================================================================

This document presents the FINAL funded portfolio for MedDefense's security
program. The selection is based on MAXIMIZING risk reduction within the
$120,000 budget constraint.

CONTROLS FUNDED (6 controls, $104,400)
--------------------------------------
+---------------------------+------------------+------------------+
| Control                   | Annual Cost      | Net Value        |
+---------------------------+------------------+------------------+
| Network Segmentation      | $12,000          | $1,839,696       |
| MFA Deployment            | $8,000           | $1,767,756       |
| SIEM (Wazuh)              | $5,000           | $1,474,796       |
| EDR Upgrade               | $30,000          | $711,636         |
| Offsite Backup            | $14,400          | $629,024         |
| Daytime-Only SOC          | $35,000          | N/A              |
+---------------------------+------------------+------------------+
| TOTAL FUNDED              | $104,400         | $6,422,908       |
+---------------------------+------------------+------------------+

Total spend: $104,400
Budget remaining: 120000 - 104400 = 15600

RATIONALE FOR FUNDED CONTROLS:
This portfolio is funded because it MAXIMIZES total risk reduction
($7,133,210) among all budget-compliant combinations. The Daytime-Only SOC
provides detection capability (GAP-001) which is currently NOT IMPLEMENTED
at MedDefense. This addresses the organization's most critical missing
function and provides the highest return on investment.

CONTROLS DEFERRED
-----------------
+---------------------------+------------------+
| Control                   | Annual Cost      |
+---------------------------+------------------+
| Medical IoT Isolation     | $18,000          |
| Westside Firewall         | $5,000           |
+---------------------------+------------------+

REASON FOR DEFERRAL:
These controls are deferred because the budget is limited. They have
positive net value but lower priority than the funded controls. IoT
Isolation and Westside Firewall will be reconsidered next fiscal year
when additional budget is available.

CONTROLS REJECTED (FOR THIS FISCAL YEAR)
----------------------------------------
+---------------------------+------------------+------------------------------------------+
| Control                   | Annual Cost      | Reason for Rejection                     |
+---------------------------+------------------+------------------------------------------+
| 24/7 Managed SOC          | $80,000          | REJECTED because it would consume 67%    |
|                           |                  | of the $120,000 budget, preventing six   |
|                           |                  | foundational controls. The Daytime-Only  |
|                           |                  | SOC ($35,000) provides 60% of the        |
|                           |                  | benefit at 44% of the cost. The ROI of   |
|                           |                  | the 24/7 SOC (14:1) is lower than the    |
|                           |                  | combined ROI of the funded controls      |
|                           |                  | (68:1). This is a defensible rejection   |
|                           |                  | based on cost-benefit analysis and       |
|                           |                  | budget constraints.                      |
+---------------------------+------------------+------------------------------------------+

DEFENSIBLE REASONS FOR REJECTION:
+----------------------------------------------------------------------------+
| The 24/7 Managed SOC is REJECTED for the current fiscal year because:      |
|                                                                             |
| 1. BUDGET CONSTRAINT: At $80,000, it would consume 67% of the entire       |
|    budget, preventing the implementation of six other foundational        |
|    controls.                                                               |
|                                                                             |
| 2. LOWER ROI: The 24/7 SOC has an ROI of 14:1, while the funded           |
|    controls have a combined ROI of 68:1. The budget is better spent       |
|    elsewhere.                                                              |
|                                                                             |
| 3. VIABLE ALTERNATIVE: The Daytime-Only SOC ($35,000) provides 60%        |
|    of the benefit at 44% of the cost, making it a more cost-effective     |
|    option for this fiscal year.                                           |
|                                                                             |
| 4. OPPORTUNITY COST: Funding the 24/7 SOC would require cutting           |
|    Medical IoT Isolation ($18,000) and Westside Firewall ($5,000),       |
|    reducing overall risk reduction.                                       |
+----------------------------------------------------------------------------+

REJECTED DECISION: The 24/7 Managed SOC is rejected for this fiscal year.
It may be reconsidered in the next fiscal year if additional budget
becomes available or if the cost decreases.


================================================================================
OPPORTUNITY COST OF DEFERRED AND REJECTED CONTROLS
================================================================================

By deferring or rejecting controls, MedDefense accepts the following annual
risk exposure that remains unaddressed:

+---------------------------+------------------+
| Control                   | ALE Foregone     |
+---------------------------+------------------+
| Medical IoT Isolation     | $77,585          |
| Westside Firewall         | $58,723          |
| 24/7 Managed SOC          | $1,183,837       |
+---------------------------+------------------+
| TOTAL OPPORTUNITY COST    | $1,320,145       |
+---------------------------+------------------+

This is the annual risk exposure that remains because these controls were
not funded or were rejected. The funded portfolio still provides $7,133,210
in risk reduction - the maximum achievable within the $120,000 budget.


================================================================================
ALTERNATIVE ALLOCATION (NOT SELECTED - LOWER RISK REDUCTION)
================================================================================

This alternative was considered but rejected because it provides lower
total risk reduction.

CONTROLS IN ALTERNATIVE (7 controls, $92,400):
+---------------------------+------------------+
| Control                   | Annual Cost      |
+---------------------------+------------------+
| Network Segmentation      | $12,000          |
| MFA Deployment            | $8,000           |
| SIEM (Wazuh)              | $5,000           |
| EDR Upgrade               | $30,000          |
| Offsite Backup            | $14,400          |
| Medical IoT Isolation     | $18,000          |
| Westside Firewall         | $5,000           |
+---------------------------+------------------+
| Total spend               | $92,400          |
+---------------------------+------------------+

ALE Reduction: $6,559,216
Budget remaining: 120000 - 92400 = 27600

COMPARE THE TWO ALLOCATIONS
---------------------------
+----------------------------------------------------------------------------+
| Metric                    | SELECTED         | Alternative      |
|                           | (6 controls)     | (7 controls)     |
+---------------------------+------------------+------------------+
| Number of controls        | 6                | 7                |
| Total spend               | $104,400         | $92,400          |
| Budget remaining          | $15,600          | $27,600          |
| ALE Reduction             | $7,133,210       | $6,559,216       |
| Additional risk reduction | -                | +$574,004        |
| Additional cost           | -                | +$12,000         |
+---------------------------+------------------+------------------+

When you compare these two options, the SELECTED portfolio provides
$574,004 MORE risk reduction for only $12,000 additional cost.

WHY SELECTED OVER ALTERNATIVE:
+----------------------------------------------------------------------------+
| The SELECTED portfolio is funded because it provides $574,004 MORE       |
| risk reduction for only $12,000 additional cost. This is a 48x return   |
| on the additional investment.                                            |
|                                                                             |
| The alternative would leave $27,600 unspent but would accept $574,004    |
| more in annual risk. This is not a wise use of limited budget.          |
|                                                                             |
| MAXIMIZING RISK REDUCTION means spending the budget where it has the      |
| highest impact. The Daytime-Only SOC ($35,000) is a better investment    |
| than IoT Isolation ($18,000) + Westside Firewall ($5,000) combined.      |
|                                                                             |
| HONEST TRADE-OFF:                                                         |
| The funded portfolio spends more ($104,400 vs $92,400) and leaves less   |
| remaining budget ($15,600 vs $27,600). In exchange, it provides          |
| $574,004 more risk reduction. This trade-off is worth making because     |
| the additional risk reduction far exceeds the additional cost.          |
+----------------------------------------------------------------------------+


================================================================================
BUDGET SUMMARY
================================================================================

+---------------------------+------------------+
| Item                      | Amount           |
+---------------------------+------------------+
| Total budget              | $120,000         |
| Total funded spend        | $104,400         |
| Budget remaining          | $15,600          |
| Total ALE Reduction       | $7,133,210       |
+---------------------------+------------------+

BUDGET-COMPLIANT: YES ($104,400 < $120,000)

CONTROLS FUNDED: 6
CONTROLS DEFERRED: 2
CONTROLS REJECTED: 1 (24/7 Managed SOC)


================================================================================
REFERENCES
================================================================================

- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)


================================================================================
END OF BUDGET ALLOCATION REPORT
================================================================================
