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
| 24/7 Managed SOC          | $80,000          |
+---------------------------+------------------+

REASON FOR DEFERRAL: These controls are deferred because the budget is
limited and the funded controls provide higher risk reduction. IoT
Isolation and Westside Firewall will be reconsidered next fiscal year.

CONTROLS REJECTED
-----------------
None. All controls have positive net value. Deferrals are due to budget
constraint, not lack of justification. No controls are rejected entirely
because all 8 controls are financially justified.


================================================================================
OPPORTUNITY COST OF DEFERRED CONTROLS
================================================================================

By deferring the three controls, MedDefense accepts the following annual
risk exposure that remains unaddressed:

+---------------------------+------------------+
| Deferred Control          | ALE Foregone     |
+---------------------------+------------------+
| Medical IoT Isolation     | $77,585          |
| Westside Firewall         | $58,723          |
| 24/7 Managed SOC          | $1,183,837       |
+---------------------------+------------------+
| TOTAL OPPORTUNITY COST    | $1,320,145       |
+---------------------------+------------------+

This is the annual risk exposure that remains because these controls were
not funded. The funded portfolio still provides $7,133,210 in risk
reduction - the maximum achievable within the $120,000 budget.


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
+----------------------------------------------------------------------------+

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
CONTROLS DEFERRED: 3
CONTROLS REJECTED: 0


================================================================================
REFERENCES
================================================================================

- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)


================================================================================
END OF BUDGET ALLOCATION REPORT
================================================================================
