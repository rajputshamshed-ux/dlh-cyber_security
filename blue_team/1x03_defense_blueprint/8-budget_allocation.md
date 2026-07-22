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
FINAL DECISION: FUNDED PORTFOLIO (6 controls, $104,400)
================================================================================

CONTROLS FUNDED
---------------
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

Total spend: $104,400
Budget remaining: 120000 - 104400 = 15600

RATIONALE FOR SELECTION:
This portfolio is selected because it MAXIMIZES total risk reduction
($7,133,210) among all budget-compliant combinations. The Daytime-Only SOC
provides detection capability (GAP-001) which is currently NOT IMPLEMENTED
at MedDefense. This addresses the organization's most critical missing
function.

WHY THIS PORTFOLIO MAXIMIZES RISK REDUCTION:
+----------------------------------------------------------------------------+
| The alternative (7 controls, $92,400) provides $6,559,216 in risk         |
| reduction. This portfolio provides $7,133,210 - a difference of          |
| $574,004 MORE risk reduction for only $12,000 additional cost.          |
|                                                                             |
| For every additional dollar spent, MedDefense receives $47.83 in risk     |
| reduction. This is an excellent return on investment.                    |
+----------------------------------------------------------------------------+

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
limited and the selected controls provide higher risk reduction. IoT
Isolation and Westside Firewall will be reconsidered next fiscal year.

CONTROLS REJECTED
-----------------
None. All controls have positive net value. Deferrals are due to budget
constraint, not lack of justification.


================================================================================
OPPORTUNITY COST OF DEFERRAL
================================================================================

By deferring the three controls, MedDefense accepts the following annual
risk exposure:

+---------------------------+------------------+
| Deferred Control          | ALE Foregone     |
+---------------------------+------------------+
| Medical IoT Isolation     | $77,585          |
| Westside Firewall         | $58,723          |
| 24/7 Managed SOC          | $1,183,837       |
+---------------------------+------------------+
| Total                     | $1,320,145       |
+---------------------------+------------------+

This is the risk that remains unaddressed due to budget constraints. The
selected portfolio still provides $7,133,210 in risk reduction - the
maximum achievable within the $120,000 budget.


================================================================================
ALTERNATIVE CONSIDERED (NOT SELECTED - LOWER RISK REDUCTION)
================================================================================

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

COMPARISON
----------
+----------------------------------------------------------------------------+
| Metric                    | SELECTED         | Alternative      |
|                           | (6 controls)     | (7 controls)     |
+---------------------------+------------------+------------------+
| Total spend               | $104,400         | $92,400          |
| Budget remaining          | $15,600          | $27,600          |
| ALE Reduction             | $7,133,210       | $6,559,216       |
| Additional risk reduction | -                | +$574,004        |
| Additional cost           | -                | +$12,000         |
+---------------------------+------------------+------------------+

WHY SELECTED OVER ALTERNATIVE:
+----------------------------------------------------------------------------+
| The SELECTED portfolio provides $574,004 MORE risk reduction for only     |
| $12,000 additional cost. This is a 48x return on the additional          |
| investment. The alternative would leave $27,600 unspent but would       |
| accept $574,004 more in annual risk.                                   |
|                                                                             |
| MAXIMIZING RISK REDUCTION means spending the budget where it has the      |
| highest impact. The Daytime-Only SOC ($35,000) is a better investment    |
| than IoT Isolation ($18,000) + Westside Firewall ($5,000) combined.      |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY
================================================================================

SELECTED PORTFOLIO: 6 controls, $104,400
Budget remaining: $15,600
Total ALE Reduction: $7,133,210
Budget-compliant: YES ($104,400 < $120,000)

This portfolio MAXIMIZES risk reduction within the $120,000 budget.


================================================================================
REFERENCES
================================================================================

- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)


================================================================================
END OF BUDGET ALLOCATION REPORT
================================================================================
