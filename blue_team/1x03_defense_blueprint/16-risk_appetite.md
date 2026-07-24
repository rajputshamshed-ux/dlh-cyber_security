================================================================================
                    RISK APPETITE DEBATE - MEDDEFENSE HEALTH SYSTEMS
                    Task 16: The Risk Appetite Debate
================================================================================

Exercise: Task 16 - The Risk Appetite Debate
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Define MedDefense's risk appetite and demonstrate that risk
          acceptance is a legitimate, documented governance decision.

Sources: 1x03 Risk Register (T10), 1x03 Cost-Benefit Analysis (T7),
         1x03 Budget Allocation (T8), 1x03 Red Team (T15)


================================================================================
PART 1: RISK APPETITE STATEMENT
================================================================================

+----------------------------------------------------------------------------+
| RISK APPETITE STATEMENT - MEDDEFENSE HEALTH SYSTEMS                        |
|                                                                             |
| MedDefense Health Systems is committed to protecting patient safety and    |
| preserving the confidentiality, integrity, and availability of patient     |
| data as its highest priorities. The organization accepts a MODERATE        |
| level of operational and financial risk, provided that all risks to        |
| patient safety are either mitigated or accompanied by documented           |
| compensating measures. Risks with an inherent score of 20 or above         |
| (CRITICAL) require explicit Board or CEO approval for acceptance.          |
| Acceptance decisions are documented, reviewed quarterly, and re-evaluated  |
| when the threat landscape changes.                                        |
+----------------------------------------------------------------------------+


================================================================================
PART 2: THE THREE DECISIONS
================================================================================

DECISION 1: MEDICAL IOT COMPROMISE (PATIENT SAFETY)
---------------------------------------------------
+------------------+--------------------------------------------------+
| Risk             | RISK-005 - Medical IoT Compromise (Patient        |
|                  | Safety)                                          |
+------------------+--------------------------------------------------+
| Treatment        | ACCEPT (WITH COMPENSATING CONTROLS)              |
| Decision         |                                                  |
+------------------+--------------------------------------------------+
| Authority        | James Chen (Deputy CISO) + Dr. Patricia Morales  |
|                  | (CEO) - approved by CEO on recommendation of    |
|                  | Deputy CISO                                      |
+------------------+--------------------------------------------------+
| Justification    | The cost to fully isolate and secure all         |
|                  | 200+ medical IoT devices is estimated at         |
|                  | $18,000 per year (from T7). The ALE for a       |
|                  | patient safety incident is $88,000 (from T6).   |
|                  | While the cost is less than the ALE, the         |
|                  | compensating controls (default credential       |
|                  | change, network monitoring, vendor coordination) |
|                  | reduce the likelihood to an acceptable level.    |
|                  | Accepting the residual risk is rational given    |
|                  | the budget constraints.                          |
+------------------+--------------------------------------------------+
| Compensating     | - Default credentials changed (Quick Win #1)    |
| Measure          | - IoT network monitoring (included in C-020)    |
|                  | - Quarterly vendor coordination for updates    |
|                  | - Incident response plan includes IoT-specific  |
|                  |   procedures                                     |
+------------------+--------------------------------------------------+
| Review Trigger   | - If a medical IoT-related security incident    |
|                  |   occurs                                         |
|                  | - If firmware updates become available          |
|                  | - If FDA issues a new advisory                  |
|                  | - Quarterly review of threat landscape          |
+------------------+--------------------------------------------------+


DECISION 2: WESTSIDE CLINIC CONSUMER ROUTER
--------------------------------------------
+------------------+--------------------------------------------------+
| Risk             | RISK-008 - Westside Clinic Perimeter Breach      |
+------------------+--------------------------------------------------+
| Treatment        | ACCEPT (DEFERRED FROM T8)                        |
| Decision         |                                                  |
+------------------+--------------------------------------------------+
| Authority        | Sarah Park (IT Director) + James Chen (Deputy   |
|                  | CISO) - approved jointly                        |
+------------------+--------------------------------------------------+
| Justification    | The cost to replace the Netgear router with an  |
|                  | enterprise firewall is $5,000 (from T7). The    |
|                  | ALE for Westside perimeter breach is $58,723   |
|                  | (from T6). The cost is less than the ALE, but   |
|                  | the likelihood is LOW (3/5) and the risk is     |
|                  | contained to the Westside site. The budget was  |
|                  | prioritized to fund higher-impact controls      |
|                  | (MFA, SIEM, Segmentation). Accepting this risk  |
|                  | is rational given the budget constraint.        |
+------------------+--------------------------------------------------+
| Compensating     | - VPN is encrypted (site-to-site)               |
| Measure          | - Westside has limited clinical services        |
|                  | - No PHI stored at Westside                     |
|                  | - Network monitoring for Westside traffic       |
|                  | - Re-evaluated in 6 months                     |
+------------------+--------------------------------------------------+
| Review Trigger   | - If a security incident occurs at Westside     |
|                  | - If the consumer router is compromised         |
|                  | - If budget becomes available                    |
|                  | - Quarterly review                             |
+------------------+--------------------------------------------------+


DECISION 3: SHADOW IT ON THE NETWORK
-------------------------------------
+------------------+--------------------------------------------------+
| Risk             | RISK-009 - Shadow IT on the Network              |
+------------------+--------------------------------------------------+
| Treatment        | ACCEPT (PARTIAL)                                 |
| Decision         |                                                  |
+------------------+--------------------------------------------------+
| Authority        | James Chen (Deputy CISO) + Sarah Park (IT       |
|                  | Director) - approved jointly                    |
+------------------+--------------------------------------------------+
| Justification    | Shadow IT devices (unknown Linux servers,        |
|                  | Raspberry Pi) were identified in 1x02. The      |
|                  | cost to fully investigate and remediate all     |
|                  | shadow IT is estimated at $5,000 (from T7).     |
|                  | The risk is HIGH (inherent risk score 16).      |
|                  | However, the devices have been identified and   |
|                  | are now known. Accepting the residual risk is   |
|                  | rational while prioritizing other controls.     |
|                  | (From 1x02 Findings 028/029).                  |
+------------------+--------------------------------------------------+
| Compensating     | - Known devices are documented (from 1x02)      |
| Measure          | - Quarterly network scans to identify new       |
|                  |   devices (from T11)                            |
|                  | - Segmented network zones reduce blast radius   |
|                  | - Incident response plan includes shadow IT     |
+------------------+--------------------------------------------------+
| Review Trigger   | - If new shadow IT devices are discovered       |
|                  | - If a shadow IT device is compromised          |
|                  | - Quarterly review of network scan results      |
+------------------+--------------------------------------------------+


================================================================================
PART 3: THE DEBATE
================================================================================

JAMES CHEN (SECURITY-FIRST)
---------------------------
+----------------------------------------------------------------------------+
| James Chen's Argument for Mitigation:                                      |
|                                                                             |
| The MRI Windows XP workstation is a PERMANENT, UNPATCHABLE backdoor        |
| into MedDefense's network. It has THREE weaponized exploits                |
| (EternalBlue, BlueKeep, MS08-067) and is listed in CISA KEV. The          |
| $2.1M replacement cost is not relevant - the real cost of inaction is     |
| $40M+ in recovery costs, delayed cancer treatments, and potential         |
| patient harm (Breach 3 from 1x00 Task 13). The MRI is on the              |
| Medical Device Zone (VLAN 30), but the PACS communication path provides   |
| a viable pivot to the EHR. We cannot accept a risk that directly          |
| threatens patient safety and exposes the entire network.                   |
+----------------------------------------------------------------------------+

ROBERT KIM (COST-FIRST)
-----------------------
+----------------------------------------------------------------------------+
| Robert Kim's Argument for Acceptance:                                      |
|                                                                             |
| The MRI scanner is a $2.1M capital asset that cannot be replaced until    |
| its lease expires in 18 months. Virtualization and compensating           |
| controls cost $50,000 (from T15). The ALE is $88,000 (from T6), which    |
| is close to the cost of controls. We have implemented segmentation       |
| (VLAN 30) to isolate the MRI, and the $120,000 budget is already fully  |
| allocated to higher-priority controls (MFA, SIEM, Segmentation).          |
| Accepting this risk with compensating controls is the rational           |
| financial decision. The probability of a patient safety incident is      |
| LOW (3/5) and the direct patient harm scenario is extremely rare.        |
| We should accept the risk and re-evaluate when the lease expires.        |
+----------------------------------------------------------------------------+

MY VERDICT
----------
+----------------------------------------------------------------------------+
| My Verdict:                                                               |
|                                                                             |
| I find James's argument more compelling in this specific case. The MRI   |
| is not just another vulnerability - it is a PERMANENT, UNPATCHABLE       |
| backdoor with WEAPONIZED exploits that are actively being used in       |
| ransomware campaigns. The real-world cost of inaction has been           |
| validated at $40M+ (Breach 3 from 1x00 Task 13). While Robert's          |
| financial concerns are valid and the budget constraint is real, the      |
| $50,000 cost of mitigation is a small fraction of the potential          |
| $40M+ loss. Patient safety must be the highest priority. However,       |
| I would propose a compromise: accept the risk for the next 6 months     |
| while implementing low-cost compensating controls (application          |
| whitelisting, host firewall) immediately, and budget for full           |
| virtualization in the next fiscal year. This balances the urgent        |
| security need with the financial reality.                               |
+----------------------------------------------------------------------------+

COMPROMISE POSITION
-------------------
+----------------------------------------------------------------------------+
| RECOMMENDED APPROACH:                                                     |
|                                                                             |
| Phase 1 (Immediate - 2 weeks):                                            |
| - Implement host-based firewall on MRI (C-017) - $0 (configuration)      |
| - Change default credentials on MRI (Quick Win #1) - $0                 |
| - Document accepted risk with CEO approval                               |
|                                                                             |
| Phase 2 (1 month):                                                        |
| - Implement application whitelisting (C-016) - $500                     |
| - Deploy network monitoring for MRI traffic (C-020) - $1,000            |
|                                                                             |
| Phase 3 (6 months):                                                       |
| - Evaluate virtualization of MRI control workstation - $5,000-$10,000   |
| - Re-assess risk acceptance                                              |
|                                                                             |
| This approach addresses the security concern while respecting budget    |
| constraints.                                                              |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY
================================================================================

+----------+------------------+------------------+------------------------------------------+
| Risk ID  | Risk Description  | Treatment        | Justification                            |
+----------+------------------+------------------+------------------------------------------+
| RISK-005 | Medical IoT      | ACCEPT           | Compensating controls reduce risk to     |
|          | Compromise       | (with Compens.)  | acceptable level; budget prioritized     |
+----------+------------------+------------------+------------------------------------------+
| RISK-008 | Westside         | ACCEPT           | Cost of mitigation > ALE; risk          |
|          | Perimeter        | (Deferred)       | contained; budget prioritized            |
+----------+------------------+------------------+------------------------------------------+
| RISK-009 | Shadow IT        | ACCEPT           | Known devices documented; quarterly      |
|          |                  | (Partial)        | scanning detects new devices             |
+----------+------------------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Risk Register (1x03 T10)
- Cost-Benefit Analysis (1x03 T7)
- Budget Allocation (1x03 T8)
- Red Team (1x03 T15)
- Reality Check (1x00 T13 - Breach 3)


================================================================================
END OF RISK APPETITE DEBATE REPORT
================================================================================
