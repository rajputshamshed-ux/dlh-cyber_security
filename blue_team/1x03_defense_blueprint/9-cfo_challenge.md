================================================================================
                    CFO CHALLENGE - MEDDEFENSE HEALTH SYSTEMS
                    Task 9: The CFO Challenge
================================================================================

Exercise: Task 9 - The CFO Challenge
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Defend your security recommendations against realistic financial
          pushback, proving you can communicate risk in the language of
          business.

Source: cfo-pushback.txt, Cost-Benefit Analysis (T7), ALE Workshop (T6)
Budget: $120,000


================================================================================
OBJECTION 1: "The ALE numbers are hypothetical. Breaches never cost exactly
$165 per record. You are asking me to spend $100,000 on something that might
never happen."
================================================================================

+------------------+--------------------------------------------------+
| Objection         | 1. "The ALE numbers are hypothetical. Breaches    |
|                   | never cost exactly $165 per record. You are      |
|                   | asking me to spend $100,000 on something that    |
|                   | might never happen."                             |
+------------------+--------------------------------------------------+
| Acknowledgment    | You are right that no breach costs exactly $165  |
|                   | per record - the actual cost could be higher or  |
|                   | lower. The $165 figure is the average from the   |
|                   | Ponemon Institute, the most credible source in   |
|                   | healthcare security. It is the best estimate we  |
|                   | have.                                            |
+------------------+--------------------------------------------------+
| Counter-Evidence  | HHS fines have reached $1.5M per violation. The  |
|                   | 2023 HHS report found 93% of healthcare          |
|                   | organizations had a breach in 3 years. This is   |
|                   | not "might never happen" - it is statistically   |
|                   | likely. Our ALE for a data breach is $4.3M.      |
+------------------+--------------------------------------------------+
| Business Framing  | Spending $104,400 reduces an annual expected     |
|                   | loss of $1.3M. That is a 12x ROI on our          |
|                   | investment. The $100,000 cost is a small         |
|                   | fraction of the potential liability.             |
+------------------+--------------------------------------------------+
| Recommendation    | I recommend we proceed with the $104,400 package. |
|                   | If you are concerned, we can implement a phased  |
|                   | approach over 6 months with quarterly reviews.   |
+------------------+--------------------------------------------------+


================================================================================
OBJECTION 2: "If the average hospital gets breached once every 3-4 years,
why are we assuming a breach every 2 years for MedDefense ? That seems like
you are inflating the risk."
================================================================================

+------------------+--------------------------------------------------+
| Objection         | 2. "If the average hospital gets breached once   |
|                   | every 3-4 years, why are we assuming a breach    |
|                   | every 2 years for MedDefense ? That seems like   |
|                   | you are inflating the risk."                    |
+------------------+--------------------------------------------------+
| Acknowledgment    | You are right to question the ARO. The average   |
|                   | hospital is indeed 1 in 3-4 years.               |
+------------------+--------------------------------------------------+
| Counter-Evidence  | MedDefense is NOT average. We have:              |
|                   | - No MFA (GAP-004)                               |
|                   | - No patch management (GAP-014)                  |
|                   | - A flat network (GAP-003)                       |
|                   | - Windows XP on the network (GAP-007)            |
|                   | - Evidence of active scanning (crypto-miner)     |
|                   | Three regional hospitals within 200 miles hit in |
|                   | 8 months. MedDefense is HIGHER RISK than average.|
+------------------+--------------------------------------------------+
| Business Framing  | If we use the average ARO (0.25 instead of 0.5), |
|                   | the ALE is $2.1M instead of $4.3M. The           |
|                   | investment is still justified. The difference    |
|                   | is $2.2M - still a significant risk.            |
+------------------+--------------------------------------------------+
| Recommendation    | I can recalculate ALE with a conservative 0.25  |
|                   | ARO. The investment is still justified.         |
+------------------+--------------------------------------------------+


================================================================================
OBJECTION 3: "The 24/7 SOC is $80,000. Our entire security budget is $120,000.
You are asking me to spend two-thirds of our budget on one control. That is
not responsible. What is the minimum we can spend and still have a credible
security program ?"
================================================================================

+------------------+--------------------------------------------------+
| Objection         | 3. "The 24/7 SOC is $80,000. Our entire security |
|                   | budget is $120,000. You are asking me to spend   |
|                   | two-thirds of our budget on one control. That is |
|                   | not responsible. What is the minimum we can      |
|                   | spend and still have a credible security         |
|                   | program ?"                                       |
+------------------+--------------------------------------------------+
| Acknowledgment    | You are absolutely right. $80,000 is a           |
|                   | significant portion of the budget.               |
+------------------+--------------------------------------------------+
| Counter-Evidence  | I have already rejected the 24/7 SOC. The final  |
|                   | recommendation funds a Daytime-Only SOC          |
|                   | ($35,000) plus other foundational controls. The  |
|                   | total is $104,400. The minimum credible program  |
|                   | is: Segmentation + MFA + SIEM + EDR + Offsite    |
|                   | Backup + Daytime SOC = $104,400.                |
+------------------+--------------------------------------------------+
| Business Framing  | This is the minimum spend to:                    |
|                   | - Stop credential theft (MFA)                    |
|                   | - Contain attacks (Segmentation)                |
|                   | - Detect threats (SIEM + SOC)                   |
|                   | - Recover from incidents (Offsite Backup)        |
+------------------+--------------------------------------------------+
| Recommendation    | I recommend we adopt the $104,400 package.       |
+------------------+--------------------------------------------------+


================================================================================
OBJECTION 4: "I am not convinced that the Westside Clinic needs a $5,000
firewall. They have been using that Netgear router for years without any
problems. Why is this suddenly urgent ?"
================================================================================

+------------------+--------------------------------------------------+
| Objection         | 4. "I am not convinced that the Westside Clinic  |
|                   | needs a $5,000 firewall. They have been using    |
|                   | that Netgear router for years without any        |
|                   | problems. Why is this suddenly urgent ?"        |
+------------------+--------------------------------------------------+
| Acknowledgment    | You are right that the Netgear router has worked |
|                   | for years. It has provided connectivity.         |
+------------------+--------------------------------------------------+
| Counter-Evidence  | The Netgear Nighthawk is a consumer-grade device |
|                   | designed for homes, not medical facilities. It   |
|                   | has no enterprise logging, no IDS/IPS, and no    |
|                   | granular ACL management. A hospital was breached |
|                   | through a compromised consumer router.           |
+------------------+--------------------------------------------------+
| Business Framing  | The $5,000 cost is <1% of the annual security    |
|                   | budget. The risk of not replacing it is a        |
|                   | breach at Westside that could cost $1M+.         |
+------------------+--------------------------------------------------+
| Recommendation    | I recommend we keep this in the budget. It is a  |
|                   | $5,000 one-time cost for a quick win.            |
+------------------+--------------------------------------------------+


================================================================================
OBJECTION 5: "This is a lot of spending on technology. What about training ?
What about process ? You are recommending $104,400 in tools and services.
Where is the investment in people and procedures ?"
================================================================================

+------------------+--------------------------------------------------+
| Objection         | 5. "This is a lot of spending on technology.     |
|                   | What about training ? What about process ? You   |
|                   | are recommending $104,400 in tools and services. |
|                   | Where is the investment in people and            |
|                   | procedures ?"                                   |
+------------------+--------------------------------------------------+
| Acknowledgment    | This is an excellent point. Security is not just |
|                   | technology. People and process are equally       |
|                   | important.                                       |
+------------------+--------------------------------------------------+
| Counter-Evidence  | Our assessment shows:                            |
|                   | - Training completion: 58-71% (GAP-013)          |
|                   | - No formal IR plan (GAP-002)                   |
|                   | - No security policies                           |
|                   | People and process gaps are critical.            |
+------------------+--------------------------------------------------+
| Business Framing  | I recommend allocating the remaining $15,600 to: |
|                   | - $8,000: Security awareness training program    |
|                   | - $5,000: Incident response plan development     |
|                   | - $2,600: Policy documentation                   |
|                   | This makes our program complete.                 |
+------------------+--------------------------------------------------+
| Recommendation    | Allocate the remaining $15,600 to training,      |
|                   | IR plan development, and policy documentation.   |
+------------------+--------------------------------------------------+


================================================================================
CLOSING STATEMENT
================================================================================

+----------------------------------------------------------------------------+
| The total cost of inaction is $6.3M in annual expected losses from the     |
| five biggest risks we identified. The cost of our proposed program is     |
| $104,400 in technology plus $15,600 in training and process, totaling     |
| $120,000. This investment reduces our annual expected loss to             |
| approximately $1.4M, saving $4.9M per year. The ROI is 41:1.              |
|                                                                             |
| If we do nothing, we accept:                                               |
| - $4.3M risk of a data breach                                             |
| - $1.3M risk of a VPN compromise                                          |
| - $360K risk of insider data theft                                        |
| - $273K risk of ransomware                                                |
| - $45K risk of a patient safety incident                                  |
|                                                                             |
| Total expected loss: $6.3M.                                                |
|                                                                             |
| The $120,000 investment is not an expense. It is insurance against a      |
| $6.3M annual loss. For every dollar spent, we reduce risk by $41.         |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- cfo-pushback.txt
- Cost-Benefit Analysis (1x03 T7)
- ALE Workshop (1x03 T6)
- Budget Allocation (1x03 T8)


================================================================================
END OF CFO CHALLENGE REPORT
================================================================================
