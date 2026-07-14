================================================================================
                    RISK DECISIONS - MEDDEFENSE HEALTH SYSTEMS
                    Task 14: The Risk Decisions
================================================================================

Exercise: Task 14 - The Risk Decisions
Analyst: shamshed rajput
Date: 14/07/2026
 

Objective: Apply risk treatment strategies to prioritized gaps under
          realistic budget and operational constraints.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Risk Treatment
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Respond Function
- ISO 27001: A.8.2 (Risk Treatment)
- HHS HICP: Healthcare Cybersecurity Practices

Sources: Task 12 Gap Analysis, Task 13 Reality Check, healthcare-breach-summaries.txt

Budget Constraint: $120,000 annual security budget


================================================================================
1. GAP PRIORITIZATION (TOP 7)
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap ID           | Gap Title                              | Risk Level       |
+----------+------------------+----------------------------------------+------------------+
| #1       | GAP-007          | No Compensating Controls for MRI       | CRITICAL         |
|          |                  | (Windows XP)                           |                  |
+----------+------------------+----------------------------------------+------------------+
| #2       | GAP-003          | Medical IoT on Flat Network - No       | CRITICAL         |
|          |                  | Segmentation                           |                  |
+----------+------------------+----------------------------------------+------------------+
| #3       | GAP-014          | No Patch Management for Network        | CRITICAL         |
|          |                  | Devices                                |                  |
+----------+------------------+----------------------------------------+------------------+
| #4       | GAP-001          | No SIEM or Log Monitoring              | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #5       | GAP-004          | No MFA Anywhere                        | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #6       | GAP-015          | No Automated User Offboarding          | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+
| #7       | GAP-002          | No Incident Response Plan              | CRITICAL         |
+----------+------------------+----------------------------------------+------------------+


================================================================================
2. RISK TREATMENT DECISIONS
================================================================================

-------------------------------------------------------------------------------
GAP-007: NO COMPENSATING CONTROLS FOR MRI (WINDOWS XP)
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-007                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No Compensating Controls for MRI (Windows XP)    |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                         |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Breach 3 (Community Hospital Gamma) describes    |
|                  | the EXACT same scenario: Windows 7 EOL device    |
|                  | on a flat network with no compensating controls. |
|                  | The result was $40M recovery costs and delayed   |
|                  | cancer treatments. MedDefense has an MRI running |
|                  | Windows XP (EOL 2014) with the SAME vulnerability|
|                  | on the SAME flat network. The cost of mitigation |
|                  | ($10K) is negligible compared to the potential   |
|                  | loss ($40M+). This is the #1 priority.          |
+------------------+--------------------------------------------------+
| Proposed         | 1. Network Segmentation: Isolate MRI on         |
| Control(s)       |    dedicated VLAN (Technical / Compensating)     |
|                  | 2. Application Whitelisting: Allow ONLY         |
|                  |    approved applications (Technical /            |
|                  |    Compensating)                                 |
|                  | 3. Host-Based Firewall: Block inbound to        |
|                  |    vulnerable services (Technical /              |
|                  |    Compensating)                                 |
+------------------+--------------------------------------------------+
| Estimated Cost   | $5,000 - $10,000                                 |
|                  | (firewall reconfiguration + VLAN setup +         |
|                  | whitelisting configuration)                      |
+------------------+--------------------------------------------------+
| Implementation   | Quick Win (< 1 week)                             |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | CRITICAL reduction. If the MRI is compromised,   |
| Reduction        | the attacker cannot pivot laterally to the EHR,  |
|                  | billing, or AD. The blast radius is contained    |
|                  | to the MRI VLAN.                                 |
+------------------+--------------------------------------------------+
| Trade-offs       | Must ensure PACS communication is maintained.    |
|                  | Minimal clinical impact if configured correctly. |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-003: MEDICAL IOT ON FLAT NETWORK - NO SEGMENTATION
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-003                                          |
+------------------+--------------------------------------------------+
| Gap Title        | Medical IoT on Flat Network - No Segmentation    |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                         |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | All 3 breaches involved lateral movement across  |
|                  | flat networks. MedDefense's IoT devices (80      |
|                  | monitors, 120 infusion pumps, MRI) are on the    |
|                  | SAME flat network as workstations and servers.   |
|                  | Marcus noted: "If someone gets on the network    |
|                  | they can reach the pumps." This is a life-safety |
|                  | risk (CISA Healthcare Guide).                    |
+------------------+--------------------------------------------------+
| Proposed         | 1. Dedicated VLAN for ALL medical IoT devices    |
| Control(s)       |    (Technical / Preventive)                      |
|                  | 2. Strict firewall rules between IoT VLAN and    |
|                  |    internal network (Technical / Preventive)     |
|                  | 3. Network traffic monitoring for IoT devices    |
|                  |    (Technical / Detective - C-020)               |
+------------------+--------------------------------------------------+
| Estimated Cost   | $8,000 - $12,000                                 |
|                  | (network reconfiguration + monitoring setup)     |
+------------------+--------------------------------------------------+
| Implementation   | Short-term (< 1 month)                           |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | CRITICAL reduction. Prevents lateral movement    |
| Reduction        | from compromised workstations to life-safety     |
|                  | devices. Limits blast radius of any compromise.  |
+------------------+--------------------------------------------------+
| Trade-offs       | Requires coordination with biomedical            |
|                  | engineering. Must ensure device functionality    |
|                  | is not disrupted.                                |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-014: NO PATCH MANAGEMENT FOR NETWORK DEVICES
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-014                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No Patch Management for Network Devices          |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                         |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Breach 1 (unpatched VPN) and Breach 3            |
|                  | (unpatched patient portal) both started with     |
|                  | unpatched perimeter devices. MedDefense has NO   |
|                  | documented patch management for VPN, firewall,   |
|                  | or switches. The FortiGate 100F may have         |
|                  | unpatched vulnerabilities. This is how attackers |
|                  | gain initial access.                             |
+------------------+--------------------------------------------------+
| Proposed         | 1. Formal patch management program for network   |
| Control(s)       |    devices (Administrative / Preventive)         |
|                  | 2. Monthly maintenance schedule (Administrative  |
|                  |    / Preventive)                                 |
|                  | 3. Inventory of all network devices with         |
|                  |    firmware versions (Administrative /           |
|                  |    Preventive)                                   |
+------------------+--------------------------------------------------+
| Estimated Cost   | $2,000 (IT administration time)                  |
+------------------+--------------------------------------------------+
| Implementation   | Quick Win (< 1 week)                             |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | HIGH reduction. Eliminates the primary entry     |
| Reduction        | point used in 2 of the 3 breaches.              |
+------------------+--------------------------------------------------+
| Trade-offs       | Requires scheduled maintenance windows. Must    |
|                  | coordinate with IT operations.                   |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-001: NO SIEM OR LOG MONITORING
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-001                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No SIEM or Log Monitoring                        |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE (partial)                               |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | ALL 3 breaches went undetected for extended      |
|                  | periods (3 hours to 47 days) due to NO           |
|                  | detection capability. MedDefense has NO SIEM,    |
|                  | NO centralized logging, and NO alerting. The     |
|                  | crypto-miner on billing-srv-01 ran for weeks     |
|                  | without detection. A full SIEM license costs     |
|                  | ~$80K (67% of budget). Wazuh (open-source) is    |
|                  | a viable alternative with budget constraints.   |
+------------------+--------------------------------------------------+
| Proposed         | 1. Deploy Wazuh SIEM (open-source)               |
| Control(s)       |    (Technical / Detective)                       |
|                  | 2. Centralize logs from ALL critical systems     |
|                  |    (Technical / Detective)                       |
|                  | 3. Basic alerting for critical events            |
|                  |    (Technical / Detective)                       |
+------------------+--------------------------------------------------+
| Estimated Cost   | $5,000 (installation + configuration + server)   |
+------------------+--------------------------------------------------+
| Implementation   | Short-term (< 1 month)                           |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | MODERATE to HIGH reduction. Provides detection   |
| Reduction        | capability where none exists. Attacks will be    |
|                  | detected in hours/days instead of weeks.        |
+------------------+--------------------------------------------------+
| Trade-offs       | Open-source solution is less comprehensive than  |
|                  | commercial SIEM. Requires dedicated staff time   |
|                  | for maintenance and tuning.                     |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-004: NO MFA ANYWHERE
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-004                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No MFA Anywhere                                  |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                         |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Breach 2 (insider threat) was enabled by NO MFA. |
|                  | Credential theft is the #1 entry vector in       |
|                  | healthcare (HHS HICP). MedDefense has NO MFA     |
|                  | except James's personal account. If an attacker  |
|                  | obtains a password, they have full access to     |
|                  | EHR, AD, and VPN.                                |
+------------------+--------------------------------------------------+
| Proposed         | 1. MFA for ALL remote access (VPN)               |
| Control(s)       |    (Technical / Preventive)                      |
|                  | 2. MFA for all AD administrative accounts        |
|                  |    (Technical / Preventive)                      |
|                  | 3. MFA for EHR remote access (Technical /        |
|                  |    Preventive)                                   |
+------------------+--------------------------------------------------+
| Estimated Cost   | $6,000 - $10,000 (Azure AD Premium P1 or        |
|                  | equivalent licenses)                             |
+------------------+--------------------------------------------------+
| Implementation   | Short-term (< 1 month)                           |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | CRITICAL reduction. Phished credentials are no   |
| Reduction        | longer sufficient. Attackers must bypass a       |
|                  | second authentication factor.                   |
+------------------+--------------------------------------------------+
| Trade-offs       | User impact: clinicians must adapt to additional |
|                  | authentication steps. Requires user training.    |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-015: NO AUTOMATED USER OFFBOARDING
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-015                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No Automated User Offboarding                    |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE                                         |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Breach 2 (insider threat) showed a former        |
|                  | employee retained access for 47 days because the |
|                  | offboarding process relied on a manager to       |
|                  | submit a ticket. MedDefense has NO automated     |
|                  | process to deactivate accounts. The same risk    |
|                  | exists.                                          |
+------------------+--------------------------------------------------+
| Proposed         | 1. HR → IT integration for automated account     |
| Control(s)       |    deactivation (Administrative / Preventive)    |
|                  | 2. Quarterly review of active accounts           |
|                  |    (Administrative / Detective)                  |
|                  | 3. Detection of dormant accounts (Administrative |
|                  |    / Detective)                                  |
+------------------+--------------------------------------------------+
| Estimated Cost   | $3,000 (integration development + coordination)  |
+------------------+--------------------------------------------------+
| Implementation   | Short-term (< 1 month)                           |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | HIGH reduction. Eliminates the risk of former    |
| Reduction        | employees retaining access to PHI and critical   |
|                  | systems.                                         |
+------------------+--------------------------------------------------+
| Trade-offs       | Requires HR department coordination. The         |
|                  | integration must be carefully tested.           |
+------------------+--------------------------------------------------+


-------------------------------------------------------------------------------
GAP-002: NO INCIDENT RESPONSE PLAN
-------------------------------------------------------------------------------

+------------------+--------------------------------------------------+
| Gap ID           | GAP-002                                          |
+------------------+--------------------------------------------------+
| Gap Title        | No Incident Response Plan                        |
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Treatment        | MITIGATE (partial)                               |
| Strategy         |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Breach 1 had 11 days of EHR downtime and $5M     |
|                  | recovery costs because there was NO IR plan.     |
|                  | MedDefense's January ransomware incident was     |
|                  | handled ad-hoc over 4 days. A documented IR plan |
|                  | is essential for reducing recovery time and cost.|
+------------------+--------------------------------------------------+
| Proposed         | 1. Document formal IR plan (Administrative /     |
| Control(s)       |    Corrective)                                   |
|                  | 2. Tabletop exercises (2x/year) (Administrative  |
|                  |    / Corrective)                                 |
|                  | 3. Annual plan review (Administrative /          |
|                  |    Corrective)                                   |
+------------------+--------------------------------------------------+
| Estimated Cost   | $2,000 (documentation + coordination)            |
+------------------+--------------------------------------------------+
| Implementation   | Short-term (< 1 month)                           |
| Effort           |                                                  |
+------------------+--------------------------------------------------+
| Expected Risk    | MODERATE reduction. Reduces recovery time and    |
| Reduction        | cost. A plan is only useful if practiced.        |
+------------------+--------------------------------------------------+
| Trade-offs       | An untested plan is equivalent to NO plan.       |
|                  | Requires ongoing commitment to practice.        |
+------------------+--------------------------------------------------+


================================================================================
3. BUDGET SUMMARY
================================================================================

+----------+------------------+----------------------------------------+------------------+------------------+
| Priority | Gap ID           | Proposed Control(s)                    | Estimated Cost   | Effort           |
+----------+------------------+----------------------------------------+------------------+------------------+
| #1       | GAP-007          | Network Segmentation + App             | $10,000          | Quick Win        |
|          |                  | Whitelisting + Host Firewall           |                  | (< 1 week)       |
+----------+------------------+----------------------------------------+------------------+------------------+
| #2       | GAP-003          | IoT VLAN + Monitoring                  | $12,000          | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #3       | GAP-014          | Patch Management Program               | $2,000           | Quick Win        |
|          |                  |                                        |                  | (< 1 week)       |
+----------+------------------+----------------------------------------+------------------+------------------+
| #4       | GAP-001          | Wazuh SIEM (open-source) + Alerts      | $5,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #5       | GAP-004          | MFA (Azure AD Premium P1)              | $8,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #6       | GAP-015          | HR → IT Offboarding Integration        | $3,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
| #7       | GAP-002          | IR Plan Documentation + Tabletop       | $2,000           | Short-term       |
|          |                  |                                        |                  | (< 1 month)      |
+----------+------------------+----------------------------------------+------------------+------------------+
|          |                  | TOTAL                                  | $42,000          |                  |
+----------+------------------+----------------------------------------+------------------+------------------+

+----------------------------------------------------------------------------+
| BUDGET OVERVIEW                                                            |
|                                                                             |
| Total Budget:                    $120,000                                   |
| Total Mitigation Costs:          $42,000                                    |
| Budget Remaining:                $78,000                                    |
|                                                                             |
| The remaining $78,000 can be allocated to:                                  |
| - Contingency for unexpected costs ($20,000)                               |
| - Future year initiatives:                                                 |
|   - Commercial SIEM upgrade if Wazuh insufficient ($50,000)               |
|   - Advanced EDR for servers ($30,000)                                    |
|   - Security awareness training program ($15,000)                         |
+----------------------------------------------------------------------------+


================================================================================
4. DEFERRAL PLAN (IF BUDGET EXCEEDED)
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap ID           | Deferral Strategy                      | Justification    |
+----------+------------------+----------------------------------------+------------------+
| #1       | GAP-007          | DO NOT DEFER                           | Life-safety risk |
|          |                  |                                        | $40M+ potential  |
|          |                  |                                        | loss             |
+----------+------------------+----------------------------------------+------------------+
| #2       | GAP-003          | DO NOT DEFER                           | Life-safety risk |
|          |                  |                                        | Patient safety   |
+----------+------------------+----------------------------------------+------------------+
| #3       | GAP-014          | DO NOT DEFER                           | Low cost, high   |
|          |                  |                                        | impact           |
+----------+------------------+----------------------------------------+------------------+
| #4       | GAP-001          | Defer to next fiscal year if budget   | Wazuh open-source|
|          |                  | insufficient                           | is acceptable    |
|          |                  |                                        | alternative      |
+----------+------------------+----------------------------------------+------------------+
| #5       | GAP-004          | Defer to next fiscal year if budget   | Phased deployment|
|          |                  | insufficient                           | (VPN first)      |
+----------+------------------+----------------------------------------+------------------+
| #6       | GAP-015          | Defer to next fiscal year if budget   | Manual process   |
|          |                  | insufficient                           | temporarily      |
+----------+------------------+----------------------------------------+------------------+
| #7       | GAP-002          | Defer to next fiscal year if budget   | Important but    |
|          |                  | insufficient                           | not life-safety  |
+----------+------------------+----------------------------------------+------------------+

Justification for Deferrals:
- GAP-001 (SIEM): Wazuh open-source provides a viable stopgap at $5K
- GAP-004 (MFA): Can be phased in starting with VPN access only
- GAP-015 (Offboarding): Manual process with HR oversight is acceptable temporarily
- GAP-002 (IR Plan): Can be documented with minimal resources even if budget is tight


================================================================================
5. EXECUTIVE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
|                                                                             |
| THE PROBLEM:                                                               |
| MedDefense has 7 CRITICAL gaps that expose the organization to patient     |
| safety risks, PHI breaches, and regulatory penalties.                     |
|                                                                             |
| THE BUDGET:                                                                |
| $120,000 annual security budget.                                          |
|                                                                             |
| THE SOLUTION:                                                              |
| $42,000 allocated to the TOP 7 priorities.                                 |
| $78,000 remaining for contingency and future initiatives.                 |
|                                                                             |
| TOP 3 IMMEDIATE PRIORITIES:                                                |
| 1. MRI Windows XP Compensating Controls ($10K) - Life-safety risk         |
| 2. Medical IoT Network Segmentation ($12K) - Patient safety risk           |
| 3. Patch Management Program ($2K) - Prevents perimeter breaches           |
|                                                                             |
| WHY THESE DECISIONS:                                                       |
| All three breaches validated that:                                         |
| - Flat networks enable lateral movement                                   |
| - Unpatched perimeter devices are entry points                            |
| - No detection means extended dwell time                                  |
| - No IR plan means extended recovery                                      |
|                                                                             |
| If MedDefense implements these 7 controls for $42K, the organization      |
| will have:                                                                 |
| - Compensated for the MRI Windows XP vulnerability                        |
| - Segmented IoT devices from the flat network                             |
| - Established a patch management program                                 |
| - Deployed basic detection (Wazuh)                                        |
| - Implemented MFA for critical systems                                    |
| - Automated user offboarding                                               |
| - Documented an IR plan                                                   |
|                                                                             |
| NIST SP 800-30 Risk Treatment Framework:                                   |
| All 7 gaps are being MITIGATED. The risk is reduced to an acceptable      |
| level within the $120K budget.                                            |
+----------------------------------------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. All 7 gaps are CRITICAL and require mitigation. There are no gaps
   suitable for Transfer, Accept, or Avoid at this time.

2. Total mitigation cost ($42K) is well within the $120K budget.

3. The top 3 priorities (MRI, IoT, Patch Management) address life-safety
   risks and perimeter vulnerabilities.

4. $78K remains available for contingency and future initiatives.

5. Wazuh open-source SIEM provides a cost-effective detection solution
   ($5K vs $80K for commercial SIEM).

6. All 7 controls can be implemented within 1 month (Quick Wins + Short-term).

7. This plan is Board-ready: it shows specific gaps, specific controls,
   specific costs, and specific risk reduction.

8. The plan is supported by real-world breach data (Task 13) that validates
   these priorities.


================================================================================
7. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Risk Treatment
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Respond Function
- ISO 27001: A.8.2 (Risk Treatment)
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices

Sources: Task 12 Gap Analysis, Task 13 Reality Check, healthcare-breach-summaries.txt


================================================================================
END OF RISK DECISIONS REPORT
================================================================================
