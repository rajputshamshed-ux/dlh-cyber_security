================================================================================
                    RED TEAM YOUR BLUEPRINT - MEDDEFENSE HEALTH SYSTEMS
                    Task 15: Red Team Your Blueprint
================================================================================

Exercise: Task 15 - Red Team Your Blueprint
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Attack your own security strategy to find its weaknesses before an
          adversary does.

Sources: 1x01 Kill Chains, 1x01 Threat Actor Matrix, 1x03 Budget Allocation (T8),
         1x03 Control Selection (T11), 1x03 Segmentation Architecture (T14)

Assumption: All controls from T8 are fully implemented:
- Network Segmentation (6 VLANs)
- MFA on VPN and administrative accounts
- SIEM (Wazuh)
- EDR on all servers
- Offsite immutable backups
- Daytime-Only SOC


================================================================================
PART 1: THE ATTACKER'S PERSPECTIVE
================================================================================

CONTEXT: I am a BlackReef ransomware affiliate. I have studied MedDefense's
defenses. I know they have implemented segmentation, MFA, SIEM, EDR, and
offsite backups. I also know what they DID NOT fund: Medical IoT Isolation,
Westside Firewall, and 24/7 SOC.

WHICH KILL CHAIN IS STILL VIABLE?
---------------------------------
+----------------------------------------------------------------------------+
| KILL CHAIN #4: WINDOWS XP MRI → PIVOT TO EHR                              |
|                                                                             |
| Why this kill chain is STILL viable:                                       |
|                                                                             |
| 1. The MRI workstation runs Windows XP (EOL 2014) with weaponized         |
|    exploits (EternalBlue, BlueKeep).                                     |
|                                                                             |
| 2. MRI Isolation was NOT funded (deferred from T8). The MRI is still on  |
|    the network with the Medical Device Zone (VLAN 30).                   |
|                                                                             |
| 3. Once I compromise the MRI, I can leverage the flat network            |
|    vulnerability within the Medical Device Zone.                          |
|                                                                             |
| 4. From the Medical Device Zone, I can pivot to the Server Zone through   |
|    the PACS communication path (port 11112) which must remain open for   |
|    clinical operations.                                                   |
|                                                                             |
| 5. The MRI has no EDR (Windows XP cannot run modern EDR).                 |
|                                                                             |
| 6. The Daytime-Only SOC (8am-6pm) means my attack at 2am goes            |
|    undetected until morning.                                              |
+----------------------------------------------------------------------------+

ALTERNATIVE ATTACK PATH (4-5 STEPS)
-----------------------------------
+----------------------------------------------------------------------------+
| ALTERNATIVE ATTACK PATH: MRI → EHR PIVOT                                   |
|                                                                             |
| Step 1 - Reconnaissance:                                                   |
| Scan the network for Windows XP systems. Discover the MRI workstation     |
| on the Medical Device Zone (VLAN 30). Identify open ports 445 (SMB)      |
| and 3389 (RDP).                                                           |
|                                                                             |
| Step 2 - Initial Access:                                                  |
| Exploit EternalBlue (CVE-2017-0144) on the MRI workstation. Gain         |
| SYSTEM-level access. The MRI has NO EDR and NO compensating controls.    |
|                                                                             |
| Step 3 - Establish Foothold:                                              |
| Install a backdoor and maintain persistence. The MRI is in the Medical   |
| Device Zone but I can move within that zone freely.                      |
|                                                                             |
| Step 4 - Pivot to Server Zone:                                            |
| Use the MRI's legitimate access to the PACS server (port 11112) to pivot |
| to the Server Zone. The PACS server must communicate with the MRI for   |
| clinical operations. I compromise the PACS server.                      |
|                                                                             |
| Step 5 - Access EHR:                                                      |
| From the PACS server, move to ehr-db-01. The PACS server has legitimate  |
| access to the EHR for patient data. I exfiltrate PHI and deploy          |
| ransomware.                                                               |
+----------------------------------------------------------------------------+
| GAPS EXPLOITED:                                                            |
| - GAP-007 (No Compensating Controls for MRI) - DEFERRED                 |
| - GAP-003 (Medical IoT on Flat Network) - PARTIAL (segmented but not    |
|   isolated from critical communication paths)                            |
| - Daytime-Only SOC (night attack = no detection)                         |
| - No 24/7 monitoring                                                    |
+----------------------------------------------------------------------------+

INSIDER THREAT SCENARIO REMAINING DANGEROUS
-------------------------------------------
+----------------------------------------------------------------------------+
| INSIDER THREAT: NEGLIGENT DATA EXFILTRATION                               |
|                                                                             |
| Despite the new controls, the following insider threat remains dangerous: |
|                                                                             |
| 1. USB restrictions GPO is implemented (Quick Win #4), but DLP was       |
|    deferred (from T8).                                                   |
|                                                                             |
| 2. A clinician uses their personal smartphone to take a photo of a       |
|    patient record displayed on a workstation. The photo syncs to their   |
|    personal cloud account.                                               |
|                                                                             |
| 3. No MDM for personal devices (GAP-013 from 1x00).                      |
|                                                                             |
| 4. The Daytime-Only SOC does not monitor physical security events or     |
|    unauthorized data access patterns.                                    |
|                                                                             |
| 5. Even with training (Quick Win #5), human error remains the most       |
|    difficult gap to close.                                               |
+----------------------------------------------------------------------------+
| GAPS EXPLOITED:                                                            |
| - GAP-010 (No Administrative Detective Controls - Audits) - DEFERRED    |
| - GAP-013 (No Email Filtering/Mail Rule Monitoring) - DEFERRED          |
| - No DLP (deferred from T8)                                             |
| - No MDM for personal devices (not in scope)                            |
+----------------------------------------------------------------------------+


================================================================================
PART 2: THE HONEST ASSESSMENT
================================================================================

OVERALL RESIDUAL RISK ASSESSMENT
--------------------------------
+----------------------------------------------------------------------------+
| OVERALL RESIDUAL RISK: HIGH                                                |
|                                                                             |
| Justification:                                                             |
|                                                                             |
| The implemented controls address the HIGHEST LIKELIHOOD threats           |
| (ransomware via VPN, credential theft). However, the following           |
| significant risks remain:                                                 |
|                                                                             |
| 1. MRI Windows XP remains a PERMANENT BACKDOOR (GAP-007).                |
|    The segmentation partially contains it but the PACS communication      |
|    path provides a viable pivot.                                          |
|                                                                             |
| 2. Night-time attacks are undetected (Daytime-Only SOC).                  |
|                                                                             |
| 3. Insider threats are not fully addressed (no DLP, no MDM).             |
|                                                                             |
| 4. The flat network within each zone still allows lateral movement        |
|    within that zone.                                                      |
|                                                                             |
| 5. The 80% kill chain disruption is significant, but the remaining 20%   |
|    (Kill Chain #4 and Supply Chain) are CATASTROPHIC if exploited.      |
+----------------------------------------------------------------------------+

SINGLE BIGGEST REMAINING GAP
----------------------------
+----------------------------------------------------------------------------+
| THE SINGLE BIGGEST REMAINING GAP:                                          |
|                                                                             |
| MRI WINDOWS XP (GAP-007) - NO COMPENSATING CONTROLS                       |
|                                                                             |
| Why this is the biggest remaining gap:                                     |
|                                                                             |
| 1. It is a PERMANENT, UNPATCHABLE vulnerability.                         |
| 2. It is a CRITICAL life-safety asset (45 MRI studies/day).              |
| 3. It has WEAPONIZED EXPLOITS (EternalBlue, BlueKeep, MS08-067).        |
| 4. It provides a pivot path to the EHR database.                         |
| 5. It was DEFERRED from the budget due to cost constraints.              |
| 6. The segmentation architecture partially mitigates but does NOT        |
|    eliminate the risk.                                                    |
| 7. Real-world breach (Breach 3 from 1x00 Task 13) validated $40M+        |
|    recovery costs for this exact scenario.                               |
+----------------------------------------------------------------------------+

#1 PRIORITY FOR NEXT YEAR'S BUDGET
-----------------------------------
+----------------------------------------------------------------------------+
| #1 PRIORITY FOR NEXT YEAR'S BUDGET:                                        |
|                                                                             |
| MRI WINDOWS XP COMPENSATING CONTROLS ($50,000)                             |
|                                                                             |
| Proposed actions:                                                          |
|                                                                             |
| 1. Phase 1 - IMMEDIATE: Virtualize the MRI control workstation           |
|    (cost: $5,000-$10,000). This allows the Windows XP system to run     |
|    in an isolated virtual environment with snapshots and rollback.      |
|                                                                             |
| 2. Phase 2 - SHORT-TERM: Implement full compensating controls:           |
|    - Application whitelisting (C-016 from 1x00)                         |
|    - Host-based firewall (C-017 from 1x00)                              |
|    - 24/7 network monitoring of MRI traffic (C-020 from 1x00)           |
|    (cost: $15,000)                                                       |
|                                                                             |
| 3. Phase 3 - LONG-TERM: Evaluate MRI replacement or upgrade of the      |
|    control workstation (cost: $30,000-$50,000 if replacement needed)     |
|                                                                             |
| Why this should be #1 priority:                                           |
|                                                                             |
| 1. It addresses a PERMANENT vulnerability.                               |
| 2. It protects a CRITICAL life-safety asset.                            |
| 3. It closes the remaining 20% kill chain risk.                         |
| 4. Real-world breach data validates the $40M+ cost of inaction.         |
| 5. It is the single gap that, if exploited, bypasses ALL other          |
|    implemented controls.                                                 |
+----------------------------------------------------------------------------+


================================================================================
RED TEAM SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| RED TEAM SUMMARY                                                           |
|                                                                             |
| The security blueprint survives the red team exercise, but with           |
| SIGNIFICANT RESIDUAL RISK.                                                 |
|                                                                             |
| Strengths:                                                                 |
| - Segmentation disrupts 80% of kill chains                              |
| - MFA stops credential theft                                              |
| - SIEM + Daytime SOC provides detection during business hours            |
| - Offsite backups enable recovery                                         |
|                                                                             |
| Weaknesses:                                                               |
| - MRI Windows XP is a permanent backdoor                                 |
| - Night-time attacks go undetected                                       |
| - Insider threats remain (no DLP, no MDM)                                |
| - Vendor accounts (MedTech) still have direct access                    |
|                                                                             |
| The biggest investment for next year should be MRI compensating          |
| controls. This closes the remaining 20% kill chain risk and protects     |
| patient safety.                                                           |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Kill Chains (1x01 T10)
- Threat Actor Matrix (1x01 T6)
- Budget Allocation (1x03 T8)
- Control Selection (1x03 T11)
- Segmentation Architecture (1x03 T14)
- Insider Threat Assessment (1x01 T3)
- Reality Check (1x00 T13 - Breach 3)


================================================================================
END OF RED TEAM YOUR BLUEPRINT REPORT
================================================================================
