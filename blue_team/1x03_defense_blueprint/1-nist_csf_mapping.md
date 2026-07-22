================================================================================
                    NIST CSF MAPPING - MEDDEFENSE HEALTH SYSTEMS
                    Task 1: The NIST CSF Mapping
================================================================================

Exercise: Task 1 - The NIST CSF Mapping
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Apply NIST CSF 2.0 to MedDefense by mapping the organization's
          current security posture to each of the six core functions.

Source: nist-csf-reference.txt, Projects 1x00, 1x01, 1x02


================================================================================
NIST CSF CURRENT PROFILE - MEDDEFENSE HEALTH SYSTEMS
================================================================================


FUNCTION 1: GOVERN (Establish and Monitor Security Strategy)
------------------------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: NOT IMPLEMENTED                                             |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - No formal CISO position (James Chen is Deputy CISO, acting)             |
| - No documented security strategy or roadmap                              |
| - No security governance structure or reporting chain                     |
| - Security budget was only recently approved (from 1x00)                  |
| - No risk management framework or risk register                           |
| - No security policies beyond a basic password policy (from Artifact 3)   |
| - Marcus's notes: "Nobody is looking at the security program"             |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - No formal security governance or oversight                             |
| - No documented security strategy or roadmap                             |
| - No risk management framework                                            |
| - No executive-level security champion (CISO position vacant)            |
| - No security metrics or KPIs                                             |
| - No security budget planning process                                    |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): PARTIAL                                          |
|                                                                             |
| JUSTIFICATION: MedDefense should aim to establish a basic governance      |
| structure: appoint an interim CISO (or confirm James Chen), document a   |
| security strategy based on the 1x00-1x02 findings, create a simple risk  |
| register, and establish quarterly reporting to the Board. Full "Managed"  |
| requires formal risk management framework, which is unrealistic in       |
| 6 months given the current maturity.                                     |
+----------------------------------------------------------------------------+


FUNCTION 2: IDENTIFY (Understand What You Need to Protect)
-----------------------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: PARTIAL                                                    |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - Asset inventory was created in 1x00 (Task 7) - but it did NOT exist    |
|   before you arrived (IT had scattered records)                           |
| - Asset criticality assessment was completed (1x00 Task 8)               |
| - Data map was created (1x00 Task 9)                                     |
| - Threat landscape analysis was completed (1x01)                         |
| - Gap analysis was completed (1x00 Task 12, 1x02 Task 16)               |
|                                                                             |
| However:                                                                   |
| - Asset inventory is INCOMPLETE (shadow IT discovered in 1x00 T11 and    |
|   1x02 T28/29)                                                            |
| - No formal business impact analysis (BIA)                                |
| - No supply chain risk assessment (vendor accounts)                      |
| - No formal risk assessment methodology                                  |
| - Asset inventory is not maintained (no update process)                  |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - Asset inventory is not maintained continuously                         |
| - Shadow IT discovered but not fully addressed                           |
| - No formal BIA or risk assessment process                               |
| - Supply chain risks not formally assessed                              |
| - No process to update the threat landscape regularly                    |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): MANAGED                                         |
|                                                                             |
| JUSTIFICATION: MedDefense has made significant progress in Identify      |
| through the three projects. With a formal process for asset inventory    |
| maintenance, shadow IT remediation, and regular BIA updates, MedDefense  |
| can reach "Managed" within 6 months. This is achievable because the      |
| foundational work is already done.                                       |
+----------------------------------------------------------------------------+


FUNCTION 3: PROTECT (Implement Safeguards)
-------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: PARTIAL                                                    |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - Basic preventive controls exist (firewall, AV, password policy)        |
| - 20 controls identified in 1x00 Task 4                                  |
| - Control matrix shows: 8 Preventive, 5 Detective, 1 Corrective          |
| - C-005 (SSH hardening) is the ONLY Strong control                       |
| - 40% of controls are WEAK (exist on paper, poorly implemented)          |
| - 30% of controls are PROPOSED (not implemented)                         |
| - No MFA anywhere (GAP-004)                                              |
| - No network segmentation (GAP-003)                                      |
| - No compensating controls for MRI (GAP-007)                             |
| - No patch management program (GAP-014)                                  |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - No MFA (GAP-004) - most critical protective gap                       |
| - No network segmentation (GAP-003) - amplifies all vulnerabilities      |
| - No patch management program (GAP-014)                                  |
| - No compensating controls for EOL systems (GAP-007)                    |
| - No egress filtering (GAP-008)                                          |
| - No vendor account management (GAP-012)                                |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): MANAGED                                         |
|                                                                             |
| JUSTIFICATION: MedDefense has controls but they are inconsistently       |
| implemented and poorly configured. The goal should be to move to         |
| "Managed" by:                                                             |
| - Implementing MFA (GAP-004)                                             |
| - Implementing network segmentation (GAP-003)                            |
| - Establishing a patch management program (GAP-014)                      |
| - Implementing compensating controls for MRI (GAP-007)                  |
| - Enforcing existing policies                                             |
| This is ambitious but achievable with the $120K budget.                  |
+----------------------------------------------------------------------------+


FUNCTION 4: DETECT (Find Incidents When They Happen)
-----------------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: NOT IMPLEMENTED                                            |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - NO SIEM or centralized logging (GAP-001)                               |
| - NO intrusion detection system (IDS/IPS)                                |
| - NO automated security alerting                                          |
| - NO network monitoring for IoT devices                                  |
| - NO log monitoring or review                                             |
| - Marcus's notes: "No centralized log management system exists"          |
| - Artifact 8 (Log Management): "No SIEM. No alerts. Marcus kept         |
|   talking about a SIEM... never got to install anything"                |
| - The crypto-miner on billing-srv-01 ran for weeks undetected           |
| - The January ransomware was discovered when files became inaccessible  |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - NO detection capability whatsoever                                      |
| - No visibility into security events                                     |
| - Attacks go undetected for weeks or months                              |
| - No forensic evidence (logs not preserved)                              |
| - No way to validate if controls are working                            |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): PARTIAL                                         |
|                                                                             |
| JUSTIFICATION: "Managed" detection requires a fully operational SIEM    |
| with alerting - this is unrealistic in 6 months with one analyst.        |
| MedDefense should aim for "Partial" by:                                   |
| - Deploying a basic SIEM (Wazuh open-source)                             |
| - Centralizing logs from critical systems                                |
| - Configuring basic alerts for security events                          |
| - Implementing network monitoring (C-020 from 1x00)                     |
| This is achievable within the $120K budget.                             |
+----------------------------------------------------------------------------+


FUNCTION 5: RESPOND (Act on Detected Incidents)
------------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: NOT IMPLEMENTED                                            |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - NO formal Incident Response Plan (GAP-002)                             |
| - NO tested IR procedures                                                 |
| - January ransomware incident was handled "ad-hoc" over 4 days          |
| - Marcus's notes: "No formal incident response plan exists"              |
| - No designated incident response team                                   |
| - No communication plan (internal, external, regulatory)                 |
| - No playbooks for common scenarios (ransomware, data breach)           |
| - No forensic capabilities                                                |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - NO IR plan - would be improvised during an incident                   |
| - No designated response team                                            |
| - No communication procedures                                            |
| - No forensic capabilities                                               |
| - No lessons learned process                                             |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): PARTIAL                                         |
|                                                                             |
| JUSTIFICATION: A complete IR plan with playbooks and testing is a       |
| multi-month effort. MedDefense should aim for "Partial" by:              |
| - Documenting a basic IR plan (adapted from NIST SP 800-61)             |
| - Designating response roles (James Chen leads, Sarah Park assists)     |
| - Creating communication templates (internal, Board, regulatory)        |
| - Conducting a tabletop exercise for ransomware scenario               |
| This is achievable within 6 months.                                     |
+----------------------------------------------------------------------------+


FUNCTION 6: RECOVER (Restore Operations After an Incident)
-----------------------------------------------------------

+----------------------------------------------------------------------------+
| CURRENT LEVEL: NOT IMPLEMENTED                                            |
+----------------------------------------------------------------------------+
| EVIDENCE:                                                                  |
| - NO Disaster Recovery Plan documented (GAP-002)                         |
| - NO Business Continuity Plan documented                                 |
| - NO tested recovery procedures                                           |
| - Marcus's notes: "No business continuity plan. No disaster recovery    |
|   plan. If Central loses power beyond what the UPS can handle (about    |
|   20 minutes), there is no documented procedure"                        |
| - Backups exist (C-009) but NOT tested                                   |
| - Full DR test: "Never performed" (Artifact 5)                          |
| - Backups are co-located (C-009 weakness)                               |
+----------------------------------------------------------------------------+
| KEY GAPS:                                                                  |
| - No BCP or DR plan                                                      |
| - Backups not tested                                                     |
| - Backups co-located with production systems                            |
| - No offsite/cloud backups                                               |
| - No RTO/RPO defined for critical systems                               |
| - No alternate site or cloud failover                                   |
+----------------------------------------------------------------------------+
| TARGET LEVEL (6 MONTHS): PARTIAL                                         |
|                                                                             |
| JUSTIFICATION: A full DR plan with testing and alternate sites is a     |
| long-term effort. MedDefense should aim for "Partial" by:               |
| - Documenting a basic DR plan for critical systems (EHR, billing)       |
| - Defining RTO/RPO for critical assets                                   |
| - Testing backup restoration for at least one critical system           |
| - Implementing offsite/immutable backups                                 |
| - Documenting the BCP for clinical operations                           |
| This is achievable within 6 months.                                     |
+----------------------------------------------------------------------------+


================================================================================
CURRENT PROFILE SUMMARY
================================================================================

+------------------+---------------------+------------------------------------------+
| Function         | Current Level       | Target Level (6 Months)                  |
+------------------+---------------------+------------------------------------------+
| GOVERN           | NOT IMPLEMENTED     | PARTIAL                                  |
+------------------+---------------------+------------------------------------------+
| IDENTIFY         | PARTIAL             | MANAGED                                  |
+------------------+---------------------+------------------------------------------+
| PROTECT          | PARTIAL             | MANAGED                                  |
+------------------+---------------------+------------------------------------------+
| DETECT           | NOT IMPLEMENTED     | PARTIAL                                  |
+------------------+---------------------+------------------------------------------+
| RESPOND          | NOT IMPLEMENTED     | PARTIAL                                  |
+------------------+---------------------+------------------------------------------+
| RECOVER          | NOT IMPLEMENTED     | PARTIAL                                  |
+------------------+---------------------+------------------------------------------+


================================================================================
CALIBRATION NOTES
================================================================================

+----------------------------------------------------------------------------+
| CALIBRATION POINTS:                                                         |
|                                                                             |
| 1. IDENTIFY: MedDefense had NO asset inventory before 1x00. The inventory  |
|    was built from scattered documentation. This is why Identify is        |
|    rated PARTIAL - the work was done but is not maintained.               |
|                                                                             |
| 2. PROTECT: The vulnerability scan revealed the state of protective       |
|    controls. 40% are WEAK, 30% are PROPOSED. Only 1 control is STRONG.   |
|    This is why Protect is PARTIAL - controls exist but are poorly         |
|    implemented.                                                            |
|                                                                             |
| 3. DETECT: Marcus's notes explicitly stated "No centralized log           |
|    management system exists." This is why Detect is NOT IMPLEMENTED.     |
|    There is zero monitoring capability.                                   |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- nist-csf-reference.txt
- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment (1x02)
- NIST CSF 2.0: https://www.nist.gov/cyberframework

Cross-References:
- Asset Registry (1x00 Task 7)
- Gap Analysis (1x00 Task 12)
- Control Matrix (1x00 Task 10)
- Threat Actor Matrix (1x01 Task 6)


================================================================================
END OF NIST CSF MAPPING REPORT
================================================================================
