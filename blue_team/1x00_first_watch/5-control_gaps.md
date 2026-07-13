================================================================================
                    CONTROL GAPS ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 5: The Missing Pieces
================================================================================

Exercise: Task 5 - The Missing Pieces
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Identify systemic gaps in a control framework by analyzing what
          is absent, not just what is present.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST CSF 2.0: Identify Function
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare security practices

Source: Control Summary Matrix (Task 4) + meddefense-controls-artifacts.txt


================================================================================
1. CONTROL SUMMARY MATRIX (FROM TASK 4)
================================================================================

+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
|                  | Preventive      | Detective       | Corrective      | Compensating     | Deterrent       |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Technical        | C-001, C-002,   | C-004, C-008,   | C-009            | [EMPTY]          | [EMPTY]         |
|                  | C-003, C-005,   | C-010, C-014    |                  |                  |                 |
|                  | C-008           |                 |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Administrative   | C-006, C-007,   | [EMPTY]         | [EMPTY]         | [EMPTY]          | [EMPTY]         |
|                  | C-013           |                 |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Physical         | [EMPTY]         | C-011, C-012    | [EMPTY]         | [EMPTY]          | C-011, C-012    |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+


================================================================================
2. IDENTIFIED CONTROL GAPS
================================================================================

GAP ID: G-001
Gap Description: No detective controls for critical servers (EHR, PACS, billing).
                No SIEM, no log monitoring, no alerting for suspicious activity
                on core infrastructure. While firewalls log some traffic, logs
                are not forwarded or analyzed in real-time.
Category x Function Missing: Technical - Detective
Affected Asset(s) or Zone: ehr-srv-01, ehr-db-01, pacs-srv-01, billing-srv-01,
                          ad-dc-01/02, backup-srv-01
Risk if Unaddressed: An attacker could compromise a critical server (EHR,
                     billing, PACS) and remain undetected for months.
                     (NIST SP 800-12: Confidentiality and Integrity violations
                     would go unnoticed). The crypto-miner on billing-srv-01
                     was not detected by any active monitoring.
Evidence: Artifact 8 (Log Management): "No centralized log management system
          exists. No automated alerting." No detective controls in Technical
          category for servers (Matrix cell empty). The crypto-miner ran
          for weeks without detection. Artifact 1: Firewall logs stored
          locally only.

SOURCE: Matrix - Technical Detective cell (only C-004 firewall logging,
        C-008/010 Sophos for workstations, C-014 AD logging without alerting)


GAP ID: G-002
Gap Description: No administrative detective controls. No security audits,
                compliance reviews, log reviews, vulnerability assessments,
                penetration tests or periodic security assessments are
                conducted. No formal process to identify weaknesses.
Category x Function Missing: Administrative - Detective
Affected Asset(s) or Zone: Entire organization (all systems, processes, staff)
Risk if Unaddressed: Without administrative detective controls, systemic
                     weaknesses go unidentified. Policies may be outdated or
                     ineffective. The organization has no way to measure its
                     security posture or track improvements over time.
                     (ISO 27001 Gap Analysis: Without audits, gaps remain
                     invisible). HIPAA compliance has never been assessed.
Evidence: Artifact 3: Password policy "Last reviewed: 18 months ago."
          Artifact 4: "No MDM deployed." Marcus notes: "HIPAA compliance
          has never been formally assessed." Artifact 7: Training last
          conducted 10 months ago. No compliance audits documented in any
          artifact.

SOURCE: Matrix - Administrative Detective cell (EMPTY)


GAP ID: G-003
Gap Description: No administrative corrective controls. No incident response
                plan, no business continuity plan, no disaster recovery plan.
                No formal process to respond to, contain, or recover from
                security incidents.
Category x Function Missing: Administrative - Corrective
Affected Asset(s) or Zone: Entire organization (all systems, all patients,
                          all operations)
Risk if Unaddressed: When a major incident occurs (ransomware, data breach,
                     system outage), the organization has no structured
                     response. The January ransomware incident was handled
                     "ad-hoc" over 4 days. This dramatically increases recovery
                     time, business impact, and regulatory exposure.
                     (NIST SP 800-61: Without IR plan, response is chaotic).
Evidence: Artifact 5: "Full DR test: Never performed." Marcus notes: "No
          formal incident response plan exists. When the ransomware hit
          billing-srv-01 in January, the response was ad-hoc." Artifact 8:
          No SIEM, no alerts. Artifact 5: "No offsite/cloud backup."

SOURCE: Matrix - Administrative Corrective cell (EMPTY)


GAP ID: G-004
Gap Description: No physical preventive controls. Server room has no restricted
                badge access (same generic badge for everyone). Network closets
                have no locks. No cameras in server room or network closet
                areas. No visitor logs.
Category x Function Missing: Physical - Preventive
Affected Asset(s) or Zone: Server room (all Central servers), network closets
                          (switches, patch panels), IT infrastructure
Risk if Unaddressed: Unauthorized individuals can physically access servers
                     and network infrastructure. They can steal, damage, or
                     compromise equipment. An attacker can install malicious
                     hardware or plug into network ports. Physical access
                     bypasses ALL technical controls.
                     (NIST SP 800-53 PE-3: Physical access control is fundamental)
Evidence: Observation 1 from Walk-through: "Door uses same generic badge that
          every employee receives. No camera. No visitor log." Observation 2:
          "Network closet has no lock. Door is ajar." Artifact 6: No cameras
          in server room area. Artifact 6: No guard patrols.

SOURCE: Matrix - Physical Preventive cell (EMPTY)


GAP ID: G-005
Gap Description: No compensating controls for unpatchable critical systems.
                MRI scanner runs Windows XP (5+ years unsupported). CT scanner
                OS unknown. These critical medical devices cannot be patched
                and have no compensating controls (isolation, network
                segmentation, application whitelisting, host-based firewall).
Category x Function Missing: Technical - Compensating
Affected Asset(s) or Zone: MRI scanner (Windows XP), CT scanner (OS unknown),
                          potentially other medical IoT devices (patient
                          monitors, infusion pumps)
Risk if Unaddressed: The MRI scanner running Windows XP is a "CRITICAL"
                     vulnerability as documented by Marcus. An attacker who
                     compromises any system on the flat network can exploit
                     known vulnerabilities in Windows XP to pivot to the MRI.
                     The device could be disabled, manipulated, or used as a
                     pivot point. (CISA Healthcare Guide: Medical device
                     security is critical for patient safety)
Evidence: Artifact 2 (IT Asset List): "MRI scanner: CRITICAL -- runs Windows XP."
          Marcus notes: "See separate file." (File not provided). Network
          Diagram: MRI on same flat network (10.10.0.0/16). No VLANs.
          No documented compensating controls in any artifact.

SOURCE: Matrix - Technical Compensating cell (EMPTY)


GAP ID: G-006
Gap Description: No technical detective controls for medical IoT devices.
                Patient monitors, infusion pumps, MRI, CT scanner are on
                the same network with no monitoring. No network monitoring
                for medical device traffic. No alerts for anomalous behavior.
Category x Function Missing: Technical - Detective (for IoT)
Affected Asset(s) or Zone: ~80 Philips patient monitors, ~120 BD Alaris pumps,
                          1 MRI scanner (Windows XP), 1 CT scanner, other
                          IoT medical devices
Risk if Unaddressed: An attacker could compromise a medical IoT device without
                     detection. Patient monitor readings could be manipulated,
                     infusion pump dosages altered, or devices disabled.
                     This creates life-safety risks for patients.
                     (HHS HICP: Medical device security is a healthcare
                     priority). The flat network means no network segmentation
                     to limit access.
Evidence: Artifact 2: IoT devices documented as connected to same network.
          Artifact 5 (Network Diagram): Everything on 10.10.0.0/16, No VLANs.
          Marcus notes: "Those Philips monitors are on the same network as
          everything else. The infusion pumps too. If someone gets on the
          network they can reach the pumps." Artifact 8: No log management
          or monitoring of any kind.

SOURCE: Matrix - Technical Detective cell (no IoT coverage)


GAP ID: G-007
Gap Description: No administrative deterrent controls. No clear disciplinary
                policies for security violations. No enforcement of
                consequences for policy violations. No executive-level
                accountability for security.
Category x Function Missing: Administrative - Deterrent
Affected Asset(s) or Zone: All employees, contractors, vendors
Risk if Unaddressed: Without consequences, employees may not take security
                     seriously. Shared accounts continue ("raduser/radiology1").
                     Staff stay logged into EHR between shifts (sign says
                     "do not log out"). Propped fire doors go unreported.
                     Security culture is weak. (NIST SP 800-53 AT-2: Training
                     and awareness require reinforcement)
Evidence: Artifact 3: Shared account policy exists but "radiology uses
          'raduser / radiology1'... Nothing happened" (Marcus notes).
          Artifact 7: 58-71% training completion rates. James Chen email
          to HR: "58% completion at Westside is unacceptable."
          Observation 3: Sign "For efficiency, please do not log out between
          shifts" - encourages insecure behavior.

SOURCE: Matrix - Administrative Deterrent cell (EMPTY)


GAP ID: G-008
Gap Description: No physical corrective controls. No fire suppression system
                documented. No backup power testing. No physical recovery
                procedures for fire, flood, or other physical disasters.
Category x Function Missing: Physical - Corrective
Affected Asset(s) or Zone: Server room (Central), network closets, all IT
                          infrastructure, patient care systems
Risk if Unaddressed: A physical incident (fire, flood, power outage) would
                     destroy critical infrastructure. No documented recovery
                     procedure. The backup NAS is in the same room as servers
                     (fire would destroy both). UPS has about 20 minutes
                     capacity with no documented procedure when it fails.
                     (NIST SP 800-53 CP-2: Business continuity requires
                     physical recovery planning)
Evidence: Artifact 5: "NAS is in the same server room, on the same network,
          same rack. If we lose the room, we lose both." Marcus notes:
          "If Central loses power beyond what the UPS can handle (about 20
          minutes), there is no documented procedure for clinical operations."
          Artifact 6: No cameras in server room. No fire suppression systems
          documented. No physical recovery procedures in any artifact.

SOURCE: Matrix - Physical Corrective cell (EMPTY)


================================================================================
3. GAP SUMMARY TABLE
================================================================================

+----------+--------------------------------------------------+-----------------------------+------------------+
| Gap ID   | Gap Description                                  | Category x Function Missing | Severity         |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-001    | No detective controls for critical servers       | Technical - Detective       | CRITICAL         |
|          | (EHR, PACS, billing, AD, backup)                |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-002    | No administrative detective controls             | Administrative - Detective  | CRITICAL         |
|          | (audits, compliance reviews, assessments)       |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-003    | No administrative corrective controls            | Administrative - Corrective | CRITICAL         |
|          | (IR plan, BCP, DR plan)                         |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-004    | No physical preventive controls                  | Physical - Preventive       | CRITICAL         |
|          | (restricted badge access, locks, cameras)       |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-005    | No compensating controls for unpatchable        | Technical - Compensating    | CRITICAL         |
|          | systems (MRI Windows XP, CT scanner)            |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-006    | No detective controls for medical IoT devices   | Technical - Detective       | CRITICAL         |
|          | (monitors, pumps, imaging equipment)            | (IoT coverage)              |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-007    | No administrative deterrent controls             | Administrative - Deterrent  | HIGH             |
|          | (disciplinary policies, enforcement)            |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+
| G-008    | No physical corrective controls                  | Physical - Corrective       | HIGH             |
|          | (fire suppression, recovery procedures)         |                             |                  |
+----------+--------------------------------------------------+-----------------------------+------------------+


================================================================================
4. PATTERN ANALYSIS - THE BIG PICTURE
================================================================================

4.1 CONTROL DISTRIBUTION PATTERN
--------------------------------
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
|                  | Preventive      | Detective       | Corrective      | Compensating     | Deterrent       |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Technical        | 5 controls      | 3 controls      | 1 control       | 0 controls       | 0 controls      |
|                  | (C-001, C-002,  | (C-004, C-008,  | (C-009)         |                  |                 |
|                  | C-003, C-005,   | C-010, C-014)   |                 |                  |                 |
|                  | C-008)          |                 |                 |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Administrative   | 3 controls      | 0 controls      | 0 controls      | 0 controls       | 0 controls      |
|                  | (C-006, C-007,  |                 |                 |                  |                 |
|                  | C-013)          |                 |                 |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Physical         | 0 controls      | 2 controls      | 0 controls      | 0 controls       | 2 controls      |
|                  |                 | (C-011, C-012)  |                 |                  | (C-011, C-012)  |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+

4.2 OBSERVED PATTERNS
---------------------
+----------------------------------------------------------------------------+
| PATTERN 1: PREVENTION HEAVY, DETECTION LIGHT                               |
|                                                                             |
| Preventive controls dominate (8 controls). Detective controls (5) are      |
| underdeveloped. Corrective (1), Compensating (0), Deterrent (2) are        |
| severely lacking.                                                           |
|                                                                             |
| This means MedDefense focuses on stopping incidents but has limited        |
| ability to know when they happen or what to do about them.                 |
+----------------------------------------------------------------------------+
| PATTERN 2: TECHNICAL OVER ADMINISTRATIVE/PHYSICAL                          |
|                                                                             |
| Technical controls (10) far exceed Administrative (3) and Physical (2).   |
| The organization relies on technology to solve security problems but      |
| lacks policies, procedures, and physical safeguards.                       |
+----------------------------------------------------------------------------+
| PATTERN 3: THE DETECTIVE GAP ACROSS ALL CATEGORIES                        |
|                                                                             |
| Detective controls are weak across ALL categories:                         |
| - Technical: Firewall logs only (no SIEM/alerts)                          |
| - Administrative: None (no audits, no assessments)                        |
| - Physical: Cameras are self-monitored (no active monitoring)             |
+----------------------------------------------------------------------------+
| PATTERN 4: NO COMPENSATING CONTROLS ANYWHERE                              |
|                                                                             |
| Compensating controls are completely absent in all categories.             |
| This is critical for healthcare where unpatchable devices (MRI Windows    |
| XP) are common. No alternative controls exist.                            |
+----------------------------------------------------------------------------+
| PATTERN 5: CORRECTIVE CONTROLS ARE ISOLATED                               |
|                                                                             |
| The only corrective control is Veeam backups (Technical).                 |
| No administrative corrective (IR plan, BCP, DR plan).                      |
| No physical corrective (fire suppression, recovery procedures).            |
| Recovery from a major incident would be chaotic.                          |
+----------------------------------------------------------------------------+

4.3 ANSWER: WHAT PATTERN DO YOU SEE ?
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense's security posture is PREVENTION-ORIENTED but lacks            |
| adequate DETECTION and CORRECTIVE controls.                               |
|                                                                             |
| The organization has invested in stopping attacks (firewall, AV, SSH      |
| hardening, password policies) but has almost no ability to know when      |
| an attack succeeds (no SIEM, no audits, no monitoring) or what to do      |
| when it does (no IR plan, no BCP, no DR plan).                            |
|                                                                             |
| IMPLICATION:                                                               |
| If an attacker bypasses preventive controls, MedDefense has:              |
| - No way to detect the breach (no detective controls)                     |
| - No plan to respond (no IR/BCP/DR)                                       |
| - No way to recover (backups only, not tested)                            |
| - No alternative controls (no compensating controls)                      |
|                                                                             |
| This means a single successful attack could cause catastrophic damage     |
| before anyone even knows it happened.                                     |
+----------------------------------------------------------------------------+


================================================================================
5. KEY FINDINGS - SYSTEMIC BLIND SPOTS
================================================================================

1. The organization is PREVENTION-HEAVY and DETECTION-LIGHT.
   (NIST CSF 2.0: Detection is a core function of cybersecurity)

2. Detective controls are missing in ALL categories:
   - Technical: No SIEM/log monitoring for servers
   - Administrative: No audits or assessments
   - Physical: No active camera monitoring

3. Compensating controls do not exist in ANY category.
   Critical for healthcare (unpatchable devices like MRI Windows XP).

4. Administrative controls are severely underrepresented.
   Only 3 of 14 controls are administrative.

5. Corrective controls are limited to backups (no testing).
   No IR plan, BCP, or DR plan documented.

6. Physical security has significant gaps:
   - No preventive controls (locks, restricted access)
   - No corrective controls (fire suppression, recovery)

7. The flat network (10.10.0.0/16) means ALL gaps are amplified.
   Compromise of any system = compromise of all systems.


================================================================================
6. PRIORITIZED RECOMMENDATIONS
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap              | Recommended Action                    | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | G-001            | Deploy SIEM and centralized logging.  | NIST SP 800-53   |
|          | (No server       | Implement alerts for critical events. | AU-6             |
|          |  detection)      |                                        |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | G-003            | Develop and test Incident Response,   | NIST SP 800-53   |
|          | (No IR/BCP/DR)   | BCP, and DR plans.                    | IR-8, CP-2       |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | G-004            | Implement restricted badge access to  | NIST SP 800-53   |
|          | (No physical     | server room. Install cameras. Visitor | PE-3, PE-6       |
|          |  preventive)     | log.                                   |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | G-005            | Implement compensating controls for   | NIST SP 800-53   |
|          | (No compensating)| MRI Windows XP: isolate from network, | SC-7             |
|          |                  | application whitelisting.             |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | G-006            | Implement network monitoring for      | NIST SP 800-53   |
|          | (No IoT          | medical IoT traffic. Deploy network   | SI-4             |
|          |  detection)      | segmentation.                          |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | G-002            | Conduct formal security assessments   | NIST SP 800-53   |
|          | (No admin        | and compliance audits.                 | RA-5, CA-2       |
|          |  detective)      |                                        |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | G-007            | Implement disciplinary policy for     | NIST SP 800-53   |
|          | (No admin        | security violations. Enforce          | AT-2             |
|          |  deterrent)      | consequences.                          |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | G-008            | Install fire suppression in server    | NIST SP 800-53   |
|          | (No physical     | room. Document physical recovery      | PE-13, CP-2      |
|          |  corrective)     | procedures.                            |                  |
+----------+------------------+----------------------------------------+------------------+


================================================================================
7. KEY TAKEAWAYS
================================================================================

1. Prevention without detection is a false sense of security.
   You can stop many attacks, but the one that gets through will be invisible.

2. Detection without response is noise without action.
   Even if you detect an attack, without a plan you cannot respond effectively.

3. The flat network (10.10.0.0/16) amplifies every gap.
   A compromise anywhere becomes a compromise everywhere.

4. Compensating controls are essential in healthcare.
   Unpatchable devices (MRI Windows XP) require alternative protections.

5. Administrative controls are the foundation of security culture.
   Without policies, audits, and enforcement, technical controls are incomplete.

6. Physical security enables all other controls.
   If physical access is unrestricted, no technical or administrative control
   can be fully effective.

7. The pattern is clear: Prevention heavy, detection light, corrective absent.
   MedDefense is prepared to stop attacks but not to survive them.


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- NIST SP 800-61 Rev.2: Incident Handling
- NIST CSF 2.0: Identify Function
- CISA Healthcare and Public Health Sector Guide
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF CONTROL GAPS ANALYSIS REPORT
================================================================================
