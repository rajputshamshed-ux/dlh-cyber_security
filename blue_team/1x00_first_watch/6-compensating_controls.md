*================================================================================
                    THE LEGACY DILEMMA - MEDDEFENSE HEALTH SYSTEMS
                    Task 6: The Legacy Dilemma
================================================================================

Exercise: Task 6 - The Legacy Dilemma
Analyst: shamshed rajput 
Date: 13/07/2026

Objective: Design a compensating control strategy for a system that cannot be
          patched, upgraded or replaced, under real operational constraints.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls (SC-7, CM-3, CM-6, SI-4, IR-8, PE-3)
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function
- CISA Healthcare Guide: Healthcare threat context
- HHS HICP: Healthcare security practices

Source: Task 4 Control Matrix, Network Diagram, Walk-through Observations


================================================================================
1. ASSET CONTEXT
================================================================================

ASSET SUMMARY
--------------
+------------------+--------------------------------------------------+
| Asset            | Siemens MAGNETOM MRI Scanner                      |
+------------------+--------------------------------------------------+
| Cost             | $2.1 million                                      |
+------------------+--------------------------------------------------+
| Age              | 6 years into 12-year lifespan                     |
+------------------+--------------------------------------------------+
| OS               | Windows XP Embedded (EOL April 2014 - 12+ years)  |
+------------------+--------------------------------------------------+
| Function         | Diagnostic imaging - 45 studies/day               |
+------------------+--------------------------------------------------+
| Network Status   | Connected to PACS server, REQUIRES connectivity   |
+------------------+--------------------------------------------------+
| Network Location | Same VLAN as hospital workstations (10.10.0.0/16) |
+------------------+--------------------------------------------------+
| Certification    | Manufacturer certification tied to Windows XP     |
+------------------+--------------------------------------------------+
| Status           | CRITICAL - flagged by Marcus (sticky note)        |
+------------------+--------------------------------------------------+

CONSTRAINTS (REAL OPERATIONAL)
------------------------------
+----------------------------------------------------------------------------+
| 1. CANNOT patch the system     | Windows XP EOL - no patches available            |
| 2. CANNOT upgrade the OS       | Manufacturer certification voided                |
| 3. CANNOT replace the device   | $2.1M cost, 6 years into 12-year lifespan       |
| 4. CANNOT disconnect network   | Must transmit imaging studies to PACS           |
| 5. NO budget for replacement   | Capital expenditure not approved                 |
+----------------------------------------------------------------------------+


================================================================================
2. RISK ANALYSIS
================================================================================

Why this MRI workstation represents a CRITICAL security risk to the
ENTIRE MedDefense network:

+----------------------------------------------------------------------------+
| The MRI workstation runs Windows XP Embedded, an operating system that     |
| has not received security patches since April 2014 (12+ years). It has     |
| known, publicly disclosed vulnerabilities that are easily exploitable by   |
| attackers (e.g., EternalBlue, MS17-010).                                   |
|                                                                             |
| The MRI workstation is currently on the SAME FLAT NETWORK (10.10.0.0/16)  |
| as every other device at MedDefense Central: EHR servers, billing systems, |
| AD domain controllers, and other clinical workstations.                    |
|                                                                             |
| An attacker who compromises this unprotected Windows XP machine (via a     |
| single exploit) can pivot laterally across the entire flat network to      |
| access the EHR, billing, PACS, and other critical systems.                 |
|                                                                             |
| The MRI cannot be patched or isolated without clinical impact. This        |
| creates a permanent, unmanaged entry point into the heart of the           |
| MedDefense network that threatens ALL CIA pillars:                         |
| - Confidentiality: PHI and billing data exposed                           |
| - Integrity: Patient data modified, MRI images manipulated                |
| - Availability: MRI or other systems disabled (ransomware)                |
+----------------------------------------------------------------------------+

NIST SP 800-30 RISK COMPONENTS DECOMPOSED
------------------------------------------
+------------------+--------------------------------------------------+
| Component        | Analysis                                         |
+------------------+--------------------------------------------------+
| THREAT           | Cybercriminal, ransomware operator, or insider   |
| (NIST SP 800-30) | Exploiting known vulnerabilities in Windows XP   |
|                  | (e.g., EternalBlue, MS17-010)                    |
+------------------+--------------------------------------------------+
| VULNERABILITY    | Windows XP EOL - 12+ years unpatched             |
| (NIST SP 800-30) | Same flat network as all other hospital systems  |
|                  | No compensating controls in place                |
|                  | No network segmentation                          |
+------------------+--------------------------------------------------+
| LIKELIHOOD       | HIGH - Public exploits available, flat network   |
| (NIST SP 800-30) | makes lateral movement trivial                   |
+------------------+--------------------------------------------------+
| IMPACT           | CRITICAL - Patient safety, PHI exposure,         |
| (NIST SP 800-30) | operational disruption, regulatory fines         |
+------------------+--------------------------------------------------+
| RISK             | CRITICAL - This is a single point of failure     |
| (NIST SP 800-30) | that can compromise the ENTIRE network           |
+------------------+--------------------------------------------------+

NIST SP 800-53 CONTROL FAMILIES AT RISK:
- AC (Access Control): No restrictions on network access
- SC-7 (Boundary Protection): No segmentation protecting the MRI
- SI-2 (Flaw Remediation): Cannot patch, no compensating controls
- CM-3 (Change Control): No configuration management
- RA-5 (Vulnerability Scanning): Unpatched vulnerability


================================================================================
3. COMPENSATING CONTROL STRATEGY
================================================================================

What is a compensating control ?
--------------------------------
+----------------------------------------------------------------------------+
| NIST SP 800-53: A compensating control is an alternative control used     |
| when the ideal control is not feasible or is too costly.                  |
|                                                                             |
| In this case, the ideal control (patching Windows XP) is NOT feasible.    |
| Therefore, we must implement compensating controls to reduce risk.        |
|                                                                             |
| HHS HICP: For healthcare organizations, compensating controls are          |
| essential for legacy medical devices that cannot be updated.              |
+----------------------------------------------------------------------------+


CONTROL 1: NETWORK SEGMENTATION - ISOLATION VLAN
------------------------------------------------
+------------------+--------------------------------------------------+
| Control Name     | Network Segmentation - MRI Isolation VLAN        |
+------------------+--------------------------------------------------+
| Description      | Create a dedicated VLAN for the MRI workstation  |
|                  | and other medical imaging devices. Implement     |
|                  | strict firewall rules between the MRI VLAN and   |
|                  | the rest of the network. Allow ONLY necessary    |
|                  | traffic: PACS communication (specific ports),    |
|                  | and block ALL other traffic including internet   |
|                  | access and intra-VLAN communication to other     |
|                  | subnets.                                         |
+------------------+--------------------------------------------------+
| Category         | Technical                                        |
+------------------+--------------------------------------------------+
| Function         | Preventive and Compensating                       |
+------------------+--------------------------------------------------+
| How it reduces   | Limits the blast radius of a compromise. If the  |
| risk             | MRI is exploited, the attacker is contained in   |
|                  | the isolated VLAN and cannot pivot to the main   |
|                  | hospital network (EHR, billing, AD). Lateral     |
|                  | movement is blocked by firewall rules.           |
+------------------+--------------------------------------------------+
| Limitations /    | Requires firewall configuration changes. PACS    |
| Residual Risk    | traffic must be carefully identified. If rules   |
|                  | are too permissive, isolation fails. Residual    |
|                  | risk: MRI itself remains vulnerable, but impact  |
|                  | is contained.                                     |
+------------------+--------------------------------------------------+
| Implementation   | 1-2 weeks (firewall configuration + VLAN setup)  |
| Timeline         |                                                  |
+------------------+--------------------------------------------------+
| NIST Reference   | SP 800-53 SC-7 (Boundary Protection)            |
+------------------+--------------------------------------------------+


CONTROL 2: APPLICATION WHITELISTING
-----------------------------------
+------------------+--------------------------------------------------+
| Control Name     | Application Whitelisting (Windows XP)            |
+------------------+--------------------------------------------------+
| Description      | Implement application whitelisting on the MRI    |
|                  | workstation. Allow ONLY approved applications    |
|                  | (MRI control software, PACS client, required     |
|                  | system files). Block ALL other executables,      |
|                  | scripts, and DLLs from running.                  |
+------------------+--------------------------------------------------+
| Category         | Technical                                        |
+------------------+--------------------------------------------------+
| Function         | Preventive and Compensating                       |
+------------------+--------------------------------------------------+
| How it reduces   | Even if an attacker exploits a vulnerability to  |
| risk             | execute code on the MRI workstation, the         |
|                  | whitelisting prevents execution of malware,      |
|                  | ransomware, or tools needed for lateral          |
|                  | movement. The attacker cannot run their payload. |
+------------------+--------------------------------------------------+
| Limitations /    | Requires careful initial configuration.          |
| Residual Risk    | Whitelisting can be bypassed if the attacker     |
|                  | exploits a vulnerability in an allowed           |
|                  | application. Residual risk: system remains       |
|                  | vulnerable, but exploitation is much harder.     |
+------------------+--------------------------------------------------+
| Implementation   | 2-3 weeks (application inventory + testing)      |
| Timeline         |                                                  |
+------------------+--------------------------------------------------+
| NIST Reference   | SP 800-53 CM-6 (Configuration Settings),         |
|                  | CIS Control 2 (Software Inventory)              |
+------------------+--------------------------------------------------+


CONTROL 3: HOST-BASED FIREWALL
------------------------------
+------------------+--------------------------------------------------+
| Control Name     | Host-Based Firewall (Windows XP Firewall)        |
+------------------+--------------------------------------------------+
| Description      | Configure the Windows XP built-in firewall on    |
|                  | the MRI workstation. Block ALL inbound           |
|                  | connections except from authorized PACS server   |
|                  | IP addresses. Block ALL outbound connections     |
|                  | except to the PACS server. Disable unnecessary   |
|                  | ports and services (NetBIOS, SMB, RDP, etc.).    |
+------------------+--------------------------------------------------+
| Category         | Technical                                        |
+------------------+--------------------------------------------------+
| Function         | Preventive and Compensating                       |
+------------------+--------------------------------------------------+
| How it reduces   | Reduces the attack surface by blocking inbound   |
| risk             | connections to vulnerable services (SMB, NetBIOS)|
|                  | that are commonly exploited (e.g., EternalBlue). |
|                  | Limits the ability of an attacker to connect to  |
|                  | the MRI from the network.                        |
+------------------+--------------------------------------------------+
| Limitations /    | Windows XP firewall has limited capabilities     |
| Residual Risk    | compared to modern firewalls. If an attacker     |
|                  | gains access via an allowed service (PACS),      |
|                  | firewall is bypassed. Residual risk: attacker    |
|                  | could still exploit allowed services.            |
+------------------+--------------------------------------------------+
| Implementation   | 1 day (configuration change)                     |
| Timeline         |                                                  |
+------------------+--------------------------------------------------+
| NIST Reference   | SP 800-53 SC-7 (Boundary Protection)            |
+------------------+--------------------------------------------------+


CONTROL 4: PHYSICAL ACCESS RESTRICTION
--------------------------------------
+------------------+--------------------------------------------------+
| Control Name     | Physical Access Restriction - MRI Room           |
+------------------+--------------------------------------------------+
| Description      | Restrict physical access to the MRI suite and    |
|                  | the MRI workstation. Implement badge-only        |
|                  | access for authorized radiology staff. Install   |
|                  | a camera in the MRI workstation area. Maintain   |
|                  | a visitor log for anyone entering the MRI room.  |
+------------------+--------------------------------------------------+
| Category         | Physical                                         |
+------------------+--------------------------------------------------+
| Function         | Preventive and Compensating                       |
+------------------+--------------------------------------------------+
| How it reduces   | Physical access to the MRI workstation could     |
| risk             | allow an attacker to connect malicious devices,  |
|                  | install malware directly, or steal the system.   |
|                  | Restricting physical access reduces this risk.   |
+------------------+--------------------------------------------------+
| Limitations /    | Does not protect against network-based attacks.  |
| Residual Risk    | Staff with authorized access could still         |
|                  | compromise the system.                           |
+------------------+--------------------------------------------------+
| Implementation   | 1 week (badge programming + camera installation) |
| Timeline         |                                                  |
+------------------+--------------------------------------------------+
| NIST Reference   | SP 800-53 PE-3 (Physical Access Control)        |
+------------------+--------------------------------------------------+


CONTROL 5: ADMINISTRATIVE - INCIDENT RESPONSE PLAN FOR MRI
----------------------------------------------------------
+------------------+--------------------------------------------------+
| Control Name     | MRI-Specific Incident Response Procedure         |
+------------------+--------------------------------------------------+
| Description      | Develop and document a specific incident         |
|                  | response procedure for the MRI workstation.      |
|                  | Include:                                          |
|                  | - Steps to isolate the MRI if compromised        |
|                  | - Contacts for radiology department              |
|                  | - Procedure for clinical continuity (downtime)   |
|                  | - Process for forensic investigation             |
|                  | - Communication plan for leadership and patients |
+------------------+--------------------------------------------------+
| Category         | Administrative                                   |
+------------------+--------------------------------------------------+
| Function         | Corrective and Compensating                       |
+------------------+--------------------------------------------------+
| How it reduces   | Ensures a structured response if the MRI is      |
| risk             | compromised. Reduces recovery time and           |
|                  | operational impact. Ensures clinical services    |
|                  | can continue during an incident.                 |
+------------------+--------------------------------------------------+
| Limitations /    | A plan is only useful if tested and practiced.   |
| Residual Risk    | Without testing, staff may not know how to       |
|                  | execute the plan. Residual risk: ineffective     |
|                  | execution.                                        |
+------------------+--------------------------------------------------+
| Implementation   | 1 week (documentation + approval)                |
| Timeline         |                                                  |
+------------------+--------------------------------------------------+
| NIST Reference   | SP 800-53 IR-8 (Incident Response Plan)         |
+------------------+--------------------------------------------------+


================================================================================
4. IMPLEMENTATION PRIORITY
================================================================================

Which ONE control provides the GREATEST risk reduction ?

+----------------------------------------------------------------------------+
| PRIORITY #1: NETWORK SEGMENTATION - ISOLATION VLAN                        |
| (Control 1)                                                               |
|                                                                             |
| JUSTIFICATION:                                                             |
|                                                                             |
| The single greatest risk is that an attacker who compromises the MRI      |
| Windows XP workstation can pivot laterally across the ENTIRE flat         |
| network to access EHR, billing, AD, and other critical systems.           |
|                                                                             |
| Network segmentation (isolating the MRI on its own VLAN) is the ONLY      |
| control that directly addresses this "lateral movement" risk. It limits   |
| the blast radius of any compromise and prevents the MRI from being a      |
| gateway to the rest of the organization.                                   |
|                                                                             |
| All other controls (application whitelisting, host firewall, monitoring,  |
| physical access) are valuable but address either the vulnerability        |
| itself (difficult) or detection (after the fact).                          |
|                                                                             |
| Segmentation is the strongest preventive measure that:                     |
| - Does NOT require modifying the MRI OS (acceptable)                      |
| - Does NOT require clinical downtime (can be configured with minimal      |
|   impact)                                                                  |
| - Provides immediate risk reduction                                       |
| - Addresses the primary risk vector (lateral movement)                    |
|                                                                             |
| COMPARISON:                                                                |
| - Without segmentation: 1 compromise = entire network = CATASTROPHE       |
| - With segmentation: 1 compromise = contained = RECOVERABLE               |
|                                                                             |
| This is the highest leverage control because it changes the ARCHITECTURE  |
| of the problem, not just the symptoms.                                     |
+----------------------------------------------------------------------------+

SECONDARY PRIORITY (if budget allows):
+----------------------------------------------------------------------------+
| PRIORITY #2: APPLICATION WHITELISTING                                     |
| (Control 2)                                                               |
|                                                                             |
| If segmentation is the "outer wall" (preventing escape), whitelisting     |
| is the "inner wall" (preventing execution). Together, they provide        |
| defense in depth.                                                          |
+----------------------------------------------------------------------------+


================================================================================
5. EXECUTIVE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
|                                                                             |
| THE PROBLEM:                                                               |
| The MRI scanner at MedDefense Central runs Windows XP (EOL since 2014).   |
| It is on the same flat network as all other hospital systems.              |
| An attacker can exploit this single vulnerable system to compromise the   |
| ENTIRE MedDefense network.                                                 |
|                                                                             |
| THE CONSTRAINTS:                                                           |
| The MRI cannot be patched, upgraded, or replaced. It cannot be            |
| disconnected from the network. All obvious solutions are blocked.          |
|                                                                             |
| THE SOLUTION:                                                              |
| Implement compensating controls:                                           |
| 1. NETWORK SEGMENTATION (IMMEDIATE - PRIORITY #1)                         |
|    - Isolate MRI on dedicated VLAN with strict firewall rules             |
|    - Prevents lateral movement from MRI to the rest of the network        |
|                                                                             |
| 2. APPLICATION WHITELISTING (SECONDARY)                                   |
|    - Blocks execution of malware or unauthorized tools                    |
|                                                                             |
| 3. HOST-BASED FIREWALL (ADDITIONAL)                                       |
|    - Blocks inbound connections to vulnerable services                    |
|                                                                             |
| WHY SEGMENTATION FIRST:                                                    |
| It provides the GREATEST risk reduction by addressing the primary risk    |
| vector (lateral movement) without requiring OS changes or clinical        |
| downtime. It limits any compromise to the MRI VLAN, protecting the        |
| entire hospital network.                                                   |
|                                                                             |
| NIST CSF 2.0 - IDENTIFY FUNCTION:                                          |
| This is an example of ID.RA-1 (Threats and vulnerabilities identified)   |
| and ID.RA-2 (Risks identified). The compensating control strategy         |
| represents a MITIGATE risk treatment approach (NIST SP 800-30).           |
+----------------------------------------------------------------------------+


================================================================================
6. KEY TAKEAWAYS
================================================================================

1. Legacy systems (Windows XP) are NOT optional to secure - they represent
   a permanent backdoor into the entire network.

2. The flat network architecture (10.10.0.0/16) is the PRIMARY amplifier
   of this risk. Segmentation is the highest priority.

3. Compensating controls are essential when patching is not possible.
   They must be layered for defense in depth.

4. The MRI's value ($2.1M, 45 studies/day) makes isolation a priority
   over replacement. Compensating controls extend its safe lifespan.

5. Clinical operations must be preserved. Controls must be implemented
   without disrupting MRI functionality.

6. Detection (monitoring) is important but comes AFTER containment
   (segmentation). Prevent lateral movement first.

7. Documentation and testing are critical. A plan that is not tested
   is not a plan.

8. This is not an IT problem - it is a PATIENT SAFETY and BUSINESS
   CONTINUITY problem. (CISA Healthcare Guide)


================================================================================
7. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls (SC-7, CM-3, CM-6, SI-4, IR-8, PE-3)
- NIST SP 800-53: Compensating Controls definition
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF LEGACY DILEMMA ANALYSIS REPORT
================================================================================
