================================================================================
                    CONTROL LANDSCAPE ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 4: The Control Landscape
================================================================================

Exercise: Task 4 - The Control Landscape
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Identify, classify and document existing security controls using
          the professional dual-axis taxonomy: category (Technical /
          Administrative / Physical) and function (Preventive / Detective /
          Corrective / Compensating / Deterrent).

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare security practices

Source: meddefense-controls-artifacts.txt (8 artifacts)
Total controls identified: 14


================================================================================
1. INVENTORY OF IDENTIFIED CONTROLS
================================================================================

CONTROL ID: C-001
Control Name: Firewall - Perimeter Protection (FortiGate 100F)
Description: FortiGate 100F firewall enforces perimeter access control.
             Allows inbound HTTP/HTTPS to web-srv-01 (DMZ). Allows VPN
             connections from Westside and HQ to internal networks.
             Denies all other inbound traffic (default deny).
Category: Technical
Function: Preventive
Asset(s) Protected: Entire internal network (10.10.0.0/16) from external
                    threats; web-srv-01 exposed to internet
Source: Artifact 1 (Firewall Config) - Rules 1, 2, 3, 5


CONTROL ID: C-002
Control Name: Firewall - Outbound NAT (Egress)
Description: Allows all internal traffic to initiate outbound connections
             to the internet with NAT. No egress filtering applied.
Category: Technical
Function: Preventive (partial) - allows connectivity but does not restrict
          outbound traffic
Asset(s) Protected: Internal users access to internet; no restriction on
                    outbound malicious traffic
Source: Artifact 1 (Firewall Config) - Rule 4


CONTROL ID: C-003
Control Name: Firewall - VPN Access (Westside and HQ)
Description: Site-to-site VPN tunnels allow Westside and HQ to connect to
             Central's internal server subnet. Permits ALL services
             (not restricted to specific ports/protocols).
Category: Technical
Function: Preventive
Asset(s) Protected: Westside and HQ connectivity to Central servers
Source: Artifact 1 (Firewall Config) - Rules 2, 3


CONTROL ID: C-004
Control Name: Firewall - Logging
Description: Firewall logs all traffic (inbound, VPN, outbound) locally.
             UTM logging enabled for VPN and outbound traffic. Logs
             retained for 30 days locally. No forwarding to SIEM.
Category: Technical
Function: Detective
Asset(s) Protected: Network perimeter visibility; forensic evidence
Source: Artifact 1 (Firewall Config) - logtraffic settings


CONTROL ID: C-005
Control Name: SSH Hardening - ehr-srv-01
Description: SSH configured with key-only authentication, root login
             disabled, password auth disabled, MaxAuthTries=3,
             LoginGraceTime=60s, X11 forwarding disabled, TCP forwarding
             disabled. Applies ONLY to ehr-srv-01.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 (SSH Configuration) - /etc/ssh/sshd_config


CONTROL ID: C-006
Control Name: Password Policy - Active Directory
Description: Enforces password requirements via AD Group Policy:
             minimum 8 characters, complexity (upper/lower/number/special),
             90-day rotation, 5-password history, account lockout after
             5 failed attempts for 30 minutes. Applies to Windows systems only.
Category: Administrative
Function: Preventive
Asset(s) Protected: All AD-authenticated Windows systems and user accounts
Source: Artifact 3 (Password Policy) - Sections 2, 5


CONTROL ID: C-007
Control Name: Password Policy - Shared Accounts
Description: Policy discourages shared accounts but permits them when
             individual accounts are not feasible. Requires password change
             when any user with access leaves.
Category: Administrative
Function: Preventive
Asset(s) Protected: Systems with shared account access (e.g., radiology PACS)
Source: Artifact 3 (Password Policy) - Section 3


CONTROL ID: C-008
Control Name: Sophos Endpoint Protection
Description: Antivirus/endpoint protection deployed on Windows workstations
             (372 of 387 managed devices). Current signatures on 341
             devices. Blocks malware, quarantines threats.
Category: Technical
Function: Preventive and Detective
Asset(s) Protected: Windows workstations (clinical, administrative)
Source: Artifact 4 (Sophos Status Report)


CONTROL ID: C-009
Control Name: Veeam Backups - Nightly Full
Description: Daily full backups at 02:00 AM for critical VMs (ehr-srv-01,
             ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01).
             Destination: NAS-01 (same room/network/rack). Retention: 14 days.
Category: Technical
Function: Corrective
Asset(s) Protected: EHR (application + database), billing, AD, file shares,
                    website/patient portal
Source: Artifact 5 (Backup Configuration)


CONTROL ID: C-010
Control Name: Sophos Detections - Alerting
Description: Sophos Central console generates alerts on malware detections.
             Recent detections: Adware (20 days), CryptoMiner (15 days),
             Phishing URL (8 days), Trojan (3 days). Alerts are visible
             in the console but no automated notification configured.
Category: Technical
Function: Detective
Asset(s) Protected: Windows workstations with malicious activity detected
Source: Artifact 4 (Sophos Status Report) - Recent Detections


CONTROL ID: C-011
Control Name: Guard Service - ClearView Security
Description: One uniformed security guard at Central main entrance lobby.
             Hours: Monday-Friday, 07:00-19:00. Duties: visitor registration,
             badge verification, incident reporting. No patrols.
Category: Physical
Function: Deterrent and Detective
Asset(s) Protected: Main entrance to Central hospital
Source: Artifact 6 (Physical Security Contract)


CONTROL ID: C-012
Control Name: Camera System - Central
Description: 4 analog cameras at Central: main entrance (2), ER entrance (1),
             parking garage entrance (1). DVR storage for 30 days.
             Self-monitored (no 24/7 monitoring). No cameras in server
             room area, network closets or administrative wing.
Category: Physical
Function: Detective and Deterrent
Asset(s) Protected: Main entrance, ER entrance, parking garage
Source: Artifact 6 (Physical Security Contract + Tom Reeves notes)


CONTROL ID: C-013
Control Name: Security Awareness Training - "CyberSafe Basics"
Description: Annual 45-minute online security awareness training for all
             staff. Covers password hygiene, phishing recognition,
             physical security, incident reporting.
Category: Administrative
Function: Preventive
Asset(s) Protected: All staff awareness of security basics
Source: Artifact 7 (Training Records)


CONTROL ID: C-014
Control Name: AD Event Logging (no alerting)
Description: Active Directory logs critical security events locally.
             No alerting configured. Logs reviewed manually only when
             issues are reported.
Category: Technical
Function: Detective (minimal - no active monitoring)
Asset(s) Protected: AD authentication events; forensic evidence
Source: Artifact 8 (Log Management - verbal summary)


================================================================================
2. CONTROL SUMMARY MATRIX
================================================================================

+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
|                  | Preventive      | Detective       | Corrective      | Compensating     | Deterrent       |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Technical        | C-001, C-003,   | C-004, C-008,   | C-009            | [EMPTY]          | [EMPTY]         |
|                  | C-005, C-008,   | C-010, C-014    |                  |                  |                 |
|                  | C-002 (partial) |                 |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Administrative   | C-006, C-007,   | [EMPTY]         | [EMPTY]         | [EMPTY]          | [EMPTY]         |
|                  | C-013           |                 |                  |                  |                 |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+
| Physical         | [EMPTY]         | C-011, C-012    | [EMPTY]         | [EMPTY]          | C-011, C-012    |
+------------------+-----------------+-----------------+-----------------+------------------+-----------------+

TOTAL CONTROLS IDENTIFIED: 14


================================================================================
3. GAP ANALYSIS - EMPTY CELLS IN MATRIX
================================================================================

+------------------+-----------------+------------------------------------------+
| Category         | Function        | GAP Description                          |
+------------------+-----------------+------------------------------------------+
| Technical        | Compensating    | No compensating controls identified. No  |
|                  |                 | alternative controls for unpatchable     |
|                  |                 | systems (e.g., MRI Windows XP).          |
+------------------+-----------------+------------------------------------------+
| Technical        | Deterrent       | No technical deterrent controls (e.g.,   |
|                  |                 | warning banners, honeypots).             |
+------------------+-----------------+------------------------------------------+
| Administrative   | Detective       | No administrative detective controls     |
|                  |                 | (e.g., security audits, compliance       |
|                  |                 | reviews, log reviews).                   |
+------------------+-----------------+------------------------------------------+
| Administrative   | Corrective      | No administrative corrective controls    |
|                  |                 | (e.g., incident response plan, DR plan,  |
|                  |                 | BCP documentation).                      |
+------------------+-----------------+------------------------------------------+
| Administrative   | Compensating    | No administrative compensating controls. |
+------------------+-----------------+------------------------------------------+
| Administrative   | Deterrent       | No administrative deterrent controls     |
|                  |                 | (e.g., disciplinary policies,            |
|                  |                 | consequences for policy violations).     |
+------------------+-----------------+------------------------------------------+
| Physical         | Preventive      | No physical preventive controls (e.g.,   |
|                  |                 | locks on server room, restricted badge   |
|                  |                 | access, locked network closets).         |
+------------------+-----------------+------------------------------------------+
| Physical         | Corrective      | No physical corrective controls (e.g.,   |
|                  |                 | fire suppression, UPS testing,           |
|                  |                 | physical recovery procedures).           |
+------------------+-----------------+------------------------------------------+
| Physical         | Compensating    | No physical compensating controls.       |
+------------------+-----------------+------------------------------------------+


================================================================================
4. DETAILED CONTROL OBSERVATIONS
================================================================================

TECHNICAL CONTROLS:
-------------------
+----------+----------------------------------------+----------------------------------+
| Control  | Strength                               | Weakness                         |
+----------+----------------------------------------+----------------------------------+
| C-001    | Perimeter firewall with default deny.  | No network segmentation (flat    |
|          | VPN access for remote sites.          | network). VPN too permissive.   |
+----------+----------------------------------------+----------------------------------+
| C-002    | Outbound internet access provided.     | No egress filtering. Allows any  |
|          |                                        | outbound traffic, including to   |
|          |                                        | mining pools (billing-srv-01).  |
+----------+----------------------------------------+----------------------------------+
| C-003    | Site-to-site VPN functionality.        | "ALL" services allowed. No port  |
|          |                                        | restriction.                     |
+----------+----------------------------------------+----------------------------------+
| C-004    | Firewall logging enabled.              | Logs stored locally. No          |
|          |                                        | forwarding to SIEM. No alerting. |
+----------+----------------------------------------+----------------------------------+
| C-005    | SSH hardening on ehr-srv-01.           | Other Linux servers NOT hardened |
|          |                                        | (password auth still enabled).  |
+----------+----------------------------------------+----------------------------------+
| C-008    | Sophos endpoint protection active.     | Servers NOT covered. 31 devices  |
|          | Current detections blocked.            | outdated. 15 devices not         |
|          |                                        | reporting. iPads not managed.   |
+----------+----------------------------------------+----------------------------------+
| C-009    | Daily backups for critical VMs.        | NAS co-located (same room/       |
|          |                                        | network/rack). pacs-srv-01 NOT   |
|          |                                        | backed up. No offsite/cloud.    |
+----------+----------------------------------------+----------------------------------+
| C-010    | Malware detection alerts in Sophos.    | No automated notifications.      |
|          | Recent detections handled.             | No integration with SIEM.       |
+----------+----------------------------------------+----------------------------------+
| C-014    | AD logging enabled.                    | No alerting. No monitoring.      |
|          |                                        | No centralized log management.  |
+----------+----------------------------------------+----------------------------------+

ADMINISTRATIVE CONTROLS:
-----------------------
+----------+----------------------------------------+----------------------------------+
| Control  | Strength                               | Weakness                         |
+----------+----------------------------------------+----------------------------------+
| C-006    | Password policy meets baseline         | No MFA required. Linux systems   |
|          | standards. Enforced via GPO.           | not covered.                     |
+----------+----------------------------------------+----------------------------------+
| C-007    | Shared account policy documented.      | No enforcement. Radiology still  |
|          |                                        | uses shared account.             |
+----------+----------------------------------------+----------------------------------+
| C-013    | Annual security awareness training.    | Low completion rates (58-71%).   |
|          |                                        | Generic content. No phishing     |
|          |                                        | simulations. No role-specific.   |
+----------+----------------------------------------+----------------------------------+

PHYSICAL CONTROLS:
-----------------
+----------+----------------------------------------+----------------------------------+
| Control  | Strength                               | Weakness                         |
+----------+----------------------------------------+----------------------------------+
| C-011    | Guard at main entrance. Visitor sign-  | Limited hours (M-F, 7AM-7PM).   |
|          | in and badge verification.             | No patrols. No weekend/night.   |
|          |                                        | No guards at Westside or HQ.    |
+----------+----------------------------------------+----------------------------------+
| C-012    | Cameras at key entry points. 30-day    | No cameras in server room,       |
|          | DVR storage.                           | network closets, admin wing.    |
|          |                                        | Self-monitored. No active       |
|          |                                        | monitoring.                     |
+----------+----------------------------------------+----------------------------------+


================================================================================
5. HIDDEN CONTROLS (NOT EVIDENCED - ABSENCE IS A GAP)
================================================================================

The following controls are notable by their ABSENCE from the artifacts:

+------------------+--------------------------------------------------+
| Missing Control  | Evidence of Absence                              |
+------------------+--------------------------------------------------+
| MFA              | Artifact 3: "MFA is recommended but not          |
|                  | currently required."                             |
+------------------+--------------------------------------------------+
| Incident Response | Artifact 8: No IR plan. No SIEM. No alerts.     |
| Plan             |                                                  |
+------------------+--------------------------------------------------+
| Network          | Artifact 1: Flat network (Marcus notes). No VLAN |
| Segmentation     | configuration documented.                        |
+------------------+--------------------------------------------------+
| Server Protection| Artifact 4: "Server protection license not       |
| (EDR/AV)         | purchased."                                      |
+------------------+--------------------------------------------------+
| Offsite/Cloud    | Artifact 5: "None. Budget denied by CFO."        |
| Backup           |                                                  |
+------------------+--------------------------------------------------+
| Restrictive      | Artifact 1: Rules 2,3,4 allow "ALL" services.    |
| Network Access   | No least privilege.                              |
+------------------+--------------------------------------------------+
| Centralized Log  | Artifact 8: "No centralized log management."     |
| Management/SIEM  |                                                  |
+------------------+--------------------------------------------------+
| Physical Access  | Artifact 6: No cameras in server room area.      |
| Monitoring       |                                                  |
+------------------+--------------------------------------------------+
| BCP/DR Plan      | Artifact 5: "Full DR test: Never performed."     |
|                  | No documented plan.                              |
+------------------+--------------------------------------------------+
| Patch Management | Artifact 4: 31 devices outdated. No patch        |
|                  | management program documented.                   |
+------------------+--------------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. Only 14 controls identified across 8 artifacts.
   (NIST SP 800-53 Rev.5 has over 400 controls in 20 families)

2. Technical controls dominate (10 of 14).
   Administrative and Physical controls are underrepresented.

3. Gaps exist in ALL three categories:
   - Technical: No compensating controls for unpatchable systems
   - Administrative: No detective, corrective, compensating, deterrent
   - Physical: No preventive or corrective controls

4. The most CRITICAL GAPS:
   - No network segmentation (flat network)
   - No MFA
   - No incident response plan
   - No offsite/cloud backups
   - No physical access control to server room

5. Controls are inconsistent:
   - ehr-srv-01 is hardened (SSH key-only)
   - Other Linux servers are NOT hardened
   - Windows workstations have AV; servers do NOT

6. Budget has been a barrier for multiple controls:
   - Server protection license denied
   - Cloud backup denied
   - Physical security upgrades "on the roadmap"


================================================================================
7. RECOMMENDATIONS - PRIORITIZED GAPS
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Gap              | Recommended Control                   | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Physical Access  | Implement restricted badge access to   | NIST SP 800-53   |
|          | to Server Room   | server room. Install cameras. Visitor  | PE-3, PE-6       |
|          |                  | log.                                   |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | No MFA           | Require MFA for all remote access and  | NIST SP 800-53   |
|          |                  | privileged accounts.                   | IA-2             |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | No Incident      | Develop and test formal IR plan.       | NIST SP 800-53   |
|          | Response Plan    |                                        | IR-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | No Offsite       | Implement offsite/cloud backups.       | NIST SP 800-53   |
|          | Backups          | Test recovery procedures.              | CP-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Flat Network     | Implement VLAN segmentation. Isolate   | NIST SP 800-53   |
|          |                  | IoT/medical devices.                   | SC-7             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | No Server        | Purchase and deploy AV/EDR for all     | NIST SP 800-53   |
|          | Protection       | servers (Windows and Linux).           | SI-3             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | No SIEM          | Deploy centralized logging/SIEM.       | NIST SP 800-53   |
|          |                  | Implement alerting.                    | AU-6             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Outdated SSH     | Harden SSH on ALL Linux servers.       | NIST SP 800-53   |
|          | Configuration    | Disable password auth.                 | CM-6             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Training         | Improve completion rates. Add          | NIST SP 800-53   |
|          | Completion       | healthcare-specific content.           | AT-2             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function
- CISA Healthcare and Public Health Sector Guide
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF CONTROL LANDSCAPE ANALYSIS REPORT
================================================================================
