================================================================================
                    ATTACK SURFACE MAP - MEDDEFENSE HEALTH SYSTEMS
                    Task 7: The Attack Surface
================================================================================

Exercise: Task 7 - The Attack Surface
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Systematically map MedDefense's attack surface across three
          dimensions: external, internal and human.

Methodology References:
- NIST SP 800-30: Attack surface definition
- CISA Advisory AA24-131A (File 1)
- BlackReef Ransomware Profile (File 7)
- CIS Controls v8: Control 1 (Inventory), Control 7 (Vulnerability Management)

Cross-References to Project 1x00:
- Asset Registry (Task 7): All assets
- Network Scan Summary (Task 7): Ports and services
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Walk-through Observations (Task 3): Physical security


================================================================================
SECTION 1: EXTERNAL SURFACE (ACCESSIBLE FROM THE INTERNET)
================================================================================

+----------------------------------------------------------------------------+
| EXTERNAL ENTRY POINT 1: PATIENT PORTAL (web-srv-01)                       |
+----------------------------------------------------------------------------+
| Asset           | web-srv-01 (Ubuntu 20.04 LTS - Public Website +       |
|                 | Patient Portal)                                      |
+------------------+------------------------------------------------------+
| Ports/Protocols  | HTTP (80), HTTPS (443) - Publicly accessible          |
+------------------+------------------------------------------------------+
| Protection       | C-001: Firewall - Perimeter (FortiGate 100F)         |
| Exists           | C-002: Firewall - Outbound (NAT enabled)              |
|                  | C-009: Veeam Backups (backup-srv-01)                  |
+------------------+------------------------------------------------------+
| Gaps             | GAP-016: No Web Application Security Testing          |
|                  | (SAST/DAST) - No vulnerability scanning               |
|                  | GAP-014: No Patch Management - OS updates may be     |
|                  | missing                                               |
|                  | GAP-001: No SIEM - Compromise undetected              |
|                  | GAP-004: No MFA - Patient portal credentials          |
|                  | vulnerable                                            |
+------------------+------------------------------------------------------+
| Risk Scenario    | Attacker exploits an unpatched web application        |
|                  | vulnerability in the patient portal. They gain        |
|                  | access to web-srv-01, pivot to the internal network   |
|                  | via the flat network (GAP-003), and reach the EHR,    |
|                  | billing, and AD. This is EXACTLY the Breach 3         |
|                  | scenario from Task 13.                                |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| EXTERNAL ENTRY POINT 2: VPN ENDPOINT (FortiGate 100F)                     |
+----------------------------------------------------------------------------+
| Asset           | FortiGate 100F - VPN endpoint for Westside Clinic   |
|                 | and Corporate HQ                                     |
+------------------+------------------------------------------------------+
| Ports/Protocols  | IPSec VPN (UDP 500, 4500), SSL VPN (HTTPS) -         |
|                  | Publicly accessible                                   |
+------------------+------------------------------------------------------+
| Protection       | C-001: Firewall - Perimeter (FortiGate 100F)         |
| Exists           | C-003: Firewall - VPN Access (site-to-site)           |
|                  | C-004: Firewall Logging (local logs)                  |
+------------------+------------------------------------------------------+
| Gaps             | GAP-014: No Patch Management - VPN appliance         |
|                  | vulnerabilities (CVE) may be unpatched                |
|                  | GAP-004: No MFA - VPN access does not require MFA    |
|                  | GAP-001: No SIEM - VPN logs are not forwarded or     |
|                  | analyzed                                             |
|                  | GAP-012: No Vendor Account Management - VPN          |
|                  | accounts may include dormant or shared accounts      |
+------------------+------------------------------------------------------+
| Risk Scenario    | Attacker exploits an unpatched VPN vulnerability.     |
|                  | They gain direct access to the internal network.     |
|                  | This is EXACTLY the Breach 1 scenario from Task 13.  |
|                  | The 280-bed regional hospital case (File 4) started  |
|                  | this way.                                             |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| EXTERNAL ENTRY POINT 3: EMAIL INFRASTRUCTURE (O365)                       |
+----------------------------------------------------------------------------+
| Asset           | Microsoft O365 E3 - Email, SharePoint, OneDrive      |
+------------------+------------------------------------------------------+
| Ports/Protocols  | SMTP (25, 587), HTTPS (443), IMAP (993), POP3 (995)  |
|                  | - Cloud-based, publicly accessible                    |
+------------------+------------------------------------------------------+
| Protection       | C-006: Password Policy (AD)                          |
| Exists           | C-013: Security Awareness Training (limited)         |
+------------------+------------------------------------------------------+
| Gaps             | GAP-013: No Email Filtering or Mail Rule Monitoring  |
|                  | GAP-004: No MFA for O365 accounts                    |
|                  | GAP-001: No SIEM - No monitoring of O365 activity    |
|                  | GAP-015: No Offboarding - Former employees retain    |
|                  | O365 access                                          |
+------------------+------------------------------------------------------+
| Risk Scenario    | Attacker phishes an employee, gains O365 access.     |
|                  | They create mail forwarding rules to exfiltrate PHI, |
|                  | financial data, or strategic information. This is    |
|                  | the Breach 2 scenario from Task 13.                 |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| EXTERNAL ENTRY POINT 4: DNS AND DOMAIN                                   |
+----------------------------------------------------------------------------+
| Asset           | meddefense.com - Public DNS infrastructure            |
+------------------+------------------------------------------------------+
| Ports/Protocols  | DNS (UDP 53)                                          |
+------------------+------------------------------------------------------+
| Protection       | Limited - DNS hosting provider security              |
| Exists           |                                                      |
+------------------+------------------------------------------------------+
| Gaps             | No DMARC/DKIM/SPF monitoring documented              |
|                  | GAP-001: No SIEM - DNS activity not monitored        |
|                  | GAP-010: No Audits - DNS configuration not reviewed  |
+------------------+------------------------------------------------------+
| Risk Scenario    | Attacker exploits misconfigured DNS (DNS              |
|                  | hijacking, subdomain takeover). They redirect        |
|                  | traffic to a malicious site (typosquatting scenario  |
|                  | from Task 4). Patients enter credentials on a fake   |
|                  | portal.                                               |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| EXTERNAL SURFACE SUMMARY                                                   |
+----------------------------------------------------------------------------+
| TOTAL EXTERNAL ENTRY POINTS: 4                                             |
|                                                                             |
| CRITICAL GAPS AFFECTING EXTERNAL SURFACE:                                  |
| - GAP-014: No Patch Management (VPN, web server)                          |
| - GAP-004: No MFA (VPN, O365, patient portal)                            |
| - GAP-001: No SIEM (all external access undetected)                      |
| - GAP-016: No Web Application Security Testing (patient portal)          |
+----------------------------------------------------------------------------+


================================================================================
SECTION 2: INTERNAL SURFACE (ACCESSIBLE ONCE INSIDE THE NETWORK)
================================================================================

+----------------------------------------------------------------------------+
| INTERNAL SURFACE - EXPOSED SERVICES                                       |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 1: POSTGRESQL DATABASE (ehr-db-01)                  |
+----------------------------------------------------------------------------+
| Asset           | ehr-db-01 (Ubuntu 20.04 LTS - EHR Database -        |
|                 | PostgreSQL)                                          |
+------------------+------------------------------------------------------+
| Exposure        | Port 5432 (PostgreSQL) accessible from the entire    |
|                 | 10.10.0.0/16 network                                 |
+------------------+------------------------------------------------------+
| Why This        | The EHR database contains PHI for 50,000+ patients. |
| Matters         | ANY system on the flat network can connect to the    |
|                 | database. If an attacker compromises ANY             |
|                 | workstation, they can query the EHR database.        |
|                 | Marcus noted: "Should be restricted to ehr-srv-01    |
|                 | only."                                               |
+------------------+------------------------------------------------------+
| Gaps            | GAP-003: Flat Network - No segmentation             |
|                  | GAP-014: No Patch Management - PostgreSQL            |
|                  | vulnerabilities may be unpatched                     |
|                  | GAP-001: No SIEM - Database access not monitored     |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 2: MYSQL DATABASE (billing-srv-01)                   |
+----------------------------------------------------------------------------+
| Asset           | billing-srv-01 (Ubuntu 18.04 LTS - Billing System)  |
+------------------+------------------------------------------------------+
| Exposure        | Port 3306 (MySQL) accessible from the entire        |
|                 | 10.10.0.0/16 network                                 |
+------------------+------------------------------------------------------+
| Why This        | The billing database contains patient financial     |
| Matters         | data and insurance information. The billing server  |
|                 | has already been compromised twice (ransomware +    |
|                 | crypto-miner). Attackers on ANY system can connect  |
|                 | to the billing database.                            |
+------------------+------------------------------------------------------+
| Gaps            | GAP-003: Flat Network - No segmentation             |
|                  | GAP-014: No Patch Management - Ubuntu 18.04 LTS is  |
|                  | older and may have vulnerabilities                  |
|                  | GAP-001: No SIEM - Database access not monitored     |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 3: MANAGEMENT INTERFACES (NAS, FORTIGATE, SWITCHES) |
+----------------------------------------------------------------------------+
| Assets          | Synology NAS-01 (Backup Storage)                    |
|                 | FortiGate 100F (Firewall Management)               |
|                 | Cisco Core Switch (Network Management)              |
+------------------+------------------------------------------------------+
| Exposure        | Management interfaces accessible from the entire    |
|                 | 10.10.0.0/16 network                                |
+------------------+------------------------------------------------------+
| Why This        | Management interfaces provide administrative        |
| Matters         | control. A compromised NAS means backups are lost   |
|                 | or deleted. A compromised FortiGate means the       |
|                 | entire perimeter can be reconfigured. A             |
|                 | compromised switch means the entire network can be  |
|                 | intercepted. ALL are on the flat network.          |
+------------------+------------------------------------------------------+
| Gaps            | GAP-003: Flat Network - Management interfaces       |
|                 | accessible network-wide                            |
|                  | GAP-004: No MFA - Management interfaces no MFA     |
|                  | GAP-001: No SIEM - Management access not monitored  |
|                  | C-009 Weakness: NAS co-located - Backups            |
|                  | vulnerable                                          |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 4: LEGACY SYSTEMS (WINDOWS XP, SERVER 2012 R2)      |
+----------------------------------------------------------------------------+
| Assets          | MRI Scanner Control Workstation (Windows XP EOL)  |
|                 | print-srv-01 (Windows Server 2012 R2 EOL)          |
+------------------+------------------------------------------------------+
| Exposure        | Accessible from the entire 10.10.0.0/16 network    |
+------------------+------------------------------------------------------+
| Why This        | Windows XP (EOL 2014) has known, publicly available |
| Matters         | exploits (EternalBlue). An attacker can              |
|                 | compromise the MRI and pivot to the rest of the     |
|                 | network. Windows Server 2012 R2 (EOL Oct 2023) has  |
|                 | no security updates. These are PERMANENT            |
|                 | vulnerabilities on the internal network.            |
+------------------+------------------------------------------------------+
| Gaps            | GAP-007: No Compensating Controls for MRI (Windows  |
|                 | XP)                                                  |
|                  | GAP-003: Flat Network - Legacy systems accessible   |
|                  | network-wide                                         |
|                  | GAP-014: No Patch Management - EOL systems cannot   |
|                  | be patched                                           |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 5: MEDICAL IOT (MONITORS, PUMPS)                     |
+----------------------------------------------------------------------------+
| Assets          | Philips Patient Monitors (~80 units)                |
|                 | BD Alaris Infusion Pumps (~120 units)               |
+------------------+------------------------------------------------------+
| Exposure        | Accessible from the entire 10.10.0.0/16 network    |
+------------------+------------------------------------------------------+
| Why This        | These are LIFE-SAFETY devices. An attacker who      |
| Matters         | compromises a workstation can reach and potentially  |
|                 | manipulate patient monitors or infusion pumps.      |
|                 | Marcus noted: "If someone gets on the network they  |
|                 | can reach the pumps."                               |
+------------------+------------------------------------------------------+
| Gaps            | GAP-003: Flat Network - IoT on same network as      |
|                 | workstations                                         |
|                  | GAP-001: No SIEM - IoT traffic not monitored        |
|                  | GAP-007: No Compensating Controls - No isolation    |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 6: DEFAULT CREDENTIALS (PACS, MEDICAL IOT)          |
+----------------------------------------------------------------------------+
| Assets          | PACS Imaging System (radiology)                     |
|                 | Philips Patient Monitors                            |
|                 | BD Alaris Infusion Pumps                            |
+------------------+------------------------------------------------------+
| Exposure        | Default credentials may still be active on medical  |
|                 | devices                                              |
+------------------+------------------------------------------------------+
| Why This        | The radiology department uses a shared account      |
| Matters         | ("raduser/radiology1") - this was reported and not  |
|                 | fixed. Medical IoT devices may also have default    |
|                 | credentials (admin/admin). The Breach 3 scenario    |
|                 | (Task 13) specifically involved default credentials |
|                 | on infusion pump management interfaces.            |
+------------------+------------------------------------------------------+
| Gaps            | GAP-007: Shared Account Policy Not Enforced        |
|                  | GAP-003: Flat Network - Default credentials         |
|                  | accessible network-wide                             |
|                  | GAP-010: No Audits - No review of device           |
|                  | credentials                                         |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL ENTRY POINT 7: SHADOW IT (Dr. Patel's NAS, Raspberry Pi)        |
+----------------------------------------------------------------------------+
| Assets          | Dr. Patel's Personal NAS (Cardiology)              |
|                 | Raspberry Pi (Second Floor - Unknown)              |
+------------------+------------------------------------------------------+
| Exposure        | Connected to the 10.10.0.0/16 network - NOT        |
|                 | inventoried or managed                              |
+------------------+------------------------------------------------------+
| Why This        | Shadow IT devices are invisible to security        |
| Matters         | controls. They have NO protection (no AV, no       |
|                 | patching, no monitoring). A compromise of ANY      |
|                 | shadow IT device provides a pivot point to the     |
|                 | entire network. The Raspberry Pi has default       |
|                 | credentials and unknown purpose.                   |
+------------------+------------------------------------------------------+
| Gaps            | GAP-009: Shadow IT - Unmanaged devices             |
|                  | GAP-003: Flat Network - Shadow IT on flat network  |
|                  | GAP-010: No Audits - No discovery of shadow IT     |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| INTERNAL SURFACE SUMMARY                                                   |
+----------------------------------------------------------------------------+
| TOTAL INTERNAL ENTRY POINTS: 7                                             |
|                                                                             |
| CRITICAL GAPS AFFECTING INTERNAL SURFACE:                                  |
| - GAP-003: Flat Network (amplifies EVERY internal vulnerability)          |
| - GAP-007: No Compensating Controls (MRI Windows XP)                      |
| - GAP-009: Shadow IT (unmanaged devices)                                  |
| - GAP-001: No SIEM (internal activity undetected)                         |
+----------------------------------------------------------------------------+


================================================================================
SECTION 3: HUMAN SURFACE (PEOPLE WHO CAN BE TARGETED)
================================================================================

+----------------------------------------------------------------------------+
| HUMAN TARGET 1: CLINICAL STAFF                                             |
+----------------------------------------------------------------------------+
| Role            | Physicians, nurses, technicians (~1,400)             |
+------------------+------------------------------------------------------+
| Access Level    | EHR system, PACS, lab systems, medical devices       |
|                 | (monitors, pumps)                                    |
+------------------+------------------------------------------------------+
| Why Targetable  | Trained to be HELPFUL - clinical staff are           |
|                 | conditioned to respond to urgent requests from      |
|                 | authority figures. Low security training completion |
|                 | (58-71%). Under time pressure, likely to take       |
|                 | shortcuts. Multiple access points (EHR, VPN,        |
|                 | email).                                              |
+------------------+------------------------------------------------------+
| Social          | Vishing (Task 4, Scenario 3), Phishing (email),     |
| Engineering     | Tailgating (physical)                               |
| Vulnerability   |                                                      |
+------------------+------------------------------------------------------+
| Training/       | GAP-013: Low Training Completion - 58-71% at some   |
| Control Gaps    | sites                                                |
|                  | GAP-007: Shared Account Policy - Shared credentials |
|                  | used (radiology)                                     |
|                  | GAP-004: No MFA - Captured credentials provide      |
|                  | access                                               |
|                  | GAP-011: No Enforcement - No consequences for       |
|                  | policy violations                                   |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| HUMAN TARGET 2: RECEPTION / ADMINISTRATIVE STAFF                          |
+----------------------------------------------------------------------------+
| Role            | Front desk, receptionists, administrative assistants |
+------------------+------------------------------------------------------+
| Access Level    | Physical access to the building, first point of      |
|                 | contact for visitors, scheduling, email, phone      |
|                 | system                                               |
+------------------+------------------------------------------------------+
| Why Targetable  | First line of defense - they control who enters.    |
|                 | Trained to be HELPFUL to visitors. May not have     |
|                 | security training. May be vulnerable to             |
|                 | impersonation and pretexting.                       |
+------------------+------------------------------------------------------+
| Social          | Pretexting (Task 4, Scenario 7), Tailgating         |
| Engineering     | (physical), Vishing (phone)                          |
| Vulnerability   |                                                      |
+------------------+------------------------------------------------------+
| Training/       | GAP-013: Low Training Completion - Reception not    |
| Control Gaps    | specifically covered                                 |
|                  | GAP-010: No Audits - Visitor processes not reviewed |
|                  | GAP-011: No Enforcement - No consequences for       |
|                  | tailgating                                           |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| HUMAN TARGET 3: IT STAFF                                                    |
+----------------------------------------------------------------------------+
| Role            | System administrators, network engineers, helpdesk  |
|                 | (12 total)                                           |
+------------------+------------------------------------------------------+
| Access Level    | Administrative access to ALL systems (servers,      |
|                 | network, AD, backups). Privileged accounts.         |
+------------------+------------------------------------------------------+
| Why Targetable  | HIGHEST VALUE target. They have the "keys to the     |
|                 | kingdom." Small team (12) = overworked, stressed,   |
|                 | tired. They may take shortcuts (Scenario 5:         |
|                 | overworked admin). They are also the ones who would |
|                 | be targeted in a vishing attack pretending to be    |
|                 | from a vendor.                                      |
+------------------+------------------------------------------------------+
| Social          | Vishing (Task 4, Scenario 3), Phishing (targeted),  |
| Engineering     | Pretexting (vendor impersonation)                   |
| Vulnerability   |                                                      |
+------------------+------------------------------------------------------+
| Training/       | GAP-004: No MFA - IT admin accounts have NO MFA    |
| Control Gaps    | GAP-011: No Enforcement - No consequences for       |
|                  | security violations                                 |
|                  | GAP-001: No SIEM - Admin activity undetected        |
|                  | GAP-015: No Offboarding - Contractor accounts       |
|                  | remain active                                        |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| HUMAN TARGET 4: EXECUTIVES                                                  |
+----------------------------------------------------------------------------+
| Role            | CEO (Dr. Patricia Morales), CFO (Robert Kim),      |
|                 | COO (Angela Torres), General Counsel (David Park)  |
+------------------+------------------------------------------------------+
| Access Level    | Strategic information, financial authority,         |
|                 | email accounts with high-value data                |
+------------------+------------------------------------------------------+
| Why Targetable  | HIGHEST VALUE for BEC. They have authority to       |
|                 | approve wire transfers. They have access to         |
|                 | strategic plans, contracts, and confidential        |
|                 | communications. They are often too busy for        |
|                 | security training.                                  |
+------------------+------------------------------------------------------+
| Social          | BEC (Task 4, Scenario 2), Impersonation,            |
| Engineering     | Spear-phishing (targeted)                           |
| Vulnerability   |                                                      |
+------------------+------------------------------------------------------+
| Training/       | GAP-013: Training - Executives may skip training   |
| Control Gaps    | GAP-004: No MFA - Executive accounts have NO MFA   |
|                  | GAP-001: No SIEM - Executive email not monitored   |
|                  | GAP-011: No Enforcement - No consequences          |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| HUMAN TARGET 5: EXTERNAL CONTRACTORS                                        |
+----------------------------------------------------------------------------+
| Role            | MedTech Solutions engineers, Siemens technicians,  |
|                 | Fortinet support, Sophos support, building         |
|                 | maintenance                                          |
+------------------+------------------------------------------------------+
| Access Level    | Remote access to EHR, VPN access, physical access   |
|                 | to MRI/servers/network closets, building access    |
+------------------+------------------------------------------------------+
| Why Targetable  | They have access beyond MedDefense's direct control.|
|                 | They are outside the organization's security       |
|                 | culture. Vendor accounts may have NO MFA. They may |
|                 | have excessive privileges.                         |
+------------------+------------------------------------------------------+
| Social          | Vendor impersonation (Task 5, Supply Chain),        |
| Engineering     | Pretexting (calling IT about vendor access)        |
| Vulnerability   |                                                      |
+------------------+------------------------------------------------------+
| Training/       | GAP-012: No Vendor Account Management - No         |
| Control Gaps    | oversight of vendor accounts                        |
|                  | GAP-004: No MFA - Vendor accounts have NO MFA     |
|                  | GAP-001: No SIEM - Vendor activity not monitored   |
|                  | GAP-015: No Offboarding - Contractor accounts      |
|                  | remain active after contract ends                  |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| HUMAN SURFACE SUMMARY                                                      |
+----------------------------------------------------------------------------+
| TOTAL HUMAN TARGET ROLES: 5                                                |
|                                                                             |
| CRITICAL GAPS AFFECTING HUMAN SURFACE:                                     |
| - GAP-013: Low Training Completion (58-71% at some sites)                |
| - GAP-004: No MFA (all roles)                                             |
| - GAP-011: No Enforcement (no consequences)                               |
| - GAP-012: No Vendor Account Management (contractors)                     |
| - GAP-001: No SIEM (all activity undetected)                             |
+----------------------------------------------------------------------------+


================================================================================
SURFACE ASSESSMENT SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| SURFACE ASSESSMENT SUMMARY                                                 |
|                                                                             |
| The INTERNAL SURFACE represents the greatest risk for MedDefense TODAY.   |
|                                                                             |
| While all three surfaces have significant vulnerabilities, the internal    |
| surface is the most dangerous because of the COMBINATION of:              |
|                                                                             |
| 1. The FLAT NETWORK (GAP-003) means that a compromise of ANY system        |
|    provides access to EVERY system. A single compromised workstation      |
|    can reach the EHR database, Active Directory, billing system, and      |
|    medical IoT devices. The internal surface has NO barriers.             |
|                                                                             |
| 2. The LEGACY SYSTEMS (Windows XP MRI, Server 2012 R2) are PERMANENT      |
|    vulnerabilities that cannot be patched. They provide guaranteed entry  |
|    points for attackers who gain any internal foothold.                   |
|                                                                             |
| 3. The MEDICAL IOT (monitors, pumps) on the flat network means that a     |
|    compromise of a workstation can reach LIFE-SAFETY devices. This is     |
|    the highest-impact scenario (patient safety risk).                     |
|                                                                             |
| 4. SHADOW IT (Dr. Patel's NAS, Raspberry Pi) are invisible to security    |
|    controls and have NO protection. A compromise of a shadow IT device    |
|    provides a pivot point to the entire network.                          |
|                                                                             |
| The external surface is also dangerous (unpatched VPN, no MFA, no web     |
| app testing), but it provides the initial entry point. The internal       |
| surface is where the damage happens.                                      |
|                                                                             |
| The human surface enables access to both, but it is the internal surface  |
| that determines the severity of a breach. A ransomware attack on the      |
| flat network destroys everything. The flat network is the amplifier that  |
| turns a single compromise into a catastrophic breach.                     |
+----------------------------------------------------------------------------+


================================================================================
ATTACK SURFACE QUICK REFERENCE
================================================================================

+----------+---------------------+------------------------------------------+
| Surface  | Entry Points        | Most Critical Gap                        |
+----------+---------------------+------------------------------------------+
| EXTERNAL | Patient Portal,     | GAP-014: No Patch Management             |
|          | VPN, O365, DNS      | GAP-004: No MFA                          |
+----------+---------------------+------------------------------------------+
| INTERNAL | PostgreSQL, MySQL,  | GAP-003: Flat Network                    |
|          | Management IFs,     | GAP-007: No Compensating Controls        |
|          | Legacy Systems,     | (MRI)                                    |
|          | Medical IoT,        |                                          |
|          | Shadow IT           |                                          |
+----------+---------------------+------------------------------------------+
| HUMAN    | Clinical Staff,     | GAP-013: Low Training Completion         |
|          | Reception, IT,      | GAP-011: No Enforcement                  |
|          | Executives,         |                                          |
|          | Contractors         |                                          |
+----------+---------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- NIST SP 800-30: Attack surface definition
- CISA Advisory AA24-131A (File 1)
- BlackReef Ransomware Profile (File 7)
- CIS Controls v8: Control 1 (Inventory), Control 7 (Vulnerability Management)
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)

Cross-References to Project 1x00:
- Asset Registry (Task 7): All assets
- Network Scan Summary (Task 7): Ports and services
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Walk-through Observations (Task 3): Physical security
- Data Map (Task 9): Data classification


================================================================================
END OF ATTACK SURFACE MAP
================================================================================
