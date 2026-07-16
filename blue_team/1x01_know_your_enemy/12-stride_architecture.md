================================================================================
                    STRIDE ACROSS THE ARCHITECTURE - MEDDEFENSE HEALTH SYSTEMS
                    Task 12: STRIDE Across the Architecture
================================================================================

Exercise: Task 12 - STRIDE Across the Architecture
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Apply STRIDE at surface level to three additional critical systems
          to build a broad threat awareness across the MedDefense environment.

Methodology References:
- Microsoft STRIDE Threat Model
- NIST SP 800-30: Threat identification
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Asset Registry (Task 7): pacs-srv-01, MRI, ad-dc-01/02, FortiGate
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets


================================================================================
SYSTEM 1: PACS / MEDICAL IMAGING SYSTEM
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| System Name      | PACS / Medical Imaging System                     |
+------------------+--------------------------------------------------+
| Architecture     | - pacs-srv-01 (Windows Server 2016 - PACS Imaging)|
| Notes            | - MRI Workstation (Windows XP Embedded - EOL)    |
|                  | - CT Scanner (OS unknown)                        |
|                  | - Radiology Workstations (Windows 10)            |
|                  | - Shared account: "raduser/radiology1"          |
|                  | - All devices on flat network (10.10.0.0/16)    |
|                  | - Images transmitted unencrypted internally     |
|                  | - pacs-srv-01 NOT backed up (Artifact 5)        |
+------------------+--------------------------------------------------+

STRIDE TABLE
------------
+----------+------------------------------------------+------------------------------------------+----------+
| STRIDE   | Threat                                   | Impact                                   | Severity |
+----------+------------------------------------------+------------------------------------------+----------+
| S        | An attacker uses the shared               | - Incorrect diagnosis attributed to      | HIGH     |
| SPOOFING | "raduser/radiology1" credentials to      |   legitimate radiologist                 |
|          | log into the PACS system, impersonating  | - Legal exposure for the impersonated   |
|          | a legitimate radiologist. They modify    |   radiologist                           |
|          | or view images under that identity.     | - Patient safety risk from incorrect    |
|          | No individual accountability exists.    |   diagnosis                             |
+----------+------------------------------------------+------------------------------------------+----------+
| T        | An attacker exploits the Windows XP      | - MRI unavailable for diagnostic         | CRITICAL |
| TAMPERING| MRI workstation to alter or corrupt      |   imaging                               |
|          | imaging data. They could change a        | - Delayed diagnoses and treatment       |
|          | patient's scan results or delete images  | - $40M+ recovery costs (Breach 3)       |
|          | altogether. The MRI is on the flat      | - Patient safety risk                   |
|          | network and unpatchable.                |                                          |
+----------+------------------------------------------+------------------------------------------+----------+
| R        | A radiologist denies performing a        | - No accountability for imaging          | MEDIUM   |
| REPUDIA- | specific imaging study. The shared       |   decisions                             |
| TION     | account means multiple people can        | - Unable to determine who made an       |
|          | access the PACS system without           |   error                                 |
|          | individual attribution.                 | - Legal liability cannot be assigned   |
|          |                                         | - Patient safety investigation          |
|          |                                         |   impossible                            |
+----------+------------------------------------------+------------------------------------------+----------+
| I        | An attacker connects to the PACS server  | - Medical images exposed publicly       | CRITICAL |
| INFO     | via the flat network (no segmentation)   | - Patient PHI in images exposed        |
| DISCLOS. | and exfiltrates medical images for 45+  | - HIPAA breach notification            |
|          | MRI studies per day. Images are not      | - HHS investigation and fines          |
|          | encrypted in transit.                   | - Reputational damage                  |
+----------+------------------------------------------+------------------------------------------+----------+
| D        | Ransomware encrypts the PACS server,     | - All diagnostic images inaccessible   | CRITICAL |
| DOS      | making all medical images unavailable.   | - Radiology department cannot function  |
|          | pacs-srv-01 is NOT backed up (Artifact  | - Physicians cannot access images for  |
|          | 5), so recovery is impossible without    |   diagnosis                            |
|          | paying the ransom.                      | - Patient care delayed or cancelled    |
+----------+------------------------------------------+------------------------------------------+----------+
| E        | An attacker gains admin access to the    | - Complete control over PACS system    | HIGH     |
| ELEVATION| PACS server via the shared account or   | - Ability to modify/delete all images  |
| OF      | Windows XP exploit. They use this to     | - Use PACS as pivot point to EHR and   |
| PRIV.   | bypass application-level controls and    |   AD via flat network                  |
|          | access all imaging data.                | - Permanent backdoor installation      |
+----------+------------------------------------------+------------------------------------------+----------+

TOP THREAT FOR PACS SYSTEM
--------------------------
+------------------+--------------------------------------------------+
| Top Threat       | INFORMATION DISCLOSURE (I) + DENIAL OF SERVICE    |
|                  | (D)                                               |
+------------------+--------------------------------------------------+
| Why              | The PACS system has two CRITICAL threats:         |
|                  |                                                   |
|                  | 1. DATA EXPOSURE: Medical images contain PHI.     |
|                  |    The flat network and no encryption mean        |
|                  |    images can be intercepted or exfiltrated.      |
|                  |    Medical images are among the highest-value     |
|                  |    healthcare data.                              |
|                  |                                                   |
|                  | 2. NO BACKUP: pacs-srv-01 is NOT backed up.       |
|                  |    If ransomware encrypts the PACS server, all    |
|                  |    imaging data is lost forever unless the        |
|                  |    ransom is paid. This is a catastrophic         |
|                  |    scenario for radiology operations.            |
|                  |                                                   |
|                  | The combination of Windows XP (GAP-007), flat     |
|                  | network (GAP-003), and no backups (Artifact 5)    |
|                  | makes the PACS system highly vulnerable to       |
|                  | both disclosure and denial-of-service attacks.    |
+------------------+--------------------------------------------------+


================================================================================
SYSTEM 2: ACTIVE DIRECTORY
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| System Name      | Active Directory                                  |
+------------------+--------------------------------------------------+
| Architecture     | - ad-dc-01 (Windows Server 2019 - Primary DC)     |
| Notes            | - ad-dc-02 (Windows Server 2019 - Secondary DC)   |
|                  | - Authenticates ALL Windows users and services   |
|                  | - Password policy: 8 chars, 90-day rotation     |
|                  | - NO MFA for any account                         |
|                  | - NO monitoring of AD activity (no SIEM)         |
|                  | - ad-dc-02 NOT backed up (Artifact 5)            |
|                  | - Domain Admin accounts exist with no MFA       |
+------------------+--------------------------------------------------+

STRIDE TABLE
------------
+----------+------------------------------------------+------------------------------------------+----------+
| STRIDE   | Threat                                   | Impact                                   | Severity |
+----------+------------------------------------------+------------------------------------------+----------+
| S        | An attacker uses a phished Domain Admin   | - Complete compromise of ALL systems     | CRITICAL |
| SPOOFING | credential to impersonate an IT admin.   | - Ability to create new admin accounts   |
|          | They log into ad-dc-01 as a legitimate   | - Ability to lock out legitimate admins |
|          | administrator. No MFA means the          | - Permanent backdoor installation       |
|          | credential is sufficient.               | - No accountability                     |
+----------+------------------------------------------+------------------------------------------+----------+
| T        | An attacker modifies Active Directory    | - System-wide denial of service         | CRITICAL |
| TAMPERING| permissions after gaining admin access.  | - Attackers can grant themselves access |
|          | They could: delete users, modify group   |   to any resource                       |
|          | memberships, change password policies,   | - Ability to deploy ransomware via GPO |
|          | or create backdoor accounts.             | - Complete loss of control over domain |
+----------+------------------------------------------+------------------------------------------+----------+
| R        | An attacker deletes Active Directory     | - No forensic evidence available        | HIGH     |
| REPUDIA- | audit logs after performing malicious    | - Unable to determine extent of breach  |
| TION     | actions. With no log integrity          | - Unable to identify the attacker       |
|          | protection and no SIEM, they can erase   | - Regulatory investigation hindered    |
|          | evidence of their actions.              | - Legal liability impossible to assign |
+----------+------------------------------------------+------------------------------------------+----------+
| I        | An attacker queries Active Directory to  | - Complete list of all users and        | CRITICAL |
| INFO     | exfiltrate all user accounts, group      |   groups exposed                        |
| DISCLOS. | memberships, and password hashes. They   | - Password hashes can be cracked        |
|          | use this information for further attacks | - Attackers can use info for lateral    |
|          | against other systems.                  |   movement and privilege escalation    |
+----------+------------------------------------------+------------------------------------------+----------+
| D        | An attacker deletes ad-dc-01 from the    | - ALL authentication services offline   | CRITICAL |
| DOS      | domain after gaining admin access. They  | - No one can log in to ANY system      |
|          | could also corrupt the AD database.     | - Complete organizational shutdown      |
|          | ad-dc-02 is NOT backed up, so recovery   | - Recovery requires full rebuild       |
|          | would be extremely difficult.           | - Extended downtime (weeks)            |
+----------+------------------------------------------+------------------------------------------+----------+
| E        | An attacker exploits a privilege         | - Attacker gains complete control over  | CRITICAL |
| ELEVATION| escalation vulnerability to gain Domain  |   ALL systems                           |
| OF      | Admin access from a standard user        | - Ability to compromise every system   |
| PRIV.   | account. They then have full control     |   that uses AD authentication          |
|          | over every Windows system in the        | - Game over scenario                   |
|          | organization.                           |                                          |
+----------+------------------------------------------+------------------------------------------+----------+

TOP THREAT FOR ACTIVE DIRECTORY
-------------------------------
+------------------+--------------------------------------------------+
| Top Threat       | ELEVATION OF PRIVILEGE (E) + DENIAL OF SERVICE    |
|                  | (D)                                               |
+------------------+--------------------------------------------------+
| Why              | Active Directory is the "keys to the kingdom."    |
|                  |                                                   |
|                  | If an attacker gains Domain Admin access, they   |
|                  | can:                                               |
|                  | - Access EVERY system in the organization        |
|                  | - Deploy ransomware to ALL systems via GPO       |
|                  | - Create backdoor accounts for permanent access  |
|                  | - Delete or corrupt the AD database             |
|                  |                                                   |
|                  | The combination of NO MFA (GAP-004) and NO        |
|                  | monitoring (GAP-001) means privilege escalation   |
|                  | can occur undetected. The "game over" scenario   |
|                  | is when an attacker compromises AD - everything  |
|                  | else is already lost.                            |
|                  |                                                   |
|                  | ad-dc-02 is NOT backed up, so even the backup    |
|                  | DC is not recoverable if both are compromised.   |
+------------------+--------------------------------------------------+


================================================================================
SYSTEM 3: NETWORK INFRASTRUCTURE
================================================================================

SYSTEM OVERVIEW
---------------
+------------------+--------------------------------------------------+
| System Name      | Network Infrastructure                             |
+------------------+--------------------------------------------------+
| Architecture     | - FortiGate 100F (Perimeter Firewall)             |
| Notes            | - VPN endpoint (Westside via consumer router)    |
|                  | - VPN endpoint (HQ via building-managed network) |
|                  | - Cisco Core Switch (model unknown)              |
|                  | - Cisco Access Switches (2 per floor)            |
|                  | - Westside Netgear Nighthawk (consumer-grade)    |
|                  | - Westside unmanaged switch (brand unknown)      |
|                  | - Unsecure WiFi (Ubiquiti APs - Central)         |
|                  | - ALL on flat network (10.10.0.0/16)             |
|                  | - No internal segmentation (GAP-003)             |
|                  | - Firewall rules allow ALL outbound (GAP-008)    |
|                  | - VPN rules allow "ALL" services (too permissive)|
+------------------+--------------------------------------------------+

STRIDE TABLE
------------
+----------+------------------------------------------+------------------------------------------+----------+
| STRIDE   | Threat                                   | Impact                                   | Severity |
+----------+------------------------------------------+------------------------------------------+----------+
| S        | An attacker spoofs a legitimate VPN      | - Unauthorized access to internal        | CRITICAL |
| SPOOFING | client or impersonates the FortiGate     |   network                                |
|          | to intercept traffic. The VPN has no     | - Man-in-the-middle attacks on all      |
|          | MFA and uses a shared certificate.      |   VPN traffic                           |
|          |                                         | - Credential interception               |
+----------+------------------------------------------+------------------------------------------+----------+
| T        | An attacker modifies firewall rules      | - Complete bypass of perimeter           | CRITICAL |
| TAMPERING| to allow unauthorized access or block    |   protection                            |
|          | legitimate traffic. The FortiGate admin  | - Denial of service for legitimate      |
|          | interface is accessible on the flat      |   users                                |
|          | network and has NO MFA.                 | - Attacker can create backdoor rules   |
+----------+------------------------------------------+------------------------------------------+----------+
| R        | An attacker disables logging on the      | - No forensic evidence of network       | HIGH     |
| REPUDIA- | FortiGate and deletes firewall logs.     |   activity                             |
| TION     | With no SIEM, there is no backup of      | - Unable to determine source of attack  |
|          | logging data.                            | - Unable to identify the attacker       |
|          |                                         | - Regulatory investigation hindered    |
+----------+------------------------------------------+------------------------------------------+----------+
| I        | An attacker intercepts network traffic   | - PHI, credentials, and sensitive       | CRITICAL |
| INFO     | on the flat network. ALL traffic is in   |   data exposed                          |
| DISCLOS. | plaintext (no internal encryption).      | - All network traffic compromised      |
|          | They capture credentials (EHR, AD,       | - Complete loss of network              |
|          | billing) and patient data traversing     |   confidentiality                      |
|          | the network.                             |                                          |
+----------+------------------------------------------+------------------------------------------+----------+
| D        | An attacker exploits the consumer-grade  | - Complete network outage at Westside   | HIGH     |
| DOS      | Netgear router at Westside to cause      | - Westside clinic cannot access EHR    |
|          | a denial of service. Alternatively,      | - Patient care disrupted               |
|          | they DDoS the FortiGate VPN to prevent   | - VPN access unavailable for remote    |
|          | remote access.                          |   workers                              |
+----------+------------------------------------------+------------------------------------------+----------+
| E        | An attacker exploits the FortiGate      | - Complete control over network         | CRITICAL |
| ELEVATION| admin interface (accessible on the flat |   perimeter                            |
| OF      | network) to gain administrative control  | - Ability to reconfigure firewall,      |
| PRIV.   | of the firewall. From there, they can    |   VPN, and routing                     |
|          | reconfigure the entire network.         | - Permanent backdoor into the network |
+----------+------------------------------------------+------------------------------------------+----------+

TOP THREAT FOR NETWORK INFRASTRUCTURE
-------------------------------------
+------------------+--------------------------------------------------+
| Top Threat       | INFORMATION DISCLOSURE (I)                        |
+------------------+--------------------------------------------------+
| Why              | The network infrastructure is the FABRIC that     |
|                  | connects everything in the organization.         |
|                  |                                                   |
|                  | The flat network (GAP-003) means ALL traffic     |
|                  | is visible to ANYONE on the network. Internal     |
|                  | traffic is NOT encrypted. An attacker who        |
|                  | compromises ANY system can sniff:                 |
|                  | - EHR data (PHI)                                 |
|                  | - AD credentials                                 |
|                  | - Billing information                            |
|                  | - PACS images                                    |
|                  | - All communications between systems            |
|                  |                                                   |
|                  | Additionally, the Westside consumer-grade router |
|                  | and unmanaged switch are effectively open doors. |
|                  | The FortiGate is the ONLY perimeter defense,     |
|                  | with no redundancy or segmentation.              |
|                  |                                                   |
|                  | If the network is compromised, EVERYTHING is     |
|                  | compromised. The network is the foundation upon  |
|                  | which all other security controls rely.          |
+------------------+--------------------------------------------------+


================================================================================
STRIDE ARCHITECTURE SUMMARY
================================================================================

+----------+------------------+------------------------------------------+------------------+
| System   | Top Threat       | Severity                                 | Primary Gap      |
+----------+------------------+------------------------------------------+------------------+
| PACS /   | Information      | CRITICAL                                 | GAP-003, GAP-007 |
| Imaging  | Disclosure +     |                                          | Artifact 5 (No   |
|          | Denial of        |                                          | backup)          |
|          | Service          |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Active   | Elevation of     | CRITICAL                                 | GAP-004, GAP-001 |
| Directory| Privilege        |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Network  | Information      | CRITICAL                                 | GAP-003, GAP-008 |
| Infra.   | Disclosure       |                                          |                  |
+----------+------------------+------------------------------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. All three systems have CRITICAL threats. The severity rating across all
   systems is consistently CRITICAL or HIGH.

2. INFORMATION DISCLOSURE appears as the top threat for 2 of 3 systems
   (PACS and Network Infrastructure). The flat network enables data
   exposure across all systems.

3. The PACS system has TWO critical threats: data exposure (unencrypted
   images) and denial of service (no backups). This is the most vulnerable
   system after the EHR.

4. Active Directory is the "keys to the kingdom." Elevation of privilege
   on AD compromises EVERYTHING else. This is the game over scenario.

5. The network infrastructure supports ALL other systems. If the network
   is compromised, ALL security controls are bypassed.

6. The same GAPs appear across all three systems:
   - GAP-003: Flat Network (enables lateral movement and data exposure)
   - GAP-004: No MFA (enables credential theft)
   - GAP-001: No SIEM (enables undetected activity)

7. The pattern is consistent: MedDefense has NO SEGMENTATION and NO
   DETECTION. This makes every system vulnerable to every threat.


================================================================================
REFERENCES
================================================================================

- Microsoft STRIDE Threat Model
- NIST SP 800-30: Threat identification
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Asset Registry (Task 7): pacs-srv-01, ad-dc-01/02, FortiGate
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets


================================================================================
END OF STRIDE ACROSS THE ARCHITECTURE REPORT
================================================================================
