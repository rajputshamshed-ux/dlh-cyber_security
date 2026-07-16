================================================================================
                    THREAT SCENARIOS - MEDDEFENSE HEALTH SYSTEMS
                    Task 14: Threat Scenarios
================================================================================

Exercise: Task 14 - Threat Scenarios
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Construct 3 complete, realistic threat scenarios integrating all
          elements produced in this project.

Methodology References:
- MITRE ATT&CK Enterprise Framework
- NIST SP 800-30: Attack path analysis
- Security+ 2.1: Threat actor motivations
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Kill Chains (Task 10): Attack sequences
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets
- STRIDE on EHR (Task 11): Threat categories
- STRIDE Across Architecture (Task 12): System threats


================================================================================
SCENARIO 1: EXTERNAL - RANSOMWARE CAMPAIGN
================================================================================

TITLE
-----
+------------------+--------------------------------------------------+
| Title            | BlackReef Ransomware: VPN Exploit to EHR          |
|                  | Encryption                                        |
+------------------+--------------------------------------------------+

THREAT ACTOR
------------
+------------------+--------------------------------------------------+
| Threat Actor     | Organized Crime / RaaS Group - BlackReef          |
|                  | (Reference: T6 - Ransomware Groups #1)            |
+------------------+--------------------------------------------------+
| Motivation       | FINANCIAL GAIN - Ransom demand + data sale        |
|                  | (Security+ 2.1 - Financial)                       |
+------------------+--------------------------------------------------+
| Initial Vector   | VPN Exploit (V2 from Task 9)                      |
+------------------+--------------------------------------------------+
| Attack Surface   | EXTERNAL - Unpatched FortiGate VPN appliance      |
| Exploited        | (Reference: T7 - External Surface)                |
+------------------+--------------------------------------------------+

ATTACK SEQUENCE
---------------
+----------+--------------------------------------------------+
| STEP 1   | RECONNAISSANCE - Active Scanning (T1595)          |
|          | BlackReef affiliates scan for vulnerable          |
|          | FortiGate VPN appliances. They identify           |
|          | MedDefense's FortiGate 100F with an unpatched     |
|          | CVE.                                              |
+----------+--------------------------------------------------+
| STEP 2   | INITIAL ACCESS - External Remote Services         |
|          | (T1133)                                           |
|          | Attacker exploits the VPN vulnerability and       |
|          | gains access to MedDefense's internal network.    |
+----------+--------------------------------------------------+
| STEP 3   | DEFENSE EVASION - Impair Defenses (T1562)         |
|          | Attacker checks for AV/EDR. They disable Sophos   |
|          | on the compromised system (Sophos license does    |
|          | not cover servers).                              |
+----------+--------------------------------------------------+
| STEP 4   | CREDENTIAL ACCESS - OS Credential Dumping         |
|          | (T1003.001)                                       |
|          | Attacker uses Mimikatz to harvest credentials     |
|          | from memory. No MFA means credentials are         |
|          | directly usable.                                  |
+----------+--------------------------------------------------+
| STEP 5   | LATERAL MOVEMENT - Remote Services (T1021)        |
|          | Attacker moves laterally across the flat          |
|          | network to ad-dc-01 (Domain Controller). No       |
|          | segmentation blocks this movement.               |
+----------+--------------------------------------------------+
| STEP 6   | PRIVILEGE ESCALATION - Domain Policy               |
|          | Modification (T1484)                              |
|          | Attacker uses Domain Admin credentials to gain    |
|          | full control over the domain.                    |
+----------+--------------------------------------------------+
| STEP 7   | EXFILTRATION - Exfiltration Over C2 Channel       |
|          | (T1041)                                           |
|          | Attacker exfiltrates 35GB of patient data using   |
|          | Rclone. No egress filtering blocks this.         |
+----------+--------------------------------------------------+
| STEP 8   | IMPACT - Data Encrypted for Impact (T1486)        |
|          | Attacker deploys ransomware via Group Policy to   |
|          | ALL Windows systems. The co-located NAS is also   |
|          | encrypted.                                        |
+----------+--------------------------------------------------+

STRIDE CATEGORIES TRIGGERED
---------------------------
+------------------+--------------------------------------------------+
| STRIDE           | S: Spoofing - VPN impersonation                   |
| Categories       | T: Tampering - System modifications               |
| Triggered        | R: Repudiation - Logs deleted                     |
|                  | I: Information Disclosure - Data exfiltrated      |
|                  | D: Denial of Service - Ransomware encryption      |
|                  | E: Elevation of Privilege - Domain Admin access   |
|                  | ALL SIX STRIDE CATEGORIES ARE TRIGGERED          |
+------------------+--------------------------------------------------+

MEDDEFENSE ASSETS IMPACTED
--------------------------
+------------------+--------------------------------------------------+
| Assets           | ehr-srv-01 (CRITICAL) - EHR Application          |
| Impacted         | ehr-db-01 (CRITICAL) - EHR Database (50k+ PHI)   |
|                  | ad-dc-01 (CRITICAL) - Active Directory            |
|                  | billing-srv-01 (HIGH) - Billing System           |
|                  | NAS-01 (HIGH) - Backup Storage                    |
|                  | All Windows endpoints (~387 workstations)         |
+------------------+--------------------------------------------------+

BUSINESS IMPACT
---------------
+------------------+--------------------------------------------------+
| Clinical         | - 11+ days of EHR downtime                       |
|                  | - Ambulance diversions and cancelled procedures  |
|                  | - Clinicians forced to use paper records        |
|                  | - Patient safety risk from incomplete           |
|                  |   information                                     |
+------------------+--------------------------------------------------+
| Financial        | - $2.5M+ ransom demand                          |
|                  | - $3.2M recovery costs                           |
|                  | - $1.8M lost revenue (cancelled procedures)      |
|                  | - $350K+ HIPAA fines                             |
+------------------+--------------------------------------------------+
| Regulatory       | - HHS Office for Civil Rights investigation     |
|                  | - Mandatory HIPAA breach notification (50k+)    |
|                  | - Potential sanctions on Medicare/Medicaid      |
+------------------+--------------------------------------------------+
| Reputational     | - Loss of patient trust                         |
|                  | - Negative media coverage                        |
|                  | - Potential CEO resignation                     |
|                  | - Class action lawsuits                          |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | How Exploited                                    |
+------------------+--------------------------------------------------+
| GAP-014          | Unpatched VPN vulnerability provides initial     |
|                  | access                                            |
+------------------+--------------------------------------------------+
| GAP-003          | Flat network enables lateral movement to AD,    |
|                  | EHR, and backups                                  |
+------------------+--------------------------------------------------+
| GAP-004          | No MFA means harvested credentials are directly |
|                  | usable                                            |
+------------------+--------------------------------------------------+
| GAP-001          | No SIEM means entire attack goes undetected for  |
|                  | 5+ days                                           |
+------------------+--------------------------------------------------+
| GAP-008          | No egress filtering allows data exfiltration     |
+------------------+--------------------------------------------------+
| C-009 Weakness   | Co-located backups are encrypted with            |
|                  | production systems                                 |
+------------------+--------------------------------------------------+
| GAP-002          | No IR plan means extended recovery time          |
+------------------+--------------------------------------------------+

DETECTION OPPORTUNITIES
-----------------------
+----------+------------------+------------------------------------------+
| Step     | Detection        | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Scanning         | SIEM alerting on port scanning           |
| Step 2   | VPN Access       | MFA on VPN + SIEM alert on unusual login |
| Step 3   | AV Disable       | EDR alerting on AV disable               |
| Step 4   | Credential       | SIEM alerting on Mimikatz execution      |
|          | Harvesting       |                                          |
| Step 5   | Lateral Movement | Network segmentation + SIEM              |
| Step 6   | Privilege        | SIEM alert on privilege changes          |
|          | Escalation       |                                          |
| Step 7   | Data Exfiltration| Egress filtering + SIEM alert on large   |
|          |                  | outbound transfers                       |
| Step 8   | Ransomware       | EDR alerting on file encryption          |
+----------+------------------+------------------------------------------+


================================================================================
SCENARIO 2: INTERNAL - INSIDER DATA EXFILTRATION
================================================================================

TITLE
-----
+------------------+--------------------------------------------------+
| Title            | The Disgruntled Employee: PHI Exfiltration        |
+------------------+--------------------------------------------------+

THREAT ACTOR
------------
+------------------+--------------------------------------------------+
| Threat Actor     | Malicious Insider - Former Billing Employee      |
|                  | (Reference: T3 - Insider Malicious #4)            |
+------------------+--------------------------------------------------+
| Motivation       | REVENGE + FINANCIAL GAIN - Employee terminated    |
|                  | for performance issues; plans to sell patient    |
|                  | data on dark web                                  |
|                  | (Security+ 2.1 - Revenge + Financial)             |
+------------------+--------------------------------------------------+
| Initial Vector   | Legitimate Access Abused (Insider Malicious - V6 |
|                  | from Task 9)                                      |
+------------------+--------------------------------------------------+
| Attack Surface   | HUMAN - Former employee retains valid            |
| Exploited        | credentials due to no automated offboarding      |
|                  | (Reference: T7 - Human Surface)                  |
+------------------+--------------------------------------------------+

ATTACK SEQUENCE
---------------
+----------+--------------------------------------------------+
| STEP 1   | INITIAL ACCESS - Valid Accounts (T1078)          |
|          | Former employee uses their still-active VPN and  |
|          | EHR credentials to log into MedDefense's         |
|          | network from home. They were terminated 47 days  |
|          | ago but no one disabled the account.            |
+----------+--------------------------------------------------+
| STEP 2   | COLLECTION - Data from Information Repositories   |
|          | (T1213)                                           |
|          | Employee accesses the EHR system and runs         |
|          | queries to extract patient records. They use     |
|          | their billing privileges to download PHI for     |
|          | 1,847 individuals.                                |
+----------+--------------------------------------------------+
| STEP 3   | DEFENSE EVASION - Scheduled Job (T1053)           |
|          | Employee creates a scheduled task to extract     |
|          | data during off-hours (10 PM - 2 AM) to avoid    |
|          | detection.                                        |
+----------+--------------------------------------------------+
| STEP 4   | EXFILTRATION - Exfiltration Over C2 Channel       |
|          | (T1041)                                           |
|          | Employee exfiltrates data via personal email,    |
|          | cloud storage, or USB drive. No DLP controls     |
|          | are in place.                                     |
+----------+--------------------------------------------------+
| STEP 5   | IMPACT - Exfiltration (T1530)                     |
|          | Employee sells patient data on dark web markets. |
|          | Patients receive fraudulent medical bills,       |
|          | triggering an investigation.                     |
+----------+--------------------------------------------------+

STRIDE CATEGORIES TRIGGERED
---------------------------
+------------------+--------------------------------------------------+
| STRIDE           | S: Spoofing - Impersonating legitimate user      |
| Categories       | I: Information Disclosure - PHI exfiltrated       |
| Triggered        | R: Repudiation - Shared account if used          |
|                  | E: Elevation of Privilege - Exceeds authorized   |
|                  |    access                                         |
+------------------+--------------------------------------------------+

MEDDEFENSE ASSETS IMPACTED
--------------------------
+------------------+--------------------------------------------------+
| Assets           | ehr-db-01 (CRITICAL) - EHR Database (PHI for     |
| Impacted         | 1,847 patients)                                   |
|                  | billing-srv-01 (HIGH) - Billing system           |
|                  | (credentials used)                                |
|                  | VPN Access (CRITICAL) - Remote access            |
+------------------+--------------------------------------------------+

BUSINESS IMPACT
---------------
+------------------+--------------------------------------------------+
| Clinical         | - Patient identity theft risk                    |
|                  | - Fraudulent medical bills                       |
|                  | - Potential impact on patient care records       |
+------------------+--------------------------------------------------+
| Financial        | - $890K breach response costs                    |
|                  | - Class action lawsuit from affected patients   |
|                  | - Regulatory fines (HIPAA violation)            |
|                  | - Potential Medicare/Medicaid sanctions         |
+------------------+--------------------------------------------------+
| Regulatory       | - HHS Office for Civil Rights investigation     |
|                  | - Mandatory breach notification (1,847 patients) |
|                  | - HIPAA fine (up to $1.5M per violation)        |
+------------------+--------------------------------------------------+
| Reputational     | - Loss of patient trust                         |
|                  | - Community perception of insecure hospital     |
|                  | - Negative media coverage                        |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | How Exploited                                    |
+------------------+--------------------------------------------------+
| GAP-015          | No automated offboarding - Employee retains      |
|                  | active VPN and EHR credentials 47 days after     |
|                  | termination                                       |
+------------------+--------------------------------------------------+
| GAP-004          | No MFA - Employee credentials are sufficient to  |
|                  | access VPN and EHR                               |
+------------------+--------------------------------------------------+
| GAP-001          | No SIEM - Off-hours access and data exfiltration |
|                  | are not detected                                  |
+------------------+--------------------------------------------------+
| GAP-010          | No audits - No one reviews access logs to detect |
|                  | unauthorized access                               |
+------------------+--------------------------------------------------+
| GAP-011          | No enforcement - No consequences for policy      |
|                  | violations leading to offboarding issues         |
+------------------+--------------------------------------------------+

DETECTION OPPORTUNITIES
-----------------------
+----------+------------------+------------------------------------------+
| Step     | Detection        | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Login            | MFA + SIEM alerting on off-hours or      |
|          |                  | unusual location logins                 |
| Step 1   | Account Activity | Automated offboarding (GAP-015)          |
| Step 2   | Data Access      | SIEM alerting on large data queries      |
| Step 2   | Access Pattern   | Behavioral analytics / UEBA             |
| Step 3   | Scheduled Task   | SIEM alerting on suspicious scheduled    |
|          |                  | tasks                                     |
| Step 4   | Data Transfer    | DLP controls on email/USB/cloud          |
| Step 4   | Exfiltration     | Egress filtering + SIEM                 |
+----------+------------------+------------------------------------------+


================================================================================
SCENARIO 3: THIRD PARTY - SUPPLY CHAIN COMPROMISE
================================================================================

TITLE
-----
+------------------+--------------------------------------------------+
| Title            | MedTech Breach: Supply Chain Pivot to EHR         |
+------------------+--------------------------------------------------+

THREAT ACTOR
------------
+------------------+--------------------------------------------------+
| Threat Actor     | External Attacker via Vendor Compromise           |
|                  | (Reference: T5 - Supply Chain)                    |
+------------------+--------------------------------------------------+
| Motivation       | FINANCIAL GAIN + ESPIONAGE - Ransomware + data    |
|                  | theft                                             |
|                  | (Security+ 2.1 - Financial + Espionage)           |
+------------------+--------------------------------------------------+
| Initial Vector   | Supply Chain Compromise (V5 from Task 9)          |
+------------------+--------------------------------------------------+
| Attack Surface   | EXTERNAL - MedTech Solutions maintenance portal   |
| Exploited        | (Reference: T5 - Third Party Access)              |
+------------------+--------------------------------------------------+

ATTACK SEQUENCE
---------------
+----------+--------------------------------------------------+
| STEP 1   | RECONNAISSANCE - Active Scanning (T1595)          |
|          | Attacker scans MedTech Solutions' network and    |
|          | discovers their remote access portal for         |
|          | MedDefense's EHR system.                         |
+----------+--------------------------------------------------+
| STEP 2   | INITIAL ACCESS - Exploit Public-Facing            |
|          | Application (T1190)                               |
|          | Attacker exploits a vulnerability in MedTech's   |
|          | portal or uses stolen credentials to gain        |
|          | access to their environment.                     |
+----------+--------------------------------------------------+
| STEP 3   | LATERAL MOVEMENT - Remote Services (T1021)        |
|          | Attacker moves laterally within MedTech's        |
|          | network to find the credentials used to access   |
|          | MedDefense's EHR server.                         |
+----------+--------------------------------------------------+
| STEP 4   | INITIAL ACCESS (MedDefense) - Valid Accounts      |
|          | (T1078)                                           |
|          | Attacker uses stolen MedTech credentials to      |
|          | connect directly to ehr-srv-01 and ehr-db-01     |
|          | via the maintenance portal. No MFA on vendor    |
|          | accounts means credentials are sufficient.       |
+----------+--------------------------------------------------+
| STEP 5   | PRIVILEGE ESCALATION - Domain Policy               |
|          | Modification (T1484)                              |
|          | Attacker harvests credentials on the EHR server  |
|          | and moves laterally to Active Directory via      |
|          | the flat network. They gain Domain Admin access. |
+----------+--------------------------------------------------+
| STEP 6   | IMPACT - Data Encrypted for Impact (T1486) +     |
|          | Data Exfiltration (T1530)                         |
|          | Attacker deploys ransomware and exfiltrates PHI. |
+----------+--------------------------------------------------+

STRIDE CATEGORIES TRIGGERED
---------------------------
+------------------+--------------------------------------------------+
| STRIDE           | S: Spoofing - Impersonating MedTech engineers    |
| Categories       | T: Tampering - System modifications              |
| Triggered        | R: Repudiation - Vendor activity can be denied   |
|                  | I: Information Disclosure - PHI exfiltrated      |
|                  | D: Denial of Service - Ransomware encryption     |
|                  | E: Elevation of Privilege - Domain Admin access  |
|                  | ALL SIX STRIDE CATEGORIES ARE TRIGGERED          |
+------------------+--------------------------------------------------+

MEDDEFENSE ASSETS IMPACTED
--------------------------
+------------------+--------------------------------------------------+
| Assets           | ehr-srv-01 (CRITICAL) - EHR Application          |
| Impacted         | ehr-db-01 (CRITICAL) - EHR Database (50k+ PHI)   |
|                  | ad-dc-01 (CRITICAL) - Active Directory            |
|                  | billing-srv-01 (HIGH) - Billing System           |
|                  | NAS-01 (HIGH) - Backup Storage                    |
|                  | MedTech Solutions - Vendor trust and reputation  |
+------------------+--------------------------------------------------+

BUSINESS IMPACT
---------------
+------------------+--------------------------------------------------+
| Clinical         | - 11+ days of EHR downtime                       |
|                  | - Ambulance diversions                           |
|                  | - Clinicians forced to use paper records        |
|                  | - Patient safety risk                            |
+------------------+--------------------------------------------------+
| Financial        | - $2.5M+ ransom demand                          |
|                  | - $3M+ recovery costs                           |
|                  | - Loss of vendor contract ($145K annual)        |
|                  | - Regulatory fines and class actions            |
+------------------+--------------------------------------------------+
| Regulatory       | - HHS investigation                             |
|                  | - Mandatory HIPAA breach notification (50k+)    |
|                  | - Potential sanctions on Medicare/Medicaid     |
+------------------+--------------------------------------------------+
| Reputational     | - Loss of trust in vendors                      |
|                  | - Patient trust erosion                         |
|                  | - Negative media coverage                       |
|                  | - Damage to vendor relationships               |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | How Exploited                                    |
+------------------+--------------------------------------------------+
| GAP-012          | No vendor account management - MedTech           |
|                  | credentials have no oversight or monitoring      |
+------------------+--------------------------------------------------+
| GAP-004          | No MFA for vendor accounts - Credentials are     |
|                  | sufficient                                       |
+------------------+--------------------------------------------------+
| GAP-003          | Flat network - Lateral movement from EHR to     |
|                  | AD                                                 |
+------------------+--------------------------------------------------+
| GAP-001          | No SIEM - Vendor activity undetected             |
+------------------+--------------------------------------------------+
| GAP-008          | No egress filtering - Data exfiltration          |
|                  | unrestricted                                      |
+------------------+--------------------------------------------------+
| C-009 Weakness   | Co-located backups - Backups encrypted           |
+------------------+--------------------------------------------------+

DETECTION OPPORTUNITIES
-----------------------
+----------+------------------+------------------------------------------+
| Step     | Detection        | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Vendor Scanning  | Vendor account monitoring                |
| Step 2   | Vendor Access    | Vendor security audits                   |
| Step 3   | Lateral Movement | Vendor network monitoring                |
| Step 4   | Vendor Login     | MFA for vendor accounts (GAP-004, GAP-   |
|          |                  | 012) + SIEM alerting on vendor activity  |
| Step 5   | Lateral Movement | Network segmentation (GAP-003)           |
| Step 5   | Privilege        | SIEM alerting on admin activity          |
|          | Escalation       |                                          |
| Step 6   | Exfiltration     | Egress filtering (GAP-008) + SIEM        |
| Step 6   | Ransomware       | EDR alerting on file encryption          |
+----------+------------------+------------------------------------------+


================================================================================
SCENARIO SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+------------------------------------------+
| Scenario | Actor            | Primary Vector   | Primary Target   | STRIDE           | Gaps Exploited                           |
+----------+------------------+------------------+------------------+------------------+------------------------------------------+
| #1       | RaaS Group       | VPN Exploit      | EHR + AD         | All 6            | GAP-014, GAP-003, GAP-004, GAP-001,     |
| External | (BlackReef)      |                  |                  |                  | GAP-008, GAP-002, C-009                  |
+----------+------------------+------------------+------------------+------------------+------------------------------------------+
| #2       | Malicious Insider| Legitimate Access| EHR (PHI)        | S, I, R, E       | GAP-015, GAP-004, GAP-001, GAP-010,    |
| Internal | (Former Employee)| Abuse            |                  |                  | GAP-011                                  |
+----------+------------------+------------------+------------------+------------------+------------------------------------------+
| #3       | Supply Chain     | MedTech Vendor   | EHR + AD         | All 6            | GAP-012, GAP-004, GAP-003, GAP-001,    |
| Third    | Attacker         | Compromise       |                  |                  | GAP-008, C-009                           |
| Party    |                  |                  |                  |                  |                                          |
+----------+------------------+------------------+------------------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- MITRE ATT&CK Enterprise Framework
- NIST SP 800-30: Attack path analysis
- Security+ 2.1: Threat actor motivations
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Kill Chains (Task 10): Attack sequences
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets
- STRIDE on EHR (Task 11): Threat categories
- STRIDE Across Architecture (Task 12): System threats


================================================================================
END OF THREAT SCENARIOS REPORT
================================================================================
