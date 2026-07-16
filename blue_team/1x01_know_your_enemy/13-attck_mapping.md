================================================================================
                    ATT&CK MAPPING - MEDDEFENSE HEALTH SYSTEMS
                    Task 13: The ATT&CK Mapping
================================================================================

Exercise: Task 13 - The ATT&CK Mapping
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Map realistic attack sequences to MITRE ATT&CK tactics, building
          fluency with the framework that every SOC uses daily.

Methodology References:
- MITRE ATT&CK Enterprise Framework (14 tactics)
- NIST SP 800-30: Attack path analysis
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Kill Chains (Task 10): Attack sequences
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets


================================================================================
SCENARIO ALPHA: RANSOMWARE THROUGH UNPATCHED VPN → EHR + AD
================================================================================

SCENARIO OVERVIEW
-----------------
+------------------+--------------------------------------------------+
| Scenario         | Alpha - Ransomware Through Unpatched VPN          |
+------------------+--------------------------------------------------+
| Source           | Kill Chain #1 (Task 10)                          |
+------------------+--------------------------------------------------+
| Description      | Ransomware groups exploit an unpatched VPN        |
|                  | vulnerability to gain internal network access.    |
|                  | They move laterally across the flat network,      |
|                  | compromise Active Directory, deploy ransomware   |
|                  | via Group Policy, and encrypt the EHR, billing,   |
|                  | and backup systems.                               |
+------------------+--------------------------------------------------+


STEP 1: SCAN FOR VULNERABLE VPN APPLIANCE
-----------------------------------------
+------------------+--------------------------------------------------+
| Step             | 1                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker scans for FortiGate VPN appliances with  |
|                  | known, unpatched vulnerabilities. They identify   |
|                  | MedDefense's FortiGate 100F as a target.         |
+------------------+--------------------------------------------------+
| Tactic           | RECONNAISSANCE                                    |
+------------------+--------------------------------------------------+
| Technique        | Active Scanning (T1595)                           |
|                  | - Scanning IP blocks for vulnerable VPN devices  |
|                  | - Identifying version information from banners   |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-014: No Patch Management means the VPN       |
| Factor           | appliance may have known, unpatched               |
|                  | vulnerabilities. No SIEM means scanning activity  |
|                  | is not detected.                                  |
+------------------+--------------------------------------------------+


STEP 2: EXPLOIT VPN VULNERABILITY
---------------------------------
+------------------+--------------------------------------------------+
| Step             | 2                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker exploits a known VPN vulnerability (CVE) |
|                  | to gain initial access to MedDefense's internal   |
|                  | network.                                          |
+------------------+--------------------------------------------------+
| Tactic           | INITIAL ACCESS                                    |
+------------------+--------------------------------------------------+
| Technique        | External Remote Services (T1133)                  |
|                  | - Exploiting VPN appliance vulnerabilities       |
|                  | - Gaining network access through compromised     |
|                  |   perimeter device                                |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-014: VPN firmware not patched. GAP-004: No   |
| Factor           | MFA on VPN means a single exploit is sufficient. |
+------------------+--------------------------------------------------+


STEP 3: INSTALL BACKDOOR / PERSISTENT ACCESS
--------------------------------------------
+------------------+--------------------------------------------------+
| Step             | 3                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker installs a backdoor on a compromised     |
|                  | system for persistent access (web shell, SSH key, |
|                  | or scheduled task).                               |
+------------------+--------------------------------------------------+
| Tactic           | PERSISTENCE                                       |
+------------------+--------------------------------------------------+
| Technique        | Account Manipulation (T1098) OR                   |
|                  | Scheduled Task/Job (T1053)                        |
|                  | - Creating a new user account for persistence    |
|                  | - Installing web shell on compromised server     |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-001: No SIEM means backdoor installation is  |
| Factor           | not detected. No MFA means backdoor accounts     |
|                  | are sufficient.                                   |
+------------------+--------------------------------------------------+


STEP 4: HARVEST CREDENTIALS
---------------------------
+------------------+--------------------------------------------------+
| Step             | 4                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker uses tools like Mimikatz to harvest      |
|                  | credentials from memory, including Domain Admin   |
|                  | credentials.                                      |
+------------------+--------------------------------------------------+
| Tactic           | CREDENTIAL ACCESS                                 |
+------------------+--------------------------------------------------+
| Technique        | OS Credential Dumping: LSASS Memory (T1003.001)   |
|                  | - Extracting credentials from LSASS process       |
|                  |   memory                                         |
|                  | - Using Mimikatz to harvest NTLM hashes          |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-004: No MFA means harvested credentials      |
| Factor           | are directly usable. GAP-001: No SIEM means the  |
|                  | credential harvesting activity is not detected.  |
+------------------+--------------------------------------------------+


STEP 5: MOVE LATERALLY TO DOMAIN CONTROLLER
-------------------------------------------
+------------------+--------------------------------------------------+
| Step             | 5                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker uses harvested credentials to move       |
|                  | laterally across the flat network to the Domain   |
|                  | Controller (ad-dc-01).                            |
+------------------+--------------------------------------------------+
| Tactic           | LATERAL MOVEMENT                                  |
+------------------+--------------------------------------------------+
| Technique        | Remote Services (T1021)                           |
|                  | - Using RDP, PsExec, or WMI to move between      |
|                  |   systems                                        |
|                  | - Lateral movement enabled by flat network       |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat network means no internal          |
| Factor           | segmentation to block lateral movement. GAP-001: |
|                  | No SIEM means movement is undetected.            |
+------------------+--------------------------------------------------+


STEP 6: DEPLOY RANSOMWARE VIA GROUP POLICY
------------------------------------------
+------------------+--------------------------------------------------+
| Step             | 6                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker uses compromised Domain Admin           |
|                  | credentials to deploy ransomware to all Windows  |
|                  | systems via Group Policy Object (GPO).           |
+------------------+--------------------------------------------------+
| Tactic           | IMPACT                                            |
+------------------+--------------------------------------------------+
| Technique        | Data Encrypted for Impact (T1486)                 |
|                  | - Deploying ransomware via GPO                   |
|                  | - Encrypting all accessible systems and data     |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-004: No MFA means Domain Admin credentials   |
| Factor           | are sufficient. GAP-003: Flat network means GPO  |
|                  | reaches all systems. C-009: Co-located backups   |
|                  | are also encrypted.                               |
+------------------+--------------------------------------------------+


STEP 7: EXFILTRATE DATA BEFORE ENCRYPTION
-----------------------------------------
+------------------+--------------------------------------------------+
| Step             | 7                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker exfiltrates patient data before         |
|                  | deploying ransomware (double extortion).         |
+------------------+--------------------------------------------------+
| Tactic           | EXFILTRATION                                      |
+------------------+--------------------------------------------------+
| Technique        | Exfiltration Over C2 Channel (T1041) OR          |
|                  | Exfiltration to Cloud Storage (T1567)            |
|                  | - Using Rclone or custom scripts to exfiltrate   |
|                  |   data                                            |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-008: No egress filtering means data can      |
| Factor           | leave unrestricted. GAP-001: No SIEM means       |
|                  | exfiltration is undetected.                       |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO BETA: PHISHING → CREDENTIALS → EHR DATA EXFILTRATION
================================================================================

SCENARIO OVERVIEW
-----------------
+------------------+--------------------------------------------------+
| Scenario         | Beta - Phishing to EHR Data Exfiltration          |
+------------------+--------------------------------------------------+
| Source           | Kill Chain #2 (Task 10)                          |
+------------------+--------------------------------------------------+
| Description      | Attacker sends a targeted phishing email to a    |
|                  | clinician. The employee clicks the link and      |
|                  | enters credentials on a fake login page. The     |
|                  | attacker uses the credentials to access the EHR  |
|                  | database and exfiltrate PHI for 50,000 patients. |
+------------------+--------------------------------------------------+


STEP 1: SEND SPEAR PHISHING EMAIL
---------------------------------
+------------------+--------------------------------------------------+
| Step             | 1                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker researches MedDefense employees and     |
|                  | sends a targeted phishing email to a clinician   |
|                  | (or IT staff). The email appears to come from a  |
|                  | trusted source and asks for credential           |
|                  | verification.                                     |
+------------------+--------------------------------------------------+
| Tactic           | INITIAL ACCESS                                    |
+------------------+--------------------------------------------------+
| Technique        | Phishing: Spearphishing Link (T1566.002)          |
|                  | - Sending fraudulent emails to gather            |
|                  |   credentials or other sensitive information     |
|                  | - Using a fake login page (Evilginx2)            |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-013: Low training completion (58-71%) means  |
| Factor           | employees are vulnerable to phishing. GAP-013:   |
|                  | No phishing simulations means staff are not     |
|                  | tested.                                           |
+------------------+--------------------------------------------------+


STEP 2: CAPTURE CREDENTIALS
---------------------------
+------------------+--------------------------------------------------+
| Step             | 2                                                 |
+------------------+--------------------------------------------------+
| Description      | Employee clicks the link, lands on a fake login   |
|                  | page, and enters their credentials. The attacker  |
|                  | captures the username and password.               |
+------------------+--------------------------------------------------+
| Tactic           | CREDENTIAL ACCESS                                 |
+------------------+--------------------------------------------------+
| Technique        | Credentials from Password Stores (T1555) OR      |
|                  | Phishing: Spearphishing Link (T1566.002)         |
|                  | - Capturing credentials via fake login page      |
|                  | - Using Evilginx2 or similar tool to harvest     |
|                  |   credentials                                     |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-004: No MFA means captured credentials are   |
| Factor           | immediately usable. GAP-001: No SIEM means       |
|                  | credential capture is not detected.              |
+------------------+--------------------------------------------------+


STEP 3: ACCESS NETWORK WITH STOLEN CREDENTIALS
----------------------------------------------
+------------------+--------------------------------------------------+
| Step             | 3                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker uses stolen credentials to log into     |
|                  | MedDefense's VPN or O365. They now have a        |
|                  | foothold on the internal network.                |
+------------------+--------------------------------------------------+
| Tactic           | INITIAL ACCESS                                    |
+------------------+--------------------------------------------------+
| Technique        | Valid Accounts (T1078)                            |
|                  | - Using stolen credentials to authenticate       |
|                  | - Accessing VPN or O365 with valid credentials   |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-004: No MFA means credentials are            |
| Factor           | sufficient. GAP-001: No SIEM means login is not  |
|                  | detected.                                         |
+------------------+--------------------------------------------------+


STEP 4: DISCOVER EHR DATABASE
-----------------------------
+------------------+--------------------------------------------------+
| Step             | 4                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker scans the flat network and discovers    |
|                  | PostgreSQL port 5432 on ehr-db-01 accessible     |
|                  | network-wide.                                     |
+------------------+--------------------------------------------------+
| Tactic           | DISCOVERY                                         |
+------------------+--------------------------------------------------+
| Technique        | Network Service Scanning (T1046) OR              |
|                  | Remote System Discovery (T1018)                  |
|                  | - Scanning for open ports on the network         |
|                  | - Discovering the EHR database server            |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat network means scanning is          |
| Factor           | unrestricted. GAP-001: No SIEM means scanning    |
|                  | activity is not detected.                         |
+------------------+--------------------------------------------------+


STEP 5: CONNECT TO POSTGRESQL DATABASE
--------------------------------------
+------------------+--------------------------------------------------+
| Step             | 5                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker connects to PostgreSQL 5432 on          |
|                  | ehr-db-01 using stolen credentials. They run SQL |
|                  | queries to extract PHI.                           |
+------------------+--------------------------------------------------+
| Tactic           | COLLECTION                                        |
+------------------+--------------------------------------------------+
| Technique        | Data from Information Repositories (T1213) OR   |
|                  | SQL Injection (T1505)                            |
|                  | - Querying the EHR database directly             |
|                  | - Extracting patient records (PHI)               |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: PostgreSQL accessible network-wide.     |
| Factor           | GAP-001: No SIEM means database queries are not  |
|                  | detected.                                         |
+------------------+--------------------------------------------------+


STEP 6: EXFILTRATE PHI
----------------------
+------------------+--------------------------------------------------+
| Step             | 6                                                 |
+------------------+--------------------------------------------------+
| Description      | Attacker exfiltrates the extracted PHI via        |
|                  | encrypted channels (HTTPS, SSH tunnel, or        |
|                  | cloud storage).                                   |
+------------------+--------------------------------------------------+
| Tactic           | EXFILTRATION                                      |
+------------------+--------------------------------------------------+
| Technique        | Exfiltration Over C2 Channel (T1041) OR          |
|                  | Exfiltration to Cloud Storage (T1567)            |
|                  | - Transferring PHI to attacker-controlled        |
|                  |   servers                                         |
|                  | - Using Rclone or other tools                    |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-008: No egress filtering means data can      |
| Factor           | leave unrestricted. GAP-001: No SIEM means       |
|                  | exfiltration is undetected.                       |
+------------------+--------------------------------------------------+


================================================================================
ATT&CK COVERAGE ASSESSMENT
================================================================================

+----------------------------------------------------------------------------+
| ATT&CK COVERAGE ASSESSMENT                                                  |
|                                                                             |
| Comparing both scenarios (Alpha and Beta), the following ATT&CK tactics    |
| appear in BOTH attacks:                                                     |
|                                                                             |
| 1. INITIAL ACCESS (Tactics #3) - Both attacks require gaining entry.       |
|    Alpha: External Remote Services (T1133) - VPN exploit                   |
|    Beta: Phishing: Spearphishing Link (T1566.002) - phishing              |
|                                                                             |
| 2. CREDENTIAL ACCESS (Tactics #8) - Both attacks involve credential       |
|    theft.                                                                  |
|    Alpha: OS Credential Dumping: LSASS Memory (T1003.001) - Mimikatz      |
|    Beta: Credentials from Password Stores (T1555) - phishing              |
|                                                                             |
| 3. EXFILTRATION (Tactics #13) - Both attacks involve data exfiltration.   |
|    Alpha: Exfiltration Over C2 Channel (T1041)                            |
|    Beta: Exfiltration to Cloud Storage (T1567)                            |
|                                                                             |
| 4. LATERAL MOVEMENT (Tactics #10) - Alpha explicitly uses lateral         |
|    movement. Beta uses network scanning but could also involve lateral    |
|    movement.                                                               |
|    Alpha: Remote Services (T1021)                                         |
|                                                                             |
| 5. IMPACT (Tactics #14) - Alpha has ransomware deployment (T1486).        |
|    Beta focuses on data theft rather than destruction.                    |
|                                                                             |
| What this tells us about MedDefense's detection gaps:                      |
|                                                                             |
| The tactics that appear in BOTH attacks represent MedDefense's most       |
| urgent detection needs. Specifically, MedDefense needs the ability to     |
| detect:                                                                    |
|                                                                             |
| 1. INITIAL ACCESS: Unauthorized VPN logins and phishing attempts.          |
|    MedDefense has NO MFA and NO SIEM.                                     |
|                                                                             |
| 2. CREDENTIAL ACCESS: Credential harvesting and credential reuse.          |
|    MedDefense has NO MFA and NO monitoring of credential usage.           |
|                                                                             |
| 3. EXFILTRATION: Large data transfers outbound. MedDefense has NO         |
|    egress filtering and NO SIEM.                                           |
|                                                                             |
| The highest priority for MedDefense should be detection at the           |
| INITIAL ACCESS and CREDENTIAL ACCESS tactics. These are the earliest      |
| points in the attack chain where intervention can stop the entire         |
| sequence. Specifically:                                                    |
| - MFA for all remote access (prevents credential reuse)                  |
| - SIEM with alerting on unusual VPN logins and credential harvesting      |
| - Email filtering and phishing simulations                               |
| - Egress filtering to prevent data exfiltration                          |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- MITRE ATT&CK Enterprise Framework
- NIST SP 800-30: Attack path analysis
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Kill Chains (Task 10): Attack sequences
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to assets


================================================================================
END OF ATT&CK MAPPING REPORT
================================================================================
