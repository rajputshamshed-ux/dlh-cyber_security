================================================================================
                    INSIDER THREAT ASSESSMENT - MEDDEFENSE HEALTH SYSTEMS
                    Task 3: The Insider File
================================================================================

Exercise: Task 3 - The Insider File
Analyst: shamshed rajput 
Date: 14/07/2026
Objective: Distinguish malicious from negligent insider threats, identify
          behavioral indicators and connect each scenario to existing
          control gaps.

Methodology References:
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)
- HHS Breach Portal Statistics (File 3)
- NIST SP 800-53: AC-6 (Least Privilege), AC-11 (Session Lock), IA-5
  (Authenticator Management)
- CIS Controls v8: Control 5 (Account Management), Control 3 (Data Protection)

Cross-References to Project 1x00:
- Gap Analysis (Task 12): GAP-004, GAP-007, GAP-010, GAP-015
- Control Matrix (Task 10): C-006, C-007, C-013, C-014
- Shadow IT (Task 11): Dr. Patel's NAS
- Walk-through Observations (Task 3): Shared login, unlocked sessions


================================================================================
SCENARIO 1: THE SHARED LOGIN
================================================================================

SCENARIO DESCRIPTION
--------------------
The Radiology department uses a shared account ("raduser/radiology1") for
the PACS workstation. Multiple technicians use the same credentials
throughout the day. Nobody logs out between patients.

+------------------+--------------------------------------------------+
| Classification   | NEGLIGENT                                        |
+------------------+--------------------------------------------------+
| Justification    | The shared account is a policy violation, but   |
|                  | there is no evidence of malicious intent. The   |
|                  | technicians are sharing credentials for          |
|                  | convenience and efficiency. This is a systemic   |
|                  | failure created by IT not providing individual   |
|                  | accounts or streamlined login processes.        |
+------------------+--------------------------------------------------+
| Behavioral       | 1. Multiple concurrent sessions from different   |
| Indicators       |    workstations using the same account.         |
|                  | 2. Unusual activity hours when multiple shifts  |
|                  |    use the same credentials.                    |
|                  | 3. The same account being used from multiple    |
|                  |    IP addresses simultaneously.                  |
+------------------+--------------------------------------------------+
| Existing Control | C-007: Shared Account Policy (Administrative /  |
| (1x00)           | Preventive) - Policy exists but is NOT enforced. |
|                  | C-014: AD Logging (Technical / Detective) -      |
|                  | Logs would show shared account usage but no     |
|                  | alerting is configured.                          |
+------------------+--------------------------------------------------+
| Gap Exploited    | GAP-004: No MFA Anywhere - Shared account has   |
| (1x00)           | no individual authentication.                   |
|                  | GAP-007: Shared Account Policy Not Enforced -   |
|                  | Marcus noted: "I reported this. Nothing         |
|                  | happened."                                       |
+------------------+--------------------------------------------------+
| Recommended      | Implement individual accounts for each           |
| Mitigation       | technician with single sign-on and automatic    |
|                  | session locking after inactivity. Enforce the   |
|                  | shared account policy with consequences.        |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 2: THE GHOST ACCOUNT
================================================================================

SCENARIO DESCRIPTION
--------------------
An IT support contractor's VPN account remained active for 47 days after
their contract ended. Network logs show the account authenticated 3 times
during off-hours in the weeks after termination. This mirrors Incident F
from your 1x00 incident analysis.

+------------------+--------------------------------------------------+
| Classification   | POTENTIALLY MALICIOUS (or opportunistic)         |
+------------------+--------------------------------------------------+
| Justification    | The account was used after termination.          |
|                  | Off-hours access (10 PM - 2 AM) suggests the    |
|                  | contractor either: (a) intentionally retained   |
|                  | access for unauthorized purposes, or (b) someone |
|                  | else discovered and used the credential. Either  |
|                  | way, the access was unauthorized and the         |
|                  | motivation could be financial gain or curiosity. |
|                  | The fact that the contractor never reported the  |
|                  | termination to IT suggests negligence at         |
|                  | minimum.                                          |
+------------------+--------------------------------------------------+
| Behavioral       | 1. Login attempts from off-hours (10 PM - 2 AM). |
| Indicators       | 2. Access from an IP address not associated with |
|                  |    the contractor's normal work locations.      |
|                  | 3. Account activity after the contract end date. |
|                  | 4. Accessing systems outside the contractor's   |
|                  |    normal scope.                                 |
+------------------+--------------------------------------------------+
| Existing Control | C-006: Password Policy (Administrative /         |
| (1x00)           | Preventive) - Enforces 90-day rotation but does |
|                  | not detect dormant accounts.                    |
|                  | C-014: AD Logging (Technical / Detective) -      |
|                  | Logs exist but no alerting for anomalous access. |
+------------------+--------------------------------------------------+
| Gap Exploited    | GAP-015: No Automated User Offboarding -         |
| (1x00)           | Accounts remain active after termination.       |
|                  | GAP-001: No SIEM or Log Monitoring - Off-hours  |
|                  | access triggers no alert.                        |
+------------------+--------------------------------------------------+
| Recommended      | Implement automated account deactivation linked  |
| Mitigation       | to HR termination data. Deploy SIEM to alert on  |
|                  | off-hours access and access from unusual        |
|                  | locations.                                       |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 3: THE PERSONAL NAS
================================================================================

SCENARIO DESCRIPTION
--------------------
Dr. Patel in Cardiology connected a personal NAS device to his office
network port. He stores research data and "convenience copies" of patient
files he consults frequently. The NAS is not encrypted, not backed up
and not visible to IT. This is the shadow IT finding from 1x00 Task 11.

+------------------+--------------------------------------------------+
| Classification   | NEGLIGENT                                        |
+------------------+--------------------------------------------------+
| Justification    | Dr. Patel is not acting maliciously. He is       |
|                  | trying to solve a legitimate problem: the        |
|                  | hospital shared drive is too slow for his        |
|                  | research data. He bypassed IT controls for       |
|                  | convenience and efficiency, creating a security  |
|                  | risk without malicious intent. This is shadow    |
|                  | IT caused by unmet user needs.                  |
+------------------+--------------------------------------------------+
| Behavioral       | 1. Unknown device on the network (network scan   |
| Indicators       |    would detect).                                |
|                  | 2. New IP address appearing on the network with  |
|                  |    no associated asset record.                  |
|                  | 3. Large amounts of data being transferred to    |
|                  |    the NAS device.                              |
|                  | 4. Data storage usage on file-srv-01 remaining   |
|                  |    constant despite Dr. Patel's requests for     |
|                  |    faster storage.                               |
+------------------+--------------------------------------------------+
| Existing Control | NO controls cover this system.                   |
| (1x00)           | All 20 controls from Task 10 do NOT cover the    |
|                  | NAS.                                             |
+------------------+--------------------------------------------------+
| Gap Exploited    | GAP-009: Shadow IT Systems - 3 unmanaged         |
| (1x00)           | devices on the network with no controls.        |
|                  | GAP-010: No Administrative Detective Controls -  |
|                  | No audits to discover unauthorized devices.     |
+------------------+--------------------------------------------------+
| Recommended      | Migrate Dr. Patel's data to approved storage     |
| Mitigation       | (file-srv-01 with capacity upgrade or O365      |
|                  | SharePoint). Decommission the NAS. Implement    |
|                  | network scanning to detect unauthorized         |
|                  | devices.                                         |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 4: THE CURIOUS EMPLOYEE
================================================================================

SCENARIO DESCRIPTION
--------------------
A registration clerk at the front desk accesses the EHR records of a local
politician who was treated at MedDefense Central. She does not modify
anything. She tells a friend about the visit. The friend posts it on
social media.

+------------------+--------------------------------------------------+
| Classification   | MALICIOUS                                        |
+------------------+--------------------------------------------------+
| Justification    | The employee intentionally accessed patient      |
|                  | records without a legitimate work reason. She    |
|                  | then disclosed protected health information to   |
|                  | a third party, resulting in a public HIPAA       |
|                  | violation. The motivation appears to be          |
|                  | curiosity and gossip, not financial gain, but    |
|                  | the intent was malicious.                        |
+------------------+--------------------------------------------------+
| Behavioral       | 1. Access to a patient record that is not        |
| Indicators       |    associated with the employee's work role.    |
|                  | 2. Multiple accesses to records of a high-      |
|                  |    profile individual.                          |
|                  | 3. Access outside normal work hours or from an  |
|                  |    unusual location.                            |
|                  | 4. Employee searching for specific individuals   |
|                  |    not linked to their work assignment.          |
+------------------+--------------------------------------------------+
| Existing Control | C-014: AD Logging (Technical / Detective) -      |
| (1x00)           | EHR logs exist but are NOT monitored.           |
|                  | C-013: Security Awareness Training               |
|                  | (Administrative / Preventive) - Includes PHI    |
|                  | handling but completion is low (58-71%).        |
+------------------+--------------------------------------------------+
| Gap Exploited    | GAP-001: No SIEM or Log Monitoring - EHR access |
| (1x00)           | logs exist but are never reviewed.              |
|                  | GAP-010: No Administrative Detective Controls -  |
|                  | No compliance audits to detect unauthorized     |
|                  | access.                                          |
|                  | GAP-011: No Enforcement - No consequences for    |
|                  | policy violations.                              |
+------------------+--------------------------------------------------+
| Recommended      | Implement EHR access monitoring with alerts for  |
| Mitigation       | unauthorized access to high-profile records.    |
|                  | Conduct periodic audits of EHR access logs.     |
|                  | Enforce consequences for unauthorized access.   |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 5: THE OVERWORKED ADMIN
================================================================================

SCENARIO DESCRIPTION
--------------------
A sysadmin, overwhelmed by tickets, writes a script to automate password
resets. The script stores Active Directory admin credentials in plaintext
in a file on his desktop. He shares the script with a colleague via email
so they can "help with the backlog."

+------------------+--------------------------------------------------+
| Classification   | NEGLIGENT                                        |
+------------------+--------------------------------------------------+
| Justification    | The sysadmin is trying to solve a legitimate     |
|                  | operational problem (too many password reset     |
|                  | tickets). The action is negligent because he     |
|                  | hardcodes admin credentials in plaintext, stores |
|                  | them on his desktop, and emails them to a        |
|                  | colleague. This is a clear violation of security |
|                  | best practices, but there is no evidence of      |
|                  | malicious intent.                                |
+------------------+--------------------------------------------------+
| Behavioral       | 1. Cleartext credentials stored on a user        |
| Indicators       |    desktop.                                      |
|                  | 2. Sending sensitive information (credentials)   |
|                  |    via email.                                    |
|                  | 3. A script that performs administrative         |
|                  |    functions from an unsecured location.        |
|                  | 4. Unusual account creation or password reset   |
|                  |    activity from the sysadmin's account.        |
+------------------+--------------------------------------------------+
| Existing Control | C-006: Password Policy (Administrative /         |
| (1x00)           | Preventive) - Does not address credential storage|
|                  | practices.                                       |
|                  | C-013: Security Awareness Training               |
|                  | (Administrative / Preventive) - Should cover     |
|                  | credential management but may not.              |
+------------------+--------------------------------------------------+
| Gap Exploited    | GAP-004: No MFA Anywhere - Even if credentials  |
| (1x00)           | are compromised, MFA would block access.        |
|                  | GAP-010: No Administrative Detective Controls -  |
|                  | No audits to discover insecure credential       |
|                  | storage.                                         |
|                  | GAP-011: No Enforcement - No consequences for    |
|                  | security violations.                            |
+------------------+--------------------------------------------------+
| Recommended      | Implement Privileged Access Management (PAM)     |
| Mitigation       | with automated credential rotation and no        |
|                  | hardcoded credentials. Require MFA for all       |
|                  | administrative actions. Enforce security        |
|                  | awareness training on credential management.    |
+------------------+--------------------------------------------------+


================================================================================
PATTERN ASSESSMENT
================================================================================

+----------------------------------------------------------------------------+
| SYSTEMIC WEAKNESS AT MEDDEFENSE                                            |
|                                                                             |
| The five insider scenarios reveal a systemic weakness at MedDefense: a     |
| combination of NO DETECTIVE CONTROLS, NO ENFORCEMENT, and POOR ACCOUNT-    |
| ABILITY. In every scenario, the organization had the technical capacity   |
| to detect or prevent the incident, but lacked the processes, monitoring,   |
| or culture to do so.                                                        |
|                                                                             |
| This pattern directly connects to two findings from Project 1x00:           |
|                                                                             |
| 1. GAP-001 (No SIEM or Log Monitoring): In Scenarios 2, 4, and 5,          |
|    detection failed because logs existed but were never reviewed. The      |
|    ghost account accessed the network 3 times off-hours - no alert. The    |
|    curious employee accessed a politician's EHR - no alert. The admin      |
|    emailed credentials - no DLP alert. MedDefense has logs but no way      |
|    to use them.                                                             |
|                                                                             |
| 2. GAP-011 (No Administrative Deterrent Controls): In Scenarios 1, 4,      |
|    and 5, the culture of security was weak. The shared account was         |
|    reported and ignored ("I reported this. Nothing happened"). The         |
|    employee accessed records without consequences. The admin stored        |
|    credentials in plaintext without consequences. Without enforcement,     |
|    security policies are merely suggestions.                               |
|                                                                             |
| Additionally, GAP-010 (No Administrative Detective Controls) means there   |
| are no regular audits to discover shadow IT (Scenario 3), dormant          |
| accounts (Scenario 2), or shared logins (Scenario 1). The organization     |
| is flying blind.                                                            |
|                                                                             |
| The root cause is not a single missing control - it is a systematic        |
| failure of detection and deterrence. MedDefense knows how to stop an       |
| incident (preventive controls exist), but has no way to KNOW when one      |
| happens (detective controls) and no way to DISCOURAGE one from happening   |
| (deterrent controls). Insider threats thrive in this environment.          |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| Scenario | Classification   | Behavioral      | Existing Control         | Gap Exploited    | Recommended Mitigation                   |
|          |                  | Indicators      | (1x00)                   | (1x00)           |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| 1        | Negligent        | Concurrent      | C-007: Shared Account     | GAP-004 (No MFA) | Individual accounts + SSO + session      |
| Shared   |                  | sessions,       | Policy (exists, not       | GAP-007 (No      | lock                                      |
| Login    |                  | multiple        | enforced)                | Enforcement)     |                                          |
|          |                  | shifts          |                           |                  |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| 2        | Potentially      | Off-hours,      | C-014: AD Logging (no     | GAP-015 (No      | Automated offboarding + SIEM alerts on   |
| Ghost    | Malicious        | unusual IP,     | alerts)                  | Offboarding)     | off-hours access                          |
| Account  |                  | post-termination |                           | GAP-001 (No      |                                          |
|          |                  |                 |                           | SIEM)            |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| 3        | Negligent        | Unknown device, | NO controls cover this    | GAP-009 (Shadow  | Migrate data to approved storage +       |
| Personal |                  | network scan    | system                    | IT)              | network scanning                          |
| NAS      |                  | detection       |                           | GAP-010 (No      |                                          |
|          |                  |                 |                           | Audits)          |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| 4        | Malicious        | Unauthorized    | C-014: EHR Logging (no    | GAP-001 (No      | EHR access monitoring + periodic audits  |
| Curious  |                  | access, high-   | alerts)                  | SIEM)            | + enforcement                             |
| Employee |                  | profile target  | C-013: Training (low      | GAP-010 (No      |                                          |
|          |                  |                 | completion)              | Audits)          |                                          |
|          |                  |                 |                           | GAP-011 (No      |                                          |
|          |                  |                 |                           | Enforcement)     |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+
| 5        | Negligent        | Cleartext       | C-006: Password Policy    | GAP-004 (No      | PAM + MFA + training + enforcement       |
| Overwork. |                  | credentials,    | (does not address         | MFA)             |                                          |
| Admin    |                  | email sharing   | credential storage)      | GAP-010 (No      |                                          |
|          |                  |                 |                           | Audits)          |                                          |
|          |                  |                 |                           | GAP-011 (No      |                                          |
|          |                  |                 |                           | Enforcement)     |                                          |
+----------+------------------+-----------------+---------------------------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)
- HHS Breach Portal Statistics (File 3)
- NIST SP 800-53: AC-6 (Least Privilege), AC-11 (Session Lock), IA-5
  (Authenticator Management)
- CIS Controls v8: Control 5 (Account Management), Control 3 (Data Protection)

Cross-References to Project 1x00:
- Gap Analysis (Task 12): GAP-001, GAP-004, GAP-007, GAP-009, GAP-010,
  GAP-011, GAP-015
- Control Matrix (Task 10): C-006, C-007, C-013, C-014
- Shadow IT (Task 11): Dr. Patel's NAS
- Walk-through Observations (Task 3): Shared login, unlocked sessions


================================================================================
END OF INSIDER THREAT ASSESSMENT
================================================================================
