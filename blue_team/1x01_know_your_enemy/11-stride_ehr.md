================================================================================
                    STRIDE ON THE EHR - MEDDEFENSE HEALTH SYSTEMS
                    Task 11: STRIDE on the EHR
================================================================================

Exercise: Task 11 - STRIDE on the EHR
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Apply the STRIDE threat model in depth to MedDefense's most
          critical system to systematically identify every category of threat.

Methodology References:
- Microsoft STRIDE Threat Model
- NIST SP 800-30: Threat identification
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

System Architecture - EHR System:
- ehr-srv-01 (Ubuntu 20.04 LTS - EHR Application Server)
- ehr-db-01 (Ubuntu 20.04 LTS - PostgreSQL Database)
- Clinical workstations (Windows 10 - EHR client access)
- Flat network (10.10.0.0/16) connecting all components
- Site-to-site VPN for Westside and HQ access

Cross-References to Project 1x00:
- Asset Registry (Task 7): ehr-srv-01, ehr-db-01
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to EHR


================================================================================
1. SPOOFING (PRETENDING TO BE SOMEONE OR SOMETHING ELSE)
================================================================================

THREAT ID: EHR-S1
+------------------+--------------------------------------------------+
| Category         | SPOOFING                                         |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-S1                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker uses phished credentials to log into |
|                  | the EHR system as a legitimate physician. They   |
|                  | access patient records and prescribe controlled  |
|                  | substances under the physician's identity.       |
+------------------+--------------------------------------------------+
| Attack Vector    | Phishing (V1 from Task 9) targeting a physician. |
|                  | Captured credentials used to access EHR. No MFA, |
|                  | so credentials are sufficient.                    |
+------------------+--------------------------------------------------+
| Impact           | - False medical records attributed to a real     |
|                  |   physician                                      |
|                  | - Prescriptions issued under false identity      |
|                  | - Legal exposure for the impersonated physician  |
|                  | - Patient safety risk from unauthorized actions  |
+------------------+--------------------------------------------------+
| Existing Control | C-006: Password Policy (AD) - Weak protection    |
|                  | C-013: Security Awareness Training (limited)     |
+------------------+--------------------------------------------------+
| Gap              | GAP-004: No MFA Anywhere                         |
|                  | GAP-013: Low Training Completion                 |
+------------------+--------------------------------------------------+


THREAT ID: EHR-S2
+------------------+--------------------------------------------------+
| Category         | SPOOFING                                         |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-S2                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker exploits a vulnerability in the EHR  |
|                  | web interface to impersonate a legitimate        |
|                  | clinician. They bypass authentication entirely   |
|                  | by using a session fixation or session           |
|                  | hijacking technique.                             |
+------------------+--------------------------------------------------+
| Attack Vector    | Web application vulnerability (GAP-016) in       |
|                  | ehr-srv-01. Attacker intercepts a session token  |
|                  | or steals a session cookie.                       |
+------------------+--------------------------------------------------+
| Impact           | - Unauthorized access to all EHR functionality   |
|                  | - Complete bypass of authentication controls    |
|                  | - No accountability (actions attributed to       |
|                  |   legitimate user)                               |
+------------------+--------------------------------------------------+
| Existing Control | C-005: SSH Hardening on ehr-srv-01 (does not    |
|                  | apply to web interface)                          |
+------------------+--------------------------------------------------+
| Gap              | GAP-016: No Web Application Security Testing    |
|                  | GAP-001: No SIEM - Session hijacking undetected |
+------------------+--------------------------------------------------+


================================================================================
2. TAMPERING (MODIFYING DATA WITHOUT AUTHORIZATION)
================================================================================

THREAT ID: EHR-T1
+------------------+--------------------------------------------------+
| Category         | TAMPERING                                        |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-T1                                           |
+------------------+--------------------------------------------------+
| Description      | A malicious insider (IT admin or clinician)      |
|                  | modifies patient medication records in the EHR   |
|                  | database. They alter dosages or add incorrect    |
|                  | medications to a patient's record.               |
+------------------+--------------------------------------------------+
| Attack Vector    | Insider (Malicious) - V6 from Task 9. The        |
|                  | attacker has legitimate EHR access and uses it   |
|                  | to modify data without authorization.            |
+------------------+--------------------------------------------------+
| Impact           | - Patient receives incorrect medication          |
|                  | - Patient injury or death                        |
|                  | - Legal liability for MedDefense                |
|                  | - Loss of trust in the healthcare system        |
+------------------+--------------------------------------------------+
| Existing Control | C-014: AD Logging (logs exist but no alerts)    |
|                  | C-006: Password Policy (weak protection)        |
+------------------+--------------------------------------------------+
| Gap              | GAP-001: No SIEM - Tampering undetected         |
|                  | GAP-010: No Audits - No review of access logs   |
+------------------+--------------------------------------------------+


THREAT ID: EHR-T2
+------------------+--------------------------------------------------+
| Category         | TAMPERING                                        |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-T2                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker exploits the PostgreSQL database     |
|                  | (port 5432 accessible network-wide) to           |
|                  | directly modify patient records, bypassing the   |
|                  | EHR application layer entirely.                  |
+------------------+--------------------------------------------------+
| Attack Vector    | Open Service Ports (V3 from Task 9). Attacker    |
|                  | connects to PostgreSQL 5432 on ehr-db-01 using   |
|                  | captured credentials and runs SQL UPDATE        |
|                  | queries.                                          |
+------------------+--------------------------------------------------+
| Impact           | - Direct modification of patient data without    |
|                  |   application audit trail                        |
|                  | - Patient safety risk from incorrect data        |
|                  | - No application-level logging of the change     |
|                  | - Database integrity compromised                 |
+------------------+--------------------------------------------------+
| Existing Control | C-005: SSH Hardening (does not apply to          |
|                  | PostgreSQL)                                       |
+------------------+--------------------------------------------------+
| Gap              | GAP-003: Flat Network - PostgreSQL accessible    |
|                  | network-wide                                      |
|                  | GAP-001: No SIEM - Database modifications        |
|                  | undetected                                        |
+------------------+--------------------------------------------------+


================================================================================
3. REPUDIATION (DENYING AN ACTION OCCURRED)
================================================================================

THREAT ID: EHR-R1
+------------------+--------------------------------------------------+
| Category         | REPUDIATION                                      |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-R1                                           |
+------------------+--------------------------------------------------+
| Description      | A clinician denies ordering a medication that   |
|                  | was incorrectly prescribed to a patient. The     |
|                  | shared account ("raduser/radiology1") means      |
|                  | there is no individual accountability for who    |
|                  | performed the action.                            |
+------------------+--------------------------------------------------+
| Attack Vector    | Default / Shared Credentials (V3 from Task 9).  |
|                  | The radiology department uses a shared account,  |
|                  | so multiple people can perform actions without   |
|                  | individual attribution.                          |
+------------------+--------------------------------------------------+
| Impact           | - No accountability for medical decisions        |
|                  | - Unable to determine who made an error         |
|                  | - Legal liability cannot be assigned            |
|                  | - Patient safety investigation impossible        |
|                  | - HIPAA audit trail integrity compromised       |
+------------------+--------------------------------------------------+
| Existing Control | C-007: Shared Account Policy (exists but NOT    |
|                  | enforced)                                        |
+------------------+--------------------------------------------------+
| Gap              | GAP-007: Shared Account Policy Not Enforced     |
|                  | GAP-011: No Enforcement - No consequences        |
+------------------+--------------------------------------------------+


THREAT ID: EHR-R2
+------------------+--------------------------------------------------+
| Category         | REPUDIATION                                      |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-R2                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker deletes or modifies EHR audit logs   |
|                  | to cover their tracks. With no log integrity     |
|                  | protection (hashing, write-once storage), they   |
|                  | can erase evidence of their actions.            |
+------------------+--------------------------------------------------+
| Attack Vector    | Vulnerable Software Exploit (V4) OR Insider      |
|                  | (Malicious) - V6. The attacker gains access to   |
|                  | the EHR server and modifies or deletes log       |
|                  | files.                                           |
+------------------+--------------------------------------------------+
| Impact           | - No forensic evidence available after a breach |
|                  | - Unable to determine the extent of the breach  |
|                  | - Unable to identify the attacker               |
|                  | - Regulatory investigation hindered              |
|                  | - Legal liability impossible to assign           |
+------------------+--------------------------------------------------+
| Existing Control | None                                              |
+------------------+--------------------------------------------------+
| Gap              | GAP-001: No SIEM - Logs not centralized          |
|                  | GAP-010: No Audits - No log review               |
|                  | GAP-014: No Patch Management - Logs can be       |
|                  | deleted                                           |
+------------------+--------------------------------------------------+


================================================================================
4. INFORMATION DISCLOSURE (EXPOSING DATA TO UNAUTHORIZED PARTIES)
================================================================================

THREAT ID: EHR-I1
+------------------+--------------------------------------------------+
| Category         | INFORMATION DISCLOSURE                           |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-I1                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker exploits the PostgreSQL database     |
|                  | (port 5432 accessible network-wide) to query     |
|                  | and exfiltrate PHI for 50,000+ patients. They    |
|                  | connect directly to the database and run SELECT  |
|                  | queries without application-layer controls.     |
+------------------+--------------------------------------------------+
| Attack Vector    | Open Service Ports (V3 from Task 9). Attacker    |
|                  | connects to PostgreSQL 5432 on ehr-db-01 using   |
|                  | captured credentials and exfiltrates patient     |
|                  | data.                                            |
+------------------+--------------------------------------------------+
| Impact           | - 50,000+ patient records exposed                |
|                  | - HIPAA breach notification required            |
|                  | - HHS investigation and potential fines         |
|                  | - Class action lawsuit from affected patients   |
|                  | - Reputational damage                           |
+------------------+--------------------------------------------------+
| Existing Control | None                                              |
+------------------+--------------------------------------------------+
| Gap              | GAP-003: Flat Network - PostgreSQL accessible    |
|                  | network-wide                                      |
|                  | GAP-001: No SIEM - Exfiltration undetected       |
|                  | GAP-008: Egress Filtering - Data can leave       |
|                  | unrestricted                                      |
+------------------+--------------------------------------------------+


THREAT ID: EHR-I2
+------------------+--------------------------------------------------+
| Category         | INFORMATION DISCLOSURE                           |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-I2                                           |
+------------------+--------------------------------------------------+
| Description      | A curious employee (registration clerk) accesses  |
|                  | the EHR records of a high-profile patient        |
|                  | (politician, celebrity) without a legitimate     |
|                  | work reason. They share the information with     |
|                  | friends or post it on social media.              |
+------------------+--------------------------------------------------+
| Attack Vector    | Insider (Malicious) - V6 OR Insider (Negligent)  |
|                  | - V7. The employee has authorized access but     |
|                  | uses it for unauthorized purposes. No monitoring |
|                  | detects the unauthorized access.                 |
+------------------+--------------------------------------------------+
| Impact           | - HIPAA breach notification required            |
|                  | - Public embarrassment for MedDefense           |
|                  | - Loss of patient trust                          |
|                  | - Regulatory fines and potential lawsuits       |
|                  | - Damage to reputation of the high-profile      |
|                  |   patient                                        |
+------------------+--------------------------------------------------+
| Existing Control | C-014: AD Logging (logs exist but no alerts)    |
|                  | C-013: Security Awareness Training (limited)    |
+------------------+--------------------------------------------------+
| Gap              | GAP-001: No SIEM - Unauthorized access          |
|                  | undetected                                        |
|                  | GAP-010: No Audits - No access log review       |
|                  | GAP-011: No Enforcement - No consequences        |
+------------------+--------------------------------------------------+


================================================================================
5. DENIAL OF SERVICE (MAKING A RESOURCE UNAVAILABLE)
================================================================================

THREAT ID: EHR-D1
+------------------+--------------------------------------------------+
| Category         | DENIAL OF SERVICE                                 |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-D1                                           |
+------------------+--------------------------------------------------+
| Description      | Ransomware encrypts the EHR database, making     |
|                  | patient records completely inaccessible to       |
|                  | clinicians. This is the January ransomware       |
|                  | scenario on a larger scale.                     |
+------------------+--------------------------------------------------+
| Attack Vector    | VPN Exploit (V2) OR Phishing (V1) leading to     |
|                  | ransomware deployment via Group Policy.          |
+------------------+--------------------------------------------------+
| Impact           | - Complete EHR downtime (11+ days in real case)  |
|                  | - Clinicians forced to use paper records        |
|                  | - Medical errors from incomplete information    |
|                  | - Ambulance diversions and cancelled procedures  |
|                  | - Patient safety risk from delayed care         |
|                  | - $5M+ recovery costs                            |
+------------------+--------------------------------------------------+
| Existing Control | C-009: Veeam Backups (co-located - weak)        |
|                  | C-004: Firewall Logging (does not prevent)      |
+------------------+--------------------------------------------------+
| Gap              | GAP-003: Flat Network - Lateral movement        |
|                  | GAP-004: No MFA - Privilege escalation          |
|                  | GAP-001: No SIEM - Activity undetected          |
|                  | C-009 Weakness: Co-located backups              |
+------------------+--------------------------------------------------+


THREAT ID: EHR-D2
+------------------+--------------------------------------------------+
| Category         | DENIAL OF SERVICE                                 |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-D2                                           |
+------------------+--------------------------------------------------+
| Description      | A malicious insider (disgruntled IT admin)       |
|                  | intentionally deletes or corrupts the EHR        |
|                  | database, making patient records permanently     |
|                  | unavailable.                                      |
+------------------+--------------------------------------------------+
| Attack Vector    | Insider (Malicious) - V6. The attacker has       |
|                  | administrative access to the EHR system and      |
|                  | uses it to delete tables or corrupt data.        |
+------------------+--------------------------------------------------+
| Impact           | - Complete loss of patient records (no recovery) |
|                  | - Hospital cannot deliver safe care             |
|                  | - Massive legal liability                        |
|                  | - Regulatory fines and sanctions                |
|                  | - Financial collapse (no billing possible)      |
+------------------+--------------------------------------------------+
| Existing Control | C-009: Veeam Backups (if still available)       |
|                  | C-014: AD Logging (logs exist but no alerts)    |
+------------------+--------------------------------------------------+
| Gap              | GAP-004: No MFA - Admin account vulnerable      |
|                  | GAP-001: No SIEM - Deletion undetected          |
|                  | GAP-011: No Enforcement - No deterrent          |
+------------------+--------------------------------------------------+


================================================================================
6. ELEVATION OF PRIVILEGE (GAINING CAPABILITIES BEYOND AUTHORIZATION)
================================================================================

THREAT ID: EHR-E1
+------------------+--------------------------------------------------+
| Category         | ELEVATION OF PRIVILEGE                           |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-E1                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker compromises a Domain Admin account   |
|                  | (via phishing or credential harvesting) and uses |
|                  | it to access the EHR system with elevated        |
|                  | privileges, bypassing any application-level      |
|                  | access controls.                                  |
+------------------+--------------------------------------------------+
| Attack Vector    | Phishing (V1) OR VPN Exploit (V2) leading to     |
|                  | Domain Admin compromise. The attacker uses AD    |
|                  | admin credentials to access the EHR server.      |
+------------------+--------------------------------------------------+
| Impact           | - Complete control over EHR system              |
|                  | - Bypass of all EHR access controls             |
|                  | - Ability to modify/delete/exfiltrate all data  |
|                  | - Permanent backdoor installation               |
|                  | - No accountability (admin logs can be deleted) |
+------------------+--------------------------------------------------+
| Existing Control | C-006: Password Policy (weak protection)        |
|                  | C-014: AD Logging (logs exist but no alerts)    |
+------------------+--------------------------------------------------+
| Gap              | GAP-004: No MFA - Admin accounts no MFA        |
|                  | GAP-001: No SIEM - Admin activity undetected    |
|                  | GAP-003: Flat Network - EHR accessible          |
+------------------+--------------------------------------------------+


THREAT ID: EHR-E2
+------------------+--------------------------------------------------+
| Category         | ELEVATION OF PRIVILEGE                           |
+------------------+--------------------------------------------------+
| Threat ID        | EHR-E2                                           |
+------------------+--------------------------------------------------+
| Description      | An attacker exploits a vulnerability in the EHR  |
|                  | application to bypass role-based access          |
|                  | controls. A clinician with read-only access      |
|                  | escalates to administrative privileges within    |
|                  | the application.                                  |
+------------------+--------------------------------------------------+
| Attack Vector    | Vulnerable Software Exploit (V4) in the EHR     |
|                  | application. The attacker exploits a privilege   |
|                  | escalation vulnerability to gain admin access.   |
+------------------+--------------------------------------------------+
| Impact           | - Clinician gains administrative privileges     |
|                  | - Ability to modify patient records             |
|                  | - Ability to grant access to other users        |
|                  | - Application-level audit controls bypassed    |
|                  | - Patient safety risk from unauthorized        |
|                  |   modifications                                 |
+------------------+--------------------------------------------------+
| Existing Control | C-005: SSH Hardening (does not apply to app)    |
+------------------+--------------------------------------------------+
| Gap              | GAP-016: No Web Application Security Testing    |
|                  | GAP-001: No SIEM - Privilege escalation         |
|                  | undetected                                        |
+------------------+--------------------------------------------------+


================================================================================
STRIDE THREAT INVENTORY SUMMARY
================================================================================

+----------+------------------+------------------------------------------+------------------+
| Category | Threat ID        | Description                              | Primary Gap      |
+----------+------------------+------------------------------------------+------------------+
| SPOOFING | EHR-S1           | Phished physician credentials used      | GAP-004          |
|          |                  | to impersonate legitimate user          |                  |
+----------+------------------+------------------------------------------+------------------+
| SPOOFING | EHR-S2           | Session hijacking bypasses              | GAP-016          |
|          |                  | authentication                           |                  |
+----------+------------------+------------------------------------------+------------------+
| TAMPERING| EHR-T1           | Malicious insider modifies patient      | GAP-001          |
|          |                  | medication records                       |                  |
+----------+------------------+------------------------------------------+------------------+
| TAMPERING| EHR-T2           | PostgreSQL exploited to directly        | GAP-003          |
|          |                  | modify database                          |                  |
+----------+------------------+------------------------------------------+------------------+
| REPUDIA- | EHR-R1           | Shared account prevents accountability  | GAP-007          |
| TION     |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| REPUDIA- | EHR-R2           | Audit logs deleted to cover tracks      | GAP-001          |
| TION     |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| INFO     | EHR-I1           | PostgreSQL exploited to exfiltrate PHI  | GAP-003          |
| DISCLOS. |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| INFO     | EHR-I2           | Curious employee accesses high-profile  | GAP-001          |
| DISCLOS. |                  | patient records                          |                  |
+----------+------------------+------------------------------------------+------------------+
| DOS      | EHR-D1           | Ransomware encrypts EHR database        | GAP-003          |
+----------+------------------+------------------------------------------+------------------+
| DOS      | EHR-D2           | Malicious admin deletes EHR database    | GAP-004          |
+----------+------------------+------------------------------------------+------------------+
| EOP      | EHR-E1           | Domain Admin access to EHR              | GAP-004          |
+----------+------------------+------------------------------------------+------------------+
| EOP      | EHR-E2           | Application privilege escalation        | GAP-016          |
+----------+------------------+------------------------------------------+------------------+

TOTAL THREATS IDENTIFIED: 12 (2 per STRIDE category)


================================================================================
STRIDE SUMMARY FOR EHR
================================================================================

+----------------------------------------------------------------------------+
| STRIDE SUMMARY FOR EHR SYSTEM                                              |
|                                                                             |
| The STRIDE category that represents the GREATEST risk for the EHR system   |
| is INFORMATION DISCLOSURE (I), specifically the direct database            |
| exfiltration threat (EHR-I1).                                              |
|                                                                             |
| WHY THIS IS THE GREATEST RISK:                                              |
|                                                                             |
| 1. The EHR database contains PHI for 50,000+ patients. The exposure of     |
|    this data triggers mandatory HIPAA breach notification, HHS             |
|    investigation, potential fines, and class action lawsuits.              |
|                                                                             |
| 2. The combination of vulnerabilities makes this threat HIGHLY LIKELY:     |
|    - PostgreSQL 5432 is open to the entire flat network (GAP-003)         |
|    - No MFA means captured credentials provide access (GAP-004)           |
|    - No SIEM means exfiltration goes undetected (GAP-001)                 |
|    - No egress filtering means data can leave freely (GAP-008)            |
|                                                                             |
| 3. Unlike other STRIDE categories, this threat requires NO special        |
|    skills - any attacker on the network can query the database.           |
|                                                                             |
| 4. The healthcare context makes this particularly dangerous:              |
|    - Patient data is the highest-value target for attackers               |
|    - Healthcare records sell for $250-$1,000 per record                   |
|    - HIPAA fines can reach $1.5M per violation                           |
|    - Reputational damage in healthcare is particularly severe            |
|                                                                             |
| SECONDARY RISK: DOS (EHR-D1) is equally dangerous in a clinical context.  |
| Ransomware on the EHR system causes 11+ days of downtime, ambulance       |
| diversions, and cancelled procedures. However, Information Disclosure     |
| is more likely because it requires fewer steps and less sophistication.  |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Microsoft STRIDE Threat Model
- NIST SP 800-30: Threat identification
- MITRE ATT&CK: Tactics and techniques
- CIS Controls v8: Critical Security Controls

Cross-References to Project 1x00:
- Asset Registry (Task 7): ehr-srv-01, ehr-db-01
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Technical Vectors (Task 8): Attack vectors
- Vector-to-Asset Matrix (Task 9): Paths to EHR


================================================================================
END OF STRIDE ON THE EHR REPORT
================================================================================
