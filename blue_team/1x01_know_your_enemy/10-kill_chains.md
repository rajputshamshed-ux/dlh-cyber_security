================================================================================
                    KILL CHAINS - MEDDEFENSE HEALTH SYSTEMS
                    Task 10: The Kill Chains
================================================================================

Exercise: Task 10 - The Kill Chains
Analyst: shamshed rajput
Date: 16/07/2026
Objective: Construct complete attack chains from initial access to final
          impact for the 5 most critical threat paths against MedDefense.

Methodology References:
- MITRE ATT&CK: Tactics and techniques
- NIST SP 800-30: Attack path analysis
- BlackReef Ransomware Profile (File 7)
- CISA Advisory AA24-131A (File 1)

Cross-References to Project 1x00:
- Vector-to-Asset Matrix (Task 9): Critical paths
- Asset Registry (Task 7): All assets
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Attack Surface Map (Task 7): Entry points
- Technical Vectors (Task 8): Technical weaknesses


================================================================================
KILL CHAIN #1: RANSOMWARE THROUGH UNPATCHED VPN → EHR + AD
================================================================================

KILL CHAIN OVERVIEW
-------------------
+------------------+--------------------------------------------------+
| Title            | Ransomware Through Unpatched VPN → EHR + AD      |
+------------------+--------------------------------------------------+
| Threat Actor     | Ransomware Groups (Organized Crime) - #1 from     |
|                  | Threat Actor Matrix                               |
+------------------+--------------------------------------------------+
| Target Asset     | EHR System (C1) + Active Directory (C4) + Billing |
|                  | (C5) + Backup (C7)                                |
+------------------+--------------------------------------------------+
| Expected Impact  | 11-day EHR downtime, ambulance diversions, $5M+  |
|                  | recovery costs, CEO resignation (File 4 case).   |
|                  | CIA: Availability, Confidentiality, Integrity    |
+------------------+--------------------------------------------------+

KILL CHAIN STEPS
----------------

STEP 1 - INITIAL ACCESS
+------------------+--------------------------------------------------+
| Vector           | VPN Exploit (V2 from Task 9)                     |
+------------------+--------------------------------------------------+
| Surface          | EXTERNAL                                          |
+------------------+--------------------------------------------------+
| Detail           | Attacker scans for FortiGate VPN vulnerabilities. |
|                  | They exploit an unpatched CVE (GAP-014) to gain   |
|                  | VPN access to the internal network. This is       |
|                  | exactly how the 280-bed regional hospital breach  |
|                  | (File 4) started.                                 |
+------------------+--------------------------------------------------+

STEP 2 - ESTABLISH FOOTHOLD
+------------------+--------------------------------------------------+
| Action           | Attacker installs backdoor on a compromised       |
|                  | workstation, creates a persistent user account,  |
|                  | or adds SSH keys.                                 |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-001: No SIEM - Activity not detected          |
| Weakness         | GAP-004: No MFA - VPN access with single factor  |
|                  | GAP-014: No Patch Management - VPN unpatched     |
+------------------+--------------------------------------------------+

STEP 3 - LATERAL MOVEMENT / ESCALATION
+------------------+--------------------------------------------------+
| Action           | Attacker uses the flat network to move from the   |
|                  | VPN endpoint to the Domain Controller. They       |
|                  | harvest credentials using Mimikatz (no MFA, so   |
|                  | credentials are sufficient). They gain Domain    |
|                  | Admin access.                                     |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat Network - No segmentation          |
| Weakness         | GAP-004: No MFA - Credentials sufficient         |
|                  | GAP-001: No SIEM - Lateral movement undetected   |
+------------------+--------------------------------------------------+

STEP 4 - OBJECTIVE EXECUTION
+------------------+--------------------------------------------------+
| Action           | Attacker deploys ransomware via Group Policy to   |
|                  | all Windows systems. They encrypt the NAS backup  |
|                  | (co-located, C-009 weakness) and exfiltrate 35GB |
|                  | of patient data before encryption.                |
+------------------+--------------------------------------------------+
| Data/System      | EHR database, Active Directory, Billing system,   |
| Affected         | PACS server, all Windows endpoints, NAS backup   |
+------------------+--------------------------------------------------+

STEP 5 - IMPACT
+------------------+--------------------------------------------------+
| Business Impact  | - 11+ days of EHR downtime (paper operations)    |
|                  | - Ambulance diversions, cancelled procedures     |
|                  | - $5M+ recovery costs ($3.2M recovery + $1.8M    |
|                  |   lost revenue)                                   |
|                  | - HIPAA breach notification (PHI exfiltrated)    |
|                  | - Reputational damage, potential CEO resignation |
|                  | - Class action lawsuits from affected patients   |
+------------------+--------------------------------------------------+
| CIA Pillars      | AVAILABILITY: Systems encrypted, inaccessible    |
|                  | CONFIDENTIALITY: PHI exfiltrated                 |
|                  | INTEGRITY: Data encrypted and modified           |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | Description                                       |
+------------------+--------------------------------------------------+
| GAP-014          | No Patch Management - VPN unpatched              |
| GAP-003          | Flat Network - No segmentation                   |
| GAP-004          | No MFA - Credential theft sufficient             |
| GAP-001          | No SIEM - Activity undetected                    |
| C-009 Weakness   | Co-located backups - NAS encrypted               |
| GAP-002          | No IR Plan - Extended recovery time              |
+------------------+--------------------------------------------------+

BREAK POINTS
------------
+----------+------------------+------------------------------------------+
| Step     | Break Point      | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | VPN Exploit      | GAP-014: Patch Management Program        |
| Step 1   | VPN Access       | GAP-004: MFA on VPN                      |
| Step 2   | Foothold         | GAP-001: SIEM to detect backdoor         |
| Step 3   | Lateral Movement | GAP-003: Network Segmentation            |
| Step 3   | Credential Theft | GAP-004: MFA (prevents credential reuse) |
| Step 4   | Backup Encryption| Offsite/immutable backups                |
| Step 5   | Impact           | GAP-002: IR Plan + tested BCP/DR         |
+----------+------------------+------------------------------------------+


================================================================================
KILL CHAIN #2: PHISHING → CREDENTIALS → EHR DATA EXFILTRATION
================================================================================

KILL CHAIN OVERVIEW
-------------------
+------------------+--------------------------------------------------+
| Title            | Phishing → Credentials → EHR Data Exfiltration   |
+------------------+--------------------------------------------------+
| Threat Actor     | Ransomware Groups OR Unskilled/Opportunistic -   |
|                  | #1 or #3 from Threat Actor Matrix                 |
+------------------+--------------------------------------------------+
| Target Asset     | EHR System (C1 - patient data for 50,000+)        |
+------------------+--------------------------------------------------+
| Expected Impact  | PHI exposure, HIPAA breach notification,          |
|                  | regulatory fines, reputational damage, class      |
|                  | action lawsuit. CIA: Confidentiality              |
+------------------+--------------------------------------------------+

KILL CHAIN STEPS
----------------

STEP 1 - INITIAL ACCESS
+------------------+--------------------------------------------------+
| Vector           | Phishing / Spear Phishing (V1 from Task 9)       |
+------------------+--------------------------------------------------+
| Surface          | HUMAN                                             |
+------------------+--------------------------------------------------+
| Detail           | Attacker sends a targeted phishing email to a     |
|                  | clinician or IT staff. The email appears to come  |
|                  | from a trusted source (vendor, internal, or       |
|                  | executive) and requests credential verification.  |
|                  | The employee clicks the link and enters their     |
|                  | credentials on a fake login page.                 |
+------------------+--------------------------------------------------+

STEP 2 - ESTABLISH FOOTHOLD
+------------------+--------------------------------------------------+
| Action           | Attacker uses the captured credentials to log     |
|                  | into MedDefense's VPN or O365. They create a      |
|                  | mailbox rule to forward sensitive emails to an    |
|                  | external address or install a persistent backdoor.|
+------------------+--------------------------------------------------+
| MedDefense       | GAP-004: No MFA - Captured credentials suffice   |
| Weakness         | GAP-001: No SIEM - Login undetected              |
|                  | GAP-013: Low Training Completion - Employee       |
|                  | susceptible to phishing                           |
+------------------+--------------------------------------------------+

STEP 3 - LATERAL MOVEMENT / ESCALATION
+------------------+--------------------------------------------------+
| Action           | Attacker uses the flat network to move from the   |
|                  | compromised workstation to the EHR server. They   |
|                  | scan for open ports and discover PostgreSQL 5432  |
|                  | on ehr-db-01 accessible network-wide.             |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat Network - No segmentation          |
| Weakness         | GAP-001: No SIEM - Scanning undetected           |
+------------------+--------------------------------------------------+

STEP 4 - OBJECTIVE EXECUTION
+------------------+--------------------------------------------------+
| Action           | Attacker connects to PostgreSQL 5432 on ehr-db-01 |
|                  | using the stolen credentials. They run SQL        |
|                  | queries to extract PHI: names, DOBs, SSNs,        |
|                  | diagnoses, treatment plans, insurance info.       |
|                  | They exfiltrate the data via encrypted channels.  |
+------------------+--------------------------------------------------+
| Data/System      | EHR Database (ehr-db-01) - 50,000+ patient       |
| Affected         | records                                            |
+------------------+--------------------------------------------------+

STEP 5 - IMPACT
+------------------+--------------------------------------------------+
| Business Impact  | - 50,000+ patients notified of PHI breach        |
|                  | - HIPAA breach notification (mandatory)          |
|                  | - HHS investigation and potential fines          |
|                  | - Class action lawsuit from affected patients    |
|                  | - Reputational damage in the community           |
|                  | - Loss of patient trust                          |
+------------------+--------------------------------------------------+
| CIA Pillars      | CONFIDENTIALITY: PHI exfiltrated                 |
|                  | INTEGRITY: Data potentially modified             |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | Description                                       |
+------------------+--------------------------------------------------+
| GAP-004          | No MFA - Credential theft suffices               |
| GAP-013          | Low Training Completion - Employee susceptible   |
| GAP-003          | Flat Network - PostgreSQL accessible network-wide|
| GAP-001          | No SIEM - Activity undetected                    |
| GAP-011          | No Enforcement - No consequences for violations  |
+------------------+--------------------------------------------------+

BREAK POINTS
------------
+----------+------------------+------------------------------------------+
| Step     | Break Point      | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Phishing Email   | GAP-013: Security Awareness Training     |
| Step 1   | Phishing Email   | GAP-013: Phishing Simulations            |
| Step 1   | Credential Entry | GAP-004: MFA (renders credentials useless)|
| Step 2   | Foothold         | GAP-001: SIEM to detect unusual login    |
| Step 3   | Lateral Movement | GAP-003: Network Segmentation            |
| Step 3   | PostgreSQL 5432  | Network firewall blocking port 5432      |
| Step 4   | Data Exfiltration| GAP-008: Egress Filtering                |
+----------+------------------+------------------------------------------+


================================================================================
KILL CHAIN #3: DEFAULT CREDENTIALS → MEDICAL IOT → PATIENT SAFETY
================================================================================

KILL CHAIN OVERVIEW
-------------------
+------------------+--------------------------------------------------+
| Title            | Default Credentials → Medical IoT → Patient      |
|                  | Safety                                             |
+------------------+--------------------------------------------------+
| Threat Actor     | Unskilled/Opportunistic OR Ransomware Groups -   |
|                  | #3 or #1 from Threat Actor Matrix                 |
+------------------+--------------------------------------------------+
| Target Asset     | Medical IoT (C2 - patient monitors, infusion     |
|                  | pumps)                                             |
+------------------+--------------------------------------------------+
| Expected Impact  | Patient injury or death, FDA notification,        |
|                  | medical device security investigation, massive    |
|                  | liability. CIA: Integrity, Availability           |
+------------------+--------------------------------------------------+

KILL CHAIN STEPS
----------------

STEP 1 - INITIAL ACCESS
+------------------+--------------------------------------------------+
| Vector           | Default / Shared Credentials (V3 from Task 9)     |
+------------------+--------------------------------------------------+
| Surface          | INTERNAL (or EXTERNAL via compromised system)     |
+------------------+--------------------------------------------------+
| Detail           | Attacker compromises a workstation on the flat    |
|                  | network (via phishing, VPN, or software exploit). |
|                  | They scan the network and discover BD Alaris      |
|                  | infusion pumps with default credentials           |
|                  | (admin/admin) and Philips monitors with default   |
|                  | access.                                            |
+------------------+--------------------------------------------------+

STEP 2 - ESTABLISH FOOTHOLD
+------------------+--------------------------------------------------+
| Action           | Attacker logs into the infusion pump management   |
|                  | console using admin/admin credentials. They       |
|                  | establish a persistent connection to the device.  |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-007: Shared Account Policy Not Enforced      |
| Weakness         | GAP-003: Flat Network - IoT devices accessible   |
|                  | GAP-001: No SIEM - Login undetected              |
+------------------+--------------------------------------------------+

STEP 3 - LATERAL MOVEMENT / ESCALATION
+------------------+--------------------------------------------------+
| Action           | Attacker navigates the pump management interface. |
|                  | They identify the medication delivery schedules   |
|                  | and patient assignments. They prepare to alter    |
|                  | dosage settings.                                   |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat Network - No segmentation          |
| Weakness         | GAP-007: No Compensating Controls for IoT        |
|                  | GAP-001: No SIEM - IoT activity undetected       |
+------------------+--------------------------------------------------+

STEP 4 - OBJECTIVE EXECUTION
+------------------+--------------------------------------------------+
| Action           | Attacker modifies infusion pump dosage settings   |
|                  | for multiple patients. They could increase or     |
|                  | decrease medication delivery. Alternatively, they |
|                  | could disable patient monitor alarms.            |
+------------------+--------------------------------------------------+
| Data/System      | BD Alaris Infusion Pumps (120 units), Philips    |
| Affected         | Patient Monitors (80 units)                       |
+------------------+--------------------------------------------------+

STEP 5 - IMPACT
+------------------+--------------------------------------------------+
| Business Impact  | - Patient injury or death from incorrect         |
|                  |   medication dosage                              |
|                  | - FDA mandatory notification (medical device     |
|                  |   security incident)                             |
|                  | - Massive liability and litigation               |
|                  | - Loss of patient trust and community confidence |
|                  | - Regulatory investigation from FDA, HHS         |
+------------------+--------------------------------------------------+
| CIA Pillars      | INTEGRITY: Patient data (dosages) manipulated    |
|                  | AVAILABILITY: Devices disabled or alarms silenced|
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | Description                                       |
+------------------+--------------------------------------------------+
| GAP-003          | Flat Network - IoT devices on same network       |
| GAP-007          | No Compensating Controls for IoT                 |
| GAP-001          | No SIEM - IoT activity undetected                |
| GAP-011          | No Enforcement - Default credentials not changed |
| GAP-007          | Shared Account Policy Not Enforced               |
+------------------+--------------------------------------------------+

BREAK POINTS
------------
+----------+------------------+------------------------------------------+
| Step     | Break Point      | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Default Creds    | Change default credentials on ALL IoT    |
| Step 1   | IoT Accessibility| GAP-003: Network Segmentation (IoT VLAN) |
| Step 2   | Foothold         | GAP-001: SIEM to detect IoT login        |
| Step 3   | Lateral Movement | GAP-003: Network Segmentation            |
| Step 4   | Dosage Alteration| Application-level controls on pump mgmt  |
| Step 4   | Alarm Disable    | Monitoring of alarm status changes       |
+----------+------------------+------------------------------------------+


================================================================================
KILL CHAIN #4: WINDOWS XP MRI → PIVOT TO EHR
================================================================================

KILL CHAIN OVERVIEW
-------------------
+------------------+--------------------------------------------------+
| Title            | Windows XP MRI → Pivot to EHR                    |
+------------------+--------------------------------------------------+
| Threat Actor     | Ransomware Groups OR Unskilled/Opportunistic -   |
|                  | #1 or #3 from Threat Actor Matrix                 |
+------------------+--------------------------------------------------+
| Target Asset     | MRI (C3) → EHR System (C1)                       |
+------------------+--------------------------------------------------+
| Expected Impact  | MRI compromised, then EHR breach. Delayed        |
|                  | diagnoses, PHI exposure, ransomware deployment.  |
|                  | CIA: Availability, Integrity, Confidentiality    |
+------------------+--------------------------------------------------+

KILL CHAIN STEPS
----------------

STEP 1 - INITIAL ACCESS
+------------------+--------------------------------------------------+
| Vector           | Vulnerable Software Exploit (V4 from Task 9)     |
+------------------+--------------------------------------------------+
| Surface          | INTERNAL (via flat network)                       |
+------------------+--------------------------------------------------+
| Detail           | Attacker gains initial access through another    |
|                  | vector (phishing, VPN, or software exploit on    |
|                  | billing-srv-01). Once on the flat network, they  |
|                  | scan for Windows XP systems and discover the MRI |
|                  | workstation.                                      |
+------------------+--------------------------------------------------+

STEP 2 - ESTABLISH FOOTHOLD
+------------------+--------------------------------------------------+
| Action           | Attacker exploits EternalBlue (MS17-010) on the  |
|                  | Windows XP MRI workstation. They gain SYSTEM-    |
|                  | level access. They install a backdoor for        |
|                  | persistent access.                                |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-007: No Compensating Controls for MRI        |
| Weakness         | GAP-003: Flat Network - MRI accessible           |
|                  | GAP-001: No SIEM - Exploitation undetected       |
+------------------+--------------------------------------------------+

STEP 3 - LATERAL MOVEMENT / ESCALATION
+------------------+--------------------------------------------------+
| Action           | From the MRI workstation, the attacker scans the |
|                  | flat network. They discover PostgreSQL 5432 on   |
|                  | ehr-db-01 and SSH on ehr-srv-01. They harvest   |
|                  | credentials from memory on the MRI workstation   |
|                  | (Mimikatz) and use them to access the EHR.      |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat Network - No segmentation          |
| Weakness         | GAP-004: No MFA - Credentials sufficient         |
|                  | GAP-001: No SIEM - Lateral movement undetected  |
+------------------+--------------------------------------------------+

STEP 4 - OBJECTIVE EXECUTION
+------------------+--------------------------------------------------+
| Action           | Attacker connects to ehr-db-01 and exfiltrates   |
|                  | PHI. Alternatively, they deploy ransomware to    |
|                  | the EHR system, encrypting patient records and   |
|                  | disrupting clinical operations.                   |
+------------------+--------------------------------------------------+
| Data/System      | MRI workstation → EHR Database (ehr-db-01)      |
| Affected         |                                                   |
+------------------+--------------------------------------------------+

STEP 5 - IMPACT
+------------------+--------------------------------------------------+
| Business Impact  | - MRI unavailable for diagnostic imaging         |
|                  | - Delayed diagnoses and treatment decisions      |
|                  | - PHI breach (50,000+ patients)                  |
|                  | - Ransomware deployment (if executed)            |
|                  | - $40M+ recovery costs (Breach 3 scenario)      |
|                  | - Patient safety risk from imaging delays       |
+------------------+--------------------------------------------------+
| CIA Pillars      | AVAILABILITY: MRI and EHR unavailable           |
|                  | CONFIDENTIALITY: PHI exfiltrated                |
|                  | INTEGRITY: System compromised                    |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | Description                                       |
+------------------+--------------------------------------------------+
| GAP-007          | No Compensating Controls for MRI                 |
| GAP-003          | Flat Network - MRI on same network               |
| GAP-001          | No SIEM - Activity undetected                    |
| GAP-004          | No MFA - Credential reuse                        |
| GAP-014          | No Patch Management - Windows XP unpatched      |
+------------------+--------------------------------------------------+

BREAK POINTS
------------
+----------+------------------+------------------------------------------+
| Step     | Break Point      | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Initial Access   | GAP-014: Patch Management                 |
| Step 2   | EternalBlue      | GAP-007: Compensating Controls (MRI VLAN) |
| Step 2   | MRI Compromise   | Network segmentation (isolate MRI)       |
| Step 3   | Lateral Movement | GAP-003: Network Segmentation            |
| Step 3   | Credential Theft | GAP-004: MFA                             |
| Step 4   | EHR Access       | GAP-003: Segmentation                    |
+----------+------------------+------------------------------------------+


================================================================================
KILL CHAIN #5: SUPPLY CHAIN (MEDTECH) → EHR + AD
================================================================================

KILL CHAIN OVERVIEW
-------------------
+------------------+--------------------------------------------------+
| Title            | Supply Chain (MedTech) → EHR + AD                |
+------------------+--------------------------------------------------+
| Threat Actor     | Ransomware Groups OR Nation-State - #1 or #2     |
|                  | from Threat Actor Matrix                          |
+------------------+--------------------------------------------------+
| Target Asset     | EHR System (C1) + Active Directory (C4)          |
+------------------+--------------------------------------------------+
| Expected Impact  | Direct access to EHR and AD via vendor account.  |
|                  | $2.5M ransom demand, PHI exposure, extended      |
|                  | downtime. CIA: Availability, Confidentiality,    |
|                  | Integrity                                         |
+------------------+--------------------------------------------------+

KILL CHAIN STEPS
----------------

STEP 1 - INITIAL ACCESS
+------------------+--------------------------------------------------+
| Vector           | Supply Chain Compromise (V5 from Task 9)         |
+------------------+--------------------------------------------------+
| Surface          | EXTERNAL (via vendor)                             |
+------------------+--------------------------------------------------+
| Detail           | Attacker breaches MedTech Solutions, a third-    |
|                  | party EHR maintenance provider. They discover     |
|                  | MedTech's remote access credentials for          |
|                  | MedDefense's EHR system. These credentials have  |
|                  | NO MFA.                                           |
+------------------+--------------------------------------------------+

STEP 2 - ESTABLISH FOOTHOLD
+------------------+--------------------------------------------------+
| Action           | Attacker uses MedTech's credentials to connect    |
|                  | directly to ehr-srv-01 and ehr-db-01 via the     |
|                  | maintenance portal. They create a backdoor user  |
|                  | account for persistent access.                    |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-012: No Vendor Account Management            |
| Weakness         | GAP-004: No MFA for vendor accounts              |
|                  | GAP-001: No SIEM - Vendor activity undetected   |
+------------------+--------------------------------------------------+

STEP 3 - LATERAL MOVEMENT / ESCALATION
+------------------+--------------------------------------------------+
| Action           | From the EHR server, the attacker moves laterally|
|                  | across the flat network. They target the Domain  |
|                  | Controller and use credential harvesting tools   |
|                  | to gain Domain Admin access.                      |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-003: Flat Network - No segmentation          |
| Weakness         | GAP-004: No MFA - Credentials sufficient         |
|                  | GAP-001: No SIEM - Lateral movement undetected  |
+------------------+--------------------------------------------------+

STEP 4 - OBJECTIVE EXECUTION
+------------------+--------------------------------------------------+
| Action           | Attacker deploys ransomware to all Windows       |
|                  | systems via Group Policy. They exfiltrate PHI    |
|                  | and delete backups (NAS co-located). They issue  |
|                  | a ransom demand.                                   |
+------------------+--------------------------------------------------+
| Data/System      | EHR Database, Active Directory, Billing, PACS,   |
| Affected         | all Windows endpoints, NAS backup                |
+------------------+--------------------------------------------------+

STEP 5 - IMPACT
+------------------+--------------------------------------------------+
| Business Impact  | - Direct access to EHR without any perimeter     |
|                  |   bypass                                           |
|                  | - $2.5M ransom demand (or payment)               |
|                  | - 11+ days of EHR downtime (File 4 scenario)    |
|                  | - PHI exposure for 50,000+ patients             |
|                  | - Loss of trust in vendors                        |
|                  | - Vendor relationship damage                     |
|                  | - Regulatory fines and class action lawsuits     |
+------------------+--------------------------------------------------+
| CIA Pillars      | AVAILABILITY: Systems encrypted                  |
|                  | CONFIDENTIALITY: PHI exfiltrated                |
|                  | INTEGRITY: Systems compromised                   |
+------------------+--------------------------------------------------+

GAPS EXPLOITED
--------------
+------------------+--------------------------------------------------+
| Gap ID           | Description                                       |
+------------------+--------------------------------------------------+
| GAP-012          | No Vendor Account Management                     |
| GAP-004          | No MFA for vendor accounts                       |
| GAP-003          | Flat Network - Lateral movement                  |
| GAP-001          | No SIEM - Activity undetected                    |
| GAP-002          | No IR Plan - Extended recovery                   |
| C-009 Weakness   | Co-located backups - Backups encrypted           |
+------------------+--------------------------------------------------+

BREAK POINTS
------------
+----------+------------------+------------------------------------------+
| Step     | Break Point      | Control Required                         |
+----------+------------------+------------------------------------------+
| Step 1   | Vendor Breach    | GAP-012: Vendor Account Management       |
| Step 1   | Vendor Access    | GAP-004: MFA for vendor accounts         |
| Step 1   | Credential Theft | Vendor credential rotation               |
| Step 2   | Foothold         | GAP-001: SIEM for vendor activity        |
| Step 3   | Lateral Movement | GAP-003: Network Segmentation            |
| Step 4   | Backup Encryption| Offsite/immutable backups                |
| Step 4   | Ransomware       | GAP-002: IR Plan                         |
+----------+------------------+------------------------------------------+


================================================================================
KILL CHAIN SUMMARY
================================================================================

+----------+------------------+------------------------------------------+------------------+
| Kill     | Title            | Target Asset(s)                          | Break Points     |
| Chain    |                  |                                          | (Key Controls)   |
+----------+------------------+------------------------------------------+------------------+
| #1       | Ransomware via   | EHR + AD + Billing + Backup              | Patch Mgt, MFA,  |
|          | Unpatched VPN    |                                          | Segmentation,    |
|          |                  |                                          | SIEM, IR Plan    |
+----------+------------------+------------------------------------------+------------------+
| #2       | Phishing → EHR   | EHR (Patient Data)                       | MFA, SIEM,       |
|          | Data Exfil       |                                          | Segmentation,    |
|          |                  |                                          | Training,        |
|          |                  |                                          | Egress Filtering |
+----------+------------------+------------------------------------------+------------------+
| #3       | Default Creds →  | Medical IoT (Monitors, Pumps)            | Change Defaults, |
|          | IoT Patient      |                                          | Segmentation,    |
|          | Safety           |                                          | SIEM             |
+----------+------------------+------------------------------------------+------------------+
| #4       | Windows XP MRI   | MRI → EHR                                | Compensating     |
|          | → EHR            |                                          | Controls, MFA,   |
|          |                  |                                          | Segmentation,    |
|          |                  |                                          | SIEM             |
+----------+------------------+------------------------------------------+------------------+
| #5       | Supply Chain     | EHR + AD                                 | Vendor Mgt, MFA, |
|          | (MedTech) →      |                                          | Segmentation,    |
|          | EHR + AD         |                                          | SIEM, IR Plan    |
+----------+------------------+------------------------------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The FLAT NETWORK (GAP-003) is the PRIMARY ENABLER across ALL kill chains.
   Every attack sequence relies on lateral movement across the flat network.
   Segmentation is the single most important intervention point.

2. MFA (GAP-004) is the SECOND most critical control. It appears as a
   break point in all 5 kill chains. Without MFA, captured credentials
   provide immediate access.

3. SIEM (GAP-001) appears as a break point in all 5 kill chains. Without
   detection, every attack proceeds unseen until impact.

4. The MRI Windows XP (GAP-007) is the most dangerous single vulnerability.
   It appears as a critical enabler in Kill Chain #4 and enables lateral
   movement to the EHR.

5. Vendor accounts (GAP-012) represent a CRITICAL risk. Kill Chain #5 shows
   that a vendor breach can bypass ALL perimeter controls.

6. Every kill chain can be broken with a combination of:
   - Patch Management (GAP-014)
   - Network Segmentation (GAP-003)
   - MFA (GAP-004)
   - SIEM (GAP-001)
   - IR Plan (GAP-002)

7. The attack sequences are REALISTIC. Every step is enabled by a
   documented gap in MedDefense's posture (from Project 1x00).


================================================================================
REFERENCES
================================================================================

- MITRE ATT&CK: Tactics and techniques
- NIST SP 800-30: Attack path analysis
- BlackReef Ransomware Profile (File 7)
- CISA Advisory AA24-131A (File 1)
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)

Cross-References to Project 1x00:
- Vector-to-Asset Matrix (Task 9): Critical paths
- Asset Registry (Task 7): All assets
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor profiles
- Attack Surface Map (Task 7): Entry points
- Technical Vectors (Task 8): Technical weaknesses


================================================================================
END OF KILL CHAINS REPORT
================================================================================
