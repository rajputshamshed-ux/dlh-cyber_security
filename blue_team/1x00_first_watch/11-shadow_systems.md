================================================================================
                    SHADOW SYSTEMS - MEDDEFENSE HEALTH SYSTEMS
                    Task 11: The Shadow Systems
================================================================================

Exercise: Task 11 - The Shadow Systems
Analyst: shamshed rajput
Date: 14/07/2026

Objective: Identify and assess unmanaged assets that exist outside the
          organization's official IT governance, and determine the
          appropriate response for each.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: CM-8 (Asset Inventory), AC-6 (Least Privilege)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- NIST CSF 2.0: Identify Function - ID.AM (Asset Management)
- ISO 27001: A.8.1 (Asset Inventory), A.8.2 (Acceptable Use)

Sources: Mike Torres (IT Helpdesk Lead), Asset Registry (Task 7),
         Network Scan, Control Matrix (Task 10)


================================================================================
1. SHADOW SYSTEM ASSESSMENT 1: DR. PATEL'S PERSONAL NAS
================================================================================

SYSTEM DESCRIPTION
------------------
+------------------+--------------------------------------------------+
| System Name      | Dr. Patel's Personal NAS (Cardiology)            |
+------------------+--------------------------------------------------+
| Owner            | Dr. Patel, Cardiology Department                 |
+------------------+--------------------------------------------------+
| Location         | Dr. Patel's office, MedDefense Central            |
+------------------+--------------------------------------------------+
| Connection       | Wall port - same flat network as all other       |
|                  | hospital systems (10.10.0.0/16)                 |
+------------------+--------------------------------------------------+
| Purpose          | Store research data (hospital shared drive too   |
|                  | slow)                                            |
+------------------+--------------------------------------------------+
| Discovery Source | Mike Torres (verbal)                             |
+------------------+--------------------------------------------------+


RISK ASSESSMENT
---------------
+----------------------------------------------------------------------------+
| SENSITIVE DATA:                                                             |
| Research data likely includes:                                              |
| - Clinical research data (potentially containing PHI)                      |
| - Cardiology patient data for research studies                             |
| - Research findings and publications                                       |
| - Potentially patient identifiers or de-identified data that could be      |
|   re-identified                                                            |
|                                                                             |
| CONTROLS NOT COVERING THIS SYSTEM (from Task 10):                          |
| - C-001: Firewall - Perimeter Protection (No protection for internal       |
|          devices)                                                          |
| - C-005: SSH Hardening (No hardening applied)                             |
| - C-006: Password Policy (Not enforced - unknown credentials)             |
| - C-008: Sophos Endpoint Protection (NAS not covered)                     |
| - C-009: Veeam Backups (NAS not backed up)                                |
| - C-014: AD Logging (NAS not authenticated via AD)                        |
| - C-015: Network Segmentation (NAS on flat network)                       |
|                                                                             |
| WORST-CASE SCENARIO:                                                       |
| The NAS contains unencrypted research data with PHI. An attacker          |
| compromises the NAS via default or weak credentials. Data is exfiltrated  |
| or encrypted by ransomware. PHI breach triggers HIPAA notification and    |
| fines. Research is lost. The NAS is used as a pivot point to attack       |
| other systems on the flat network (EHR, billing, AD).                    |
+----------------------------------------------------------------------------+


RECOMMENDED RESPONSE: MIGRATE
-----------------------------
+----------------------------------------------------------------------------+
| STRATEGY: MIGRATE                                                         |
|                                                                             |
| JUSTIFICATION:                                                             |
| 1. The NAS is a consumer-grade device with no enterprise-grade security   |
|    controls. It cannot be effectively secured.                            |
| 2. Research data should be stored on approved hospital storage (file-     |
|    srv-01 or O365 SharePoint) with proper controls.                       |
| 3. The NAS is on the flat network (10.10.0.0/16) - a compromise exposes   |
|    the entire hospital network.                                           |
| 4. Dr. Patel's complaint (shared drive too slow) indicates a capacity     |
|    issue with file-srv-01 that should be addressed directly.              |
|                                                                             |
| ACTION PLAN:                                                               |
| 1. Immediately disconnect the NAS from the network.                       |
| 2. Identify all data on the NAS and determine if it contains PHI.        |
| 3. If PHI present: Secure data and investigate for breach.               |
| 4. Migrate data to approved storage:                                      |
|    - Research data: O365 SharePoint or file-srv-01 (with capacity review) |
|    - If file-srv-01 is too slow, address performance issue properly       |
| 5. Decommission the NAS (wipe or repurpose under IT control).            |
+----------------------------------------------------------------------------+


ASSET REGISTRY UPDATE
---------------------
+----------------------------------------------------------------------------+
| Asset ID:       SRV-014                                                   |
| Name:           Dr. Patel's Personal NAS (Cardiology)                     |
| Type:           Data Store                                                |
| Location:       Central - Dr. Patel's office                              |
| Owner:          Cardiology Department (Dr. Patel)                         |
| OS/Platform:    Unknown (consumer NAS)                                   |
| Critical Svs:   Research data storage                                     |
| Network Segment: 10.10.0.0/16 (flat network)                              |
| Status:         Shadow IT (To be migrated)                                |
| Notes:          Unauthorized NAS. Contains research data. Discovered      |
|                 by Mike Torres. Migrate to approved storage.             |
+----------------------------------------------------------------------------+


================================================================================
2. SHADOW SYSTEM ASSESSMENT 2: MARKETING GOOGLE DRIVE
================================================================================

SYSTEM DESCRIPTION
------------------
+------------------+--------------------------------------------------+
| System Name      | Marketing Google Drive (Personal Gmail)          |
+------------------+--------------------------------------------------+
| Owner            | Marketing Department                             |
+------------------+--------------------------------------------------+
| Location         | Cloud (Google) - not on MedDefense network       |
+------------------+--------------------------------------------------+
| Purpose          | Media files, press communications, marketing     |
|                  | materials                                        |
+------------------+--------------------------------------------------+
| Account          | Linked to someone's personal Gmail account       |
+------------------+--------------------------------------------------+
| Discovery Source | Mike Torres (verbal)                             |
+------------------+--------------------------------------------------+


RISK ASSESSMENT
---------------
+----------------------------------------------------------------------------+
| SENSITIVE DATA:                                                             |
| Marketing materials and press communications may contain:                  |
| - Draft press releases (may contain confidential information)             |
| - Marketing strategies and campaigns                                      |
| - Media files (may include images of patients, staff, or facilities)      |
| - Potentially patient information (images, testimonials)                  |
| - Internal communications about MedDefense operations                    |
| - Strategic messaging for public relations                               |
|                                                                             |
| CONTROLS NOT COVERING THIS SYSTEM (from Task 10):                          |
| - C-006: Password Policy (Personal Gmail, not AD-enforced)                |
| - C-008: Sophos Endpoint Protection (Cloud storage not covered)           |
| - C-009: Veeam Backups (No MedDefense backup)                             |
| - C-010: Sophos Detections (No monitoring)                                |
| - C-013: Security Training (Personal accounts not covered)                |
| - C-014: AD Logging (No authentication via AD)                           |
| - No DLP (Data Loss Prevention) in place for cloud storage               |
|                                                                             |
| WORST-CASE SCENARIO:                                                       |
| An attacker compromises the personal Gmail account via phishing or         |
| credential reuse. The Google Drive contains draft press releases with     |
| confidential information, patient images, or internal strategies.         |
| Confidential data is leaked to competitors or public. Reputational        |
| damage to MedDefense. If patient images are exposed, HIPAA breach.        |
| The employee's personal account is also compromised, affecting their      |
| personal data as well.                                                    |
+----------------------------------------------------------------------------+


RECOMMENDED RESPONSE: MIGRATE
-----------------------------
+----------------------------------------------------------------------------+
| STRATEGY: MIGRATE                                                         |
|                                                                             |
| JUSTIFICATION:                                                             |
| 1. Personal Gmail has NO MedDefense controls or monitoring.               |
| 2. MedDefense already has O365 (email, SharePoint, OneDrive) with         |
|    enterprise controls.                                                   |
| 3. Marketing data should be on O365 SharePoint or OneDrive for Business   |
|    - managed, backed up, and compliant.                                  |
| 4. Personal Gmail cannot be audited or controlled by MedDefense.          |
| 5. Linking business data to personal accounts violates acceptable use    |
|    policy (should be in policy).                                          |
|                                                                             |
| ACTION PLAN:                                                               |
| 1. Immediately identify all data in the personal Google Drive.            |
| 2. Migrate all MedDefense business data to O365 SharePoint or OneDrive    |
|    for Business.                                                          |
| 3. Delete all MedDefense data from personal Google Drive.                 |
| 4. Implement policy: All business data must be stored on approved         |
|    systems (O365, file-srv-01).                                           |
| 5. Provide Marketing team with proper O365 training.                     |
+----------------------------------------------------------------------------+


ASSET REGISTRY UPDATE
---------------------
+----------------------------------------------------------------------------+
| Asset ID:       DTA-003                                                   |
| Name:           Marketing Google Drive (Shadow Cloud)                    |
| Type:           Data Store                                                |
| Location:       Cloud (Google)                                            |
| Owner:          Marketing Department                                      |
| OS/Platform:    Google Drive (personal Gmail)                             |
| Critical Svs:   Marketing files, press communications, media files        |
| Network Segment: N/A (Cloud)                                              |
| Status:         Shadow IT (To be migrated)                                |
| Notes:          Unauthorized cloud storage. Linked to personal Gmail.    |
|                 Contains marketing data. Migrate to O365 SharePoint.     |
+----------------------------------------------------------------------------+


================================================================================
3. SHADOW SYSTEM ASSESSMENT 3: RASPBERRY PI (SECOND FLOOR)
================================================================================

SYSTEM DESCRIPTION
------------------
+------------------+--------------------------------------------------+
| System Name      | Raspberry Pi (Second Floor - Central)            |
+------------------+--------------------------------------------------+
| Owner            | Unknown (Previous IT intern set it up)           |
+------------------+--------------------------------------------------+
| Location         | Second floor of Central - unknown exact location |
+------------------+--------------------------------------------------+
| Purpose          | Network monitor (according to Mike Torres)       |
+------------------+--------------------------------------------------+
| Status           | "Nobody has touched it since they both left"     |
+------------------+--------------------------------------------------+
| Discovery Source | Mike Torres (verbal)                             |
+------------------+--------------------------------------------------+


RISK ASSESSMENT
---------------
+----------------------------------------------------------------------------+
| SENSITIVE DATA:                                                             |
| The Raspberry Pi may contain:                                               |
| - Network traffic captures (potentially containing PHI and credentials)   |
| - System logs and network data                                             |
| - Network topology information                                             |
| - Credentials used to access network devices (if configured)              |
| - Access to other network resources                                        |
|                                                                             |
| CONTROLS NOT COVERING THIS SYSTEM (from Task 10):                          |
| - C-001: Firewall - Perimeter Protection (Internal device, no coverage)   |
| - C-005: SSH Hardening (Unknown configuration)                            |
| - C-006: Password Policy (Not AD-enforced)                                |
| - C-008: Sophos Endpoint Protection (Raspberry Pi not covered)            |
| - C-009: Veeam Backups (Not backed up)                                    |
| - C-014: AD Logging (No AD integration)                                   |
| - C-015: Network Segmentation (On flat network - 10.10.0.0/16)           |
|                                                                             |
| WORST-CASE SCENARIO:                                                       |
| The Raspberry Pi has default credentials (or credentials left by the      |
| intern). An attacker discovers the Pi on the flat network, compromises   |
| it, and uses it as a persistent foothold. The Pi has network capture     |
| capability - the attacker can sniff traffic and capture credentials for   |
| EHR, AD, billing, and other systems. The Pi also provides a pivot point  |
| to attack the entire hospital network. No one notices because no one     |
| knows it exists. The attacker has a backdoor into MedDefense for months. |
+----------------------------------------------------------------------------+


RECOMMENDED RESPONSE: DECOMMISSION
----------------------------------
+----------------------------------------------------------------------------+
| STRATEGY: DECOMMISSION                                                    |
|                                                                             |
| JUSTIFICATION:                                                             |
| 1. No one knows what the Pi does or how it is configured.                 |
| 2. No one knows the credentials or who has access.                        |
| 3. It has been abandoned for months - no owner.                          |
| 4. Even if it is a "network monitor," it is not monitored or managed.    |
| 5. A Raspberry Pi on the flat network with unknown configuration is a    |
|    HIGH risk asset that cannot be trusted.                               |
| 6. If a network monitoring tool is needed, IT should deploy an approved  |
|    solution (not a forgotten Pi).                                         |
|                                                                             |
| ACTION PLAN:                                                               |
| 1. IMMEDIATELY locate and physically disconnect the Raspberry Pi.         |
| 2. Capture a forensic image (if needed for investigation).               |
| 3. Wipe the device completely.                                            |
| 4. If network monitoring is needed:                                      |
|    - Evaluate requirements with IT                                       |
|    - Deploy an approved, managed monitoring solution                     |
|    - Document in Asset Registry                                          |
| 5. Do NOT reconnect the Pi under any circumstances.                     |
+----------------------------------------------------------------------------+


ASSET REGISTRY UPDATE
---------------------
+----------------------------------------------------------------------------+
| Asset ID:       END-007                                                   |
| Name:           Raspberry Pi (Second Floor - Unknown)                    |
| Type:           Endpoint                                                  |
| Location:       Central - Second floor (unknown exact location)           |
| Owner:          Unknown (Previous IT intern)                              |
| OS/Platform:    Raspberry Pi OS (unknown)                                 |
| Critical Svs:   Unknown (allegedly network monitor)                       |
| Network Segment: 10.10.0.0/16 (flat network)                              |
| Status:         Shadow IT (To be decommissioned)                          |
| Notes:          Abandoned device. Set up by previous IT intern. No one   |
|                 knows credentials or purpose. Immediate locate and       |
|                 disconnect. Decommission and wipe.                       |
+----------------------------------------------------------------------------+


================================================================================
4. SHADOW IT POLICY RECOMMENDATION
================================================================================

+----------------------------------------------------------------------------+
| SHADOW IT POLICY RECOMMENDATION                                           |
|                                                                             |
| The single most effective policy change to reduce future shadow IT at     |
| MedDefense is to implement a mandatory "IT Approval for ALL Technology   |
| Purchases and Cloud Services" policy that requires any employee           |
| requesting, purchasing, or deploying any IT-related hardware, software,   |
| or cloud service to obtain formal approval from IT Security before        |
| acquisition or deployment. This policy should be linked to the            |
| procurement process, making it impossible to purchase any IT-related      |
| equipment or services without a clear security review and approval       |
| signature. Additionally, periodic network scans should be conducted to   |
| detect unauthorized devices, and an annual security awareness training    |
| module should educate all employees on the risks of shadow IT and the    |
| process for requesting IT services.                                      |
|                                                                             |
| NIST CSF 2.0 - ID.AM (Asset Management): This policy directly supports   |
| the "Identify" function by ensuring all assets are known and approved.   |
| CIS Control 1 (Inventory and Control of Enterprise Assets): Formal       |
| approval processes are essential for maintaining an accurate inventory.  |
| ISO 27001 A.8.2 (Acceptable Use): Clear policies on acceptable use of    |
| technology prevent shadow IT from being established.                     |
+----------------------------------------------------------------------------+


================================================================================
5. SUMMARY OF SHADOW SYSTEMS
================================================================================

+----------+---------------------+-----------------+-----------------+------------------+------------------------------------------+
| System   | Owner               | Discovery       | Sensitive Data  | Recommended      | Justification                            |
|          |                     | Source          |                 | Response         |                                          |
+----------+---------------------+-----------------+-----------------+------------------+------------------------------------------+
| Dr.      | Dr. Patel           | Mike Torres     | Research data   | MIGRATE          | Data belongs on approved hospital        |
| Patel's  | Cardiology          |                 | (PHI risk)      |                  | storage. NAS cannot be secured. Capacity |
| Personal |                     |                 |                 |                  | issue should be addressed properly.      |
| NAS      |                     |                 |                 |                  |                                          |
+----------+---------------------+-----------------+-----------------+------------------+------------------------------------------+
| Marketing| Marketing Dept      | Mike Torres     | Marketing,      | MIGRATE          | Business data on personal accounts is    |
| Google   |                     |                 | press, media    |                  | unacceptable. O365 is available and      |
| Drive    |                     |                 | (image risk)    |                  | controlled.                               |
+----------+---------------------+-----------------+-----------------+------------------+------------------------------------------+
| Raspberry| Unknown             | Mike Torres     | Network         | DECOMMISSION     | Abandoned, unmanaged, unknown             |
| Pi       | (Previous intern)   |                 | captures,       |                  | credentials, no owner. Cannot be         |
|          |                     |                 | credentials     |                  | trusted.                                  |
+----------+---------------------+-----------------+-----------------+------------------+------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. 3 Shadow IT systems identified. All exist outside IT governance and
   security controls. None are monitored, patched, or backed up.

2. All 3 systems are on the flat network (10.10.0.0/16) or accessible from
   it. This means a compromise of ANY shadow system can pivot to ALL
   MedDefense systems (EHR, billing, AD).

3. None of the 20 controls from the Control Matrix (Task 10) cover these
   shadow systems. They are completely invisible to security.

4. Dr. Patel's NAS demonstrates a legitimate user need (storage capacity)
   that was not met by IT, leading to shadow IT. This indicates IT should
   improve service delivery.

5. Marketing's Google Drive demonstrates that users will find alternatives
   if IT does not provide adequate solutions (cloud storage).

6. The Raspberry Pi demonstrates a lack of asset lifecycle management.
   Devices are deployed and forgotten.

7. Shadow IT represents a DIRECT PATH to compromise. Attackers know
   unmanaged devices often have weak or default credentials.

8. The flat network architecture AMPLIFIES the risk of shadow IT.
   A compromise of any shadow system = compromise of ALL systems.


================================================================================
7. RECOMMENDATIONS - SHADOW IT PREVENTION
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Locate and       | Immediate threat. Unknown device on    | NIST SP 800-53   |
|          | remove Pi        | network.                               | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Migrate NAS      | Data may contain PHI. Security risk.   | NIST SP 800-53   |
|          | data             |                                        | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Migrate Google   | Business data on personal accounts.    | NIST SP 800-53   |
|          | Drive data       |                                        | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Implement IT     | Prevent future shadow IT.              | NIST SP 800-53   |
|          | Approval Policy  |                                        | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Conduct network  | Detect other shadow systems.           | NIST SP 800-53   |
|          | scan quarterly   |                                        | RA-5             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Improve storage  | Address root cause (shared drive slow) | NIST SP 800-53   |
|          | capacity         |                                        | CM-3             |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Add training     | Educate staff on shadow IT risks.      | NIST SP 800-53   |
|          | module           |                                        | AT-2             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: CM-8 (Asset Inventory), AC-6 (Least Privilege)
- NIST SP 800-53: RA-5 (Vulnerability Scanning)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- NIST CSF 2.0: Identify Function - ID.AM (Asset Management)
- ISO 27001: A.8.1 (Asset Inventory), A.8.2 (Acceptable Use)
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF SHADOW SYSTEMS REPORT
================================================================================
