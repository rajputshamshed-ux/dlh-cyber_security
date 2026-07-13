================================================================================
                    DATA MAP - MEDDEFENSE HEALTH SYSTEMS
                    Task 9: The Data Map
================================================================================

Exercise: Task 9 - The Data Map
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Identify, classify and trace the flow of sensitive data across its
          lifecycle states to identify protection gaps.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: SC-28 (Protection of Information at Rest),
                       SC-8 (Transmission Confidentiality)
- NIST CSF 2.0: Identify Function - ID.AM (Asset Management)
- HHS HICP: Healthcare data protection practices
- CISA Healthcare Guide: Healthcare data security

Sources: Asset Registry (Task 7), Control Artifacts (Task 4),
         Walk-through Observations (Task 3), Network Diagram,
         Onboarding Packet


================================================================================
1. DATA CLASSIFICATION LEVELS
================================================================================

+------------+------------------------------------------+----------------------------------------+
| Level      | Definition                               | Examples                               |
+------------+------------------------------------------+----------------------------------------+
| RESTRICTED | Highest sensitivity. Unauthorized access | Patient medical records, SSNs, credit  |
|            | causes severe harm. Regulatory           | card numbers, diagnoses, treatment     |
|            | penalties (HIPAA).                       | plans, billing/insurance information. |
+------------+------------------------------------------+----------------------------------------+
| CONFIDENTIAL| Sensitive internal information.          | Employee salaries, strategic plans,    |
|            | Unauthorized access causes significant   | vendor contracts, financial budgets,   |
|            | harm but not life-safety.                | audit findings.                        |
+------------+------------------------------------------+----------------------------------------+
| INTERNAL   | Not for public disclosure but limited    | Internal memos, org charts, meeting    |
|            | impact if exposed.                       | notes, department schedules.           |
+------------+------------------------------------------+----------------------------------------+
| PUBLIC     | Intended for public consumption. No      | Website content, public phone numbers, |
|            | harm if disclosed.                       | marketing materials.                   |
+------------+------------------------------------------+----------------------------------------+


================================================================================
2. DATA CATEGORIES MAP
================================================================================

DATA CATEGORY 1: PATIENT MEDICAL RECORDS (EHR)
-----------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Patient Medical Records (EHR)                    |
+------------------+--------------------------------------------------+
| Classification   | RESTRICTED                                       |
+------------------+--------------------------------------------------+
| At Rest          | ehr-db-01 (PostgreSQL database, Central)         |
| (Where stored)   | Veeam backups (backup-srv-01 → NAS-01)           |
|                  | O365 (emails containing PHI)                    |
+------------------+--------------------------------------------------+
| In Transit       | Clinical workstations → EHR server (internal)    |
| (How it moves)   | Westside/HQ → VPN → EHR server                   |
|                  | Patient portal → External users (internet)       |
+------------------+--------------------------------------------------+
| In Use           | Physicians, nurses, clinical staff (Central,     |
| (By whom, on    | Westside, HQ) on Windows 10 workstations,        |
|  what)           | thin clients, iPads (unmanaged).                 |
+------------------+--------------------------------------------------+
| Current          | At Rest: PostgreSQL database (no encryption      |
| Protection       | documented). Backups to NAS (no encryption).     |
|                  | In Transit: Site-to-site VPN for remote sites.   |
|                  | Internal traffic: NO encryption (flat network).  |
|                  | In Use: Screen lock NOT enforced (Obs 3).        |
|                  | Sophos AV on workstations (outdated on 31        |
|                  | devices).                                        |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: NO encryption on database or    |
|                  |    backups.                                      |
|                  | 2. Data in transit: Internal network traffic is  |
|                  |    NOT encrypted (flat network).                 |
|                  | 3. Data in use: No screen lock policy. Unlocked  |
|                  |    EHR sessions at nurse stations (Obs 3).       |
|                  | 4. Endpoint protection: 31 workstations have     |
|                  |    outdated antivirus signatures.                |
|                  | 5. iPads (25) are UNMANAGED - no MDM.           |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: SC-28 (At Rest), SC-8 (In Transit), AC-11 (In Use)


DATA CATEGORY 2: MEDICAL IMAGING DATA (PACS)
---------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Medical Imaging Data (PACS)                      |
+------------------+--------------------------------------------------+
| Classification   | RESTRICTED                                       |
+------------------+--------------------------------------------------+
| At Rest          | pacs-srv-01 (PACS Imaging Server, Central)       |
| (Where stored)   | NOT backed up (Art 5 - "too large").            |
+------------------+--------------------------------------------------+
| In Transit       | MRI/CT → PACS Server (internal)                  |
| (How it moves)   | PACS Server → Radiology workstations             |
|                  | PACS Server → Clinical workstations (viewing)    |
+------------------+--------------------------------------------------+
| In Use           | Radiologists, physicians, clinical staff on      |
| (By whom, on    | PACS workstations and clinical workstations.    |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: PACS server has NO documented           |
| Protection       | encryption. NOT backed up (no recovery).        |
|                  | In Transit: Internal network traffic is NOT      |
|                  | encrypted (flat network).                        |
|                  | In Use: Images displayed on workstations.        |
|                  | Windows XP MRI workstation has NO protection.    |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: NO encryption on PACS server.   |
|                  | 2. Data at rest: NO backups. Complete loss of    |
|                  |    imaging data if server fails.                 |
|                  | 3. Data in transit: Internal traffic NOT         |
|                  |    encrypted.                                    |
|                  | 4. Data in use: MRI workstation Windows XP       |
|                  |    (EOL 2014) has NO protection.                 |
|                  | 5. No compensating controls for MRI.             |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: SC-28 (At Rest), SC-8 (In Transit), SI-2 (Patching)
CISA Healthcare Guide: Medical imaging data is PHI and requires protection


DATA CATEGORY 3: BILLING & FINANCIAL DATA
------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Billing & Financial Data                          |
+------------------+--------------------------------------------------+
| Classification   | RESTRICTED                                       |
+------------------+--------------------------------------------------+
| At Rest          | billing-srv-01 (Ubuntu 18.04 LTS, Central)       |
| (Where stored)   | file-srv-01 (financial reports)                  |
|                  | O365 (finance emails)                            |
+------------------+--------------------------------------------------+
| In Transit       | Finance workstations → billing-srv-01            |
| (How it moves)   | Claims → External payers (internet)              |
|                  | O365 cloud sync                                  |
+------------------+--------------------------------------------------+
| In Use           | Finance team, administrative staff on Windows    |
| (By whom, on    | workstations at HQ and Central.                 |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: billing-srv-01 (NO encryption           |
| Protection       | documented). file-srv-01 (NO encryption).       |
|                  | In Transit: Site-to-site VPN for remote access.  |
|                  | Internal traffic: NO encryption (flat network).  |
|                  | O365: Microsoft encryption (tenant-level).       |
|                  | In Use: Workstations with Sophos AV.             |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: NO encryption on billing server.|
|                  | 2. Data at rest: NO encryption on file shares.   |
|                  | 3. Data in transit: Internal traffic NOT         |
|                  |    encrypted.                                    |
|                  | 4. Data in use: Shared accounts (radiology)      |
|                  |    expose financial systems to unauthorized      |
|                  |    access.                                       |
|                  | 5. Previous ransomware incident on billing-srv-01|
|                  |    indicates vulnerability to encryption.       |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: SC-28 (At Rest), SC-8 (In Transit)
HHS HICP: Financial data may contain PHI and requires protection


DATA CATEGORY 4: EMPLOYEE HR RECORDS & PII
-------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Employee HR Records & PII                         |
+------------------+--------------------------------------------------+
| Classification   | CONFIDENTIAL                                     |
+------------------+--------------------------------------------------+
| At Rest          | file-srv-01 (HR department shares, Central)      |
| (Where stored)   | O365 (HR emails, SharePoint)                     |
|                  | ad-dc-01/02 (employee accounts)                  |
+------------------+--------------------------------------------------+
| In Transit       | HR workstations → file-srv-01 (internal)         |
| (How it moves)   | O365 cloud sync                                  |
|                  | VPN from HQ to Central                          |
+------------------+--------------------------------------------------+
| In Use           | HR staff, managers, IT (account creation) on     |
| (By whom, on    | Windows workstations at HQ.                     |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: file-srv-01 (NO encryption documented). |
| Protection       | O365: Microsoft encryption (tenant-level).       |
|                  | AD accounts protected by password policy.        |
|                  | In Transit: Site-to-site VPN for remote access.  |
|                  | Internal traffic: NO encryption (flat network).  |
|                  | In Use: Workstations with Sophos AV.             |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: NO encryption on file shares.   |
|                  | 2. Data in transit: Internal traffic NOT         |
|                  |    encrypted.                                    |
|                  | 3. Data in use: IT intern laptop on internal     |
|                  |    network had access to HR file share           |
|                  |    (Incident F, Task 1).                         |
|                  | 4. No network segmentation to protect HR data.   |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: SC-28 (At Rest), SC-8 (In Transit), AC-6 (Least Privilege)


DATA CATEGORY 5: SYSTEM CREDENTIALS & AUTHENTICATION DATA
----------------------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | System Credentials & Authentication Data        |
+------------------+--------------------------------------------------+
| Classification   | RESTRICTED                                       |
+------------------+--------------------------------------------------+
| At Rest          | ad-dc-01/02 (Active Directory database)          |
| (Where stored)   | Switch management credentials (taped to wall     |
|                  | - Obs 2)                                        |
|                  | Shared account credentials (raduser/radiology1)  |
+------------------+--------------------------------------------------+
| In Transit       | Authentication requests over the network         |
| (How it moves)   | SSH sessions (password or key-based)            |
|                  | RDP sessions                                     |
+------------------+--------------------------------------------------+
| In Use           | IT staff, system administrators, radiology       |
| (By whom, on    | department (shared account).                    |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: AD has password hashes (no encryption   |
| Protection       | documented).                                     |
|                  | In Transit: SSH key-only on ehr-srv-01 ONLY.    |
|                  | Other Linux servers: password auth enabled.     |
|                  | In Use: Shared accounts (radiology) not          |
|                  | permitted by policy but used.                   |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: Credentials taped to wall in    |
|                  |    plaintext (Obs 2).                            |
|                  | 2. Data at rest: Shared accounts not             |
|                  |    eliminated.                                   |
|                  | 3. Data in transit: SSH password auth on most    |
|                  |    Linux servers (Task 2 - only ehr-srv-01      |
|                  |    hardened).                                    |
|                  | 4. Data in use: No MFA anywhere except James     |
|                  |    personal account.                            |
|                  | 5. No privileged access management (PAM).        |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: IA-5 (Authenticator Management), AC-6 (Least Privilege)
CIS Control 5: Account Management


DATA CATEGORY 6: AUDIT LOGS
----------------------------
+------------------+--------------------------------------------------+
| Data Category    | Audit Logs                                       |
+------------------+--------------------------------------------------+
| Classification   | CONFIDENTIAL                                     |
+------------------+--------------------------------------------------+
| At Rest          | FortiGate local logs (30-day retention)          |
| (Where stored)   | Windows Event Viewer (local)                     |
|                  | Linux /var/log (local, 4-week rotation)          |
|                  | EHR application logs (vendor-managed)            |
+------------------+--------------------------------------------------+
| In Transit       | No centralization - logs stay on local systems   |
| (How it moves)   | No SIEM/forwarding.                             |
+------------------+--------------------------------------------------+
| In Use           | IT staff (manual review only when something      |
| (By whom, on    | breaks).                                         |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: Logs stored locally with limited        |
| Protection       | retention. No integrity protection (no hashing,  |
|                  | no write-once storage).                          |
|                  | In Transit: NO centralized log collection.       |
|                  | In Use: Manual review only, no automated         |
|                  | analysis.                                        |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Data at rest: NO log integrity protection.    |
|                  |    Logs can be modified or deleted by attackers. |
|                  | 2. Data in transit: NO centralization - logs     |
|                  |    are scattered across systems.                 |
|                  | 3. Data in use: NO automated alerting. No SIEM.  |
|                  | 4. Limited retention - forensic evidence may be  |
|                  |    lost after 30 days.                           |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: AU-6 (Audit Review), AU-9 (Protection of Audit Info)
CIS Control 6: Audit Log Management


DATA CATEGORY 7: CLINICAL TRIAL / RESEARCH DATA
------------------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Clinical Trial / Research Data                   |
+------------------+--------------------------------------------------+
| Classification   | RESTRICTED (or CONFIDENTIAL depending on         |
|                  | content)                                         |
+------------------+--------------------------------------------------+
| At Rest          | Unknown - not documented in any artifact.        |
| (Where stored)   | Potentially: file-srv-01, research department    |
|                  | systems, or external partners.                   |
+------------------+--------------------------------------------------+
| In Transit       | Unknown - not documented.                        |
| (How it moves)   |                                                  |
+------------------+--------------------------------------------------+
| In Use           | Research staff, clinical investigators.          |
| (By whom, on    |                                                  |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | NOT DOCUMENTED in any artifact. This data        |
| Protection       | category exists by implication (hospital with   |
|                  | clinical research) but is not inventoried.      |
+------------------+--------------------------------------------------+
| Protection Gaps  | COMPLETE GAP: This data category is not          |
|                  | documented, inventoried, or protected. Risk of   |
|                  | PHI exposure in research data is significant.    |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: CM-8 (Asset Inventory)
CISA Healthcare Guide: Clinical research data may contain PHI


DATA CATEGORY 8: PUBLIC WEBSITE CONTENT
----------------------------------------
+------------------+--------------------------------------------------+
| Data Category    | Public Website Content                            |
+------------------+--------------------------------------------------+
| Classification   | PUBLIC                                           |
+------------------+--------------------------------------------------+
| At Rest          | web-srv-01 (Public website + patient portal)     |
| (Where stored)   |                                                  |
+------------------+--------------------------------------------------+
| In Transit       | Internet users → web-srv-01 (HTTPS)              |
| (How it moves)   |                                                  |
+------------------+--------------------------------------------------+
| In Use           | Patients, public visitors, potential patients.   |
| (By whom, on    |                                                  |
|  what)           |                                                  |
+------------------+--------------------------------------------------+
| Current          | At Rest: web-srv-01 (Ubuntu 20.04).              |
| Protection       | In Transit: HTTPS (port 443).                    |
|                  | In Use: Publicly accessible.                     |
+------------------+--------------------------------------------------+
| Protection Gaps  | 1. Website defacement incident (Task 1, Incident |
|                  |    D) indicates weak web application security.   |
|                  | 2. Patient portal authentication MAY have gaps   |
|                  |    (Incident B - broken access control).         |
|                  | 3. No WAF (Web Application Firewall) documented. |
+------------------+--------------------------------------------------+

NIST SP 800-53 References: SI-7 (Software Integrity)
CIS Control 3: Data Protection


================================================================================
3. DATA FLOW DIAGRAM (TEXT REPRESENTATION)
================================================================================

+----------------------------------------------------------------------------+
|                     MEDDEFENSE HEALTH SYSTEMS - DATA FLOW                  |
+----------------------------------------------------------------------------+

[RESTRICTED - PATIENT MEDICAL RECORDS]
                                       ┌─────────────────────┐
                                       │   EHR DATABASE      │
                                       │   (ehr-db-01)       │
                                       │   ⚠️ NO ENCRYPTION   │
                                       └──────────┬──────────┘
                                                  │
                       ┌──────────────────────────┼──────────────────────────┐
                       │                          │                          │
                       ▼                          ▼                          ▼
              ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
              │   BACKUP        │       │   ETHERNET      │       │   VPN           │
              │   (NAS-01)      │       │   (Internal)    │       │   (Westside/HQ) │
              │ ⚠️ SAME ROOM    │       │ ⚠️ NO ENCRYPTION │       │ ✅ ENCRYPTED    │
              └─────────────────┘       └────────┬────────┘       └────────┬────────┘
                                                  │                          │
                                                  ▼                          ▼
                                       ┌─────────────────┐       ┌─────────────────┐
                                       │   CLINICAL      │       │   REMOTE        │
                                       │   WORKSTATIONS  │       │   WORKSTATIONS  │
                                       │ ⚠️ NO LOCK      │       │                 │
                                       └─────────────────┘       └─────────────────┘

[RESTRICTED - MEDICAL IMAGING DATA]

              ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
              │   MRI           │──────▶│   PACS SERVER   │──────▶│   RADIOLOGY     │
              │   (Windows XP)  │       │   (pacs-srv-01) │       │   WORKSTATIONS  │
              │ ⚠️ EOL 2014    │       │ ⚠️ NO BACKUP    │       │                 │
              └─────────────────┘       └─────────────────┘       └─────────────────┘

[RESTRICTED - SYSTEM CREDENTIALS]

              ┌─────────────────┐       ┌─────────────────┐
              │   SWITCH        │       │   ACTIVE        │
              │   CREDENTIALS   │       │   DIRECTORY     │
              │ ⚠️ TAPED TO WALL│       │   (ad-dc-01/02) │
              └─────────────────┘       └─────────────────┘

[CONFIDENTIAL - AUDIT LOGS]

              ┌─────────────────┐       ┌─────────────────┐
              │   FORTIGATE     │       │   WINDOWS       │
              │   LOCAL LOGS    │       │   EVENT LOGS    │
              │ ⚠️ NO SIEM     │       │ ⚠️ NO SIEM     │
              └─────────────────┘       └─────────────────┘


================================================================================
4. PROTECTION GAPS SUMMARY BY DATA STATE
================================================================================

+------------------+------------------------------------------+----------------------------------------+
| Data State       | Current Protection                       | Gap Summary                            |
+------------------+------------------------------------------+----------------------------------------+
| AT REST          | - Some backups exist (limited)           | - NO encryption on databases or file   |
|                  | - Firewall for perimeter                 |   shares                               |
|                  | - Password policy (AD)                   | - No encryption on backups             |
|                  | - Sophos AV on workstations              | - No encryption on NAS storage         |
|                  | - O365 encryption (tenant)               | - PACS NOT backed up                   |
|                  |                                          | - MRI Windows XP NO protection         |
+------------------+------------------------------------------+----------------------------------------+
| IN TRANSIT       | - Site-to-site VPN (Westside/HQ)         | - Internal network NOT encrypted       |
|                  | - HTTPS for public website               | - Flat network: all traffic visible    |
|                  | - SSH key-only on ehr-srv-01             | - SSH password auth on most Linux      |
|                  |                                          | - No network segmentation              |
+------------------+------------------------------------------+----------------------------------------+
| IN USE           | - Password policy (AD)                   | - No screen lock policy                |
|                  | - Sophos AV on workstations              | - Unlocked EHR sessions (Obs 3)        |
|                  | - Some SSH hardening (ehr-srv-01)        | - Shared accounts (radiology)          |
|                  |                                          | - No MFA anywhere                      |
|                  |                                          | - iPads unmanaged (25)                 |
|                  |                                          | - Windows XP MRI (EOL 2014)            |
|                  |                                          | - Credentials taped to wall (Obs 2)    |
+------------------+------------------------------------------+----------------------------------------+


================================================================================
5. DATA RISK SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| DATA RISK SUMMARY                                                          |
|                                                                             |
| MedDefense's most significant data protection weakness is the              |
| PROTECTION OF PATIENT MEDICAL RECORDS IN TRANSIT across the INTERNAL       |
| NETWORK and AT REST on the EHR DATABASE AND BACKUPS.                       |
|                                                                             |
| While site-to-site VPN encrypts data between sites, ALL internal network   |
| traffic within the flat 10.10.0.0/16 network is UNENCRYPTED. This means   |
| that an attacker who compromises ANY system on the network can sniff       |
| EHR traffic, intercept PHI, and capture credentials in plaintext.          |
|                                                                             |
| Additionally, the EHR database (ehr-db-01) and its backups on NAS-01      |
| have NO encryption documented. A physical theft of the server or NAS      |
| exposes RESTRICTED patient records for 50,000 patients.                    |
|                                                                             |
| The combination of:                                                         |
| 1. UNENCRYPTED internal network traffic (data in transit)                 |
| 2. UNENCRYPTED database storage (data at rest)                           |
| 3. UNLOCKED EHR sessions at nurse stations (data in use)                  |
|                                                                             |
| Creates a COMPLETE PROTECTION FAILURE across ALL THREE DATA STATES.       |
|                                                                             |
| This gap is CRITICAL because it involves RESTRICTED data (PHI) and        |
| affects the primary patient care system (EHR). A single compromise         |
| exposes the most sensitive data in the organization across every          |
| stage of its lifecycle.                                                     |
|                                                                             |
| HHS HICP: Healthcare organizations must protect PHI at rest, in transit,  |
| and in use. MedDefense has documented gaps in ALL THREE states.           |
+----------------------------------------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. 8 data categories identified. 5 are RESTRICTED (Patient Records,
   Medical Imaging, Billing, Credentials, Research). 2 are CONFIDENTIAL
   (HR Records, Audit Logs). 1 is PUBLIC (Website).

2. Protection gaps exist in ALL THREE data states (At Rest, In Transit,
   In Use). No single state is fully protected.

3. Internal network traffic is NOT encrypted. All data in transit across
   the flat network (10.10.0.0/16) is vulnerable to sniffing. This affects
   ALL RESTRICTED data categories.

4. Data at Rest: NO encryption on databases (EHR, billing), file shares,
   or backups. Physical theft of servers/NAS exposes all data.

5. Data in Use: No screen lock policy. Unlocked EHR sessions (Obs 3).
   No MFA. Shared accounts. Windows XP MRI (EOL 2014).

6. Audit logs: NO centralization, NO integrity protection, NO automated
   monitoring. Logs can be deleted by attackers without detection.

7. Clinical Trial/Research data: COMPLETE GAP. This category is not
   documented, inventoried, or protected.

8. The EHR system is the highest risk because it combines:
   - RESTRICTED data (PHI for 50,000 patients)
   - Gaps in ALL THREE states (At Rest, In Transit, In Use)
   - Single point of failure for patient care


================================================================================
7. RECOMMENDATIONS BY DATA STATE
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Data State       | Recommended Action                    | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | At Rest          | Implement encryption for all databases | NIST SP 800-53   |
|          |                  | (EHR, PACS, billing). Encrypt backup  | SC-28            |
|          |                  | data.                                  |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | In Transit       | Implement network segmentation.        | NIST SP 800-53   |
|          |                  | Encrypt internal traffic (VLANs,       | SC-8             |
|          |                  | encryption).                           |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | In Use           | Enforce screen lock policy. Implement  | NIST SP 800-53   |
|          |                  | MFA for ALL access. Eliminate shared   | AC-11, IA-2      |
|          |                  | accounts.                              |                  |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | At Rest          | Implement backup for PACS. Implement   | NIST SP 800-53   |
|          |                  | offsite/cloud backups.                 | CP-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | In Transit       | Deploy SIEM for log centralization.    | NIST SP 800-53   |
|          |                  | Implement log integrity protection.    | AU-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | In Use           | Deploy MDM for iPads. Harden SSH on    | NIST SP 800-53   |
|          |                  | ALL Linux servers.                     | CM-6             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: SC-28 (At Rest), SC-8 (In Transit), AC-11 (In Use)
- NIST CSF 2.0: Identify Function - ID.AM (Asset Management)
- CIS Controls v8: Critical Security Controls
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF DATA MAP REPORT
================================================================================
