================================================================================
                    CRYPTO INVENTORY - MEDDEFENSE HEALTH SYSTEMS
                    Task 0: The Crypto Inventory
================================================================================

Exercise: Task 0 - The Crypto Inventory
Analyst: shamshed rajput
Date: 27/07/2026
Objective: Map every data flow at MedDefense against its current
          cryptographic protection state, exposing every gap in one document.

Sources: meddefense-crypto-audit-notes.txt, 1x02 Vulnerability Scan,
         1x00 Data Map, 1x00 Asset Registry

NIST SP 800-175B Reference: Cryptographic mechanisms for data protection
NIST SP 800-111 Reference: Storage encryption guidelines


================================================================================
1. DATA PROTECTION MAP
================================================================================

DATA CATEGORY 1: PATIENT MEDICAL RECORDS (EHR DATABASE)
-------------------------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | NONE                                              |
| (Stored on       |                                                   |
| ehr-db-01)       |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | PostgreSQL data directory is stored on ext4      |
|                  | filesystem with no encryption layer. Root access |
|                  | or physical drive theft exposes all patient      |
|                  | records in plaintext.                            |
|                  | Source: Crypto Audit Notes - Patient Data        |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | PARTIAL (SSL configured but optional)            |
| (EHR App to      |                                                   |
| Database)        |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | PostgreSQL has ssl=on configured, but pg_hba.conf |
|                  | allows non-SSL connections ("hostnossl" lines    |
|                  | exist alongside "hostssl"). No enforcement that  |
|                  | ALL connections are encrypted.                   |
|                  | Source: Crypto Audit Notes - Patient Data        |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | NONE                                              |
| (Viewed on       |                                                   |
| workstations)    |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Data is decrypted in memory on ehr-srv-01 and    |
|                  | transmitted to browsers. No screen lock policy   |
|                  | on clinical workstations (screensaver timeout   |
|                  | set to "Never" in Group Policy).                |
|                  | Source: Crypto Audit Notes - Patient Data,       |
|                  | 1x00 Task 3 - Observation 3                     |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+


DATA CATEGORY 2: FINANCIAL/BILLING DATA (MYSQL)
------------------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | NONE                                              |
| (Stored on       |                                                   |
| billing-srv-01)  |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | MySQL data directory on unencrypted ext4         |
|                  | filesystem. Contains: patient names, DOBs, SSNs, |
|                  | insurance policy numbers, credit card last-4,    |
|                  | and 3 years of billing records. All readable     |
|                  | without MySQL credentials.                       |
|                  | Source: Crypto Audit Notes - Financial Data      |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | WEAK                                              |
| (Billing App     |                                                   |
| to Database)     |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | MySQL bound to 0.0.0.0 and does NOT enforce SSL  |
|                  | for connections. Billing application connects    |
|                  | via plaintext MySQL protocol over the flat       |
|                  | network.                                         |
|                  | Source: Crypto Audit Notes - Financial Data,     |
|                  | 1x02 Finding 006                                 |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | NONE                                              |
| (Viewed by       |                                                   |
| Finance staff)   |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Data decrypted in memory and displayed on        |
|                  | workstations. No screen lock policy enforced.    |
|                  | No DLP or endpoint encryption in place.          |
|                  | Source: 1x00 Control Matrix - No DLP controls    |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+


DATA CATEGORY 3: MEDICAL IMAGES (DICOM ON PACS)
------------------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | NONE                                              |
| (Stored on       |                                                   |
| pacs-srv-01)     |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | DICOM files stored on local disk without         |
|                  | encryption. Patient identifiers embedded in      |
|                  | DICOM headers (name, DOB, MRN) are readable      |
|                  | with any DICOM viewer or text editor.            |
|                  | Source: Crypto Audit Notes - Medical Images      |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | NONE                                              |
| (MRI → PACS,     |                                                   |
| PACS →           |                                                   |
| Radiology)       |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | DICOM protocol (ports 4242, 11112) with NO TLS   |
|                  | configured. All imaging data, including patient  |
|                  | identifiers in DICOM headers, traverses the      |
|                  | network in cleartext.                            |
|                  | Source: Crypto Audit Notes - Medical Images,     |
|                  | 1x02 Finding 024                                 |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | NONE                                              |
| (Viewed by       |                                                   |
| Radiologists)    |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Images displayed on radiology workstations.      |
|                  | Shared account ("raduser/radiology1") means no   |
|                  | individual accountability. No screen lock       |
|                  | policy enforced.                                 |
|                  | Source: 1x00 Task 3 - Shared Login              |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+


DATA CATEGORY 4: CREDENTIALS (ACTIVE DIRECTORY)
------------------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | WEAK                                              |
| (AD Database)    |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | NTHash (MD4) used for NTLM compatibility.        |
|                  | DES and RC4 encryption types still enabled for   |
|                  | Kerberos. DES is trivially breakable since 1999. |
|                  | RC4 allows Kerberoasting attacks to crack        |
|                  | service tickets offline.                         |
|                  | Source: Crypto Audit Notes - Credentials,        |
|                  | 1x02 Finding 018                                 |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | WEAK                                              |
| (LDAP Traffic)   |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | LDAP signing not required (1x02 Finding 007).    |
|                  | LDAP traffic can be intercepted or relayed       |
|                  | without detection.                               |
|                  | Source: 1x02 Finding 007                         |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | N/A                                               |
| (Credentials     |                                                   |
| in memory)       |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Credentials stored in LSASS memory on domain      |
|                  | controllers. No credential guard or LSA          |
|                  | protection configured.                           |
|                  | Source: 1x00 Threat Landscape - Credential       |
|                  | Harvesting (Mimikatz)                            |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+


DATA CATEGORY 5: BACKUP DATA (NAS-01)
--------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | NONE                                              |
| (Stored on       |                                                   |
| NAS-01)          |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Synology NAS stores all backup data on RAID-5    |
|                  | array with NO encryption. Database dumps from    |
|                  | PostgreSQL and MySQL are readable in plaintext.  |
|                  | NAS management interface accessible network-wide |
|                  | (1x02 Finding 015).                              |
|                  | Source: Crypto Audit Notes - Backup Data,        |
|                  | 1x02 Finding 015                                 |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | N/A                                               |
| (Backup to NAS)  |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Backup traffic traverses the flat network in     |
|                  | plaintext. Veeam uses its own protocol but no    |
|                  | encryption is configured for backup data.        |
|                  | Source: Crypto Audit Notes - Backup Data         |
+------------------+--------------------------------------------------+
| Status           | ABSENT                                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | N/A                                               |
| (Restore)        |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | N/A - Restore process uses same unencrypted      |
|                  | data path.                                       |
+------------------+--------------------------------------------------+
| Status           | N/A                                               |
+------------------+--------------------------------------------------+


DATA CATEGORY 6: EMAIL (O365)
------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | ADEQUATE (Microsoft-managed)                     |
| (O365 Mailboxes) |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | BitLocker on Microsoft datacenter disks +        |
|                  | per-mailbox encryption with Microsoft-managed    |
|                  | keys.                                            |
|                  | Source: Crypto Audit Notes - Email               |
+------------------+--------------------------------------------------+
| Status           | ADEQUATE                                          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | ADEQUATE                                          |
| (Email over      |                                                   |
| Internet)        |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | Microsoft enforces TLS 1.2 for all Exchange      |
|                  | Online connections.                              |
|                  | Source: Crypto Audit Notes - Email               |
+------------------+--------------------------------------------------+
| Status           | ADEQUATE                                          |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | WEAK                                              |
| (Email viewed    |                                                   |
| by staff)        |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | S/MIME or OME not configured. PHI is sometimes   |
|                  | emailed between physicians in plaintext.         |
|                  | Sarah's note: "I've told them not to email PHI.  |
|                  | They do it anyway."                              |
|                  | Source: Crypto Audit Notes - Email               |
+------------------+--------------------------------------------------+
| Status           | WEAK                                              |
+------------------+--------------------------------------------------+


DATA CATEGORY 7: VPN TRAFFIC (SITE-TO-SITE TUNNELS)
----------------------------------------------------
+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| AT REST          | N/A                                               |
+------------------+--------------------------------------------------+
| Evidence         | N/A                                               |
+------------------+--------------------------------------------------+
| Status           | N/A                                               |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN TRANSIT       | ADEQUATE (with one concern)                      |
| (Site-to-Site    |                                                   |
| VPN Tunnels)     |                                                   |
+------------------+--------------------------------------------------+
| Evidence         | IPSec tunnels using AES-256 with SHA-256,        |
|                  | IKEv2 with DH Group 14. Westside tunnel          |
|                  | terminates on consumer Netgear Nighthawk router  |
|                  | (unknown firmware security).                     |
|                  | Source: Crypto Audit Notes - VPN Traffic         |
+------------------+--------------------------------------------------+
| Status           | ADEQUATE (with caveat)                            |
+------------------+--------------------------------------------------+

+------------------+--------------------------------------------------+
| DATA STATE       | Protection                                       |
+------------------+--------------------------------------------------+
| IN USE           | N/A                                               |
+------------------+--------------------------------------------------+
| Evidence         | N/A                                               |
+------------------+--------------------------------------------------+
| Status           | N/A                                               |
+------------------+--------------------------------------------------+


================================================================================
2. GAP SUMMARY
================================================================================

TOTAL CELLS: 21 (7 Data Categories × 3 Data States)

+------------------+---------------------+------------------------------------------+
| Status           | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| ADEQUATE         | 2                   | 9.5%                                     |
| WEAK             | 5                   | 23.8%                                    |
| ABSENT           | 11                  | 52.4%                                    |
| N/A              | 3                   | 14.3%                                    |
+------------------+---------------------+------------------------------------------+

CRYPTO COVERAGE PERCENTAGE (Non-N/A cells):
+------------------+---------------------+------------------------------------------+
| Total non-N/A    | 18                  | 100%                                     |
| cells            |                     |                                          |
+------------------+---------------------+------------------------------------------+
| Adequate cells   | 2                   | 11.1%                                    |
| Weak cells       | 5                   | 27.8%                                    |
| Absent cells     | 11                  | 61.1%                                    |
+------------------+---------------------+------------------------------------------+

OVERALL CRYPTO COVERAGE: 11.1% (2 out of 18 cells are Adequate)

+----------------------------------------------------------------------------+
| GAP SUMMARY                                                                |
|                                                                             |
| MedDefense has CRITICAL cryptographic gaps across ALL data categories:      |
|                                                                             |
| 1. AT REST: 6 out of 6 data stores have NO encryption.                     |
|    - EHR database, billing database, PACS images, backups, AD credentials, |
|      and local disk storage are all unencrypted.                          |
|                                                                             |
| 2. IN TRANSIT: 4 out of 5 data flows are WEAK or ABSENT.                  |
|    - DICOM images, MySQL traffic, LDAP, and PostgreSQL are unencrypted.    |
|    - Only VPN traffic is adequately encrypted.                            |
|                                                                             |
| 3. IN USE: 4 out of 4 are ABSENT or WEAK.                                 |
|    - No screen lock, no DLP, no email encryption (S/MIME/OME).            |
|                                                                             |
| The only Adequate protections are:                                        |
|    - O365 at rest (Microsoft-managed)                                    |
|    - O365 in transit (TLS 1.2)                                           |
|    - VPN traffic (AES-256, partially)                                    |
|                                                                             |
| OVERALL CRYPTO COVERAGE: 11.1%                                             |
| This means 89% of MedDefense's data is NOT cryptographically protected.   |
|                                                                             |
| The most critical gaps are:                                                |
| - Patient records (ALL states)                                           |
| - Medical images (ALL states)                                            |
| - Backups (At Rest)                                                      |
| - Active Directory credentials (At Rest and In Transit)                  |
+----------------------------------------------------------------------------+


================================================================================
3. PRIORITY GAPS
================================================================================

+----------+------------------+------------------------------------------+
| Priority | Gap              | Justification                            |
+----------+------------------+------------------------------------------+
| #1       | Patient Records  | PHI for 50,000 patients. Direct HIPAA    |
|          | (At Rest)        | compliance requirement. Highest risk.   |
+----------+------------------+------------------------------------------+
| #2       | Medical Images   | PHI in DICOM headers. 45 studies/day.    |
|          | (In Transit)     | MRI Windows XP vulnerability makes       |
|          |                  | interception easier.                     |
+----------+------------------+------------------------------------------+
| #3       | Backups          | All data is stored in backups.           |
|          | (At Rest)        | Ransomware scenario targets backups.    |
+----------+------------------+------------------------------------------+
| #4       | Medical Images   | DICOM files contain embedded PHI.        |
|          | (At Rest)        |                                          |
+----------+------------------+------------------------------------------+
| #5       | Patient Records  | PostgreSQL SSL optional means data can   |
|          | (In Transit)     | be intercepted on flat network.         |
+----------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- Vulnerability Scan (1x02): Findings 005, 006, 007, 015, 018, 024
- Data Map (1x00 Task 9)
- Asset Registry (1x00 Task 7)
- NIST SP 800-175B: Cryptographic Mechanisms
- NIST SP 800-111: Guide to Storage Encryption
- HIPAA Security Rule: Encryption Standards


================================================================================
END OF CRYPTO INVENTORY REPORT
================================================================================
