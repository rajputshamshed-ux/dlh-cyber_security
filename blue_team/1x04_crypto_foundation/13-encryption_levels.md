================================================================================
                    ENCRYPTION LEVELS - MEDDEFENSE HEALTH SYSTEMS
                    Task 13: The Encryption Levels
================================================================================

Exercise: Task 13 - The Encryption Levels
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Compare the six encryption levels defined and recommend the
          appropriate level for every MedDefense data store.

Sources: NIST SP 800-111, Sec+ 1.4, meddefense-crypto-audit-notes.txt,
         1x00 Asset Registry, 1x02 Findings


================================================================================
PART 1: ENCRYPTION LEVELS COMPARISON TABLE
================================================================================

+------------------+------------------+------------------+------------------+------------------------------------------+
| Level            | Scope            | Performance      | Key Management   | Use Case                                 |
|                  |                  | Impact           | Complexity       |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+
| FULL-DISK        | Entire physical  | LOW - minimal    | LOW - single     | Protecting data on lost/stolen devices.  |
| ENCRYPTION       | or virtual disk  | overhead for     | key for entire   | Best for laptops, desktops, and servers  |
| (FDE)            | (entire OS +     | read/write       | disk             | where the device is at risk of theft.   |
|                  | all data)        | operations       |                  |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+
| PARTITION        | One logical      | LOW - minimal    | LOW - key per    | Isolating different OS partitions or     |
| ENCRYPTION       | partition on a   | overhead for     | partition        | separating OS from data. Useful when     |
|                  | disk             | read/write       |                  | encrypting only the data partition while |
|                  |                  | operations       |                  | leaving the boot partition unencrypted.  |
+------------------+------------------+------------------+------------------+------------------------------------------+
| VOLUME           | Logical volume   | LOW to MEDIUM    | MEDIUM - key     | Storage servers, NAS devices, backup     |
| ENCRYPTION       | (may span        | - depends on     | per volume       | repositories. Good for encrypting only   |
| (LUKS)           | multiple disks)  | volume size      |                  | data partitions. Volume encryption is    |
|                  |                  |                  |                  | more flexible than partition encryption  |
|                  |                  |                  |                  | because volumes can span multiple disks. |
+------------------+------------------+------------------+------------------+------------------------------------------+
| FILE-LEVEL       | Individual files | HIGHER - each    | HIGH - keys per  | Selective protection of sensitive        |
| ENCRYPTION       |                  | file encrypted   | file or group    | files, user home directories, specific   |
|                  |                  | separately       | of files         | documents. More granular than volume or  |
|                  |                  |                  |                  | partition encryption.                    |
+------------------+------------------+------------------+------------------+------------------------------------------+
| DATABASE         | Entire database  | HIGH - affects   | MEDIUM -         | Protecting entire database at rest      |
| ENCRYPTION       | or tablespace    | query            | database-level   | (TDE - Transparent Data Encryption).    |
| (TDE)            |                  | performance      | key              | Best for relational databases. Encrypts  |
|                  |                  | significantly    |                  | data at the database level, not the disk.|
|                  |                  | (indexes,        |                  | Query performance may be impacted by    |
|                  |                  | joins, sorting)  |                  | encryption/decryption overhead during    |
|                  |                  |                  |                  | reads and writes.                       |
+------------------+------------------+------------------+------------------+------------------------------------------+
| RECORD-LEVEL     | Individual       | HIGHEST - per-   | HIGHEST - keys   | Protecting specific fields like SSN,     |
| ENCRYPTION       | fields or        | record           | per field/record | credit card numbers, or diagnosis codes. |
| (Field/Column)   | records          | overhead         | or column        | Most granular level. Best for protecting |
|                  |                  |                  |                  | only the most sensitive data fields.    |
+------------------+------------------+------------------+------------------+------------------------------------------+

================================================================================
PART 2: MEDDEFENSE ENCRYPTION LEVEL MAP
================================================================================

DATA STORE 1: PATIENT RECORDS IN POSTGRESQL (ehr-db-01)
--------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | DATABASE ENCRYPTION (TDE)                        |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Patient records contain PHI for 50,000 patients.  |
|                  | TDE protects the database files at rest. This   |
|                  | is the most appropriate level because clinical   |
|                  | staff need continuous access to patient data,   |
|                  | and TDE encrypts data without changing          |
|                  | application behavior.                           |
+------------------+--------------------------------------------------+


DATA STORE 2: BACKUP DATA ON NAS-01
------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | VOLUME ENCRYPTION (LUKS)                          |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Backup data contains copies of all PHI. LUKS     |
|                  | volume encryption protects the entire backup     |
|                  | partition. This is the industry standard for     |
|                  | Linux storage and is compatible with Synology    |
|                  | DSM. Backup performance impact is minimal.      |
+------------------+--------------------------------------------------+


DATA STORE 3: FINANCIAL RECORDS IN MYSQL (billing-srv-01)
-----------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | DATABASE ENCRYPTION (TDE)                        |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Billing data contains SSNs and credit card info. |
|                  | MySQL TDE protects the database at rest without  |
|                  | changing application behavior. This is preferred |
|                  | over volume encryption because it protects the   |
|                  | data at the logical level where it is accessed. |
+------------------+--------------------------------------------------+


DATA STORE 4: MEDICAL IMAGES ON PACS (pacs-srv-01)
----------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | FILE-LEVEL ENCRYPTION                            |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | DICOM images contain embedded PHI. File-level    |
|                  | encryption allows granular protection of each    |
|                  | imaging file. This is more appropriate than      |
|                  | volume encryption because PACS images can be     |
|                  | selectively protected based on sensitivity.      |
+------------------+--------------------------------------------------+


DATA STORE 5: EMAIL DATA IN O365
---------------------------------
+------------------+--------------------------------------------------+
| Recommended      | RECORD-LEVEL ENCRYPTION (S/MIME or OME)          |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | O365 provides encryption at rest (BitLocker)     |
|                  | and in transit (TLS 1.2) by default. However,   |
|                  | PHI sent via email requires additional protection|
|                  | at the record level. MedDefense should enable    |
|                  | S/MIME or OME to encrypt individual email        |
|                  | messages containing PHI. This is the most        |
|                  | granular level and ensures patient data is       |
|                  | protected even when transmitted via email.       |
+------------------+--------------------------------------------------+


DATA STORE 6: EMPLOYEE LAPTOPS
-------------------------------
+------------------+--------------------------------------------------+
| Recommended      | FULL-DISK ENCRYPTION (BitLocker or LUKS)         |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Laptops are at high risk of theft or loss. FDE   |
|                  | protects ALL data on the device. Windows         |
|                  | BitLocker or Linux LUKS is recommended. Key      |
|                  | should be escrowed to allow recovery. This is    |
|                  | the most appropriate level for portable devices. |
+------------------+--------------------------------------------------+


DATA STORE 7: BD ALARIS PUMP FIRMWARE/CONFIGURATION
----------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | FIRMWARE SECURITY (VENDOR-MANAGED) + NETWORK     |
| Level            | ISOLATION                                       |
+------------------+--------------------------------------------------+
| Justification    | IoT devices have limited processing power and    |
|                  | cannot run full encryption. Firmware encryption  |
|                  | is managed by BD. Network isolation (VLAN 30)   |
|                  | is the primary MedDefense control.              |
+------------------+--------------------------------------------------+


DATA STORE 8: OS/DATA SEPARATION ON LEGACY SERVERS (print-srv-01)
------------------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | PARTITION ENCRYPTION                             |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | The print server runs Windows Server 2012 R2      |
|                  | (EOL). Partition encryption allows separating    |
|                  | the OS partition (unencrypted for boot) from    |
|                  | the data partition (encrypted). This is the      |
|                  | most appropriate level for legacy systems that   |
|                  | need to boot unencrypted.                       |
+------------------+--------------------------------------------------+


DATA STORE 9: EHR SENSITIVE FIELDS (DIAGNOSIS, SSN)
-----------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | RECORD-LEVEL ENCRYPTION                          |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Patient records contain highly sensitive fields  |
|                  | like diagnosis codes and SSNs. Record-level      |
|                  | encryption protects specific columns in the     |
|                  | PostgreSQL database. Even with database access,  |
|                  | attackers cannot read encrypted fields without   |
|                  | the column-level key. This is defense in depth  |
|                  | and the most granular level.                    |
+------------------+--------------------------------------------------+

================================================================================
REFERENCES
================================================================================

- NIST SP 800-111: Guide to Storage Encryption
- Sec+ 1.4: Encryption levels
- meddefense-crypto-audit-notes.txt
- 1x00 Asset Registry
- 1x02 Findings


================================================================================
END OF ENCRYPTION LEVELS REPORT
================================================================================
