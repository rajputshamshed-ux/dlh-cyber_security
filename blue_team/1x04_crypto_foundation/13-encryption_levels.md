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
|                  |                  |                  |                  | Less common than full-disk or volume.   |
+------------------+------------------+------------------+------------------+------------------------------------------+
| VOLUME           | Logical volume   | LOW to MEDIUM    | MEDIUM - key     | Storage servers, NAS devices, backup     |
| ENCRYPTION       | (may span        | - depends on     | per volume       | repositories. Good for encrypting only   |
| (LUKS)           | multiple disks)  | volume size      |                  | data partitions.                         |
+------------------+------------------+------------------+------------------+------------------------------------------+
| FILE-LEVEL       | Individual files | HIGHER - each    | HIGH - keys per  | Selective protection of sensitive        |
| ENCRYPTION       |                  | file encrypted   | file or group    | files, user home directories, specific   |
|                  |                  | separately       | of files         | documents.                               |
+------------------+------------------+------------------+------------------+------------------------------------------+
| DATABASE         | Entire database  | HIGH - affects   | MEDIUM -         | Protecting entire database at rest      |
| ENCRYPTION       | or tablespace    | query            | database-level   | (TDE - Transparent Data Encryption).    |
| (TDE)            |                  | performance      | key              | Best for relational databases.           |
+------------------+------------------+------------------+------------------+------------------------------------------+
| RECORD-LEVEL     | Individual       | HIGHEST - per-   | HIGHEST - keys   | Protecting specific fields like SSN,     |
| ENCRYPTION       | fields or        | record           | per field/record | credit card numbers, or diagnosis codes. |
| (Field/Column)   | records          | overhead         | or column        | Best for granular data protection.       |
+------------------+------------------+------------------+------------------+------------------------------------------+


================================================================================
PART 2: MEDDEFENSE ENCRYPTION LEVEL MAP
================================================================================

DATA STORE 1: PATIENT RECORDS IN POSTGRESQL (ehr-db-01)
--------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | VOLUME ENCRYPTION (LUKS) + DATABASE ENCRYPTION    |
| Level            | (TDE)                                            |
+------------------+--------------------------------------------------+
| Justification    | Patient records contain PHI for 50,000 patients.  |
|                  | LUKS protects the underlying storage against     |
|                  | physical theft. TDE protects the database files  |
|                  | from unauthorized access at the OS level. The   |
|                  | combination provides defense in depth.            |
+------------------+--------------------------------------------------+
| Performance      | LUKS adds ~15-20% CPU overhead for I/O           |
| Impact           | operations. TDE adds additional overhead for     |
|                  | query processing. Acceptable for a hospital      |
|                  | EHR with moderate transaction volume.            |
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
|                  | DSM. Backup performance impact is minimal        |
|                  | (sequential writes during off-peak hours).       |
+------------------+--------------------------------------------------+


DATA STORE 3: FINANCIAL RECORDS IN MYSQL (billing-srv-01)
-----------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | VOLUME ENCRYPTION (LUKS) + DATABASE ENCRYPTION    |
| Level            | (TDE)                                            |
+------------------+--------------------------------------------------+
| Justification    | Billing data contains SSNs, insurance info, and  |
|                  | credit card data. LUKS protects the storage      |
|                  | against theft. MySQL TDE (Enterprise) protects   |
|                  | the database files. Alternative: encrypt data    |
|                  | at the application level (record-level).         |
+------------------+--------------------------------------------------+


DATA STORE 4: MEDICAL IMAGES ON PACS (pacs-srv-01)
----------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | VOLUME ENCRYPTION (LUKS) + FILE-LEVEL            |
| Level            | ENCRYPTION                                       |
+------------------+--------------------------------------------------+
| Justification    | DICOM images contain embedded PHI. LUKS protects |
|                  | the storage. File-level encryption allows for    |
|                  | granular protection of individual DICOM files.   |
|                  | Performance impact is acceptable for imaging     |
|                  | workloads where read access is frequent.         |
+------------------+--------------------------------------------------+


DATA STORE 5: EMAIL DATA IN O365
---------------------------------
+------------------+--------------------------------------------------+
| Recommended      | MICROSOFT-MANAGED ENCRYPTION                      |
| Level            | (O365 DEFAULT)                                   |
+------------------+--------------------------------------------------+
| Justification    | Microsoft manages encryption for O365 at rest    |
|                  | (BitLocker) and in transit (TLS 1.2). No action  |
|                  | needed. However, MedDefense should enable S/MIME |
|                  | or OME for PHI sent via email to prevent         |
|                  | plaintext exposure.                              |
+------------------+--------------------------------------------------+


DATA STORE 6: EMPLOYEE LAPTOPS
-------------------------------
+------------------+--------------------------------------------------+
| Recommended      | FULL-DISK ENCRYPTION (LUKS or BitLocker)         |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | Laptops are at high risk of theft or loss. FDE   |
|                  | protects ALL data on the device. Windows         |
|                  | BitLocker or Linux LUKS is recommended. Key      |
|                  | should be escrowed to allow recovery.            |
+------------------+--------------------------------------------------+


DATA STORE 7: BD ALARIS PUMP FIRMWARE/CONFIGURATION
----------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | FIRMWARE SECURITY (VENDOR-MANAGED) + NETWORK     |
| Level            | ISOLATION                                       |
+------------------+--------------------------------------------------+
| Justification    | IoT devices have limited processing power.       |
|                  | Firmware encryption is managed by BD. Network    |
|                  | isolation (VLAN 30 from segmentation design) is  |
|                  | the primary MedDefense control.                  |
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
