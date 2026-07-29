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


DATA STORE 8: OS/DATA SEPARATION ON LEGACY SERVERS (print-srv-01)
------------------------------------------------------------------
+------------------+--------------------------------------------------+
| Recommended      | PARTITION ENCRYPTION                             |
| Level            |                                                  |
+------------------+--------------------------------------------------+
| Justification    | The print server runs Windows Server 2012 R2      |
|                  | (EOL). Partition encryption allows separating    |
|                  | the OS partition (unencrypted for boot) from    |
|                  | the data partition (encrypted). This reduces    |
|                  | encryption overhead on the OS while protecting  |
|                  | configuration files and logs.                   |
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
|                  | the column-level key. This is defense in depth. |
+------------------+--------------------------------------------------+
