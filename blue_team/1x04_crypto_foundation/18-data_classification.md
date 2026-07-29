================================================================================
                    DATA CLASSIFICATION MATRIX - MEDDEFENSE HEALTH SYSTEMS
                    Task 18: The Data Classification Matrix
================================================================================

Exercise: Task 18 - The Data Classification Matrix
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Apply data protection principles to produce a comprehensive data
          classification policy for MedDefense that drives every encryption
          decision. Encryption intensity is a spectrum, determined by
          data sensitivity.

Sources: 1x00 Asset Registry, 1x02 Vulnerability Findings, 1x03 Risk Register,
         T13 Encryption Levels, T14 Key Management Plan, T15 Crypto Posture
         Audit, HIPAA Security Rule (45 CFR § 164.312), NIST SP 800-60 Vol 1


================================================================================
PART 1: DATA TYPE INVENTORY
================================================================================

All MedDefense data assets classified by data type. Some data belongs to
multiple types simultaneously (e.g., patient billing records are both
PHI and Financial).

+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| ID | Data Asset                  | REGULATED        | PII              | FINANCIAL        | INTELLECTUAL     | OPERATIONAL      |
|    |                             | (HIPAA/PHI)      | (Personally      | (PCI-DSS,        | PROPERTY         | (Business        |
|    |                             |                  | Identifiable     | Accounting)      | (Trade Secrets,  | Continuity)      |
|    |                             |                  | Information)     |                  | Research)        |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 01 | Patient Records             | X                | X                |                  |                  |                  |
|    | (PostgreSQL ehr-db-01)      |                  |                  |                  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 02 | Diagnosis Codes             | X                |                  |                  |                  |                  |
|    | (ICD-10, embedded in EHR)   |                  |                  |                  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 03 | Patient SSN / Insurance ID  | X                | X                | X                |                  |                  |
|    | (EHR sensitive fields)      |                  |                  |                  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 04 | Medical Images (DICOM)      | X                | X                |                  |                  |                  |
|    | (PACS pacs-srv-01)          |                  | (PHI in headers) |                  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 05 | Billing Records             | X                | X                | X                |                  |                  |
|    | (MySQL billing-srv-01)      | (linked to PHI)  | (SSN, DOB)       | (CC, insurance)  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 06 | Patient Appointment Data    | X                | X                |                  |                  | X                |
|    | (in transit via portal)     |                  |                  |                  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 07 | Backup Data (NAS-01)        | X                | X                | X                |                  | X                |
|    |                             | (copies of all)  | (copies of all)  | (copies of all)  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 08 | Email (O365)                | X                | X                | X                |                  | X                |
|    |                             | (PHI in emails)  | (patient info)   | (billing comms)  |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 09 | Employee Records (HR)       |                  | X                | X                |                  | X                |
|    |                             |                  | (SSN, DOB, addr) | (salary, bank)   |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 10 | Active Directory Credentials|                  |                  |                  |                  | X                |
|    | (Kerberos, NTLM hashes)     |                  |                  |                  |                  | (Critical infra) |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 11 | Encryption Keys             | X                |                  |                  |                  | X                |
|    | (KMS, LUKS keys, TLS keys)  | (protect PHI)    |                  |                  |                  | (Critical infra) |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 12 | Security Audit Logs         | X                | X                |                  |                  | X                |
|    | (SIEM, access logs)         | (may contain PHI)| (user activity)  |                  |                  | (IR required)    |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 13 | Vendor Contracts            |                  |                  | X                |                  | X                |
|    | (legal agreements)          |                  |                  | (pricing, terms) |                  | (procurement)    |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 14 | Clinical Research Data      | X                | X                |                  | X                |                  |
|    | (anonymized trials)         | (derived from PHI)|                 |                  | (proprietary)    |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 15 | Hospital Cafeteria Menu     |                  |                  |                  |                  | X                |
|    | (public website)            |                  |                  |                  |                  | (non-sensitive)  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 16 | Facility Floor Plans        |                  |                  |                  |                  | X                |
|    |                             |                  |                  |                  |                  | (internal use)   |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+
| 17 | Board Meeting Minutes       |                  |                  | X                |                  | X                |
|    |                             |                  |                  | (budget, ALE)    |                  |                  |
+----+-----------------------------+------------------+------------------+------------------+------------------+------------------+


================================================================================
PART 2: CLASSIFICATION LEVELS
================================================================================

+------------------+------------------+------------------+------------------+------------------+
| Attribute        | PUBLIC           | INTERNAL         | CONFIDENTIAL     | RESTRICTED       |
+------------------+------------------+------------------+------------------+------------------+
| DEFINITION       | Information      | Information      | Information      | Information      |
|                  | intended for     | intended for     | intended for     | whose            |
|                  | public           | use within       | limited internal | unauthorized     |
|                  | dissemination.   | MedDefense.      | distribution.    | disclosure       |
|                  | No harm if       | Disclosure may   | Disclosure could | could cause      |
|                  | disclosed.       | cause minor      | cause significant| SEVERE harm:     |
|                  |                  | embarrassment or | financial, legal,| patient harm,    |
|                  |                  | operational      | or reputational  | regulatory       |
|                  |                  | inconvenience.   | harm.            | penalties,       |
|                  |                  |                  |                  | litigation,      |
|                  |                  |                  |                  | or loss of life. |
+------------------+------------------+------------------+------------------+------------------+
| EXAMPLES         | - Hospital       | - Staff directory| - Financial      | - Patient records|
|                  |   address, phone | - Internal       |   reports,       |   (PHI)          |
|                  | - Visiting hours |   policies       |   budgets        | - Diagnosis codes|
|                  | - Cafeteria menu | - Meeting        | - Vendor         | - SSN / Insurance|
|                  | - Public website |   schedules      |   contracts      |   IDs            |
|                  |   content        | - Training       | - Board meeting  | - Medical images |
|                  | - Services list  |   materials      |   minutes        |   (DICOM)        |
|                  | - Physician bios | - IT runbooks    | - Employee       | - Credentials    |
|                  |                  | - Floor plans    |   records (HR)   |   (passwords,    |
|                  |                  | - Non-sensitive  | - Security audit |   Kerberos keys) |
|                  |                  |   emails         |   logs           | - Encryption keys|
|                  |                  |                  | - Clinical       | - Billing records|
|                  |                  |                  |   research data  |   (CC, SSN)      |
|                  |                  |                  |                  | - Auth tokens    |
+------------------+------------------+------------------+------------------+------------------+
| WHO CAN ACCESS   | ANYONE           | All MedDefense   | Authorized       | Authorized       |
|                  | (no auth)        | employees,       | personnel with   | personnel with   |
|                  |                  | contractors      | business need    | specific access  |
|                  |                  | under NDA        | ONLY. Access     | granted via      |
|                  |                  |                  | logged and       | formal approval. |
|                  |                  |                  | audited.         | Access logged,   |
|                  |                  |                  |                  | audited, and     |
|                  |                  |                  |                  | reviewed monthly.|
+------------------+------------------+------------------+------------------+------------------+
| ENCRYPTION       | NONE             | TLS 1.2+ in      | AT REST:         | AT REST:         |
| AT REST          | No encryption    | transit only.    | AES-256 (GCM or  | AES-256-GCM      |
|                  | required.        | AT REST:         | XTS). Volume or  | with HSM-backed  |
|                  |                  | Optional. Can    | database         | key management.  |
|                  |                  | use volume       | encryption.      | Database TDE +   |
|                  |                  | encryption if    |                  | field-level for  |
|                  |                  | storage is       |                  | sensitive fields.|
|                  |                  | shared.          |                  | LUKS for backups.|
+------------------+------------------+------------------+------------------+------------------+
| ENCRYPTION       | NONE             | TLS 1.2 minimum.| TLS 1.3 with     | TLS 1.3 with     |
| IN TRANSIT       |                  | Standard HTTPS.  | AES-256-GCM or   | AES-256-GCM or   |
|                  |                  | Internal network | ChaCha20-Poly1305| ChaCha20-Poly1305|
|                  |                  | can use internal | cipher suites.   | HSTS enforced.   |
|                  |                  | CA certs.       | Mutual TLS where | Mutual TLS +     |
|                  |                  |                  | feasible (DICOM, | client certs.    |
|                  |                  |                  | DB connections). | No downgrade.    |
+------------------+------------------+------------------+------------------+------------------+
| KEY MANAGEMENT   | NONE             | Standard key     | Keys managed in  | HSM-backed KMS   |
|                  |                  | management.      | centralized KMS. | for master keys. |
|                  |                  | Keys may be      | Access logged.   | Envelope         |
|                  |                  | stored with      | Rotation:        | encryption.      |
|                  |                  | service config.  | annually.        | Rotation: 90-day |
|                  |                  |                  |                  | or immediate.    |
+------------------+------------------+------------------+------------------+------------------+
| CONSEQUENCE OF   | No impact.       | Minor            | SIGNIFICANT      | SEVERE /         |
| EXPOSURE         | Public            | operational      | IMPACT:          | CATASTROPHIC:    |
|                  | information by   | inconvenience.   | - Financial loss |- Patient harm or|
|                  | definition.      | Embarrassment    |   ($100K-$1M)    |   safety risk.   |
|                  |                  | at worst.        | - Reputational   | - HIPAA fines    |
|                  |                  |                  |   damage         |   ($50K-$1.5M/yr|
|                  |                  |                  | - Contractual    |   per category). |
|                  |                  |                  |   penalties      | - OCR mandatory  |
|                  |                  |                  | - Competitor     |   investigation. |
|                  |                  |                  |   advantage      | - Class-action   |
|                  |                  |                  |                  |   lawsuits.      |
|                  |                  |                  |                  | - Loss of        |
|                  |                  |                  |                  |   accreditation. |
|                  |                  |                  |                  |   ($24.95M total |
|                  |                  |                  |                  |   per 1x03 ALE). |
+------------------+------------------+------------------+------------------+------------------+
| DATA TYPES       | OPERATIONAL      | OPERATIONAL      | PII, FINANCIAL,  | REGULATED (PHI), |
| MAPPED           | (non-sensitive)  | (internal only)  | INTELLECTUAL     | PII (SSN),       |
|                  |                  |                  | PROPERTY, LEGAL  | FINANCIAL (CC),  |
|                  |                  |                  |                  | LEGAL (ePHI)     |
+------------------+------------------+------------------+------------------+------------------+
| MEDDEFENSE       | - Cafeteria menu | - Staff directory| - Billing records| - Patient records|
| DATA ASSETS      | - Public website | - Floor plans    |   (partial)      |   (full EHR)     |
| (from Part 1)    | - Visiting hours | - Meeting scheds | - Vendor contracts| - Diagnosis codes|
|                  | - Physician bios | - IT runbooks    | - Employee HR    | - Medical images |
|                  |                  | - Training docs  | - Board minutes  | - SSN/Insurance  |
|                  |                  |                  | - Research data  | - Credentials    |
|                  |                  |                  | - Audit logs     | - Encryption keys|
|                  |                  |                  |                  | - Backups        |
+------------------+------------------+------------------+------------------+------------------+


================================================================================
PART 3: CLASSIFICATION DECISION TREE
================================================================================

MedDefense employees follow this decision tree when they encounter a new type
of data or are unsure about the classification of existing data. If multiple
paths apply, the HIGHEST classification level wins.

    START
      │
      ▼
    ┌─────────────────────────────────────────────────┐
    │ Q1: Does this data contain patient health       │
    │     information (PHI/ePHI) as defined by HIPAA? │
    │     (Name + diagnosis, treatment, payment,      │
    │      medical record number, dates of service,   │
    │      images with embedded PHI, etc.)            │
    └─────────────────────────────────────────────────┘
      │                         │
      ▼ YES                     ▼ NO
    ┌──────────────┐          ┌─────────────────────────────────────────────────┐
    │ RESTRICTED   │          │ Q2: Does this data contain personally           │
    │              │          │     identifiable information (PII) that         │
    │ Apply all    │          │     could be used for identity theft?           │
    │ Restricted   │          │     (Full SSN, driver's license, passport,      │
    │ controls     │          │      bank account + routing number,             │
    │ immediately. │          │      date of birth + full name + address)       │
    └──────────────┘          └─────────────────────────────────────────────────┘
                                │                         │
                                ▼ YES                     ▼ NO
                              ┌──────────────────────────┐ ┌─────────────────────────────────────────────────┐
                              │ RESTRICTED or            │ │ Q3: Does this data contain financial            │
                              │ CONFIDENTIAL             │ │     information that could cause monetary       │
                              │ (depending on severity)  │ │     loss if exposed?                            │
                              │                          │ │     (Credit card numbers, bank account numbers, │
                              │ SSN + health data →      │ │      financial reports, budgets, salary info,   │
                              │ RESTRICTED               │ │      vendor pricing, ALE calculations)           │
                              │                          │ └─────────────────────────────────────────────────┘
                              │ Employee HR without      │   │                         │
                              │ health data →            │   ▼ YES                     ▼ NO
                              │ CONFIDENTIAL             │ ┌──────────────────────────┐ ┌─────────────────────────────────────────────────┐
                              └──────────────────────────┘ │ CONFIDENTIAL             │ │ Q4: Is this data proprietary to MedDefense,     │
                                                           │                          │ │     would its disclosure benefit a competitor   │
                                                           │ Apply Confidential       │ │     or harm our business?                      │
                                                           │ controls.                │ │     (Clinical research data, proprietary        │
                                                           └──────────────────────────┘ │      treatment protocols, internal algorithms,   │
                                                                                        │      strategic plans)                           │
                                                                                        └─────────────────────────────────────────────────┘
                                                                                          │                         │
                                                                                          ▼ YES                     ▼ NO
                                                                                        ┌──────────────────────────┐ ┌─────────────────────────────────────────────────┐
                                                                                        │ CONFIDENTIAL             │ │ Q5: Is this data intended for internal         │
                                                                                        │                          │ │     MedDefense use only and not for public      │
                                                                                        │ Apply Confidential       │ │     distribution?                              │
                                                                                        │ controls.                │ │     (Staff directory, policies, training       │
                                                                                        └──────────────────────────┘ │      materials, floor plans, IT documentation,  │
                                                                                                                    │      meeting schedules, non-sensitive emails)    │
                                                                                                                    └─────────────────────────────────────────────────┘
                                                                                                                      │                         │
                                                                                                                      ▼ YES                     ▼ NO
                                                                                                                    ┌──────────────────────────┐ ┌──────────────┐
                                                                                                                    │ INTERNAL                 │ │ PUBLIC       │
                                                                                                                    │                          │ │              │
                                                                                                                    │ Apply Internal           │ │ No special   │
                                                                                                                    │ controls.                │ │ protection   │
                                                                                                                    │ TLS in transit.          │ │ required.    │
                                                                                                                    └──────────────────────────┘ └──────────────┘

    DECISION TREE RULES:
    1. If data matches multiple questions, the HIGHEST classification wins.
    2. When in doubt, classify ONE LEVEL HIGHER than your best guess and
       consult the Security Team for a formal determination.
    3. Combining non-sensitive data can create sensitive data. Example:
       patient name (PII) + medical procedure (PHI) = RESTRICTED.
    4. If the data is a copy, backup, export, or report derived from
       RESTRICTED data, it REMAINS RESTRICTED. Classification follows
       the data, not the format.
    5. Encryption keys and credentials are ALWAYS RESTRICTED, regardless
       of the data they protect. Key compromise = all data compromise.


================================================================================
PART 4: DATA SOVEREIGNTY AND GEOLOCATION
================================================================================

THE QUESTION:
MedDefense is considering migrating backups to AWS cloud storage (from the
1x03 roadmap). If the AWS region is in a different state or country, what
HIPAA implications arise? Does encryption mitigate the sovereignty concern?

THE ANSWER:

Data sovereignty matters for healthcare because the legal jurisdiction
governing the physical location of the data determines which laws apply
to data access, breach notification, and government data requests. When
MedDefense stores patient data in an AWS region located in a different
U.S. state, that state's data breach notification laws apply in addition
to federal HIPAA — and if the region is in a foreign country (e.g., AWS
eu-west-1 in Ireland), the data becomes subject to that country's
privacy laws (such as GDPR), which may impose stricter consent,
processing, and cross-border transfer requirements than HIPAA alone.
This creates a multi-jurisdictional compliance burden that MedDefense's
legal team must evaluate before migration.

HIPAA does not prohibit offshore storage of ePHI, but it imposes two
critical obligations: (1) MedDefense must execute a Business Associate
Agreement (BAA) with AWS that explicitly covers the specific region and
service, and (2) MedDefense remains fully liable for any breach regardless
of the data's physical location. The BAA must address the foreign
jurisdiction's data protection laws and government access provisions
(e.g., the U.S. CLOUD Act, which permits U.S. law enforcement to compel
production of data stored overseas by U.S.-based companies).

Encryption partially mitigates sovereignty risk but does NOT eliminate it.
If MedDefense encrypts backups with AES-256-GCM and holds the keys in a
U.S.-based HSM (never exporting them to the AWS region), the cloud provider
cannot access the plaintext data. However, encryption does not resolve
all sovereignty concerns: (a) legal obligations to disclose encrypted data
may still apply (a court can compel MedDefense to decrypt), (b) metadata
(file names, timestamps, size) is often unencrypted and can reveal PHI
patterns, (c) the physical location of ciphertext may still trigger
jurisdictional data protection obligations regardless of whether the
provider can read it. Encryption is a necessary technical control but
is not a substitute for legal due diligence on the chosen AWS region's
sovereignty implications.


================================================================================
PART 5: ENCRYPTION REQUIREMENTS BY CLASSIFICATION
================================================================================

+------------------+------------------+------------------+------------------+------------------+
| ENCRYPTION       | PUBLIC           | INTERNAL         | CONFIDENTIAL     | RESTRICTED       |
| REQUIREMENT      |                  |                  |                  |                  |
+------------------+------------------+------------------+------------------+------------------+
| AT REST LEVEL    | None             | File or Volume   | Volume or        | Database TDE +   |
| (from T13)       |                  | (if shared)      | Database TDE     | Field-Level      |
+------------------+------------------+------------------+------------------+------------------+
| ALGORITHM        | N/A              | AES-256-XTS or   | AES-256-GCM      | AES-256-GCM      |
|                  |                  | AES-256-GCM      |                  |                  |
+------------------+------------------+------------------+------------------+------------------+
| IN TRANSIT       | None required    | TLS 1.2 minimum  | TLS 1.3 with     | TLS 1.3 with     |
|                  | (optional TLS)   |                  | forward secrecy  | mutual TLS       |
+------------------+------------------+------------------+------------------+------------------+
| KEY MANAGEMENT   | N/A              | KMS (software)   | KMS + audit      | HSM-backed KMS   |
| (from T14)       |                  |                  | logging          | (never in RAM)   |
+------------------+------------------+------------------+------------------+------------------+
| KEY ROTATION     | N/A              | Annually or      | Annually         | 90 days to       |
|                  |                  | on compromise    |                  | Annually         |
+------------------+------------------+------------------+------------------+------------------+
| ACCESS LOGGING   | None             | Optional         | Required         | Required +       |
|                  |                  |                  |                  | Monthly Review   |
+------------------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- HIPAA Security Rule (45 CFR § 164.312): Technical Safeguards
- HIPAA Privacy Rule (45 CFR § 164.514): De-identification of PHI
- NIST SP 800-60 Vol 1: Guide for Mapping Types of Information to Security Categories
- NIST SP 800-88: Guidelines for Media Sanitization
- T13 Encryption Levels Recommendation
- T14 Key Management Plan
- T15 Crypto Posture Audit
- 1x03 Risk Register & Data Protection Roadmap
- AWS HIPAA Compliance Whitepaper
- CLOUD Act (18 U.S.C. § 2523)


================================================================================
END OF DATA CLASSIFICATION MATRIX
================================================================================
