================================================================================
                    OBFUSCATION TOOLKIT - MEDDEFENSE HEALTH SYSTEMS
                    Task 7: The Obfuscation Toolkit
================================================================================

Exercise: Task 7 - The Obfuscation Toolkit
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Distinguish between encryption, hashing and obfuscation
          techniques, design a tokenization scheme for MedDefense, and
          evaluate steganography as both a protection tool and a threat
          vector.

Sources: meddefense-crypto-audit-notes.txt, 1x00 Data Map, 1x02 Findings


================================================================================
PART 1: TECHNIQUE COMPARISON
================================================================================

+------------------+------------------+------------------+------------------------------------------+
| Technique        | What it does     | Reversible?      | Healthcare Use Case                      |
+------------------+------------------+------------------+------------------------------------------+
| ENCRYPTION       | Transforms data  | YES - with the   | Encrypting EHR database at rest          |
|                  | using a key.     | correct key.     | (Patient records on ehr-db-01).          |
|                  | The original     |                  | Protects PHI from unauthorized access.   |
|                  | data becomes     |                  |                                          |
|                  | unreadable.      |                  |                                          |
+------------------+------------------+------------------+------------------------------------------+
| HASHING          | Creates a fixed- | NO - one-way.    | Storing passwords in Active Directory.   |
|                  | length string    | Original cannot  | When a user logs in, the entered         |
|                  | from data.       | be recovered.    | password is hashed and compared.         |
|                  | Same input =     |                  | The actual password is never stored.     |
|                  | same hash.       |                  |                                          |
+------------------+------------------+------------------+------------------------------------------+
| TOKENIZATION     | Replaces data    | YES - via a      | Processing credit card payments.         |
|                  | with a non-      | secure vault/    | The billing system stores tokens,        |
|                  | sensitive token. | mapping table.   | not actual card numbers.                 |
|                  |                  |                  | Reduces PCI compliance scope.            |
+------------------+------------------+------------------+------------------------------------------+
| DATA MASKING     | Hides parts of   | PARTIAL - only   | Displaying patient data in EHR.          |
|                  | data while       | the masked parts | Nurses see full name and diagnosis;      |
|                  | preserving       | are hidden.      | receptionists see only limited info.     |
|                  | format.          |                  | Protects PHI from unauthorized eyes.     |
+------------------+------------------+------------------+------------------------------------------+
| STEGANOGRAPHY    | Hides data       | YES - with the   | NOT RECOMMENDED FOR PROTECTION.          |
|                  | inside other     | right extraction | BUT: A threat vector where an insider    |
|                  | harmless data.   | method.          | hides patient data inside DICOM images.  |
|                  | (e.g., hidden    |                  | Detection is very difficult.             |
|                  | text in an       |                  |                                          |
|                  | image).          |                  |                                          |
+------------------+------------------+------------------+------------------------------------------+


================================================================================
PART 2: MEDDEFENSE TOKENIZATION DESIGN
================================================================================

WHAT DATA IS TOKENIZED
----------------------
+----------------------------------------------------------------------------+
| DATA TOKENIZED: Credit card numbers for patient billing.                   |
|                                                                             |
| Format:                                                                     |
| - Original: 4111-1111-1111-1111 (16 digits)                               |
| - Token:    TK-XXXXXXXXXX (10 character alphanumeric)                     |
|            Example: TK-7F3A9B2E1C                                        |
|                                                                             |
| Characteristics:                                                           |
| - The token has no mathematical relationship to the card number           |
| - The token is stored in the billing database instead of the card number  |
| - Only the billing system uses tokens for transactions                   |
| - Tokens are unique to each card number                                  |
+----------------------------------------------------------------------------+

WHERE IS THE VAULT STORED
-------------------------
+----------------------------------------------------------------------------+
| VAULT LOCATION: Separate secure server (not on the billing network).      |
|                                                                             |
| VAULT CONTENTS:                                                            |
| +------------------+------------------+----------------------------------+ |
| | Token            | Real Data        | Patient ID                      | |
| +------------------+------------------+----------------------------------+ |
| | TK-7F3A9B2E1C   | 4111-1111-1111-1111 | MED-50421                    | |
| | TK-2D8A1F4E7B   | 5555-5555-5555-4444 | MED-50422                    | |
| +------------------+------------------+----------------------------------+ |
|                                                                             |
| VAULT PROTECTION:                                                          |
| 1. ENCRYPTION: The vault database is encrypted with AES-256-GCM           |
| 2. ACCESS CONTROLS: Only the tokenization service can access the vault    |
| 3. NETWORK SEGREGATION: The vault server is on a separate VLAN with       |
|    strict firewall rules                                                  |
| 4. MFA: Administrative access to the vault requires MFA                   |
| 5. AUDIT LOGGING: All vault access is logged and monitored               |
| 6. BACKUP: Encrypted backups stored offsite                              |
+----------------------------------------------------------------------------+

WHAT HAPPENS IF THE VAULT IS COMPROMISED
----------------------------------------
+----------------------------------------------------------------------------+
| 1. ALL tokenized data becomes accessible                                 |
| 2. The attacker can map tokens back to real card numbers                  |
| 3. This is equivalent to a full data breach                              |
| 4. Impact: PCI breach notification, HIPAA breach notification, fines     |
|                                                                             |
| MITIGATION:                                                                |
| - Use a Hardware Security Module (HSM) for key storage                  |
| - Implement token rotation (tokens expire after 12 months)               |
| - Monitor vault access patterns for anomalies                            |
| - Have an incident response plan specifically for vault compromise       |
+----------------------------------------------------------------------------+

TOKENIZATION VS ENCRYPTION
--------------------------
+----------------------------------------------------------------------------+
| ADVANTAGES OF TOKENIZATION OVER ENCRYPTION:                                |
|                                                                             |
| 1. REDUCED PCI SCOPE: Tokens are NOT credit card data - PCI compliance    |
|    requirements are much lower for tokenized data.                       |
|                                                                             |
| 2. NO KEY MANAGEMENT: Tokens don't require encryption keys.               |
|                                                                             |
| 3. DATA FORMAT: Tokens can be format-preserving, making integration       |
|    with existing systems easier.                                          |
|                                                                             |
| 4. SEARCHABILITY: Tokens allow some search operations without             |
|    decrypting data.                                                       |
|                                                                             |
| DISADVANTAGES OF TOKENIZATION:                                             |
|                                                                             |
| 1. VAULT IS A SINGLE POINT OF FAILURE: If the vault is compromised,       |
|    ALL tokenized data is exposed.                                         |
|                                                                             |
| 2. LATENCY: Tokenization requires a lookup operation.                     |
|                                                                             |
| 3. COST: A secure vault with HSMs is expensive.                          |
|                                                                             |
| RECOMMENDATION: Use TOKENIZATION for credit card data and ENCRYPTION     |
| for all other PHI (EHR database, backups, etc.).                         |
+----------------------------------------------------------------------------+


================================================================================
PART 3: DATA MASKING EXAMPLES
================================================================================

+------------------+---------------------+---------------------+---------------------+
| Data Field       | Full Value          | Nurse (Clinical)    | Billing Clerk       | Reception           |
+------------------+---------------------+---------------------+---------------------+---------------------+
| SSN              | 987-65-4321         | XXX-XX-4321         | XXX-XX-4321         | XXX-XX-4321         |
+------------------+---------------------+---------------------+---------------------+---------------------+
| Patient Name     | Maria Gonzalez      | Maria Gonzalez      | M. Gonzalez         | Patient 50421       |
+------------------+---------------------+---------------------+---------------------+---------------------+
| Diagnosis        | Type 2 Diabetes    | Type 2 Diabetes     | [HIDDEN]            | [HIDDEN]            |
+------------------+---------------------+---------------------+---------------------+---------------------+

JUSTIFICATION
-------------
+------------------+--------------------------------------------------+
| Role             | Justification                                    |
+------------------+--------------------------------------------------+
| Nurse            | Needs FULL access to patient name and diagnosis |
| (Clinical)       | to provide safe, effective care. SSN is masked  |
|                  | because it is not needed for clinical care.     |
+------------------+--------------------------------------------------+
| Billing Clerk    | Needs patient name (last name + initial) and    |
|                  | masked SSN to process claims. Diagnosis is      |
|                  | hidden because it is not needed for billing.    |
+------------------+--------------------------------------------------+
| Reception        | Only needs patient identifier (MRN) to check    |
|                  | in patients. Name, SSN, and diagnosis are       |
|                  | hidden because they are not needed for          |
|                  | reception duties.                               |
+------------------+--------------------------------------------------+


================================================================================
PART 4: STEGANOGRAPHY AS THREAT VECTOR
================================================================================

+----------------------------------------------------------------------------+
| STEGANOGRAPHY AS A THREAT VECTOR FOR MEDDEFENSE                           |
|                                                                             |
| Steganography is a serious concern for MedDefense's data loss prevention   |
| program because DICOM medical images are large, routinely transferred,    |
| and appear perfectly legitimate. A malicious insider could embed           |
| exfiltrated patient data (SSNs, PHI, financial records) within the pixels |
| of a legitimate MRI or CT scan using steganography tools. The image       |
| would look identical to any other imaging file, and normal traffic        |
| between the MRI workstation and the PACS server would not raise           |
| suspicion. This is harder to detect than traditional data exfiltration   |
| because the data is hidden inside authorized file types, making DLP      |
| agents that scan for sensitive content ineffective. The Network          |
| Monitoring control from 1x03 (C-020) would help detect this by            |
| identifying unusual traffic patterns, such as large outbound transfers   |
| of DICOM files to external IPs that do not belong to known partners.     |
| Additionally, the SIEM (GAP-001) should be configured to alert on        |
| anomalous DICOM file transfers outside normal business hours.            |
+----------------------------------------------------------------------------+

HOW STEGANOGRAPHY WORKS IN DICOM FILES
--------------------------------------
+----------------------------------------------------------------------------+
| DICOM images are large (10-50 MB per study). The Least Significant Bit   |
| (LSB) method can hide data in the image pixels.                          |
|                                                                             |
| Original pixel value: 10011010 (154)                                     |
| Modified pixel value: 10011011 (155) - only 1 bit changed               |
|                                                                             |
| A human cannot see the difference. A DICOM viewer shows the same image.  |
| An attacker can hide 8 MB of text in a 50 MB DICOM image.               |
+----------------------------------------------------------------------------+

MITIGATION STRATEGIES FOR MEDDEFENSE
------------------------------------
+----------------------------------------------------------------------------+
| 1. NETWORK MONITORING (C-020 from 1x03): Alert on large outbound         |
|    DICOM transfers to unknown IPs.                                      |
|                                                                             |
| 2. SIEM (GAP-001): Log DICOM transfers and correlate with user          |
|    behavior (e.g., transfers at 2 AM from a radiologist who never works  |
|    night shifts).                                                         |
|                                                                             |
| 3. DATA LOSS PREVENTION (DLP): Deploy DLP that inspects DICOM headers   |
|    and looks for embedded PHI.                                           |
|                                                                             |
| 4. USER TRAINING (GAP-013): Educate staff on steganography risks.       |
|                                                                             |
| 5. ACCESS CONTROLS: Restrict who can export DICOM files.                |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- 1x00 Data Map (Task 9)
- 1x03 Strategy: GAP-001, GAP-013, C-020
- PCI DSS: Tokenization requirements
- HIPAA: Data masking requirements


================================================================================
END OF OBFUSCATION TOOLKIT REPORT
================================================================================
