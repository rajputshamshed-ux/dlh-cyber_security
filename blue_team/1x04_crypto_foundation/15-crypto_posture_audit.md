================================================================================
                    CRYPTO POSTURE AUDIT - MEDDEFENSE HEALTH SYSTEMS
                    Task 15: The Crypto Posture Audit
================================================================================

Exercise: Task 15 - The Crypto Posture Audit
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Produce a systematic, evidence-based assessment of MedDefense's
          entire cryptographic posture. Every "Weak" or "Absent" finding from
          the T0 Data Protection Map is expanded into a full Crypto Finding
          with a clear remediation path.

Sources: T0 Data Protection Map, 1x02 Vulnerability Findings, 1x03 Risk Register
         & ALE, T6 Algorithm Analysis, T10 TLS Configuration, T11 PKI Audit,
         T12 LUKS Implementation, T13 Encryption Levels, T14 Key Management Plan


================================================================================
PART 1: CRYPTO FINDINGS - WEAK OR ABSENT CONTROLS
================================================================================

----------------------------------------------------------------------
FINDING CRYPTO-001
----------------------------------------------------------------------

Finding ID:          CRYPTO-001
Data Category:       PATIENT RECORDS (PHI) - PostgreSQL Database (ehr-db-01)
Data State:          At Rest
Current Protection:  NONE. The PostgreSQL database stores 50,000 patient records
                     in plaintext on disk. No TDE, no filesystem encryption,
                     no column-level encryption.
Vulnerability       1x02-F004: PostgreSQL Database - No Encryption at Rest
Reference:
Risk Reference:      1x03-R-004: Unauthorized Patient Database Access
                     ALE: $2,495,000/year
Algorithm            N/A. No algorithm in use. The requirement is AES-256-GCM
Assessment:          for symmetric encryption of data at rest, as per T6
                     algorithm analysis. AES-256-GCM provides both
                     confidentiality (encryption) and authenticity (integrity)
                     in a single, high-performance mode.
Recommended          AES-256-GCM for tablespace-level Transparent Data
Protection:          Encryption (TDE). PostgreSQL supports this via
                     pg_tde extension or filesystem-level encryption.
                     Key length: 256 bits. Mode: GCM (authenticated encryption).
Encryption Level:    DATABASE ENCRYPTION (TDE) - as per T13 recommendation
Key Management:      Master Key stored in AWS KMS with HSM backing, as per
                     T14 Key Management Plan. DEKs are generated per
                     tablespace, encrypted by the master key, and stored
                     in the database header (envelope encryption).
Implementation       IMMEDIATE. This is the highest-risk finding in the
Priority:            organization. A breach of this database would be
                     catastrophic (50,000 records * $499/record = $24.95M).
                     Encryption must be deployed before any other Phase 1
                     activity.


----------------------------------------------------------------------
FINDING CRYPTO-002
----------------------------------------------------------------------

Finding ID:          CRYPTO-002
Data Category:       PATIENT RECORDS (PHI) - Patient Portal TLS (patient-portal-srv-01)
Data State:          In Transit
Current Protection:  TLS 1.0. This protocol has been broken since 2011
                     (BEAST attack, 2011; POODLE attack, 2014). It uses
                     obsolete cipher suites (RC4, 3DES) and does not support
                     modern authenticated encryption. Certificate expires
                     in 18 days.
Vulnerability        1x02-F001: Patient Portal Running TLS 1.0
Reference:           1x02-F005: TLS Certificate Expiring
Risk Reference:      1x03-R-007: Patient Portal Data Breach
                     ALE: $875,000/year
Algorithm            FAIL. TLS 1.0 uses deprecated algorithms:
Assessment:          - Cipher: RC4-MD5, TLS_RSA_WITH_3DES_EDE_CBC_SHA
                     - Key Exchange: RSA (no forward secrecy)
                     - Hash: SHA-1 (collision attacks practical)
                     Modern standard is TLS 1.3 with ECDHE key exchange
                     and AES-256-GCM or ChaCha20-Poly1305.
Recommended          TLS 1.3 with the following cipher suites:
Protection:          - TLS_AES_256_GCM_SHA384 (primary)
                     - TLS_CHACHA20_POLY1305_SHA256 (fallback for mobile)
                     Certificate: 256-bit ECDSA, issued by Let's Encrypt
                     with automated 90-day renewal. HSTS enabled.
Encryption Level:    SESSION/TRANSPORT ENCRYPTION (TLS)
Key Management:      Private key stored with OS-level protection (chmod 400),
                     automated renewal via certbot. As per T14 Plan.
Implementation       IMMEDIATE. Certificate expires in 18 days. Downtime
Priority:            of patient portal disrupts care for 800+ patients/day.
                     TLS 1.0 is trivially downgradeable and sniffable on
                     any network path.


----------------------------------------------------------------------
FINDING CRYPTO-003
----------------------------------------------------------------------

Finding ID:          CRYPTO-003
Data Category:       BACKUP DATA (PHI) - NAS-01
Data State:          At Rest
Current Protection:  NONE. Backup data is stored in plaintext on a NAS
                     device on the same flat network as every other device,
                     including the compromised print server.
Vulnerability        1x02-F003: Backup Data Stored Unencrypted on NAS
Reference:
Risk Reference:      1x03-R-010: Backup Data Exfiltration
                     ALE: $420,000/year
Algorithm            N/A. No encryption in use. The recommendation is
Assessment:          AES-256-XTS for LUKS volume encryption, as XTS is
                     the standard mode for full-volume encryption (no
                     authentication tag overhead per sector).
Recommended          LUKS2 volume encryption with AES-256-XTS.
Protection:          Key length: 256 bits. Mode: XTS (standard for disk).
                     LUKS header stored on the volume with PBKDF2
                     key derivation (iterations: >1,000,000).
Encryption Level:    VOLUME ENCRYPTION (LUKS) - as per T13 recommendation
Key Management:      LUKS key wrapped by TPM on NAS-01 or unlocked via
                     Tang/Clevis network-based key management. Recovery
                     key escrowed in physical safe (dual control). As per
                     T14 Plan.
Implementation       IMMEDIATE. Backup data contains a complete copy of
Priority:            the patient database. If NAS-01 is compromised via
                     the flat network, all historical patient data is
                     exfiltrated in plaintext.


----------------------------------------------------------------------
FINDING CRYPTO-004
----------------------------------------------------------------------

Finding ID:          CRYPTO-004
Data Category:       MEDICAL IMAGES (DICOM) - PACS Server (pacs-srv-01)
Data State:          In Transit (between MRI workstation and PACS server)
Current Protection:  NONE. DICOM traffic flows unencrypted via TCP port 104
                     or 11112. No TLS wrapping, no DICOM TLS profile,
                     no VPN encapsulation.
Vulnerability        1x02-F002: DICOM Traffic Unencrypted
Reference:
Risk Reference:      1x03-R-012: Unauthorized Interception of Medical Images
                     ALE: $175,000/year
Algorithm            N/A. DICOM standard supports DICOM TLS Secure
Assessment:          Transport Connection Profile. The recommended
                     algorithm is TLS 1.2 or 1.3 with mutual authentication
                     (both client and server certificates).
Recommended          Enable DICOM TLS per NEMA PS3.15. Require:
Protection:          - TLS 1.2 minimum (TLS 1.3 preferred)
                     - Cipher: AES-256-GCM
                     - Mutual TLS (client certificate for MRI workstation)
                     - Certificate issued by internal MedDefense CA
Encryption Level:    SESSION/TRANSPORT ENCRYPTION (TLS)
Key Management:      Server certificate on PACS, client certificate on
                     MRI workstation. Internal CA managed by Security Team.
                     Certificate rotation: annually. As per T14 Plan.
Implementation       PHASE 1. Medical images contain embedded PHI in
Priority:            DICOM headers. Interception on the internal network
                     is a realistic threat given the flat network design
                     and compromised endpoints.


----------------------------------------------------------------------
FINDING CRYPTO-005
----------------------------------------------------------------------

Finding ID:          CRYPTO-005
Data Category:       AUTHENTICATION - Kerberos Authentication
Data State:          In Transit (authentication protocol)
Current Protection:  Kerberos with DES encryption type (etype des-cbc-crc).
                     DES has been broken since 1999 (EFF DES Cracker: <24h).
                     Brute-forceable in minutes today.
Vulnerability        1x02-F007: Kerberos Accepts DES Encryption
Reference:
Risk Reference:      1x03-R-003: Authentication Protocol Downgrade
                     ALE: $615,000/year
Algorithm            FAIL. DES key length: 56 bits (effectively 2^56).
Assessment:          Modern standard is AES-256 for Kerberos. Microsoft
                     AD supports AES256-CTS-HMAC-SHA1-96 and AES128-CTS-
                     HMAC-SHA1-96 since Windows Server 2008.
Recommended          Enforce Kerberos AES-256 encryption types ONLY.
Protection:          - Disable RC4-HMAC, DES-CBC-CRC, DES-CBC-MD5
                     - Enable only: AES256-CTS-HMAC-SHA1-96
                     - Apply via Group Policy: Network security: Configure
                       encryption types allowed for Kerberos
Encryption Level:    PROTOCOL ENCRYPTION (Authentication)
Key Management:      Kerberos keys are derived from user/service passwords.
                     Enforce password complexity policy (15+ characters)
                     to protect against offline Kerberos AS-REP roasting.
Implementation       IMMEDIATE. An attacker with network access can request
Priority:            a Kerberos ticket encrypted with DES, capture it, and
                     crack the service account password in minutes. This
                     leads to full domain compromise.


----------------------------------------------------------------------
FINDING CRYPTO-006
----------------------------------------------------------------------

Finding ID:          CRYPTO-006
Data Category:       FINANCIAL RECORDS - MySQL Database (billing-srv-01)
Data State:          At Rest
Current Protection:  NONE. Billing database containing SSNs, credit card
                     information, and insurance IDs is stored in plaintext.
Vulnerability        1x02-F008: MySQL Database - No Encryption at Rest
Reference:
Risk Reference:      1x03-R-013: Financial Data Breach
                     ALE: $340,000/year
Algorithm            N/A. Recommended: AES-256-GCM for MySQL TDE or
Assessment:          tablespace encryption. MySQL 8.0 supports InnoDB
                     tablespace encryption with AES-256.
Recommended          MySQL InnoDB Tablespace Encryption with AES-256-GCM.
Protection:          Keyring plugin (keyring_file or keyring_aws_kms)
                     for master key storage.
Encryption Level:    DATABASE ENCRYPTION (TDE) - as per T13 recommendation
Key Management:      MySQL Keyring connected to AWS KMS or stored with
                     restrictive filesystem permissions (chmod 600).
                     Rotation: annually. As per T14 Plan.
Implementation       PHASE 1. SSN and credit card data are subject to PCI
Priority:            DSS and state breach notification laws.


----------------------------------------------------------------------
FINDING CRYPTO-007
----------------------------------------------------------------------

Finding ID:          CRYPTO-007
Data Category:       VPN TUNNELS - Inter-Site Communication
Data State:          In Transit
Current Protection:  IPsec VPN exists but uses weak cipher suites
                     (3DES for encryption, SHA-1 for integrity, DH Group 2
                     for key exchange). DH Group 2 (1024-bit) is breakable
                     by nation-state actors.
Vulnerability        1x02-F012: VPN Uses Weak Cipher Suites
Reference:
Risk Reference:      1x03-R-009: Inter-Site Network Sniffing
                     ALE: $280,000/year
Algorithm            WEAK. 3DES provides only 112 bits of effective
Assessment:          security and is slow. SHA-1 is collision-broken.
                     DH Group 2 (1024-bit) is below the 2048-bit minimum.
Recommended          IPsec IKEv2 with:
Protection:          - Encryption: AES-256-GCM
                     - Integrity: SHA-384
                     - DH Group: 14 (2048-bit) or 19 (ECP-256)
                     - Pseudo-Random Function: PRF-HMAC-SHA-384
Encryption Level:    TUNNEL ENCRYPTION (VPN)
Key Management:      Pre-shared keys rotated every 6-12 months. Stored
                     on firewall appliances. Access: Network Security
                     Engineer via jump host with MFA. As per T14 Plan.
Implementation       PHASE 1. Inter-site traffic contains patient data,
Priority:            financial transactions, and Active Directory replication.
                     Weak VPN encryption exposes all of this over the WAN.


----------------------------------------------------------------------
FINDING CRYPTO-008
----------------------------------------------------------------------

Finding ID:          CRYPTO-008
Data Category:       EMAIL DATA (PHI) - Office 365
Data State:          In Transit
Current Protection:  TLS 1.2 opportunistic (STARTTLS) between mail servers.
                     No enforcement. Can downgrade to plaintext SMTP.
                     No end-to-end email encryption (S/MIME or OME) for
                     messages containing PHI sent to external recipients.
Vulnerability        1x02-F009: Email Encryption Not Enforced
Reference:
Risk Reference:      1x03-R-014: PHI Disclosure via Email
                     ALE: $120,000/year
Algorithm            OPPORTUNISTIC. Office 365 uses TLS 1.2 by default
Assessment:          but opportunistic encryption can silently downgrade
                     to plaintext. S/MIME uses AES-256-CBC or AES-256-GCM
                     for message encryption.
Recommended          Enforce TLS 1.2 minimum in Exchange Online connectors.
Protection:          Enable Office 365 Message Encryption (OME) for all
                     emails containing PHI. Deploy S/MIME certificates
                     for clinical staff communicating with external partners.
Encryption Level:    RECORD-LEVEL ENCRYPTION (S/MIME or OME) - per T13
Key Management:      S/MIME certificates issued by internal CA or trusted
                     third-party CA. Private keys stored on users' smart
                     cards or TPM-protected workstations. As per T14 Plan.
Implementation       PHASE 1. Medical staff email PHI daily. A single
Priority:            misdirected email causes a reportable breach.


----------------------------------------------------------------------
FINDING CRYPTO-009
----------------------------------------------------------------------

Finding ID:          CRYPTO-009
Data Category:       EMPLOYEE DEVICES - Laptops (50+ devices)
Data State:          At Rest
Current Protection:  NONE. Employee laptops have no full-disk encryption.
                     A lost or stolen laptop exposes all local data,
                     including cached patient data, VPN configurations,
                     and saved credentials.
Vulnerability        1x02-F014: Employee Laptops - No Disk Encryption
Reference:
Risk Reference:      1x03-R-015: Lost/Stolen Device Data Exposure
                     ALE: $95,000/year
Algorithm            N/A. Recommended: AES-256-XTS for BitLocker (Windows)
Assessment:          or LUKS2 (Linux). XTS is the standard mode for
                     full-disk encryption.
Recommended          Windows: BitLocker with AES-256-XTS. TPM + PIN for
Protection:          pre-boot authentication.
                     Linux: LUKS2 with AES-256-XTS. TPM binding or
                     passphrase with PBKDF2.
Encryption Level:    FULL-DISK ENCRYPTION - as per T13 recommendation
Key Management:      Recovery keys escrowed in Active Directory (BitLocker)
                     or a secure key escrow server. Access: IT Support
                     (break-glass, audited). As per T14 Plan.
Implementation       PHASE 1. 50+ laptops with clinical and administrative
Priority:            data leave the building daily. Theft is a statistical
                     certainty.


----------------------------------------------------------------------
FINDING CRYPTO-010
----------------------------------------------------------------------

Finding ID:          CRYPTO-010
Data Category:       EHR SENSITIVE FIELDS - SSN, Diagnosis Codes
Data State:          At Rest (within the database)
Current Protection:  NONE at field level. Even after TDE deployment
                     (CRYPTO-001), any user with database access can
                     SELECT and view SSNs and diagnosis codes in plaintext.
                     TDE protects against file theft, not database access.
Vulnerability        1x02-F015: No Field-Level Encryption for SSN/Diagnosis
Reference:
Risk Reference:      1x03-R-004: Unauthorized Patient Database Access
                     (same risk, additional layer of defense)
Algorithm            N/A. Recommended: AES-256-GCM for application-level
Assessment:          field encryption. The application encrypts the SSN
                     before writing to the database column.
Recommended          PostgreSQL pgcrypto extension or application-level
Protection:          encryption with AES-256-GCM. Encrypt SSN, diagnosis
                     codes, and insurance ID columns. Decryption requires
                     a separate key, not the database master key.
Encryption Level:    RECORD-LEVEL ENCRYPTION - as per T13 recommendation
Key Management:      Field encryption key stored in AWS KMS (separate from
                     TDE master key). Application service account has
                     decrypt permission. Database administrator role does
                     NOT have access. As per T14 Plan.
Implementation       PHASE 2. This is defense in depth. Even if the database
Priority:            is accessed via SQL injection or compromised credentials,
                     the most sensitive fields remain encrypted.


================================================================================
PART 2: POSTURE SCORE
================================================================================

POSTURE SCORE CALCULATION:

Total Data Flows in T0 Data Protection Map:  15
Data Flows with "Strong" Protection (baseline):  3 (T0 pre-assessment)
Data Flows with "Weak" or "Absent" Controls:    10 (above findings)
Data Flows with Defined Remediation Path:       10 (100% of findings)

CURRENT POSTURE SCORE: 3/15 = 20%
(Baseline strong controls as a percentage of total data flows)

AFTER PHASE 1 REMEDIATION: 11/15 = 73%
(IMMEDIATE + PHASE 1 findings remediated)

AFTER PHASE 2 REMEDIATION: 15/15 = 100%
(All findings remediated, including field-level encryption)

DEFINITION: The Posture Score represents the percentage of MedDefense's
data flows that have either adequate cryptographic protection today or a
fully defined, funded, and scheduled remediation path. MedDefense currently
has a 20% score but a 100% remediation coverage rate — every identified gap
has a specific, evidence-backed fix.


================================================================================
PART 3: TOP 3 CRYPTO RISKS
================================================================================

Ranked by Combined Impact (ALE * Vulnerability Exposure) and Remediation Urgency.

----------------------------------------------------------------------
RANK 1: PATIENT DATABASE AT REST - NO ENCRYPTION
----------------------------------------------------------------------

Finding ID:     CRYPTO-001
Risk ID:        1x03-R-004
ALE:            $2,495,000/year
Why #1:         This is MedDefense's crown jewel. 50,000 patient records
                in plaintext. No encryption at any level (disk, volume,
                file, database, or field). The ehr-db-01 server sits on a
                flat network with a compromised legacy print server
                (1x02-F006). A single vulnerability exploit or insider
                threat results in a catastrophic, practice-ending breach
                costing $24.95M. The ALE alone is 2.8x higher than the
                #2 risk. This finding represents existential risk to
                the organization.
Remediation:    IMMEDIATE. Deploy PostgreSQL TDE with AES-256-GCM + AWS KMS
                with HSM backing. T13 Level: Database Encryption. T14 Plan:
                Key 1. This is the first encryption turned on in Phase 1.


----------------------------------------------------------------------
RANK 2: PATIENT PORTAL TLS 1.0 + EXPIRING CERTIFICATE
----------------------------------------------------------------------

Finding ID:     CRYPTO-002
Risk ID:        1x03-R-007
ALE:            $875,000/year
Why #2:         TLS 1.0 is a 15-year-old broken protocol that can be
                decrypted in transit by anyone on the network path
                (BEAST, POODLE, CRIME). Combined with a certificate that
                expires in 18 days, this is a time-bomb. When the cert
                expires, 800+ patients/day lose portal access. The exposure
                of PHI in transit is constant and ongoing. The dual threat
                (protocol + expiration) makes this the second-highest
                priority.
Remediation:    IMMEDIATE (before certificate expiry). Deploy TLS 1.3 with
                Let's Encrypt certificate and automated renewal. T10 Config.
                T14 Plan: Key 3. Must be done within 18 days.


----------------------------------------------------------------------
RANK 3: KERBEROS ACCEPTING DES ENCRYPTION
----------------------------------------------------------------------

Finding ID:     CRYPTO-005
Risk ID:        1x03-R-003
ALE:            $615,000/year
Why #3:         DES is a 56-bit algorithm breakable in minutes. Kerberos
                with DES means an attacker can request a service ticket
                encrypted with DES, capture it offline, and crack the
                service account password. This leads to Kerberoasting
                attacks and full Active Directory domain compromise.
                From domain compromise, every other control (database,
                backups, VPN, email) becomes irrelevant. A single cracked
                service account snowballs into total infrastructure
                compromise. The ALE accounts for this blast radius.
Remediation:    IMMEDIATE. Enforce AES-256-only Kerberos encryption types
                via Group Policy. Disable RC4 and DES. Combined with
                service account password rotation (managed service
                accounts for all services).


================================================================================
SUMMARY
================================================================================

Total Crypto Findings:              10
IMMEDIATE Priority:                  4  (CRYPTO-001, 002, 003, 005)
PHASE 1 Priority:                    4  (CRYPTO-004, 006, 007, 008, 009)
PHASE 2 Priority:                    1  (CRYPTO-010)
Current Posture Score:               20% (3/15 data flows strong)
Post-Phase 1 Posture Score:          73% (11/15 data flows strong)
Total ALE Addressed:                 $5,415,000/year
Total Mitigation Cost (Annual):      ~$3,000/year (KMS, HSM, certificates)
Return on Security Investment:       1804x


================================================================================
REFERENCES
================================================================================

- T0 Data Protection Map
- 1x02 Vulnerability Assessment Findings
- 1x03 Risk Register & ALE Calculations
- T6 Algorithm Analysis
- T10 TLS Configuration & Certificate Inspection
- T11 PKI Audit
- T12 LUKS Implementation & Backup Encryption
- T13 Encryption Levels Recommendation
- T14 Key Management Plan
- NIST SP 800-175B: Cryptographic Standards
- NIST SP 800-111: Storage Encryption


================================================================================
END OF CRYPTO POSTURE AUDIT
================================================================================
