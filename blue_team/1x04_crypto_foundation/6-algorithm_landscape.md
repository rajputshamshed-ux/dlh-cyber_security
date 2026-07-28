================================================================================
                    ALGORITHM LANDSCAPE - MEDDEFENSE HEALTH SYSTEMS
                    Task 6: The Algorithm Landscape
================================================================================

Exercise: Task 6 - The Algorithm Landscape
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Build the definitive reference table of cryptographic algorithms,
          mapped against MedDefense's current and recommended usage,
          identifying every deprecated algorithm still in production.

Sources: meddefense-crypto-audit-notes.txt, 1x02 Findings, NIST SP 800-175B


================================================================================
1. ALGORITHM REFERENCE TABLE
================================================================================

SYMMETRIC ALGORITHMS
--------------------
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Algorithm        | Type     | Key Size (bits) | Primary Use Case          | Status  | Why Deprecated/Broken    | MedDefense Usage                         |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| AES-128          | Symmetric| 128              | General encryption        | Current | N/A                       | ✅ Recommended for backups, non-critical |
|                  |          |                  |                           |         |                           | data                                      |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| AES-192          | Symmetric| 192              | General encryption        | Current | N/A                       | ✅ Recommended (less common)             |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| AES-256          | Symmetric| 256              | High-security encryption | Current | N/A                       | ✅ RECOMMENDED for EHR, PHI, patient     |
|                  |          |                  |                           |         |                           | data, backups                            |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| ChaCha20-Poly1305| Symmetric| 256              | Mobile/low-power devices  | Current | N/A                       | ✅ Recommended for IoT devices, mobile   |
|                  | (AEAD)   |                  |                           |         |                           | (BD Alaris pumps, Philips monitors)      |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| DES              | Symmetric| 56               | Legacy encryption         | BROKEN  | 56-bit key brute-forced   | ❌ NOT IN USE - Should not be used       |
|                  |          |                  |                           |         | since 1999               |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| 3DES             | Symmetric| 112 (effective)  | Legacy encryption         | DEPRE-  | 3DES is weak, NIST        | ❌ NOT IN USE - Should be replaced with  |
|                  |          |                  |                           | CATED   | deprecated it in 2023    | AES                                       |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| RC4              | Symmetric| 40-2048          | Stream cipher             | BROKEN  | Biases in keystream       | ❌ Finding 018: RC4 enabled in AD       |
|                  | (Stream) |                  |                           |         | allow recovery            | (Kerberos) - MUST DISABLE                |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Blowfish         | Symmetric| 32-448           | Legacy encryption         | DEPRE-  | 64-bit block size         | ❌ NOT IN USE - Should not be used       |
|                  |          |                  |                           | CATED   | vulnerable to birthday    |                                          |
|                  |          |                  |                           |         | attacks                   |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+

ASYMMETRIC ALGORITHMS
---------------------
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Algorithm        | Type     | Key Size (bits) | Primary Use Case          | Status  | Why Deprecated/Broken    | MedDefense Usage                         |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| RSA-2048         | Asymmetr.| 2048             | Key exchange, signatures  | Current | N/A                       | ✅ TLS key exchange, VPN, digital        |
|                  |          |                  |                           |         |                           | signatures                               |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| RSA-4096         | Asymmetr.| 4096             | High-security key exchange| Current | N/A                       | ✅ CA certificates, long-term keys      |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| ECC P-256        | Asymmetr.| 256              | Key exchange, signatures  | Current | N/A                       | ✅ RECOMMENDED for IoT devices, mobile,  |
|                  |          |                  |                           |         |                           | constrained environments                 |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| ECC P-384        | Asymmetr.| 384              | High-security key exchange| Current | N/A                       | ✅ Recommended for long-term security    |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Diffie-Hellman   | Asymmetr.| Variable (2048+) | Key exchange              | Current | N/A (with proper params)  | ✅ VPN key exchange (with certificates)  |
| (DH)             |          |                  |                           |         |                           |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| ECDHE            | Asymmetr.| Variable (P-256) | Key exchange (Perfect     | Current | N/A                       | ✅ TLS 1.3, recommended for patient      |
| (Elliptic Curve) |          |                  | Forward Secrecy)          |         |                           | portal                                   |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+

HASH ALGORITHMS
---------------
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Algorithm        | Type     | Output Size      | Primary Use Case          | Status  | Why Deprecated/Broken    | MedDefense Usage                         |
|                  |          | (bits)           |                           |         |                           |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| MD5              | Hash     | 128              | Legacy hashing            | BROKEN  | Collision attacks since   | ❌ Finding 018: MD5 used in RC4         |
|                  |          |                  |                           |         | 2004                      | (Kerberos) - MUST REPLACE               |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| SHA-1            | Hash     | 160              | Legacy hashing            | BROKEN  | Collision attacks since   | ❌ NOT IN USE - Should not be used      |
|                  |          |                  |                           |         | 2017                      |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| SHA-256          | Hash     | 256              | General hashing           | Current | N/A                       | ✅ File integrity, digital signatures,   |
|                  |          |                  |                           |         |                           | password hashing                         |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| SHA-512          | Hash     | 512              | High-security hashing     | Current | N/A                       | ✅ Recommended for high-security         |
|                  |          |                  |                           |         |                           | applications                             |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| SHA-3            | Hash     | 224, 256, 384,   | Modern hashing            | Current | N/A                       | ✅ Recommended for future-proof          |
|                  |          | 512              |                           |         |                           | applications                             |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+

KEY DERIVATION ALGORITHMS
-------------------------
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Algorithm        | Type     | Output Size      | Primary Use Case          | Status  | Why Deprecated/Broken    | MedDefense Usage                         |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| PBKDF2           | KDF      | Configurable     | Password hashing          | Current | N/A (weak without high   | ✅ Acceptable with 100,000+ iterations  |
|                  |          |                  |                           |         | iterations)              |                                          |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| bcrypt           | KDF      | 184 (salt+hash)  | Password hashing          | Current | N/A                       | ✅ Recommended for application           |
|                  |          |                  |                           |         |                           | passwords                                |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| Argon2           | KDF      | Configurable     | Password hashing          | Current | N/A                       | ✅ RECOMMENDED (memory-hard, winner of   |
|                  |          |                  |                           |         |                           | Password Hashing Competition)           |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+
| scrypt           | KDF      | Configurable     | Password hashing          | Current | N/A                       | ✅ Good alternative, memory-hard        |
+------------------+----------+------------------+---------------------------+---------+---------------------------+------------------------------------------+


================================================================================
2. MEDDEFENSE CRYPTO GAP ANALYSIS
================================================================================

+----------------------------------------------------------------------------+
| GAP 1: RC4 ENABLED IN KERBEROS (Finding 018)                               |
|                                                                             |
| Current: RC4-HMAC is still enabled for Kerberos tickets                     |
| Problem: RC4 is BROKEN (keystream biases allow recovery)                   |
| Impact: Attackers can perform Kerberoasting attacks and crack RC4 tickets  |
|         offline because RC4 uses MD5 internally                           |
| Replacement: AES-256-CTS-HMAC-SHA1-96                                     |
| Action: Disable RC4 and DES, enforce AES-256 only                         |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 2: LDAP SIGNING NOT REQUIRED (Finding 007)                             |
|                                                                             |
| Current: LDAP signing is not enforced on domain controllers                 |
| Problem: LDAP traffic can be intercepted and modified (relay attacks)      |
| Impact: Attackers can modify directory objects or extract credentials      |
| Replacement: Enforce LDAP signing and enable LDAPS (LDAP over TLS)         |
| Action: Enable LDAP signing via Group Policy, configure LDAPS              |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 3: DICOM TRAFFIC WITHOUT ENCRYPTION (Finding 024)                     |
|                                                                             |
| Current: DICOM protocol on ports 4242/11112 with NO TLS                    |
| Problem: Medical images and patient identifiers traverse in cleartext     |
| Impact: Anyone on the flat network can intercept PHI contained in images  |
| Replacement: DICOM TLS (DICOM PS3.15)                                     |
| Action: Configure DICOM TLS between MRI, PACS, and radiology workstations |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 4: TLS 1.0 SUPPORT ON PATIENT PORTAL (Finding 005)                    |
|                                                                             |
| Current: TLS 1.0 and TLS 1.2 are supported                                 |
| Problem: TLS 1.0 is vulnerable to BEAST, POODLE, Lucky Thirteen           |
| Impact: Patient data can be intercepted or decrypted                      |
| Replacement: TLS 1.2 with modern cipher suites OR TLS 1.3                 |
| Action: Disable TLS 1.0 and 1.1, enable TLS 1.2/1.3 with GCM cipher suites|
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 5: POSTGRESQL WITH OPTIONAL SSL (Crypto Audit Notes)                  |
|                                                                             |
| Current: SSL is configured but NOT enforced ("hostnossl" lines exist)     |
| Problem: Connections can fall back to plaintext                           |
| Impact: EHR data can be intercepted on the flat network                   |
| Replacement: Enforce SSL for ALL connections                              |
| Action: Remove "hostnossl" lines from pg_hba.conf, require SSL           |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 6: MYSQL WITHOUT SSL (Finding 006)                                    |
|                                                                             |
| Current: MySQL bound to 0.0.0.0, SSL NOT enforced                         |
| Problem: Billing data traverses the network in plaintext                  |
| Impact: Patient financial data (SSNs, insurance) can be intercepted       |
| Replacement: Enable MySQL SSL, bind to localhost or restrict access       |
| Action: Configure MySQL SSL, require SSL for all connections             |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 7: NAS BACKUPS WITHOUT ENCRYPTION (Finding 015)                       |
|                                                                             |
| Current: Synology NAS stores all backups in plaintext                     |
| Problem: Backup data (including PHI) is readable if NAS is compromised    |
| Impact: Ransomware can delete OR read all backups                        |
| Replacement: Synology shared folder encryption or LUKS                    |
| Action: Enable encryption on NAS, ensure key is stored SEPARATELY        |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| GAP 8: AD CREDENTIALS WITH WEAK HASH (Crypto Audit Notes)                |
|                                                                             |
| Current: NTHash (MD4) is used for NTLM compatibility                      |
| Problem: MD4 is broken, NTHash can be cracked offline                    |
| Impact: Attackers with hashes can recover passwords                      |
| Replacement: Disable NTLM, enforce Kerberos with AES-256                 |
| Action: Audit NTLM usage, disable where possible, enforce AES-256        |
+----------------------------------------------------------------------------+


================================================================================
3. RECOMMENDED REPLACEMENT SUMMARY
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Priority | Current          | Problem          | Replacement      | Action           |
+----------+------------------+------------------+------------------+------------------+
| #1       | RC4 (Kerberos)   | BROKEN           | AES-256          | Disable RC4 in   |
|          |                  |                  |                  | AD               |
+----------+------------------+------------------+------------------+------------------+
| #2       | TLS 1.0          | VULNERABLE       | TLS 1.2/1.3      | Disable TLS 1.0  |
|          | (Portal)         |                  | with GCM         | on web-srv-01    |
+----------+------------------+------------------+------------------+------------------+
| #3       | DICOM plaintext  | CLEARTEXT        | DICOM TLS        | Configure TLS    |
|          | (PACS)           |                  |                  | on pacs-srv-01   |
+----------+------------------+------------------+------------------+------------------+
| #4       | PostgreSQL SSL   | OPTIONAL         | Enforce SSL      | Remove           |
|          | optional         |                  |                  | "hostnossl"      |
+----------+------------------+------------------+------------------+------------------+
| #5       | MySQL plaintext  | CLEARTEXT        | MySQL SSL        | Configure SSL    |
|          |                  |                  |                  | on billing-srv-01|
+----------+------------------+------------------+------------------+------------------+
| #6       | NAS plaintext    | CLEARTEXT        | LUKS/Synology    | Enable           |
|          |                  |                  | encryption       | encryption       |
+----------+------------------+------------------+------------------+------------------+
| #7       | NTHash (MD4)     | BROKEN           | AES-256          | Disable NTLM,    |
|          |                  |                  | Kerberos         | enforce AES-256  |
+----------+------------------+------------------+------------------+------------------+
| #8       | LDAP plaintext   | CLEARTEXT        | LDAPS            | Configure        |
|          |                  |                  |                  | LDAP signing     |
+----------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- 1x02 Findings: 005, 006, 007, 015, 018, 024
- NIST SP 800-175B: Cryptographic Mechanisms
- NIST SP 800-57: Key Management
- HIPAA Security Rule: Encryption Standards


================================================================================
END OF ALGORITHM LANDSCAPE REPORT
================================================================================
