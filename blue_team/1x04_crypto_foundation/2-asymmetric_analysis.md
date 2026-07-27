================================================================================
                    ASYMMETRIC ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 2: The Asymmetric Engine
================================================================================

Exercise: Task 2 - The Asymmetric Engine
Analyst: shamshed rajput
Date: 27/07/2026
Objective: Generate RSA and ECC key pairs, discover the size limitation of
          asymmetric encryption through experimentation, and understand why
          the hybrid model exists.

Sources: meddefense-crypto-audit-notes.txt, 1x02 Vulnerability Scan


================================================================================
PART 1: RSA KEY GENERATION AND ENCRYPTION
================================================================================

1.1 GENERATE RSA-2048 KEY PAIR
------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl genrsa -out rsa_private.pem 2048          |
| (Private Key)    |                                                   |
+------------------+--------------------------------------------------+
| Command          | openssl rsa -in rsa_private.pem -pubout -out      |
| (Public Key)     | rsa_public.pem                                    |
+------------------+--------------------------------------------------+
| Private Key Size | 1.7 KB                                            |
+------------------+--------------------------------------------------+
| Public Key Size  | 451 bytes                                         |
+------------------+--------------------------------------------------+

1.2 ENCRYPT SMALL FILE WITH PUBLIC KEY
--------------------------------------
+------------------+--------------------------------------------------+
| Command          | echo "Patient: Jane Doe | DOB: 1985-03-14 | MRN:  |
| (Create File)    | MED-50421 | Diagnosis: Atrial Fibrillation" >       |
|                  | patient.txt                                       |
+------------------+--------------------------------------------------+
| Command          | openssl rsautl -encrypt -in patient.txt -out      |
| (Encrypt)        | patient.enc -pubin -inkey rsa_public.pem          |
+------------------+--------------------------------------------------+
| Command          | openssl rsautl -decrypt -in patient.enc -out      |
| (Decrypt)        | patient_dec.txt -inkey rsa_private.pem            |
+------------------+--------------------------------------------------+
| Result           | patient_dec.txt contains the original message     |
+------------------+--------------------------------------------------+

1.3 ATTEMPT TO ENCRYPT LARGE FILE (100MB)
------------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl rsautl -encrypt -in testfile -out         |
|                  | testfile.enc -pubin -inkey rsa_public.pem        |
+------------------+--------------------------------------------------+
| Error Message    | RSA operation error                               |
|                  | error:0406D06E:rsa routines:                      |
|                  | RSA_padding_add_PKCS1_type_2:data too large for   |
|                  | key size                                          |
+------------------+--------------------------------------------------+
| Why It Fails     | RSA-2048 can only encrypt data up to the key      |
|                  | size minus padding (approximately 245 bytes).     |
|                  | The 100MB file is far larger than this limit.    |
+------------------+--------------------------------------------------+
| Real-World       | RSA cannot encrypt large files directly. It is   |
| Implication      | only used for small data exchange (symmetric     |
|                  | keys, signatures). Bulk data encryption requires  |
|                  | symmetric algorithms like AES.                   |
+------------------+--------------------------------------------------+


================================================================================
PART 2: ECC KEY GENERATION
================================================================================

2.1 GENERATE ECC KEY PAIR (P-256 CURVE)
---------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl ecparam -genkey -name prime256v1 -out     |
| (Private Key)    | ecc_private.pem                                   |
+------------------+--------------------------------------------------+
| Command          | openssl ec -in ecc_private.pem -pubout -out       |
| (Public Key)     | ecc_public.pem                                    |
+------------------+--------------------------------------------------+
| Private Key Size | 245 bytes                                         |
+------------------+--------------------------------------------------+
| Public Key Size  | 179 bytes                                         |
+------------------+--------------------------------------------------+

2.2 SIZE COMPARISON: RSA VS ECC
-------------------------------
+------------------+------------------+------------------------------------------+
| Key Type         | File Size        | Ratio                                    |
+------------------+------------------+------------------------------------------+
| RSA-2048 Private | 1.7 KB           | 7x larger than ECC                       |
+------------------+------------------+------------------------------------------+
| ECC P-256 Private| 245 bytes        | 1x (baseline)                            |
+------------------+------------------+------------------------------------------+

2.3 WHY ECC MATTERS FOR MEDDEFENSE
----------------------------------
+----------------------------------------------------------------------------+
| ECC achieves equivalent security to RSA with much smaller keys because it  |
| relies on the elliptic curve discrete logarithm problem, which is harder   |
| to solve than RSA's factoring problem.                                     |
|                                                                             |
| For MedDefense's constrained environments (BD Alaris pumps with limited    |
| processing power, Philips monitors), ECC is the better choice because:    |
| - Smaller keys = less storage required                                    |
| - Faster computation = less battery/CPU usage                            |
| - Same security level with smaller footprint                             |
+----------------------------------------------------------------------------+


================================================================================
PART 3: THE HYBRID MODEL
================================================================================

3.1 WHY THE HYBRID MODEL EXISTS
-------------------------------
+----------------------------------------------------------------------------+
| THE HYBRID MODEL COMBINES THE BEST OF BOTH WORLDS:                         |
|                                                                             |
| 1. Asymmetric encryption (RSA/ECC) solves the key distribution problem:   |
|    - Two parties who have never met can securely exchange a symmetric key |
|    - No need to share a secret beforehand                                |
|                                                                             |
| 2. Symmetric encryption (AES) solves the performance problem:              |
|    - Fast enough for large data (100MB files, streaming)                  |
|    - No size limitations                                                  |
|                                                                             |
| 3. The hybrid model works like this:                                      |
|    a) Client generates a random symmetric key (session key)              |
|    b) Client encrypts the session key with server's public key (RSA)    |
|    c) Client sends encrypted session key to server                       |
|    d) Server decrypts the session key with its private key (RSA)        |
|    e) Both now share the SAME symmetric key                              |
|    f) All bulk data is encrypted with AES using that key                 |
+----------------------------------------------------------------------------+

3.2 CONNECTION TO MEDDEFENSE PATIENT PORTAL
-------------------------------------------
+----------------------------------------------------------------------------+
| When a patient connects to MedDefense's patient portal via HTTPS:         |
|                                                                             |
| KEY EXCHANGE (Asymmetric - RSA/ECC):                                       |
| - During the TLS handshake, the patient's browser and the server         |
|   negotiate a shared secret using asymmetric encryption.                 |
| - This establishes a secure channel without prior key sharing.           |
| - The server's certificate contains its public key.                     |
|                                                                             |
| BULK DATA ENCRYPTION (Symmetric - AES):                                   |
| - After the key exchange, ALL patient data (medical records, lab        |
|   results, messages) is encrypted with AES using the negotiated         |
|   session key.                                                           |
| - This ensures fast encryption/decryption of large amounts of data.     |
|                                                                             |
| This is why TLS is efficient: asymmetric for the handshake (small data), |
| symmetric for the bulk data (large data).                                |
+----------------------------------------------------------------------------+


================================================================================
PART 4: KEY LENGTH TABLE
================================================================================

+------------------+------------------+------------------+------------------+------------------+------------------+
| Algorithm        | Type             | Key Lengths      | Equivalent       | Status           | MedDefense       |
|                  |                  |                  | Security         |                  | Usage            |
+------------------+------------------+------------------+------------------+------------------+------------------+
| AES              | Symmetric        | 128, 192, 256    | 128-bit          | ✅ APPROVED      | EHR at rest,     |
|                  |                  |                  |                  |                  | backups, VPN     |
+------------------+------------------+------------------+------------------+------------------+------------------+
| AES-256          | Symmetric        | 256              | 256-bit          | ✅ APPROVED      | Patient data,    |
|                  |                  |                  |                  | (RECOMMENDED)    | TLS 1.3          |
+------------------+------------------+------------------+------------------+------------------+------------------+
| RSA-2048         | Asymmetric       | 2048             | 112-bit          | ✅ APPROVED      | TLS handshake,   |
|                  |                  |                  |                  |                  | key exchange     |
+------------------+------------------+------------------+------------------+------------------+------------------+
| RSA-4096         | Asymmetric       | 4096             | 140-bit          | ✅ APPROVED      | Long-term keys,  |
|                  |                  |                  |                  |                  | CA certificates  |
+------------------+------------------+------------------+------------------+------------------+------------------+
| ECC P-256        | Asymmetric       | 256              | 128-bit          | ✅ APPROVED      | Medical devices, |
|                  |                  |                  |                  | (RECOMMENDED)    | constrained IoT  |
+------------------+------------------+------------------+------------------+------------------+------------------+
| ECC P-384        | Asymmetric       | 384              | 192-bit          | ✅ APPROVED      | High-security,   |
|                  |                  |                  |                  |                  | long-term keys   |
+------------------+------------------+------------------+------------------+------------------+------------------+
| ChaCha20-        | Symmetric        | 256              | 256-bit          | ✅ APPROVED      | Mobile devices,  |
| Poly1305         | (AEAD)           |                  |                  |                  | low-power IoT    |
+------------------+------------------+------------------+------------------+------------------+------------------+
| DES              | Symmetric        | 56               | 56-bit           | ❌ BROKEN        | NONE -           |
|                  |                  |                  |                  | (EOL 2001)       | DEPRECATED       |
+------------------+------------------+------------------+------------------+------------------+------------------+
| 3DES             | Symmetric        | 168              | 112-bit          | ⚠️ WEAK          | NONE -           |
|                  |                  |                  |                  | (Deprecated)     | DEPRECATED       |
+------------------+------------------+------------------+------------------+------------------+------------------+
| RC4              | Symmetric        | 40-2048          | Variable         | ❌ BROKEN        | NONE -           |
|                  | (Stream)         |                  |                  | (EOL 2015)       | DEPRECATED       |
+------------------+------------------+------------------+------------------+------------------+------------------+

APPROVED FOR HEALTHCARE:
+------------------+--------------------------------------------------+
| ✅ APPROVED      | AES-256, AES-192, AES-128, RSA-2048, RSA-4096,   |
|                  | ECC P-256, ECC P-384, ChaCha20-Poly1305          |
+------------------+--------------------------------------------------+
| ❌ NOT APPROVED  | DES, 3DES, RC4                                   |
+------------------+--------------------------------------------------+
| ⚠️ WEAK          | 3DES (deprecated, use AES instead)               |
+------------------+--------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- NIST SP 800-175B: Cryptographic Mechanisms
- NIST SP 800-57: Key Management
- HIPAA Security Rule: Encryption Standards
- OpenSSL man pages: man openssl-rsa, man openssl-ec

Cross-References:
- Crypto Inventory (1x04 T0)
- Symmetric Engine (1x04 T1)
- Asset Registry (1x00 T7): BD Alaris pumps, Philips monitors


================================================================================
END OF ASYMMETRIC ANALYSIS REPORT
================================================================================
