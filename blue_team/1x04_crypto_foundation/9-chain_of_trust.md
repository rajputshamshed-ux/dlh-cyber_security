================================================================================
                    CHAIN OF TRUST - MEDDEFENSE HEALTH SYSTEMS
                    Task 9: The Chain of Trust
================================================================================

Exercise: Task 9 - The Chain of Trust
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Capture and verify a complete certificate chain, understand how
          trust propagates from root to leaf, and analyze what happens when
          the chain breaks.

Sources: 1x02 Finding 013 (Certificate expires in 18 days), 1x03 MCQ T25


================================================================================
PART 1: CAPTURE THE FULL CHAIN
================================================================================

COMMAND TO CAPTURE FULL CHAIN
-----------------------------
+----------------------------------------------------------------------------+
| openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | |
| openssl x509 -text                                                         |
+----------------------------------------------------------------------------+

CAPTURE EACH CERTIFICATE SEPARATELY
-----------------------------------
+----------------------------------------------------------------------------+
| # Get the full chain in one file                                         |
| openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | |
| openssl x509 -text > github_chain.txt                                    |
|                                                                             |
| # Extract leaf certificate (first cert)                                   |
| openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | |
| sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' |     |
| head -1 | openssl x509 -text > leaf.pem                                  |
|                                                                             |
| # Extract intermediate certificate (second cert)                         |
| openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | |
| sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' |     |
| tail -1 | openssl x509 -text > intermediate.pem                          |
+----------------------------------------------------------------------------+

CHAIN STRUCTURE
---------------
+----------+------------------+------------------------------------------+
| Position | Role             | Details                                  |
+----------+------------------+------------------------------------------+
| 1        | LEAF             | CN = github.com                          |
|          |                  | O = GitHub, Inc.                         |
|          |                  | Issuer: DigiCert TLS RSA SHA256 2020 CA1 |
+----------+------------------+------------------------------------------+
| 2        | INTERMEDIATE     | CN = DigiCert TLS RSA SHA256 2020 CA1    |
|          |                  | O = DigiCert Inc                         |
|          |                  | Issuer: DigiCert Global Root CA          |
+----------+------------------+------------------------------------------+
| 3        | ROOT             | CN = DigiCert Global Root CA             |
|          |                  | O = DigiCert Inc                         |
|          |                  | Issuer: DigiCert Global Root CA          |
|          |                  | (self-signed)                            |
+----------+------------------+------------------------------------------+

SUBJECT / ISSUER MATCHING
-------------------------
+----------------------------------------------------------------------------+
| Leaf Certificate:                                                          |
| Subject: CN = github.com, O = GitHub, Inc.                               |
| Issuer:  CN = DigiCert TLS RSA SHA256 2020 CA1, O = DigiCert Inc         |
|                                                                             |
| Intermediate Certificate:                                                  |
| Subject: CN = DigiCert TLS RSA SHA256 2020 CA1, O = DigiCert Inc         |
| Issuer:  CN = DigiCert Global Root CA, O = DigiCert Inc                  |
|                                                                             |
| Root Certificate:                                                          |
| Subject: CN = DigiCert Global Root CA, O = DigiCert Inc                  |
| Issuer:  CN = DigiCert Global Root CA, O = DigiCert Inc (self-signed)    |
|                                                                             |
| The Issuer of the leaf matches the Subject of the intermediate.            |
| The Issuer of the intermediate matches the Subject of the root.           |
| This creates the chain of trust.                                          |
+----------------------------------------------------------------------------+


================================================================================
PART 2: MANUAL CHAIN VERIFICATION
================================================================================

VERIFY WITH FULL CHAIN
----------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl verify -CAfile root.pem -CApath /etc/ssl/certs leaf.pem           |
|                                                                             |
| OR (if you have the full chain in one file):                               |
| cat root.pem intermediate.pem > chain.pem                                 |
| openssl verify -CAfile chain.pem leaf.pem                                 |
|                                                                             |
| EXPECTED OUTPUT:                                                           |
| leaf.pem: OK                                                              |
+----------------------------------------------------------------------------+

VERIFY WITHOUT INTERMEDIATE
---------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl verify -CAfile root.pem leaf.pem                                  |
|                                                                             |
| EXPECTED OUTPUT:                                                           |
| error 2 at 1 depth lookup: unable to get issuer certificate               |
| leaf.pem: verification failed                                             |
+----------------------------------------------------------------------------+

EXPLANATION
-----------
+----------------------------------------------------------------------------+
| This demonstrates why servers must send the full certificate chain.        |
| The client trusts the ROOT CA, but cannot verify the leaf certificate     |
| without the intermediate that bridges the trust from the root to the      |
| leaf. If the server only sends the leaf certificate, the browser cannot   |
| verify it and will show a connection error. MedDefense must ensure its    |
| portal sends the FULL chain (leaf + intermediate) to avoid patient       |
| connection errors.                                                        |
+----------------------------------------------------------------------------+


================================================================================
PART 3: REVOCATION MECHANISMS
================================================================================

CRL (CERTIFICATE REVOCATION LIST)
---------------------------------
+----------------------------------------------------------------------------+
| WHAT IT IS:                                                               |
| A list of revoked certificates (serial numbers) published by the CA.      |
|                                                                             |
| HOW THE CLIENT USES IT:                                                    |
| The client downloads the CRL from the URL in the certificate's CRL        |
| Distribution Point extension and checks if the certificate serial         |
| number is on the list.                                                    |
|                                                                             |
| MAIN LIMITATION:                                                          |
| - CRLs can be large (sometimes several MB)                              |
| - Clients must download the entire list to check one certificate         |
| - Updated infrequently (sometimes only every 7 days)                    |
| - Creates bandwidth and latency issues                                   |
+----------------------------------------------------------------------------+

OCSP (ONLINE CERTIFICATE STATUS PROTOCOL)
-----------------------------------------
+----------------------------------------------------------------------------+
| WHAT IT IS:                                                               |
| A real-time protocol to check if a certificate is revoked.                |
|                                                                             |
| HOW IT IMPROVES ON CRLs:                                                   |
| - Real-time response (no waiting for updates)                            |
| - Much smaller payload (only one certificate check per request)          |
| - Lower bandwidth usage                                                  |
| - No need to download large CRL files                                    |
|                                                                             |
| OCSP STAPLING:                                                            |
| The server pre-fetches the OCSP response and "staples" it to the         |
| TLS handshake. This eliminates the need for the client to make an        |
| additional OCSP request, improving performance and privacy.              |
+----------------------------------------------------------------------------+

MEDDEFENSE CERTIFICATE REVOCATION PROCEDURE
-------------------------------------------
+----------------------------------------------------------------------------+
| SCENARIO: The portal's private key is compromised (exposed in Git).       |
|                                                                             |
| SEQUENCE OF ACTIONS:                                                       |
| 1. IMMEDIATE: Revoke the certificate with the CA                          |
|    - Use the CA's revocation portal (Let's Encrypt, DigiCert, etc.)      |
|    - Request immediate revocation of the certificate                     |
|                                                                             |
| 2. IMMEDIATE: Generate a new private key (RSA-2048 or ECC P-256)         |
|    - openssl genrsa -out portal_new.key 2048                            |
|                                                                             |
| 3. Generate a new CSR (Certificate Signing Request)                       |
|    - openssl req -new -key portal_new.key -out portal.csr               |
|                                                                             |
| 4. Submit CSR to CA for a new certificate                                 |
|                                                                             |
| 5. Deploy the new certificate and key to web-srv-01                       |
|                                                                             |
| 6. Remove the compromised key from ALL locations (Git, backups, etc.)    |
|                                                                             |
| 7. Rotate the key on any systems that used the compromised key           |
|    (e.g., if used for mutual TLS, API authentication)                    |
|                                                                             |
| 8. Notify patients if the breach occurred before revocation              |
|                                                                             |
| 9. Update incident response documentation with lessons learned           |
|                                                                             |
| WHY THIS SEQUENCE:                                                         |
| - Revocation first prevents continued use of compromised certificate     |
| - New key generation ensures the replacement is secure                   |
| - Deployment restores the secure portal                                  |
+----------------------------------------------------------------------------+


================================================================================
PART 4: TRUST STORE EXPLORATION
================================================================================

FIND THE TRUST STORE
--------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| find /etc/ssl/certs -name "*.pem" | wc -l                                 |
| find /usr/share/ca-certificates -name "*.crt" | wc -l                    |
|                                                                             |
| Typical location: /etc/ssl/certs/                                          |
| Number of Root CA certificates: ~150-200 (depends on distro)             |
+----------------------------------------------------------------------------+

INSPECT A ROOT CA CERTIFICATE
-----------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl x509 -in /etc/ssl/certs/ca-certificates.crt -text | less         |
|                                                                             |
| OR for a specific cert:                                                    |
| openssl x509 -in /usr/share/ca-certificates/mozilla/DigiCert_Global_Root_CA.crt -text |
+----------------------------------------------------------------------------+

EXPECTED FINDINGS
-----------------
+----------------------------------------------------------------------------+
| ROOT CA VALIDITY PERIOD:                                                   |
| Typically 20-30 years (e.g., 2006-2036)                                   |
|                                                                             |
| WHY THIS IS SURPRISING:                                                    |
| Root CA certificates have VERY long validity periods (often 20+ years).   |
| This is because:                                                          |
| - They are the foundation of trust                                       |
| - Replacing them requires updating ALL clients                           |
| - They are stored in the browser/system trust store                     |
| - Compromising a root CA would require re-issuing ALL certificates       |
|                                                                             |
| This is why root CA keys are kept in Hardware Security Modules (HSMs)    |
| and protected with extreme security.                                     |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- 1x02 Finding 013 (Certificate expires in 18 days)
- 1x03 MCQ T25 (Key exposure in Git)
- NIST SP 800-57: Key Management
- RFC 5280: Certificate and CRL Profile
- RFC 6960: OCSP


================================================================================
END OF CHAIN OF TRUST REPORT
================================================================================
