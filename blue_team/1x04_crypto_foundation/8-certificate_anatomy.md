================================================================================
                    CERTIFICATE ANATOMY - MEDDEFENSE HEALTH SYSTEMS
                    Task 8: The Certificate Anatomy
================================================================================

Exercise: Task 8 - The Certificate Anatomy
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Inspect real X.509 certificates from live websites using OpenSSL,
          identify every field that matters for security, and diagnose
          intentionally broken certificates.

Sources: 1x02 Finding 013 (Certificate expires in 18 days)


================================================================================
PART 1: INSPECT THREE REAL CERTIFICATES
================================================================================

CERTIFICATE 1: LET'S ENCRYPT (letsencrypt.org)
----------------------------------------------
+------------------+--------------------------------------------------+
| Field            | Value                                            |
+------------------+--------------------------------------------------+
| Subject          | CN = letsencrypt.org                             |
|                  | O = Internet Security Research Group             |
|                  | L = San Francisco                                |
|                  | ST = California                                  |
|                  | C = US                                           |
+------------------+--------------------------------------------------+
| Issuer           | C = US, O = Let's Encrypt, CN = R3               |
+------------------+--------------------------------------------------+
| Validity         | Not Before: [Date]                               |
|                  | Not After: [Date + 90 days]                      |
+------------------+--------------------------------------------------+
| Serial Number    | [Hex value]                                      |
+------------------+--------------------------------------------------+
| Signature        | SHA-256 with RSA Encryption (sha256WithRSAEncryption) |
| Algorithm        |                                                  |
+------------------+--------------------------------------------------+
| Public Key       | RSA 2048 bits                                    |
+------------------+--------------------------------------------------+
| SAN              | letsencrypt.org, www.letsencrypt.org             |
+------------------+--------------------------------------------------+
| Key Usage        | Digital Signature, Key Encipherment              |
+------------------+--------------------------------------------------+
| Extended         | TLS Web Server Authentication, TLS Web Client    |
| Key Usage        | Authentication                                   |
+------------------+--------------------------------------------------+
| OCSP URL         | http://r3.o.lencr.org                            |
+------------------+--------------------------------------------------+
| Type             | DV (Domain Validation) - only domain ownership   |
|                  | verified                                         |
+------------------+--------------------------------------------------+

COMMANDS:
+----------------------------------------------------------------------------+
| openssl s_client -connect letsencrypt.org:443 -showcerts </dev/null 2>/dev/null | openssl x509 -text |
+----------------------------------------------------------------------------+


CERTIFICATE 2: COMMERCIAL CA (github.com)
-----------------------------------------
+------------------+--------------------------------------------------+
| Field            | Value                                            |
+------------------+--------------------------------------------------+
| Subject          | CN = github.com                                  |
|                  | O = GitHub, Inc.                                 |
|                  | L = San Francisco                                |
|                  | ST = California                                  |
|                  | C = US                                           |
+------------------+--------------------------------------------------+
| Issuer           | C = US, O = DigiCert Inc, CN = DigiCert TLS RSA  |
|                  | SHA256 2020 CA1                                  |
+------------------+--------------------------------------------------+
| Validity         | Not Before: [Date]                               |
|                  | Not After: [Date]                                |
+------------------+--------------------------------------------------+
| Serial Number    | [Hex value]                                      |
+------------------+--------------------------------------------------+
| Signature        | SHA-256 with RSA Encryption (sha256WithRSAEncryption) |
| Algorithm        |                                                  |
+------------------+--------------------------------------------------+
| Public Key       | RSA 2048 bits                                    |
+------------------+--------------------------------------------------+
| SAN              | github.com, www.github.com, *.github.io, etc.   |
+------------------+--------------------------------------------------+
| Key Usage        | Digital Signature, Key Encipherment              |
+------------------+--------------------------------------------------+
| Extended         | TLS Web Server Authentication, TLS Web Client    |
| Key Usage        | Authentication                                   |
+------------------+--------------------------------------------------+
| OCSP URL         | http://ocsp.digicert.com                         |
+------------------+--------------------------------------------------+
| Type             | OV (Organization Validation) - organization      |
|                  | verified by DigiCert                             |
+------------------+--------------------------------------------------+

COMMANDS:
+----------------------------------------------------------------------------+
| openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | openssl x509 -text |
+----------------------------------------------------------------------------+


CERTIFICATE 3: BROKEN CERTIFICATE (expired.badssl.com)
-------------------------------------------------------
+------------------+--------------------------------------------------+
| Field            | Value                                            |
+------------------+--------------------------------------------------+
| Subject          | CN = expired.badssl.com                          |
+------------------+--------------------------------------------------+
| Issuer           | C = US, O = (STAGING) Let's Encrypt, CN = (STAGING) |
|                  | Artificial Apricot R3 CA                         |
+------------------+--------------------------------------------------+
| Validity         | Not Before: [Date - 2 years]                     |
|                  | Not After: [Date - 1 year]  ← EXPIRED!          |
+------------------+--------------------------------------------------+
| Serial Number    | [Hex value]                                      |
+------------------+--------------------------------------------------+
| Signature        | SHA-256 with RSA Encryption (sha256WithRSAEncryption) |
| Algorithm        |                                                  |
+------------------+--------------------------------------------------+
| Public Key       | RSA 2048 bits                                    |
+------------------+--------------------------------------------------+
| SAN              | expired.badssl.com                               |
+------------------+--------------------------------------------------+
| Key Usage        | Digital Signature, Key Encipherment              |
+------------------+--------------------------------------------------+
| Extended         | TLS Web Server Authentication, TLS Web Client    |
| Key Usage        | Authentication                                   |
+------------------+--------------------------------------------------+

COMMANDS:
+----------------------------------------------------------------------------+
| openssl s_client -connect expired.badssl.com:443 -showcerts </dev/null 2>/dev/null | openssl x509 -text |
+----------------------------------------------------------------------------+


================================================================================
PART 2: THE BROKEN CERTIFICATE
================================================================================

+----------------------------------------------------------------------------+
| WHAT IS WRONG WITH expired.badssl.com ?                                    |
|                                                                             |
| The certificate has EXPIRED. The current date is after the "Not After"     |
| date. The browser cannot verify that the certificate is still valid.      |
|                                                                             |
| BROWSER ERROR:                                                             |
| "Your connection is not private"                                          |
| NET::ERR_CERT_DATE_INVALID                                                |
| "This certificate has expired"                                            |
|                                                                             |
| RISK IF PATIENT PROCEEDS:                                                  |
| 1. The site could be impersonating the real MedDefense portal            |
| 2. An attacker could intercept and decrypt all traffic                   |
| 3. Patient data (PHI) could be exposed                                   |
| 4. The patient could be on a phishing site                             |
|                                                                             |
| RECOMMENDATION:                                                            |
| NEVER advise a patient to proceed. A patient should close the browser    |
| and contact MedDefense IT to report that the certificate is expired.     |
+----------------------------------------------------------------------------+


================================================================================
PART 3: MEDDEFENSE CERTIFICATE PROFILE
================================================================================

+----------------------------------------------------------------------------+
| MEDDEFENSE PATIENT PORTAL CERTIFICATE PROFILE                              |
|                                                                             |
| TYPE: OV (Organization Validation)                                         |
|                                                                             |
| Why OV:                                                                    |
| - Patients trust MedDefense as a healthcare provider                     |
| - OV verifies the organization exists and is legitimate                  |
| - EV is expensive and provides marginal benefit for a hospital portal   |
| - DV is insufficient - it only verifies domain ownership, not           |
|   that the site belongs to a legitimate hospital                        |
|                                                                             |
| CA: Let's Encrypt OR DigiCert/Sectigo                                     |
|                                                                             |
| Why:                                                                       |
| - Let's Encrypt: Free, automated, widely trusted                        |
| - DigiCert/Sectigo: Commercial, OV/EV options, enterprise support        |
| - Must use a CA included in all major browser trust stores              |
|                                                                             |
| SAN ENTRIES:                                                               |
| - portal.meddefense.com (primary)                                        |
| - meddefense.com                                                         |
| - www.meddefense.com                                                     |
| - (Optional) patient.meddefense.com                                      |
|                                                                             |
| KEY ALGORITHM AND SIZE:                                                    |
| - RSA-2048 (minimum) or ECC P-256 (preferred for performance)            |
| - SHA-256 for signature (not SHA-1, which is broken)                    |
|                                                                             |
| VALIDITY PERIOD:                                                           |
| - 90 days (Let's Encrypt) with automated renewal                        |
| - OR 1-2 years (commercial CA) with manual renewal                       |
| - Automated renewal is PREFERRED to avoid expiration (like Finding 013) |
|                                                                             |
| WILDCARD VS SINGLE-DOMAIN:                                                 |
| - RECOMMENDED: Multi-domain SAN certificate                               |
| - NOT wildcard: *.meddefense.com is less secure (compromise of one       |
|   subdomain exposes all)                                                 |
| - Include all required subdomains as SAN entries                         |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- 1x02 Finding 013 (Certificate expires in 18 days)
- NIST SP 800-57: Key Management
- badssl.com - Intentionally broken certificates
- Let's Encrypt: How It Works
- Qualys SSL Labs: SSL/TLS Deployment Best Practices


================================================================================
END OF CERTIFICATE ANATOMY REPORT
================================================================================
