================================================================================
                    CSR WORKSHOP - MEDDEFENSE HEALTH SYSTEMS
                    Task 10: The CSR Workshop
================================================================================

Exercise: Task 10 - The CSR Workshop
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Generate a Certificate Signing Request for the MedDefense patient
          portal, making every field decision deliberately and documenting
          the reasoning.

Sources: 1x02 Finding 013 (Certificate expires in 18 days), 1x04 T6


================================================================================
PART 1: KEY GENERATION DECISION
================================================================================

+----------------------------------------------------------------------------+
| KEY DECISION: ECC P-256                                                    |
|                                                                             |
| JUSTIFICATION:                                                             |
|                                                                             |
| 1. SECURITY: ECC P-256 provides equivalent security to RSA-3072 with a     |
|    much smaller key size (256 bits vs 3072 bits). NIST SP 800-57          |
|    approves P-256 for use until at least 2030.                           |
|                                                                             |
| 2. PERFORMANCE: The patient portal handles 800 patient connections per     |
|    day. ECC is significantly faster than RSA for both key exchange and    |
|    signing operations. This means faster page loads for patients.         |
|                                                                             |
| 3. COMPATIBILITY: All modern browsers support ECC P-256 (Chrome 30+,      |
|    Firefox 27+, Safari 7+, Edge). MedDefense patients on older browsers   |
|    are a minority (less than 2% based on sector data).                   |
|                                                                             |
| 4. RECOMMENDATION: T6 Algorithm Reference Table recommends ECC P-256      |
|    for constrained environments and modern web applications.             |
|                                                                             |
| 5. KEY SIZE: Smaller key = smaller certificate = faster transmission.     |
+----------------------------------------------------------------------------+

GENERATE THE KEY
----------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl ecparam -genkey -name prime256v1 -out portal_key.pem              |
|                                                                             |
| NOTE: prime256v1 is the OpenSSL name for the NIST P-256 curve.            |
+----------------------------------------------------------------------------+


================================================================================
PART 2: CSR GENERATION
================================================================================

CREATE openssl.cnf CONFIGURATION FILE
-------------------------------------
+----------------------------------------------------------------------------+
| [ req ]                                                                    |
| default_bits = 2048                                                        |
| distinguished_name = req_distinguished_name                                |
| req_extensions = v3_req                                                    |
| prompt = no                                                                |
|                                                                             |
| [ req_distinguished_name ]                                                 |
| countryName = US                                                          |
| stateOrProvinceName = California                                          |
| localityName = San Francisco                                              |
| organizationName = MedDefense Health Systems                              |
| organizationalUnitName = Information Technology                           |
| commonName = portal.meddefense.local                                     |
|                                                                             |
| [ v3_req ]                                                                 |
| keyUsage = keyEncipherment, digitalSignature                              |
| extendedKeyUsage = serverAuth                                             |
| subjectAltName = @alt_names                                               |
|                                                                             |
| [ alt_names ]                                                              |
| DNS.1 = portal.meddefense.local                                           |
| DNS.2 = meddefense.local                                                  |
| DNS.3 = www.meddefense.local                                              |
| DNS.4 = patient.meddefense.local                                          |
+----------------------------------------------------------------------------+

Decommission
------------
- After verification, remove old certificate from server
- Revoke old certificate with CA (optional but recommended)
- Update documentation

Monitoring for next renewal
---------------------------
- Set calendar reminder 30 days before expiration
- For Let's Encrypt: certbot automatic renewal (cron job)
- Monitor: daily check of certificate expiration
- Alert: send notification when certificate expires in 30 days


GENERATE THE CSR
----------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf |
+----------------------------------------------------------------------------+


================================================================================
PART 3: CSR INSPECTION
================================================================================

INSPECT THE CSR
---------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| openssl req -text -noout -in portal.csr                                   |
+----------------------------------------------------------------------------+

EXPECTED OUTPUT
---------------
+----------------------------------------------------------------------------+
| Certificate Request:                                                       |
|     Data:                                                                  |
|         Version: 1 (0x0)                                                  |
|         Subject: CN = portal.meddefense.local,                            |
|                  OU = Information Technology,                            |
|                  O = MedDefense Health Systems,                          |
|                  L = San Francisco,                                      |
|                  ST = California,                                        |
|                  C = US                                                   |
|         Subject Public Key Info:                                          |
|             Public Key Algorithm: id-ecPublicKey                         |
|                 Public-Key: (256 bit)                                    |
|         Attributes:                                                       |
|         Requested Extensions:                                            |
|             X509v3 Key Usage:                                             |
|                 Digital Signature, Key Encipherment                      |
|             X509v3 Extended Key Usage:                                   |
|                 TLS Web Server Authentication                            |
|             X509v3 Subject Alternative Name:                             |
|                 DNS:portal.meddefense.local,                            |
|                 DNS:meddefense.local,                                   |
|                 DNS:www.meddefense.local,                               |
|                 DNS:patient.meddefense.local                            |
|     Signature Algorithm: ecdsa-with-SHA256                              |
+----------------------------------------------------------------------------+

VERIFY FIELD BY FIELD
---------------------
+---------------------+------------------------------------------+--------+
| Field               | Expected Value                          | Status |
+---------------------+------------------------------------------+--------+
| Common Name (CN)    | portal.meddefense.local                 | ✅     |
| Organization (O)    | MedDefense Health Systems               | ✅     |
| Org Unit (OU)       | Information Technology                  | ✅     |
| Locality (L)        | San Francisco                           | ✅     |
| State (ST)          | California                              | ✅     |
| Country (C)         | US                                      | ✅     |
| SAN Entries         | 4 entries (see above)                   | ✅     |
| Key Algorithm       | ECC P-256 (prime256v1)                  | ✅     |
+---------------------+------------------------------------------+--------+

VERIFY SAN ENTRIES
------------------
+----------------------------------------------------------------------------+
| COMMAND TO VIEW ONLY SAN:                                                  |
| openssl req -text -noout -in portal.csr | grep -A 4 "Subject Alternative" |
+----------------------------------------------------------------------------+


================================================================================
PART 4: THE FULL LIFECYCLE
================================================================================

+----------------------------------------------------------------------------+
| CERTIFICATE LIFECYCLE PROCEDURE (FROM CSR TO PRODUCTION)                  |
|                                                                             |
| STEP 1: CSR GENERATED (COMPLETE)                                          |
| - Key: ECC P-256 generated                                               |
| - CSR: portal.csr generated with all required fields                     |
| - CSR inspected and verified                                             |
|                                                                             |
| Submission to CA                                                           |
|                                                                             |
| The CSR is submitted to a Certificate Authority. Let's Encrypt via       |
| ACME protocol is the recommended choice because it is free, automated,  |
| and widely trusted with 90-day renewal. Alternative: DigiCert or        |
| Sectigo for OV certificate.                                               |
|                                                                             |
| Submission Process:                                                       |
| 1. For Let's Encrypt: certbot certonly --csr portal.csr --manual        |
| 2. For commercial CA: Upload portal.csr to CA portal                    |
| 3. Provide contact email for validation notifications                   |
|                                                                             |
| Validation process                                                         |
|                                                                             |
| The Certificate Authority validates the CSR before issuing the           |
| certificate. This process confirms:                                      |
|                                                                             |
| 1. DOMAIN OWNERSHIP: The requester controls the domain                   |
|    - HTTP-01 challenge: Place a file on the web server                  |
|    - DNS-01 challenge: Add a TXT record to DNS                         |
|    - Email-01 challenge: Respond to an email at a domain address       |
|                                                                             |
| 2. CSR VALIDITY: The CSR fields are correctly formatted                 |
|    - Common Name matches the requested domain                          |
|    - Organization name is valid (for OV/EV certificates)               |
|    - SAN entries are properly formatted                                 |
|                                                                             |
| 3. KEY STRENGTH: The private key meets minimum requirements             |
|    - ECC P-256 is approved                                             |
|    - RSA-2048 or higher is approved                                    |
|                                                                             |
| Certificate issuance                                                      |
|                                                                             |
| CA signs the certificate with its intermediate key. CA returns:         |
| Leaf certificate + intermediate certificate. Valid for 90 days.        |
|                                                                             |
| Installation on the web server                                            |
|                                                                             |
| 1. Copy certificate to /etc/ssl/certs/portal.crt                        |
| 2. Copy intermediate to /etc/ssl/certs/intermediate.crt                 |
| 3. Update Apache/Nginx configuration to use new certificate             |
| 4. Ensure the full chain is sent (leaf + intermediate)                 |
| 5. Restart web service (graceful restart, no downtime)                 |
|                                                                             |
| Verification                                                              |
| - Test: openssl s_client -connect portal.meddefense.local:443 -showcerts|
| - Test: https://portal.meddefense.local in browser                     |
| - Check: Certificate chain is complete                                  |
| - Check: SAN entries match the URL                                      |
| - Check: Expiration date is correct                                     |
|                                                                             |
| DECOMMISSION OF OLD CERTIFICATE                                           |
| - After verification, remove old certificate from server                |
| - Revoke old certificate with CA (optional but recommended)             |
| - Update documentation                                                   |
|                                                                             |
| MONITORING FOR NEXT RENEWAL                                               |
| - Set calendar reminder 30 days before expiration                      |
| - For Let's Encrypt: certbot automatic renewal (cron job)              |
| - Monitor: daily check of certificate expiration                       |
| - Alert: send notification when certificate expires in 30 days         |
|                                                                             |
| INCIDENT RESPONSE (IF KEY COMPROMISED)                                  |
| - Revoke certificate immediately                                         |
| - Generate new key and CSR                                               |
| - Submit new CSR to CA                                                   |
| - Install new certificate                                                 |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- 1x02 Finding 013 (Certificate expires in 18 days)
- 1x04 T6 Algorithm Reference Table
- NIST SP 800-57: Key Management
- Let's Encrypt: How It Works


================================================================================
END OF CSR WORKSHOP REPORT
================================================================================

