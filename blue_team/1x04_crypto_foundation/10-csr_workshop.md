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
+----------------------------------------------------------------------------+
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
+----------------------------------------------------------------------------+

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
| Step 1: CSR GENERATED (COMPLETE)                                          |
| - Key: ECC P-256 generated                                               |
| - CSR: portal.csr generated with all required fields                     |
| - CSR inspected and verified                                             |
|                                                                             |
| STEP 2: SUBMISSION TO CA                                                   |
|                                                                             |
| CA CHOICE: Let's Encrypt via ACME protocol                              |
| - REASON: Free, automated, widely trusted, 90-day renewal               |
| - ALTERNATIVE: DigiCert or Sectigo for OV certificate                    |
|                                                                             |
| SUBMISSION PROCESS:                                                       |
| 1. For Let's Encrypt: Use certbot tool                                   |
|    sudo certbot certonly --csr portal.csr --manual                       |
| 2. For commercial CA: Upload portal.csr to CA portal (e.g., DigiCert)   |
| 3. Provide contact email for validation notifications                   |
|                                                                             |
| Step 3: VALIDATION PROCESS (CA VERIFIES)                                 |
| - Let's Encrypt: HTTP-01 challenge (place file on web server)           |
| - OR DNS-01 challenge (add TXT record to DNS)                          |
| - CA verifies: Domain ownership is proven                              |
| - CA verifies: CSR fields are valid                                     |
| - CA verifies: Key is strong enough                                     |
|                                                                             |
| Step 4: CERTIFICATE ISSUANCE                                               |
| - CA signs the certificate with its intermediate key                    |
| - CA returns: Leaf certificate + intermediate certificate               |
| - Certificate is valid for 90 days (Let's Encrypt)                     |
|                                                                             |
| Step 5: INSTALLATION ON WEB SERVER                                        |
| - Copy certificate to web-srv-01: /etc/ssl/certs/portal.crt             |
| - Copy intermediate to: /etc/ssl/certs/intermediate.crt                 |
| - Update Apache/Nginx configuration to use new certificate              |
| - Ensure the full chain is sent (leaf + intermediate)                   |
| - Restart web service (graceful restart, no downtime)                  |
|                                                                             |
| Step 6: VERIFICATION                                                      |
| - Test: openssl s_client -connect portal.meddefense.local:443 -showcerts|
| - Test: https://portal.meddefense.local in browser                     |
| - Check: Certificate chain is complete                                  |
| - Check: SAN entries match the URL                                      |
| - Check: Expiration date is correct                                     |
|                                                                             |
| Step 7: DECOMMISSION OF OLD CERTIFICATE                                   |
| - After verification, remove old certificate from server                |
| - Revoke old certificate with CA (optional but recommended)             |
| - Update documentation                                                   |
|                                                                             |
| Step 8: MONITORING FOR NEXT RENEWAL                                       |
| - Set calendar reminder 30 days before expiration                      |
| - For Let's Encrypt: certbot automatic renewal (cron job)              |
| - Monitor: daily check of certificate expiration                       |
| - Alert: send notification when certificate expires in 30 days         |
|                                                                             |
| Step 9: INCIDENT RESPONSE (IF KEY COMPROMISED)                          |
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
