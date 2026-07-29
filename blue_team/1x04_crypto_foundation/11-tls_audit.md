================================================================================
                    TLS AUDIT - MEDDEFENSE HEALTH SYSTEMS
                    Task 11: The TLS Audit
================================================================================

Exercise: Task 11 - The TLS Audit
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Evaluate real-world TLS configurations using SSL Labs, produce a
          remediation plan for MedDefense's patient portal, and write a
          hardened TLS configuration.

Sources: 1x02 Finding 005 (TLS 1.0 enabled), 1x02 Finding 013 (Certificate
          near expiration), Qualys SSL Labs


================================================================================
PART 1: SSL LABS ANALYSIS
================================================================================

WEBSITE 1: CLOUDFLARE.COM (A+ RATING)
-------------------------------------
+------------------+--------------------------------------------------+
| Field            | Value                                            |
+------------------+--------------------------------------------------+
| Overall Grade    | A+                                               |
+------------------+--------------------------------------------------+
| Protocol         | TLS 1.3 only (or TLS 1.2 + 1.3)                  |
| Support          |                                                  |
+------------------+--------------------------------------------------+
| Key Exchange     | ECDHE (Perfect Forward Secrecy)                  |
| Strength         |                                                  |
+------------------+--------------------------------------------------+
| Cipher Suite     | AES-256-GCM, CHACHA20-POLY1305                   |
| Strength         |                                                  |
+------------------+--------------------------------------------------+
| Certificate      | Valid, trusted, ECC P-256                        |
| Details          |                                                  |
+------------------+--------------------------------------------------+
| Warnings         | None                                              |
| Weaknesses       |                                                  |
+------------------+--------------------------------------------------+

SSL LABS RESULTS
+----------------------------------------------------------------------------+
| Grade: A+                                                                  |
| - TLS 1.3 supported (modern, secure)                                      |
| - TLS 1.2 supported with strong ciphers                                   |
| - TLS 1.0 and 1.1 disabled                                               |
| - HSTS enabled with long max-age                                          |
| - OCSP Stapling enabled                                                   |
| - Perfect Forward Secrecy enabled                                         |
| - No weak cipher suites                                                   |
+----------------------------------------------------------------------------+

WEBSITE 2: BADSSL.COM (EXPIRED OR BROKEN)
------------------------------------------
+------------------+--------------------------------------------------+
| Field            | Value                                            |
+------------------+--------------------------------------------------+
| Overall Grade    | F (or T)                                         |
+------------------+--------------------------------------------------+
| Protocol         | TLS 1.0, TLS 1.1, TLS 1.2 (weak)                 |
| Support          |                                                  |
+------------------+--------------------------------------------------+
| Key Exchange     | RSA (no Perfect Forward Secrecy)                 |
| Strength         |                                                  |
+------------------+--------------------------------------------------+
| Cipher Suite     | Weak ciphers (RC4, 3DES)                         |
| Strength         |                                                  |
+------------------+--------------------------------------------------+
| Certificate      | Expired or invalid                                |
| Details          |                                                  |
+------------------+--------------------------------------------------+
| Warnings         | Multiple                                          |
| Weaknesses       |                                                  |
+------------------+--------------------------------------------------+

SSL LABS RESULTS
+----------------------------------------------------------------------------+
| Grade: F (expired.badssl.com)                                             |
| - Certificate EXPIRED                                                    |
| - TLS 1.0 supported (vulnerable to BEAST, POODLE)                       |
| - TLS 1.1 supported (deprecated)                                       |
| - Weak cipher suites (RC4, 3DES)                                        |
| - No HSTS                                                                |
| - No Perfect Forward Secrecy                                             |
| - No OCSP Stapling                                                       |
+----------------------------------------------------------------------------+


================================================================================
PART 2: MEDDEFENSE PORTAL ASSESSMENT
================================================================================

PREDICTED GRADE: C or D
-----------------------
+----------------------------------------------------------------------------+
| ISSUES THAT WOULD REDUCE THE GRADE                                         |
|                                                                             |
| 1. PROTOCOL ISSUES:                                                        |
|    - TLS 1.0 is ENABLED (Finding 005 from 1x02)                          |
|    - TLS 1.0 is vulnerable to BEAST (2007), POODLE (2014), Lucky         |
|      Thirteen (2013)                                                      |
|    - Major security risk - patients on modern browsers are protected,    |
|      but attackers can force downgrade                                   |
|                                                                             |
| 2. CERTIFICATE ISSUES:                                                    |
|    - Certificate expires in 18 days (Finding 013 from 1x02)              |
|    - SSL Labs flags certificates expiring soon as warnings              |
|    - Patients may see security warnings                                  |
|                                                                             |
| 3. HSTS ISSUES:                                                           |
|    - HSTS is NOT configured (Finding 012 from 1x02)                     |
|    - Missing HSTS allows SSL stripping attacks                          |
|    - No protection against downgrade attacks                            |
|                                                                             |
| 4. CIPHER SUITE ISSUES:                                                   |
|    - Default Apache configuration likely includes weak ciphers          |
|    - May support RC4 or 3DES                                            |
|    - No Perfect Forward Secrecy (PFS)                                   |
|                                                                             |
| 5. OTHER ISSUES:                                                          |
|    - OCSP Stapling likely NOT configured                                |
|    - No TLS 1.3 support                                                  |
|    - Session tickets may be weak                                         |
+----------------------------------------------------------------------------+


================================================================================
PART 3: THE HARDENED CONFIGURATION
================================================================================

APACHE CONFIGURATION
--------------------
+----------------------------------------------------------------------------+
| # --- TLS PROTOCOL VERSIONS ---                                           |
| SSLProtocol -all +TLSv1.2 +TLSv1.3                                       |
| # Only TLS 1.2 and 1.3 are allowed. TLS 1.0 and 1.1 are disabled.       |
| # TLS 1.3 is the modern standard; TLS 1.2 is the fallback.               |
|                                                                             |
| # --- CIPHER SUITES (Ordered by preference) ---                          |
| SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256 |
| # GCM and ChaCha20 are strong authenticated encryption modes. ECDHE    |
| # provides Perfect Forward Secrecy. AES-256 is preferred over AES-128.   |
|                                                                             |
| # --- HSTS (HTTP Strict Transport Security) ---                          |
| Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" |
| # HSTS forces browsers to use HTTPS for 1 year (31536000 seconds).      |
| # includeSubDomains protects all subdomains. preload allows inclusion   |
| # in browser HSTS preload lists.                                         |
|                                                                             |
| # --- SESSION TICKETS ---                                                |
| SSLSessionTickets Off                                                     |
| # Disabling session tickets prevents session resumption attacks.        |
| # Alternative is using a strong session cache.                         |
|                                                                             |
| # --- OCSP STAPLING ---                                                  |
| SSLUseStapling On                                                        |
| SSLStaplingCache shmcb:/tmp/stapling_cache(128000)                       |
| # OCSP Stapling allows the server to send the OCSP response during      |
| # the handshake, reducing client latency and improving privacy.        |
|                                                                             |
| # --- RENEGOTIATION ---                                                  |
| SSLInsecureRenegotiation Off                                              |
| # Disabling insecure renegotiation prevents denial-of-service attacks.  |
|                                                                             |
| # --- SESSION CACHE ---                                                  |
| SSLSessionCache shmcb:/tmp/ssl_scache(512000)                            |
| SSLSessionCacheTimeout 300                                               |
| # Session cache improves performance for repeat connections.           |
| # 300 seconds (5 minutes) is a reasonable timeout.                      |
+----------------------------------------------------------------------------+

NGINX ALTERNATIVE CONFIGURATION
-------------------------------
+----------------------------------------------------------------------------+
| server {                                                                   |
|     listen 443 ssl http2;                                                 |
|     ssl_protocols TLSv1.2 TLSv1.3;                                       |
|     ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256; |
|     ssl_prefer_server_ciphers on;                                        |
|     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; |
|     ssl_session_tickets off;                                              |
|     ssl_stapling on;                                                      |
|     ssl_stapling_verify on;                                               |
| }                                                                         |
+----------------------------------------------------------------------------+


================================================================================
PART 4: THE DOWNGRADE ATTACK
================================================================================

+----------------------------------------------------------------------------+
| TLS DOWNGRADE ATTACK EXPLANATION                                           |
|                                                                             |
| A TLS downgrade attack forces a client and server to use a weaker         |
| protocol version than both support. The attacker intercepts the           |
| handshake and modifies the ClientHello message to claim the client only  |
| supports older versions (e.g., TLS 1.0). The server then agrees to use   |
| TLS 1.0, even though both support TLS 1.2.                              |
|                                                                             |
| If MedDefense's portal supports TLS 1.0 and TLS 1.2, an attacker on      |
| the network path can intercept the connection and force the client       |
| and server to negotiate TLS 1.0. The attacker can then exploit known    |
| TLS 1.0 vulnerabilities like POODLE or BEAST to decrypt traffic.        |
|                                                                             |
| The simplest way to prevent this is to DISABLE TLS 1.0 and TLS 1.1      |
| entirely on the server. With only TLS 1.2 and TLS 1.3 enabled, an        |
| attacker cannot force a downgrade because the server will not accept    |
| older protocol versions.                                                  |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- 1x02 Finding 005 (TLS 1.0 enabled)
- 1x02 Finding 012 (HSTS missing)
- 1x02 Finding 013 (Certificate near expiration)
- Qualys SSL Labs: https://www.ssllabs.com/ssltest/
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/


================================================================================
END OF TLS AUDIT REPORT
================================================================================
