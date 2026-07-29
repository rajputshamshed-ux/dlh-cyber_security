================================================================================
                    CRYPTOGRAPHIC ATTACK SURFACE - MEDDEFENSE HEALTH SYSTEMS
                    Task 16: The Cryptographic Attack Surface
================================================================================

Exercise: Task 16 - The Cryptographic Attack Surface
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Map six cryptographic attack types to MedDefense's specific
          weaknesses. Determine which attacks are viable today and which
          specific controls would neutralize them.

Sources: 1x02 Vulnerability Findings, 1x03 Risk Register, T6 Algorithm Analysis,
         T10 TLS Configuration, T11 PKI Audit, 1x00 Network Topology


================================================================================
PART 1: ATTACK SURFACE MAPPING
================================================================================


----------------------------------------------------------------------
ATTACK 1: TLS DOWNGRADE ATTACK
----------------------------------------------------------------------

Attack:             TLS Downgrade Attack (forcing TLS 1.0 on the patient portal)

Mechanism:          In a downgrade attack, an on-path attacker intercepts the
                    TLS handshake between the client (patient browser) and the
                    server (patient-portal-srv-01) and strips or modifies the
                    supported protocol versions advertised. The attacker forces
                    both parties to negotiate the weakest mutually supported
                    protocol — in this case, TLS 1.0. Since TLS 1.0 is
                    vulnerable to BEAST (2011), POODLE (2014), and does not
                    support authenticated encryption (AEAD), the attacker can
                    then decrypt, modify, or inject data into the session. The
                    patient never sees any warning; the connection appears
                    "secure" with a padlock icon.

MedDefense          The patient-portal-srv-01 web server currently supports
Vulnerability:      and accepts TLS 1.0 connections. The server does not
                    enforce a minimum protocol version, nor does it use
                    TLS_FALLBACK_SCSV to prevent protocol downgrade.
                    Additionally, the server lacks HTTP Strict Transport
                    Security (HSTS), so an attacker can first strip the HTTPS
                    to HTTP entirely.

Evidence:           1x02-F001: Patient Portal Running TLS 1.0
                    1x02-F005: TLS Certificate Expiring in < 18 days
                    T10 TLS Configuration Analysis: Server accepts
                    TLSv1.0, TLSv1.1, TLSv1.2. No HSTS header.
                    Cipher suites include RC4-MD5 and
                    TLS_RSA_WITH_3DES_EDE_CBC_SHA.

Viable Today:       YES. Actively exploitable. Conditions are met:
                    1. Server accepts TLS 1.0.
                    2. No TLS_FALLBACK_SCSV protection.
                    3. No HSTS to prevent initial downgrade to HTTP.
                    4. On-path position achievable on MedDefense's flat
                       internal network (print-srv-01 already compromised,
                       providing internal pivot point).
                    5. BEAST/POODLE exploitation tools are public and mature
                       (e.g., sslstrip, BetterCap, mitmproxy).
                    An attacker on the internal network, on a public Wi-Fi
                    network used by a remote patient, or on any hop between
                    the patient and the portal can execute this attack today.

Mitigation:         IMMEDIATE CONTROLS (from T10, T11, CRYPTO-002):
                    1. Disable TLS 1.0 and TLS 1.1 on patient-portal-srv-01.
                       Enforce TLS 1.3 minimum (TLS 1.2 as temporary
                       fallback only).
                    2. Deploy HSTS with max-age=31536000 and includeSubDomains.
                    3. Enable TLS_FALLBACK_SCSV on the server to detect and
                       reject protocol downgrade attempts.
                    4. Replace the expiring certificate with a 256-bit ECDSA
                       certificate from Let's Encrypt with automated renewal.
                    5. Remove all CBC-mode and RC4 cipher suites. Use only
                       AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305).


----------------------------------------------------------------------
ATTACK 2: COLLISION ATTACK (MD5 IN KERBEROS)
----------------------------------------------------------------------

Attack:             Collision Attack (exploiting MD5 in Kerberos tickets)

Mechanism:          A cryptographic hash collision occurs when two different
                    inputs produce the same hash output. MD5 is broken for
                    collision resistance: attackers can craft two distinct
                    messages with the same MD5 hash in seconds on commodity
                    hardware. In Kerberos, certain legacy encryption types
                    (specifically RC4-HMAC) use MD5 for checksum computation
                    in the Kerberos Authenticator. An attacker who can
                    generate a collision could craft a forged Authenticator
                    that passes the MD5 integrity check, allowing them to
                    impersonate a legitimate user to a service without knowing
                    the user's password. Additionally, MD5 is used in the
                    NTLM hash format, which underpins Kerberos when RC4 is
                    the negotiated etype.

MedDefense          MedDefense's Active Directory domain accepts DES-CBC-CRC
Vulnerability:      and RC4-HMAC as valid Kerberos encryption types. RC4-HMAC
                    uses MD5 in its cryptographic construction. Furthermore,
                    the domain functional level permits NTLM authentication
                    as a fallback, which also relies on MD4/MD5 hashing.
                    Any service account or user account that has an RC4
                    Kerberos ticket requested can have that ticket's integrity
                    mechanism attacked via MD5 collision techniques.

Evidence:           1x02-F007: Kerberos Accepts DES Encryption
                    T6 Algorithm Analysis: MD5 is classified as BROKEN.
                    Collision resistance: 2^18 operations (< 1 second on
                    modern hardware). Chosen-prefix collisions demonstrated
                    in practice since 2007 (Stevens et al.).
                    Active Directory assessment: RC4-HMAC and DES-CBC-CRC
                    encryption types enabled via Default Domain Policy.

Viable Today:       YES, with important nuance. Direct collision attacks on
                    Kerberos ticket integrity are complex and require specific
                    preconditions (chosen-prefix collision with the KDC's
                    response). However, the broader attack class is viable:
                    1. MD5 collisions are trivially generated (less than 1
                       second on a laptop CPU).
                    2. The presence of RC4 in Kerberos enables Kerberoasting
                       (see ATTACK 4), which is a direct consequence of weak
                       hashing in the ticket construction.
                    3. NTLM fallback (which uses MD4/MD5) is enabled, and
                       NTLM relay attacks leveraging hash weaknesses are
                       actively exploited in the wild.
                    The collision attack is less directly exploitable than
                    Kerberoasting, but its viability stems from the same root
                    cause: MD5/RC4 presence in the authentication stack.

Mitigation:         IMMEDIATE CONTROLS (from CRYPTO-005):
                    1. Disable RC4-HMAC and DES-CBC-CRC Kerberos encryption
                       types via Group Policy. Enforce AES256-CTS-HMAC-SHA1-96
                       and AES128-CTS-HMAC-SHA1-96 exclusively.
                    2. Disable NTLM authentication across the domain using
                       Group Policy: "Network security: Restrict NTLM".
                    3. Rotate all service account passwords and migrate to
                       Group Managed Service Accounts (gMSA) where supported.
                    4. Raise domain functional level to Windows Server 2016
                       or higher to enforce AES-only Kerberos and disable
                       legacy compatibility.


----------------------------------------------------------------------
ATTACK 3: BIRTHDAY ATTACK
----------------------------------------------------------------------

Attack:             Birthday Attack (theoretical — explain the math and
                    relevance)

Mechanism:          The birthday attack exploits the mathematical probability
                    of finding two inputs that hash to the same output,
                    based on the birthday paradox: in a room of only 23 people,
                    there is a >50% chance two share a birthday. Applied to
                    cryptography, if a hash function produces an n-bit output,
                    an attacker does not need 2^n attempts to find a collision.
                    They only need approximately 2^(n/2) attempts. For SHA-1
                    (160-bit output), finding a collision takes ~2^80
                    operations, not 2^160. For MD5 (128-bit), ~2^64 operations
                    — which is computationally feasible. For SHA-256 (256-bit),
                    a birthday attack requires ~2^128 operations, which is
                    currently infeasible with classical computing.

MedDefense          MedDefense uses SHA-1 in multiple legacy systems:
Vulnerability:      - TLS 1.0 on patient portal uses SHA-1 for MAC in some
                      cipher suites.
                    - VPN IPsec Phase 1 uses SHA-1 for integrity (1x02-F012).
                    - Internal PKI certificates may use SHA-1 signatures
                      (identified in T11 PKI Audit).
                    SHA-1 collisions are now practical: the SHAttered attack
                    (2017) demonstrated a full SHA-1 collision in 2^63.1
                    operations. This means an attacker can create two different
                    documents with the same SHA-1 hash, breaking digital
                    signature integrity for any system relying on SHA-1.

Evidence:           T6 Algorithm Analysis: SHA-1 collision resistance = 2^63
                    operations. SHAttered (CWI + Google, 2017) demonstrated
                    practical collision. Cost: ~$110,000 in cloud compute
                    at that time; estimated <$10,000 today.
                    T10 TLS Configuration: SHA-1 present in cipher suites.
                    T11 PKI Audit: Potential SHA-1 certificates in internal CA.
                    1x02-F012: VPN uses SHA-1 for integrity.

Viable Today:       YES, for SHA-1 specifically. A well-resourced attacker
                    (organized crime, nation-state) can generate SHA-1
                    collisions today. The cost has dropped from $110K (2017)
                    to an estimated $10K-$45K in 2026 cloud compute costs.
                    Impact at MedDefense:
                    - SHA-1 collision in a VPN handshake: attacker could
                      forge a valid IPsec packet with different payload but
                      same integrity hash, potentially injecting malicious
                      traffic into the inter-site tunnel.
                    - SHA-1 collision in a TLS certificate: attacker could
                      obtain a certificate for patient-portal.meddefense.com
                      from a CA still accepting SHA-1 signatures (rare but
                      possible with internal CA).
                    NOT viable for SHA-256. The 2^128 birthday bound remains
                    far beyond current computational capacity, even with
                    nation-state resources.

Mitigation:         CONTROLS (from CRYPTO-005, CRYPTO-007):
                    1. Replace all SHA-1 usage with SHA-256 or SHA-384.
                       - TLS: Migrate to TLS 1.3 (SHA-384 mandatory).
                       - VPN: Enforce SHA-384 for IPsec integrity.
                       - PKI: Reissue all internal certificates with SHA-256
                         signature algorithm.
                    2. Audit entire certificate inventory for SHA-1 signatures
                       (completed in T11 PKI Audit). Revoke any found.
                    3. Enforce SHA-256 minimum in all cryptographic policy
                       settings across the domain (Group Policy: "System
                       cryptography: Use FIPS 140 compliant algorithms").


----------------------------------------------------------------------
ATTACK 4: KERBEROASTING
----------------------------------------------------------------------

Attack:             Kerberoasting (exploiting RC4/DES in Kerberos for offline
                    cracking)

Mechanism:          Kerberoasting is a post-exploitation attack against
                    Kerberos service accounts. Any authenticated domain user
                    (even a low-privileged one) can request a Ticket Granting
                    Service (TGS) ticket for any Service Principal Name (SPN)
                    in the domain. The TGS ticket is encrypted with the
                    service account's NTLM hash (derived from its password).
                    The attacker extracts this encrypted ticket portion and
                    takes it offline to perform a brute-force or dictionary
                    attack against it. If the service account has a weak
                    password, the attacker cracks the hash, obtains the
                    plaintext password, and now has the privileges of that
                    service account — which is often a Domain Admin.

                    When RC4 or DES is the negotiated encryption type for the
                    ticket, the cracking process is dramatically faster:
                    - DES: 56-bit key, bruteforceable in < 24 hours on a
                      single GPU. Effectively instant with rainbow tables.
                    - RC4: The NTLM hash is an unsalted MD4 hash. GPU cracking
                      rates exceed 100 billion attempts per second (hashcat
                      benchmark on RTX 4090: ~110 GH/s for NTLM). An 8-character
                      password falls in minutes.
                    - AES: AES-256 keys are not directly derivable from
                      passwords in the same way, and the AES cipher itself
                      is resistant to GPU acceleration. Cracking is orders
                      of magnitude slower.

MedDefense          MedDefense's Active Directory domain explicitly allows
Vulnerability:      DES-CBC-CRC and RC4-HMAC as valid Kerberos encryption
                    types. Multiple service accounts exist for critical
                    services (SQL Server on ehr-db-01, MySQL on billing-srv-01,
                    backup service account for NAS-01). Password policies
                    for service accounts are unknown and likely weak (no
                    evidence of mandatory 25+ character passwords or managed
                    service accounts). An attacker who has gained an initial
                    foothold (e.g., on the compromised print-srv-01) can
                    execute Kerberoasting without any special privileges.

Evidence:           1x02-F007: Kerberos Accepts DES Encryption
                    1x02-F006: print-srv-01 Compromised (Windows Server 2012
                    R2 EOL, no security patches) — provides initial foothold
                    for a domain-authenticated user.
                    T6 Algorithm Analysis: DES (56-bit) broken since 1999.
                    RC4 considered weak, biased keystream. MD4 (NTLM) is
                    collision-broken and trivially fast to crack on GPU.
                    Active Directory: RC4-HMAC and DES-CBC-CRC etypes enabled.
                    Service accounts identified: svc_sql, svc_backup, svc_mysql,
                    svc_pacs. Password complexity and length unknown.

Viable Today:       YES. Extremely viable. This is one of the most common
                    attack paths in Active Directory environments:
                    1. An attacker on print-srv-01 has a domain user context
                       (even a low-privileged one).
                    2. They run Invoke-Kerberoast (PowerShell Empire) or
                       Rubeus.exe to request TGS tickets for all SPNs.
                    3. They extract the RC4-encrypted ticket hashes.
                    4. They run hashcat against the hashes on a cloud GPU
                       instance (cost: ~$2-5/hour for a multi-GPU node).
                    5. Weak service account passwords crack in minutes to hours.
                    6. Cracked service account credentials provide privileged
                       access to ehr-db-01, NAS-01, or other critical systems.
                    This attack requires NO privilege escalation, NO
                    administrator rights, and NO special network position.
                    It is a feature abuse, not a vulnerability exploit.

Mitigation:         IMMEDIATE CONTROLS (from CRYPTO-005, T14 Key Management):
                    1. Disable RC4-HMAC and DES-CBC-CRC Kerberos encryption
                       types via Group Policy. Enforce AES256 ONLY.
                       This does not prevent Kerberoasting entirely, but it
                       forces AES encryption on the ticket, which is
                       computationally infeasible to crack offline.
                    2. Implement Group Managed Service Accounts (gMSA) for all
                       services. gMSA passwords are automatically rotated
                       every 30 days by Active Directory and are 240+ characters
                       of random entropy — effectively uncrackable.
                    3. For service accounts that cannot use gMSA, enforce a
                       minimum 25-character password with full character set,
                       rotated every 30 days.
                    4. Monitor for Kerberoasting activity: Windows Event ID
                       4769 with RC4 encryption type is a detection signal.
                    5. Implement tiered administration (Active Directory Tier
                       Model) so that service accounts do not have Domain Admin
                       privileges.


----------------------------------------------------------------------
ATTACK 5: ON-PATH / MAN-IN-THE-MIDDLE ON UNENCRYPTED CHANNELS
----------------------------------------------------------------------

Attack:             On-Path / Man-in-the-Middle (MITM) on Unencrypted Channels

Mechanism:          An attacker positioned on the same network segment as the
                    target traffic can passively intercept (sniff) or actively
                    modify (inject) data when communications are unencrypted.
                    On a flat network, ARP spoofing or switch MAC table
                    flooding allows the attacker to redirect traffic through
                    their machine, acting as an invisible proxy. Any protocol
                    that transmits data in cleartext — HTTP, DICOM, SQL without
                    TLS, SMBv1, LDAP simple bind — exposes all data to the
                    attacker without any need to break cryptography. There is
                    simply no cryptography to break.

MedDefense          MedDefense has multiple unencrypted channels on its flat
Vulnerability:      internal network (documented in 1x00 Network Topology and
                    1x02 Findings):
                    1. DICOM traffic between MRI workstation (10.10.10.45)
                       and PACS server (10.10.10.50) flows unencrypted on
                       TCP port 11112. All medical images and embedded PHI
                       in DICOM headers are transmitted in cleartext.
                    2. Database connections from application servers to
                       ehr-db-01 and billing-srv-01 may use unencrypted
                       connections (no TLS, no PostgreSQL SSL). Connection
                       strings observed with "sslmode=disable".
                    3. SMBv1 traffic between workstations and file servers
                       (including print-srv-01) is unencrypted and uses a
                       protocol with known remote code execution
                       vulnerabilities (EternalBlue, 2017).
                    4. The flat network topology (no VLAN segmentation,
                       single broadcast domain) means any device can ARP
                       spoof any other device.

Evidence:           1x02-F002: DICOM Traffic Unencrypted Between MRI and PACS
                    1x02-F004: PostgreSQL Database - No Encryption at Rest
                    1x02-F006: print-srv-01 Running EOL Windows Server 2012 R2
                    1x00 Network Topology: Flat /24 subnet, no VLANs, no
                    network segmentation, no 802.1X port security.
                    T10 TLS Configuration: Internal database connections
                    identified as unencrypted (port 5432, no SSL).

Viable Today:       YES. Actively exploitable. The attack requires an on-path
                    position, which is already achieved:
                    1. The compromised print-srv-01 (1x02-F006) provides a
                       persistent internal foothold on the same flat network
                       as every other device.
                    2. From print-srv-01, the attacker can ARP spoof the PACS
                       server's IP address, forcing all DICOM traffic through
                       their machine. They run tcpdump or Wireshark to capture
                       every medical image in transit.
                    3. Alternatively, they ARP spoof the database server and
                       capture all SQL queries and results in plaintext,
                       including SELECT * FROM patients.
                    4. No cryptography needs to be broken. No exploit is
                       needed. This is passive traffic interception on a
                       network with no encryption and no segmentation.
                    Tools required: arpspoof, tcpdump, BetterCap — all free
                    and pre-installed on Kali Linux.

Mitigation:         PHASE 1 CONTROLS (from CRYPTO-004, Network Segmentation
                    from 1x03 Security Strategy):
                    1. Enable DICOM TLS on PACS server and MRI workstation
                       with mutual certificate authentication (TLS 1.2
                       minimum, AES-256-GCM).
                    2. Enforce PostgreSQL SSL/TLS for all database connections.
                       Set "sslmode=verify-full" in all connection strings.
                       Require client certificates for database access.
                    3. Disable SMBv1 entirely across the domain. Enforce
                       SMBv3 with encryption enabled.
                    4. Implement network segmentation (VLANs): separate
                       Clinical Devices VLAN, Server VLAN, User Workstation
                       VLAN, and Guest VLAN. Apply ACLs between segments.
                    5. Deploy 802.1X port-based network access control to
                       prevent unauthorized devices from connecting to the
                       internal network.
                    6. Remove print-srv-01 from the network immediately
                       (compromised, EOL, unpatchable).


----------------------------------------------------------------------
ATTACK 6: KEY RECOVERY FROM MEMORY
----------------------------------------------------------------------

Attack:             Key Recovery from Memory (Cold Boot / Memory Dump Attack)

Mechanism:          Encryption keys must exist in RAM in plaintext while in
                    use. When an application performs AES encryption, the AES
                    key schedule (expanded round keys derived from the master
                    key) resides in CPU registers and L1/L2/L3 cache during
                    active encryption operations, and may be present in main
                    memory (RAM) if the key material is loaded by the
                    application. An attacker with root/administrator access
                    can:
                    1. Dump the process memory of the database service
                       (e.g., postgres, mysqld) using ptrace, /proc/pid/mem,
                       or gcore.
                    2. Scan the memory dump for AES key schedules using tools
                       like aeskeyfind or bulk_extractor. AES key schedules
                       have a distinctive mathematical structure that is
                       identifiable in memory.
                    3. Extract the master encryption key or data encryption
                       keys directly from the RAM dump.
                    4. Use the extracted keys to decrypt all data at rest,
                       completely bypassing the encryption.

                    This attack neutralizes the protection of disk encryption,
                    database TDE, and file-level encryption if the keys are
                    present in memory and the attacker has root.

MedDefense          Once database encryption is deployed (CRYPTO-001), the
Vulnerability:      PostgreSQL TDE master key or DEKs will be loaded into
                    the PostgreSQL server process memory (postgres) on
                    ehr-db-01 and billing-srv-01. If an attacker gains root
                    access to these servers (e.g., via Kerberoasted service
                    account with local admin privileges, or via the
                    compromised print-srv-01 pivoting with captured
                    credentials), they can:
                    1. Dump the postgres process memory.
                    2. Extract the AES key schedule.
                    3. Use the extracted key to decrypt the database files.
                    The same applies to LUKS keys on NAS-01: if an attacker
                    has root on the NAS while the volume is mounted, they
                    can extract the LUKS master key from kernel memory using
                    dmsetup table --showkeys.

Evidence:           T6 Algorithm Analysis: AES-256 is cryptographically
                    secure. The vulnerability is not in the algorithm but
                    in key storage in memory. AES key schedules are well-
                    known structures identifiable in memory dumps.
                    T14 Key Management Plan: Recommends HSM for master key
                    storage. If the master key is in an HSM, the plaintext
                    key never enters server RAM — only the HSM's secure
                    memory. The application sends ciphertext to the HSM
                    and receives plaintext back, never seeing the key.
                    Active Directory: Kerberoasting (ATTACK 4) provides a
                    direct path to service account compromise, which may
                    have local administrator privileges on database servers.

Viable Today:       YES, after initial compromise. This is a post-exploitation
                    attack requiring root/administrator access. Viability
                    depends on:
                    1. Root access achieved? YES — Kerberoasting (ATTACK 4)
                       provides credentials for service accounts. The
                       compromised print-srv-01 provides an internal pivot
                       point. Lateral movement to ehr-db-01 is feasible.
                    2. Encryption deployed? SOON — Phase 1 deploys TDE on
                       ehr-db-01. Without proper key protection (HSM), the
                       keys are in postgres process memory.
                    3. Key extraction tools exist? YES — aeskeyfind,
                       bulk_extractor, and volatility3 are mature and
                       reliable for AES key schedule identification.
                    Current state: Encryption not yet deployed, so attack
                    is moot. Post-Phase 1 (without HSM): ATTACK VIABLE.
                    Post-Phase 1 (with HSM): ATTACK MITIGATED — the HSM
                    stores the master key; it never enters server RAM.
                    The server only sees DEKs, which are short-lived and
                    can be further protected.

Mitigation:         PHASE 1/2 CONTROLS (from T14 Key Management):
                    1. Deploy HSM (Hardware Security Module) for database
                       master key storage. The master key is generated,
                       stored, and used entirely within the HSM's tamper-
                       resistant boundary. The database server never has
                       the master key in RAM. It sends ciphertext to the
                       HSM for decryption.
                    2. For LUKS keys on NAS-01, use TPM sealing so the key
                       is released only during early boot and is protected
                       from userspace memory extraction.
                    3. Harden the database servers to prevent root compromise:
                       - Remove unnecessary local administrators.
                       - Implement Just-In-Time (JIT) privileged access.
                       - Deploy EDR (Endpoint Detection and Response) to
                         detect memory dumping tools (ptrace, gcore).
                    4. Enable Secure Boot and kernel lockdown on all servers
                       to prevent unsigned kernel modules (which can be used
                       to extract memory via /dev/mem).
                    5. Encrypt swap space to prevent keys from being written
                       to disk in plaintext if memory is swapped out.
                    6. Use AMD SEV or Intel SGX secure enclaves for the most
                       sensitive cryptographic operations, where the key
                       material is encrypted even within the CPU.


================================================================================
PART 2: ATTACK VIABILITY SUMMARY
================================================================================

+---------------------+----------+-----------------+------------------------------------------+
| Attack              | Viable   | Exploitation    | Primary Mitigation                       |
|                     | Today?   | Difficulty      |                                          |
+---------------------+----------+-----------------+------------------------------------------+
| TLS Downgrade       | YES      | LOW             | Disable TLS 1.0, enable TLS 1.3 + HSTS   |
| (Patient Portal)    |          | Public tools    | (CRYPTO-002)                             |
+---------------------+----------+-----------------+------------------------------------------+
| Collision Attack    | YES      | MODERATE        | Disable RC4/DES in Kerberos, enforce     |
| (MD5 in Kerberos)   |          | Specialized     | AES256 (CRYPTO-005)                      |
+---------------------+----------+-----------------+------------------------------------------+
| Birthday Attack     | YES for  | MODERATE-HIGH   | Replace SHA-1 with SHA-256/384 across    |
| (SHA-1)             | SHA-1    | ($10K-$45K)     | TLS, VPN, PKI (CRYPTO-002, 005, 007)    |
+---------------------+----------+-----------------+------------------------------------------+
| Kerberoasting       | YES      | VERY LOW        | Disable RC4, enforce AES Kerberos, gMSA  |
| (RC4/DES Kerberos)  |          | No privs needed | (CRYPTO-005)                             |
+---------------------+----------+-----------------+------------------------------------------+
| On-Path MITM        | YES      | VERY LOW        | TLS for all channels, network segment-   |
| (DICOM, SQL, SMB)   |          | ARP spoofing    | ation, 802.1X (CRYPTO-004)              |
+---------------------+----------+-----------------+------------------------------------------+
| Key Recovery        | POST-    | MODERATE        | HSM for master keys, TPM sealing,        |
| from Memory         | PHASE 1  | (after root)    | memory hardening (T14 Key Mgmt)          |
+---------------------+----------+-----------------+------------------------------------------+


================================================================================
PART 3: CRITICAL ATTACK PATH ANALYSIS
================================================================================

The most dangerous combined attack path at MedDefense today:

STEP 1: INITIAL FOOTHOLD
    Attacker leverages compromised print-srv-01 (1x02-F006) which already
    has a domain user session. No exploit needed. Foothold exists TODAY.

STEP 2: KERBEROASTING (ATTACK 4)
    From print-srv-01, attacker runs Kerberoast. Requests TGS tickets for
    svc_sql, svc_backup, svc_mysql. Extracts RC4-encrypted ticket hashes.
    Cracks weak service account passwords on cloud GPU in minutes to hours.
    Now has credentials for privileged service accounts.

STEP 3: ON-PATH INTERCEPTION (ATTACK 5)
    Using svc_sql credentials, attacker accesses ehr-db-01 with local admin
    rights. Alternatively, uses ARP spoofing to position as on-path for
    DICOM traffic. Captures all unencrypted medical images and database
    queries. Exfiltrates PHI in plaintext.

STEP 4: IF ENCRYPTION DEPLOYED — KEY RECOVERY (ATTACK 6)
    If TDE is deployed without HSM, attacker dumps postgres process memory
    from ehr-db-01, extracts AES key schedule, decrypts all patient data.

STEP 5: PERSISTENCE & EXFILTRATION
    Attacker exfiltrates 50,000 patient records. Total breach cost: $24.95M.

ENTIRE ATTACK CHAIN VIABILITY: ALL STEPS VIABLE TODAY.
TIME TO COMPLETE: HOURS (not days or weeks).
DETECTION LIKELIHOOD: LOW (no network monitoring, no EDR, flat network).


================================================================================
REFERENCES
================================================================================

- 1x02 Vulnerability Assessment Findings (F001, F002, F004, F005, F006, F007, F012)
- 1x03 Risk Register (R-004, R-007, R-003, R-009, R-012)
- T6 Algorithm Analysis (AES-256, SHA-256, MD5, DES, RC4)
- T10 TLS Configuration Analysis (Patient Portal)
- T11 PKI Audit (Certificate Inventory)
- T14 Key Management Plan (HSM, TPM, Key Storage)
- 1x00 Network Topology (Flat Network Diagram)
- SHAttered: First SHA-1 Collision (CWI + Google, 2017)
- Kerberoasting: Tim Medin, DerbyCon 2014
- Cold Boot Attacks: Halderman et al., 2008


================================================================================
END OF CRYPTOGRAPHIC ATTACK SURFACE REPORT
================================================================================
