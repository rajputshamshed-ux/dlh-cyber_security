================================================================================
                    THE CRYPTO EMERGENCY - CRIMSON TIDE vs. MEDDEFENSE
                    Task 4: The Crypto Emergency
================================================================================

Exercise: Task 4 - The Crypto Emergency
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Identify the specific cryptographic weaknesses that Crimson Tide
          exploits and prioritize the crypto remediations from 1x04 that
          address this attack. Answer the critical question: if the database
          had been encrypted, would the attack still succeed?

Sources: 1x04 T0 Data Protection Map, 1x04 T6 Algorithm Analysis, 1x04 T10
         TLS Configuration, 1x04 T13 Encryption Levels, 1x04 T14 Key
         Management Plan, 1x04 T15 Crypto Posture Audit (CRYPTO-001 through
         CRYPTO-010), 1x04 T16 Attack Surface, 1x04 T17 Certificate Lifecycle,
         1x04 T18 Data Classification, 1x04 T19 HIPAA Checkpoint,
         1x04 T20 Implementation Playbook, 1x05 T0 Advisory Analysis,
         1x05 T1 CVE Deep Dive, 1x05 T2 Kill Chain Overlay


================================================================================
PART 1: CRYPTO ATTACK SURFACE MAPPING
================================================================================

For each Crimson Tide phase that exploits a cryptographic weakness
(or where a crypto control would have prevented the phase).

----------------------------------------------------------------------
PHASE 2: CREDENTIAL ACCESS - KERBEROASTING + NTDS.DIT DUMP
----------------------------------------------------------------------

Phase:              PHASE 2 - Credential Access (Kerberoasting, NTDS.dit
                    dump, offline password cracking)

Crypto Weakness:    CRYPTO-005 (T15): Kerberos Accepts DES and RC4-HMAC
                    encryption types. Domain-wide policy permits weak
                    symmetric encryption for Kerberos tickets.
                    T16 Attack 4: Kerberoasting viable due to RC4
                    Kerberos etypes.

What Crimson Tide   Kerberos authentication in Active Directory uses
Exploits:           symmetric encryption to protect Ticket Granting
                    Service (TGS) tickets. When RC4-HMAC is the negotiated
                    encryption type, the ticket is encrypted with the
                    service account's NTLM hash (unsalted MD4 of the
                    password). Crimson Tide requests TGS tickets for all
                    Service Principal Names (SPNs) in the domain. They
                    extract the RC4-encrypted ticket portions and crack
                    them OFFLINE on GPU hardware at 100+ billion hashes
                    per second. Weak service account passwords crack in
                    minutes to hours. The cracked credentials provide
                    privileged access (often Domain Admin) because service
                    accounts are frequently over-provisioned.

                    Additionally, DES encryption is EVEN WEAKER (56-bit
                    key, crackable in minutes on a single GPU). The
                    presence of DES as a supported etype allows attackers
                    to DOWNGRADE the Kerberos encryption to the weakest
                    possible option, accelerating cracking further.

                    The underlying crypto failure: MedDefense uses
                    SYMMETRIC ENCRYPTION with keys derived from HUMAN-
                    MEMORABLE PASSWORDS (via unsalted MD4 hashing) to
                    protect authentication material. This is a
                    cryptographic design failure: passwords are low-
                    entropy secrets, and MD4 is a broken hash function.

Recommended         CRYPTO-005 REMEDIATION (T15):
Crypto Fix:         IMMEDIATE: Disable DES-CBC-CRC, DES-CBC-MD5, and
                    RC4-HMAC encryption types in Active Directory via
                    Group Policy. Enforce AES256-CTS-HMAC-SHA1-96
                    EXCLUSIVELY. Migrate all service accounts to Group
                    Managed Service Accounts (gMSA) with 240+ character
                    random passwords, rotated automatically every 30 days.

                    Per T20 Implementation Playbook Action #2.
                    Per T3 Emergency Plan Action T2-2.

Emergency           YES. This can be accelerated to 72 hours.
Timeline:           T2-2 is scheduled for 12-36 hours (Tier 2).
                    Prerequisites: Compromise assessment must be clean
                    (no active intrusion detected) before changing
                    Kerberos, as the change could alert an attacker and
                    trigger premature ransomware deployment.
                    Time to execute: 2 hours during maintenance window.
                    Risk: Legacy application authentication failures.
                    Mitigation: Pre-audit Kerberos event logs to identify
                    any systems using RC4/DES.

----------------------------------------------------------------------
PHASE 3: DATA COLLECTION - UNENCRYPTED PATIENT DATABASE
----------------------------------------------------------------------

Phase:              PHASE 3 - Data Collection (Exfiltration of patient
                    database, billing records, PACS images)

Crypto Weakness:    CRYPTO-001 (T15): Patient Records at Rest - PLAINTEXT.
                    No Transparent Data Encryption (TDE), no filesystem
                    encryption, no column-level encryption on ehr-db-01.
                    50,000 patient records stored in plaintext on disk.

                    CRYPTO-006 (T15): Financial Records at Rest - PLAINTEXT.
                    billing-srv-01 MySQL database stores SSNs and credit
                    card data without encryption.

                    CRYPTO-003 (T15): Backup Data at Rest - PLAINTEXT.
                    nas-01 stores complete copies of all ePHI on a
                    network share without LUKS or any encryption.

                    CRYPTO-004 (T15): Medical Images - UNENCRYPTED in
                    transit and at rest (DICOM headers contain embedded
                    PHI readable in plaintext).

What Crimson Tide   In 4 of 5 incidents documented in the CISA advisory,
Exploits:           Crimson Tide exfiltrated patient databases that were
                    stored WITHOUT ENCRYPTION AT REST. This is the
                    defining crypto failure of the campaign. The attackers
                    specifically targeted EHR systems, billing databases,
                    and backup repositories containing ePHI. Because the
                    data was plaintext on disk, exfiltration required
                    NO decryption step, NO key theft, NO cryptographic
                    attack whatsoever. The attacker simply copied files.

                    At MedDefense, the attack path is identical:
                    1. Attacker has Domain Admin (from Phase 2).
                    2. Attacker accesses ehr-db-01 via SMB, RDP, or SSH.
                    3. Attacker copies /var/lib/postgresql/15/data/ to
                       their staging server.
                    4. Attacker reads patient records, SSNs, diagnoses,
                       billing codes directly from the raw database files.
                    5. No encryption barrier exists. The cryptographic
                       protection level is ZERO.

                    The advisory states this explicitly: unencrypted
                    databases were the PRIMARY target and the PRIMARY
                    reason for catastrophic breach impact.

Recommended         CRYPTO-001 REMEDIATION (T15):
Crypto Fix:         IMMEDIATE: Deploy PostgreSQL TDE with AES-256-GCM
                    on ehr-db-01. Master encryption key stored in AWS KMS
                    with HSM backing. Envelope encryption: Data Encryption
                    Keys (DEKs) encrypted by the Customer Master Key (CMK)
                    in the HSM. The plaintext master key NEVER enters
                    ehr-db-01 RAM (only DEKs, which are short-lived).

                    CRYPTO-003 REMEDIATION: Deploy LUKS2 with AES-256-XTS
                    on nas-01 backup volume.

                    CRYPTO-006 REMEDIATION: Deploy MySQL InnoDB tablespace
                    encryption with AES-256-GCM on billing-srv-01.

                    Per T20 Implementation Playbook Actions #3 and #4.
                    Per T3 Emergency Plan Actions T2-3 and T3-1.

Emergency           PARTIALLY. Database TDE (T2-3) can be accelerated to
Timeline:           12-36 hours (Tier 2) during the planned maintenance
                    window. This is the HIGHEST PRIORITY crypto action.
                    NAS LUKS (T3-1) requires 36-72 hours due to backup
                    destruction and re-seeding time.
                    Full database encryption: achievable within 72 hours.
                    Full backup encryption: achievable within 72 hours
                    but backup re-seeding may extend to Day 4.

----------------------------------------------------------------------
PHASE 4: LATERAL MOVEMENT - UNENCRYPTED INTERNAL TRAFFIC
----------------------------------------------------------------------

Phase:              PHASE 4 - Lateral Movement (SMB, RDP, WinRM, SSH
                    across flat network)

Crypto Weakness:    CRYPTO-004 (T15): DICOM Traffic Unencrypted.
                    T16 Attack 5: On-Path MITM on unencrypted DICOM,
                    SMBv1, database connections (sslmode=disable).

                    T10 Analysis: Internal database connections use
                    unencrypted PostgreSQL protocol (port 5432, no SSL).
                    SMBv1 enabled on legacy servers (print-srv-01) with
                    no SMB encryption.

                    Network-level weakness: FLAT NETWORK TOPOLOGY
                    (1x00-GAP-001) means no cryptographic segmentation
                    between zones. No IPsec or MACsec between internal
                    segments because no segments exist.

What Crimson Tide   Crimson Tide leverages compromised credentials to
Exploits:           move laterally across the network using standard
                    administrative protocols: SMB for file access, RDP
                    for remote desktop, WinRM for PowerShell remoting,
                    and SSH for Linux systems. On MedDefense's flat
                    network, NONE of these protocols require encryption
                    at the network layer. SMBv1 (still enabled on
                    print-srv-01) has NO ENCRYPTION option whatsoever.
                    Even SMBv3 encryption is optional and not enforced.

                    The crypto failure is at multiple layers:
                    - Application layer: Database connections not
                      encrypted (no PostgreSQL SSL).
                    - Transport layer: SMBv1 has no encryption.
                    - Network layer: No IPsec between internal segments
                      (no segments to encrypt between).

                    An attacker with domain credentials can move freely
                    and all their lateral movement traffic is either
                    unencrypted (SMBv1) or uses the attacker's own
                    session encryption (RDP, SSH) which MedDefense
                    cannot inspect because there is no SSL inspection
                    and no network monitoring.

Recommended         CRYPTO-004 REMEDIATION (T15):
Crypto Fix:         PHASE 1: Enable DICOM TLS between MRI and PACS.
                    PHASE 1: Enforce PostgreSQL SSL/TLS (sslmode=verify-full)
                    for all database connections with client certificates.
                    PHASE 1: Disable SMBv1. Enforce SMBv3 with encryption.
                    PHASE 1: Deploy network segmentation (VLANs + ACLs).

                    Per T20 Implementation Playbook Action #5.
                    Per T3 Emergency Plan Actions T3-4 (DICOM TLS) and
                    T2-4 (Network segmentation planning).

Emergency           PARTIALLY. DICOM TLS (T3-4) and PostgreSQL SSL
Timeline:           enforcement are achievable within 72 hours.
                    Network segmentation is a 2-3 day configuration
                    project plus hardware procurement lead time.
                    Physical segmentation (VLANs) cannot be fully deployed
                    within 72 hours but PLANNING and PROCUREMENT (T2-4)
                    can be completed. Temporary network isolation
                    (disconnect print-srv-01 entirely, isolate critical
                    servers behind existing firewall rules on the
                    FortiGate) can be done within 72 hours.

----------------------------------------------------------------------
PHASE 6: DATA EXFILTRATION - ENCRYPTED CHANNELS
----------------------------------------------------------------------

Phase:              PHASE 6 - Data Exfiltration (Encrypted exfiltration
                    over TLS 1.3 and DNS-over-HTTPS)

Crypto Weakness:    IRONIC WEAKNESS: MedDefense FAILED to deploy strong
                    encryption internally (patient data plaintext,
                    Kerberos RC4, TLS 1.0 on portal), while the ATTACKER
                    USES strong encryption (TLS 1.3, DoH) to exfiltrate
                    data undetected.

                    Specific gaps:
                    - No SSL/TLS Decryption/Inspection on FortiGate
                      (1x00-GAP-008).
                    - No Data Loss Prevention (DLP) (1x00-GAP-009).
                    - No DNS monitoring (cannot detect DNS-over-HTTPS
                      tunneling to attacker C2).
                    - Patient portal itself uses TLS 1.0 (CRYPTO-002),
                      meaning MedDefense's OWN encryption is broken
                      while the attacker's encryption is state-of-the-art.

What Crimson Tide   Crimson Tide exfiltrates stolen data over ENCRYPTED
Exploits:           channels to blend with legitimate outbound traffic.
                    They use TLS 1.3 (the most secure TLS version) for
                    HTTPS exfiltration and DNS-over-HTTPS as an
                    alternative channel that bypasses traditional DNS
                    monitoring. Because MedDefense has no SSL inspection,
                    no DLP, and no C2 threat intelligence, the
                    exfiltration traffic is indistinguishable from
                    normal HTTPS browsing.

                    The crypto irony is profound: the attacker's use of
                    strong encryption (which MedDefense FAILED to deploy
                    for its own patient data) is what enables their
                    exfiltration to succeed undetected. If MedDefense
                    had deployed SSL inspection, the exfiltration could
                    be detected (though TLS 1.3 makes inspection more
                    complex due to Perfect Forward Secrecy). If
                    MedDefense had encrypted the database (Phase 3 fix),
                    the exfiltrated data would be USELESS ciphertext.

Recommended         CRYPTO-002 REMEDIATION (T15):
Crypto Fix:         IMMEDIATE: Deploy TLS 1.3 on patient portal with
                    automated certificate renewal (per T20 Action #1).
                    This doesn't directly block Phase 6 but improves
                    MedDefense's overall crypto posture.

                    DETECTION FIX (not crypto, but crypto-adjacent):
                    Deploy SSL/TLS Decryption/Inspection on FortiGate
                    (requires support contract renewal + configuration).
                    Deploy DLP rules to detect PHI patterns in outbound
                    traffic. Deploy DNS monitoring to detect DoH tunneling.
                    These are CG-004 and CG-005 from 1x03.

                    ULTIMATE FIX: Encrypt the database (Phase 3 fix).
                    If data is encrypted BEFORE exfiltration, the
                    attacker's strong exfiltration channel is irrelevant
                    — they are exfiltrating AES-256 ciphertext which
                    they cannot decrypt without the HSM-protected key.

Emergency           PARTIALLY. TLS 1.3 on portal (T3-2) is achievable
Timeline:           within 72 hours. SSL inspection and DLP are complex
                    configurations that require testing and tuning;
                    unlikely within 72 hours. DATABASE ENCRYPTION
                    (T2-3) is the crypto fix that neutralizes Phase 6
                    regardless of detection capability.

----------------------------------------------------------------------
PHASE 7: IMPACT - RANSOMWARE ENCRYPTION + DOUBLE EXTORTION
----------------------------------------------------------------------

Phase:              PHASE 7 - Impact (Ransomware encryption of local
                    files + double extortion threat to leak data)

Crypto Weakness:    CRYPTO-003 (T15): Backups stored in PLAINTEXT on
                    network-accessible NAS (nas-01). Ransomware can
                    encrypt the backups just as easily as production data,
                    destroying recovery capability.

                    CRYPTO-001 (T15): Patient database in PLAINTEXT.
                    If exfiltrated (Phase 3), the double extortion
                    threat ("pay us or we leak your patient data") has
                    MAXIMUM LEVERAGE because the leaked data is fully
                    readable by anyone.

                    NO IMMUTABLE BACKUPS: MedDefense has no WORM (Write
                    Once Read Many) or offline/air-gapped backup tier.
                    All backups are on a network-accessible NAS that
                    ransomware can encrypt.

What Crimson Tide   Crimson Tide deploys ransomware that encrypts files
Exploits:           using STRONG encryption (typically AES-256 + RSA-2048).
                    They target EHR systems (clinical impact), backup
                    repositories (destroys recovery), and PACS (imaging
                    impact) to maximize operational disruption and coerce
                    rapid ransom payment.

                    DOUBLE EXTORTION: Because Crimson Tide exfiltrated
                    the PLAINTEXT patient database in Phase 3, they have
                    a SECOND extortion lever: "Pay us, or we publish
                    your 50,000 patient records on the dark web." This
                    is devastating for a healthcare organization under
                    HIPAA. The data has ALREADY been exfiltrated; the
                    ransom for non-release is a separate payment from
                    the ransom for decryption.

                    The crypto failure enabling Phase 7 is two-fold:
                    1. No encryption at rest on backups → backups
                       encrypted by ransomware → no recovery.
                    2. No encryption at rest on database → exfiltrated
                       data is readable → double extortion works.

Recommended         CRYPTO-003 REMEDIATION (T15):
Crypto Fix:         IMMEDIATE: Deploy LUKS2 on nas-01 (T3-1).
                    PHASE 1: Deploy immutable/offline backups (T3-3).

                    CRYPTO-001 REMEDIATION (T15):
                    IMMEDIATE: Deploy PostgreSQL TDE on ehr-db-01 (T2-3).
                    If database is encrypted, exfiltrated data is
                    ciphertext, neutralizing the double extortion threat.

                    Per T20 Implementation Playbook Actions #3 and #4.
                    Per T3 Emergency Plan Actions T2-3 and T3-1 and T3-3.

Emergency           PARTIALLY. Physical NAS isolation (T1-2) is DONE
Timeline:           in 10 minutes (Tier 1). LUKS encryption on NAS (T3-1)
                    achievable within 72 hours. Immutable backup solution
                    (T3-3) achievable within 72 hours (cloud-based S3
                    Object Lock is faster than physical rotation).
                    Database encryption (T2-3) is THE fix for double
                    extortion — must be accelerated to 12-36 hours.


================================================================================
PART 2: ENCRYPTION PRIORITY RE-RANKING
================================================================================

ORIGINAL PRIORITY (from 1x04 T20 Implementation Playbook):

1. Action #1: Deploy TLS 1.3 on Patient Portal (CRYPTO-002)
2. Action #2: Disable DES/RC4 in Kerberos (CRYPTO-005)
3. Action #3: Deploy PostgreSQL TDE on ehr-db-01 (CRYPTO-001)
4. Action #4: Deploy LUKS on NAS-01 (CRYPTO-003)
5. Action #5: Enable DICOM TLS (CRYPTO-004)

UPDATED PRIORITY (based on Crimson Tide threat intelligence):

1. Action #3: Deploy PostgreSQL TDE on ehr-db-01 (CRYPTO-001)
   ↑ MOVED UP from #3 to #1
2. Action #2: Disable DES/RC4 in Kerberos (CRYPTO-005)
   ↔ REMAINS #2 (unchanged relative priority)
3. Action #1: Deploy TLS 1.3 on Patient Portal (CRYPTO-002)
   ↓ MOVED DOWN from #1 to #3
4. Action #4: Deploy LUKS on NAS-01 (CRYPTO-003)
   ↔ REMAINS #4 (unchanged)
5. Action #5: Enable DICOM TLS (CRYPTO-004)
   ↔ REMAINS #5 (unchanged)

REASONING FOR CHANGES:

CHANGE 1: PostgreSQL TDE moved from #3 to #1 (HIGHEST PRIORITY)
  Original rationale for #3: Patient portal certificate expiry (18 days)
  was the most time-critical crypto action. TLS 1.0 was a known
  vulnerability actively exploitable. TDE was a Phase 1 action with
  no immediate triggering event.

  UPDATED rationale for #1: The CISA advisory explicitly states that
  UNENCRYPTED PATIENT DATABASES were the primary target and primary
  cause of catastrophic breach in 4/5 Crimson Tide incidents. This is
  no longer a general "encryption best practice." It is a SPECIFIC,
  ACTIVE THREAT exploiting the EXACT vulnerability MedDefense has
  (plaintext patient database). The double extortion model means that
  even if MedDefense recovers from ransomware (via backups or paying
  the decryption ransom), the exfiltrated plaintext patient data gives
  the attacker a SECOND extortion lever.

  If MedDefense encrypts ehr-db-01 BEFORE Crimson Tide (or any copycat)
  breaches the perimeter:
  - Phase 3 exfiltration yields USELESS AES-256 ciphertext.
  - Double extortion threat is NEUTRALIZED (attacker cannot leak
    encrypted data for leverage).
  - HIPAA breach notification may still be required (data was accessed),
    but the actual PATIENT HARM from public data exposure is eliminated.
  - The $24.95M ALE from 1x03-R-004 drops to a fraction (cost of
    notification + credit monitoring, no data exposure damages).

  The patient portal certificate (18 days) remains critical but is
  OPERATIONAL (service availability) rather than DATA-CENTRIC (50,000
  patient records exposure). Service downtime is bad. Mass patient
  data exposure is existential. Data-centric > operational in priority.

CHANGE 2: Patient Portal TLS moved from #1 to #3
  The portal certificate expiry is still critical and still has an
  18-day hard deadline. But in the context of an ACTIVE RANSOMWARE
  CAMPAIGN targeting healthcare in the region, preventing the
  exfiltration of 50,000 patient records takes precedence over
  preventing a future service outage. The portal TLS upgrade is
  scheduled for 36-72 hours (Tier 3, Action T3-2), which is still
  well within the 18-day window. It is not downgraded in importance —
  it is deferred by 2 days to allow the data-centric crypto fixes
  to be deployed first.

UNCHANGED PRIORITIES:
  - Kerberos (Action #2) remains #2 because it blocks Phase 2
    (Credential Access), which is the prerequisite for Phase 3
    (Data Collection). You cannot exfiltrate the database if you
    cannot escalate to Domain Admin. Kerberos hardening + TDE are
    complementary controls that work together.
  - NAS LUKS (Action #4) remains after TDE because the NAS is
    physically isolated (T1-2) as a temporary control. TDE on the
    live database is more urgent than encryption on the already-
    isolated backups.
  - DICOM TLS (Action #5) remains lowest because it addresses a
    lower-impact attack vector (individual medical image sniffing)
    compared to mass database exfiltration.

SUMMARY TABLE:

+------+------------------+------------------+------------------+------------------+
| RANK | ORIGINAL         | UPDATED          | CHANGE           | REASON           |
|      | ACTION           | ACTION           |                  |                  |
+------+------------------+------------------+------------------+------------------+
|  1   | TLS 1.3 Portal   | PostgreSQL TDE   | MOVED UP (+2)    | CISA confirms    |
|      | (CRYPTO-002)     | (CRYPTO-001)     |                  | unencrypted DB   |
|      |                  |                  |                  | is primary target|
+------+------------------+------------------+------------------+------------------+
|  2   | Kerberos AES-256 | Kerberos AES-256 | UNCHANGED        | Blocks Phase 2   |
|      | (CRYPTO-005)     | (CRYPTO-005)     |                  | credential theft |
+------+------------------+------------------+------------------+------------------+
|  3   | PostgreSQL TDE   | TLS 1.3 Portal   | MOVED DOWN (-2)  | 18-day window    |
|      | (CRYPTO-001)     | (CRYPTO-002)     |                  | still has buffer |
+------+------------------+------------------+------------------+------------------+
|  4   | LUKS NAS-01      | LUKS NAS-01      | UNCHANGED        | NAS isolated     |
|      | (CRYPTO-003)     | (CRYPTO-003)     |                  | temporarily      |
+------+------------------+------------------+------------------+------------------+
|  5   | DICOM TLS        | DICOM TLS        | UNCHANGED        | Lower impact     |
|      | (CRYPTO-004)     | (CRYPTO-004)     |                  | vs. database     |
+------+------------------+------------------+------------------+------------------+


================================================================================
PART 3: THE "WHAT IF" CALCULATION
================================================================================

THE QUESTION:

If MedDefense's patient database had been encrypted at rest (as
recommended in 1x04 T13, PostgreSQL TDE with AES-256-GCM), what would
change about Phase 3 of the Crimson Tide attack? Would the data still
be exfiltratable? Under what conditions?

THE SCENARIO:

Assumptions:
  - ehr-db-01 has PostgreSQL TDE with AES-256-GCM deployed.
  - Database files on disk are encrypted at the tablespace level.
  - The attacker has achieved Domain Admin access (Phase 2 succeeded).
  - The attacker has root/SYSTEM access on ehr-db-01.
  - The database is RUNNING (mounted, decrypted for application access).

SCENARIO A: KEY IN HSM (RECOMMENDED ARCHITECTURE, T14 KEY MANAGEMENT)

  Architecture:    The TDE master key is stored in AWS KMS with HSM
                   backing. The master key NEVER enters ehr-db-01 RAM.
                   The PostgreSQL process uses envelope encryption:
                   - Data Encryption Keys (DEKs) are generated locally
                     for each tablespace.
                   - DEKs are encrypted ("wrapped") by the Customer
                     Master Key (CMK) in the HSM via KMS API calls.
                   - The wrapped DEKs are stored in the database header.
                   - At database startup, PostgreSQL calls KMS to unwrap
                     the DEKs. The DEKs are held in PostgreSQL process
                     memory for the session.
                   - The CMK never leaves the HSM.

  What the attacker can do:
    1. Attacker has root access to ehr-db-01.
    2. Attacker can attempt to dump PostgreSQL process memory to
       extract DEKs (T16 Attack 6: Key Recovery from Memory).
       DEKs are present in RAM while the database is running.
    3. If attacker successfully extracts DEKs from RAM, they can
       decrypt the tablespace files OFFLINE.
    4. Attacker can also query the database LIVE via the PostgreSQL
       protocol (they have credentials or can reset the postgres
       password with root access): SELECT * FROM patients.
       TDE does NOT protect against an attacker querying a LIVE,
       RUNNING database. TDE protects files at rest (stolen disk,
       offline backup theft), not live access.

  What the attacker CANNOT do:
    1. Copy the raw database files (/var/lib/postgresql/15/data/)
       and read them offline. The files are encrypted. Without the
       DEK (from RAM) or the CMK (from HSM), the files are AES-256
       ciphertext — computationally infeasible to decrypt.
    2. Access the CMK. It is in the HSM, accessible only via KMS API
       with the ehr-db-01 IAM role. The attacker can CALL the KMS API
       to unwrap DEKs (because they have root on the authorized instance),
       but they cannot EXTRACT the CMK itself.
    3. If KMS access is revoked (detected compromise → IAM role
       removed), the attacker loses the ability to unwrap new DEKs.
       Existing unwrapped DEKs in RAM remain valid until database
       restart or key rotation.

  Exfiltration vectors still viable:
    - LIVE DATABASE QUERY: SELECT * FROM patients → export to CSV →
      exfiltrate. TDE does NOT prevent this. The database is running
      and serving queries to authorized clients. If the attacker
      authenticates to PostgreSQL (with stolen credentials or by
      resetting the postgres password), they can query all data.
      TDE is transparent to authorized users.
    - MEMORY DUMP: Extract DEKs from PostgreSQL process memory →
      copy encrypted files → decrypt offline. This requires
      sophisticated memory forensics (T16 Attack 6) but is feasible
      with root access and tools like aeskeyfind.

  VERDICT: TDE with HSM DOES NOT FULLY PREVENT DATA EXFILTRATION
           if the attacker has root access and the database is running.
           BUT IT TRANSFORMS THE ATTACK from a simple file copy
           (Phase 3 as described in the advisory) into a MORE COMPLEX
           operation requiring either live database queries (which
           can be detected and rate-limited) or memory forensics
           (which requires specialized tools and time).
           WITHOUT TDE: Exfiltrate in 5 minutes (scp the data directory).
           WITH TDE + HSM: Exfiltration requires sustained database
           access or memory dump. Significantly harder, slower, and
           more detectable.

SCENARIO B: KEY ON SAME SERVER (ANTI-PATTERN - NOT RECOMMENDED)

  Architecture:    The TDE encryption key is stored in a configuration
                   file on ehr-db-01 (e.g., /etc/postgresql/pgtde.conf
                   or an environment variable). No HSM. No KMS.

  What the attacker can do:
    1. Attacker has root access to ehr-db-01.
    2. Attacker reads the configuration file: cat /etc/postgresql/pgtde.conf.
       Finds the master key in plaintext.
    3. Attacker copies the encrypted database files.
    4. Attacker decrypts the files OFFLINE using the stolen key.
    5. Total time: 5 minutes (find key) + file copy time.

  VERDICT: This is IDENTICAL in outcome to having NO encryption.
           The encryption adds a speed bump, not a barrier. The
           attacker has root, the key is on the same server, and
           the key is in plaintext. This is the "encrypted but still
           breached" scenario from the 2023 Thales report cited in
           the project introduction. KEY MANAGEMENT IS EVERYTHING.

SCENARIO C: DATABASE IS OFFLINE (POWERED OFF, DISK STOLEN)

  Architecture:    Same as A or B, but the database is NOT running.

  What the attacker can do:
    - With HSM (Scenario A): Attacker has the encrypted disk/files.
      Without the database running, they cannot call the KMS API
      (the IAM role is on the instance, which is off). They cannot
      extract DEKs from RAM (RAM is cleared). They have ONLY the
      encrypted files and wrapped DEKs in the database header.
      To decrypt, they need the CMK from the HSM, which they cannot
      access without the IAM role credentials. VERDICT: DATA IS SAFE.
    - Without HSM (Scenario B): Attacker finds the key in the config
      file on the same disk. The key is at rest alongside the
      encrypted data. VERDICT: DATA IS COMPROMISED.

  This is the scenario TDE is DESIGNED for: offline theft of storage
  media. TDE + HSM protects against stolen disks, decommissioned
  hardware, and cloud storage snapshot theft. It does NOT protect
  against an attacker with live access to a running database.

THE HONEST ANSWER:

Would Phase 3 exfiltration still succeed if the database was encrypted?

YES, partially. If MedDefense deployed TDE with HSM (the recommended
architecture from T14), the attacker with Domain Admin + root access
could still exfiltrate patient data, but through DIFFERENT METHODS
than the simple file copy described in the CISA advisory:

  Method 1: Live database query (SELECT * FROM patients via
            compromised PostgreSQL credentials). TDE does not
            prevent authorized database access.
  Method 2: Memory dump + offline decryption (extract DEK from RAM,
            copy encrypted files, decrypt). Complex but feasible.

What TDE with HSM WOULD PREVENT:
  - Simple file copy exfiltration (the method used in 4/5 CISA
    advisory incidents). The attacker cannot copy /var/lib/postgresql/
    and read the files offline.
  - Exfiltration of offline backups (if the attacker steals a backup
    file without the database running, they cannot decrypt it).
  - Double extortion leverage from stolen FILES (the attacker has
    ciphertext, not plaintext — they cannot publish patient data).
  - If the attacker is DETECTED and the IAM role is REVOKED before
    they complete live exfiltration, they lose all access to the data.

WHAT THIS MEANS FOR THE 72-HOUR PLAN:

Database encryption (T2-3) is NECESSARY but NOT SUFFICIENT. It must be
combined with:
  - Detection: MSSP monitoring (T3-5) to detect live database queries
    from unauthorized sources.
  - Access Control: Kerberos hardening (T2-2) to prevent the attacker
    from obtaining Domain Admin in the first place.
  - Network Segmentation: (T2-4 planning) to restrict which systems
    can connect to ehr-db-01 on port 5432.

DATABASE ENCRYPTION ALONE WILL NOT SAVE MEDDEFENSE if the attacker
has Domain Admin and the database is running. But it converts a
catastrophic, trivial, 5-minute plaintext exfiltration into a complex,
time-consuming, and potentially detectable operation. In incident
response, TIME and DETECTION are everything. TDE buys both.


================================================================================
REFERENCES
================================================================================

- 1x04 T0 Data Protection Map (Initial crypto state assessment)
- 1x04 T13 Encryption Levels Recommendation
- 1x04 T14 Key Management Plan (HSM architecture)
- 1x04 T15 Crypto Posture Audit (CRYPTO-001 through CRYPTO-010)
- 1x04 T16 Cryptographic Attack Surface (Attack 6: Key Recovery)
- 1x04 T17 Certificate Lifecycle Management
- 1x04 T18 Data Classification Matrix
- 1x04 T19 HIPAA Crypto Checkpoint
- 1x04 T20 Implementation Playbook
- 1x05 T0 CISA Advisory Analysis
- 1x05 T1 CVE Deep Dive
- 1x05 T2 Kill Chain Overlay
- 1x05 T3 72-Hour Emergency Plan
- Thales Data Threat Report 2023
- NIST SP 800-57 Part 1: Key Management Guidelines


================================================================================
END OF CRYPTO EMERGENCY ANALYSIS
================================================================================
