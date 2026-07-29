================================================================================
                    CERTIFICATE LIFECYCLE MANAGEMENT PLAN
                    MEDDEFENSE HEALTH SYSTEMS
                    Task 17: Certificate Lifecycle Management
================================================================================

Exercise: Task 17 - Certificate Lifecycle Management
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Design the certificate management program that prevents MedDefense
          from ever facing another "certificate expires in 18 days" emergency.
          The patient portal certificate is a symptom. This program treats
          the disease.

Sources: T10 TLS Configuration, T11 PKI Audit, 1x02-F005 (Certificate Expiry),
         T15 Crypto Posture Audit, NIST SP 800-57 Part 3 (Key Management),
         CAB Forum Baseline Requirements


================================================================================
PART 1: CERTIFICATE INVENTORY
================================================================================

Every certificate MedDefense must track, monitor, and manage. This inventory
is derived from the T11 PKI Audit, T15 Crypto Posture Audit, and the 1x00
Asset Registry. "Unknown" entries must be resolved within Phase 1.

+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| ID | Service / System     | Certificate      | Current Issuer   | Expiration       | Owner            | Status           |
|    |                      | Type             |                  | (Est. / Known)   | (Role)           |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 01 | Patient Portal       | PUBLIC TLS       | Unknown          | 2026-08-15       | Application      | EXPIRES IN       |
|    | patient-portal.       | (Leaf, Server    | Commercial CA    | (18 days from    | Administrator    | 18 DAYS          |
|    | meddefense.com        | Auth)            |                  | today)           |                  | CRITICAL         |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 02 | EHR Internal Web     | PRIVATE TLS      | MedDefense       | Unknown          | Application      | UNKNOWN          |
|    | Interface            | (Leaf, Server    | Internal CA ?    | (Expired ?)      | Administrator    | MUST AUDIT       |
|    | ehr.meddefense.local  | Auth)            |                  |                  |                  |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 03 | VPN Gateway          | PRIVATE TLS /    | Unknown          | Unknown          | Network Security | UNKNOWN          |
|    | (Site A)             | IPsec Cert       | (Self-signed ?)  |                  | Engineer         | MUST AUDIT       |
|    | vpn-a.meddefense.com  |                  |                  |                  |                  |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 04 | VPN Gateway          | PRIVATE TLS /    | Unknown          | Unknown          | Network Security | UNKNOWN          |
|    | (Site B)             | IPsec Cert       | (Self-signed ?)  |                  | Engineer         | MUST AUDIT       |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 05 | VPN Gateway          | PRIVATE TLS /    | Unknown          | Unknown          | Network Security | UNKNOWN          |
|    | (Site C)             | IPsec Cert       | (Self-signed ?)  |                  | Engineer         | MUST AUDIT       |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 06 | PACS DICOM TLS       | PRIVATE TLS      | MedDefense       | Not Yet Issued   | Clinical         | NOT YET          |
|    | (Server)             | (Leaf, Server +  | Internal CA      | (Phase 1)        | Engineering      | ISSUED           |
|    | pacs.meddefense.local | Client Auth)     |                  |                  |                  | Phase 1          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 07 | PACS DICOM TLS       | PRIVATE TLS      | MedDefense       | Not Yet Issued   | Clinical         | NOT YET          |
|    | (MRI Workstation)    | (Leaf, Client    | Internal CA      | (Phase 1)        | Engineering      | ISSUED           |
|    |                      | Auth)            |                  |                  |                  | Phase 1          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 08 | Email Signing        | S/MIME           | Not Yet Issued   | Not Yet Issued   | Security Team    | NOT YET          |
|    | (Clinical Staff)     | (End-User)       | (Internal CA or  | (Phase 1)        |                  | ISSUED           |
|    |                      |                  | Trusted Public)  |                  |                  | Phase 1          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 09 | Database TLS         | PRIVATE TLS      | MedDefense       | Not Yet Issued   | Database         | NOT YET          |
|    | PostgreSQL           | (Leaf, Server +  | Internal CA      | (Phase 1)        | Administrator    | ISSUED           |
|    | ehr-db-01             | Client Auth)     |                  |                  |                  | Phase 1          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 10 | Database TLS         | PRIVATE TLS      | MedDefense       | Not Yet Issued   | Database         | NOT YET          |
|    | MySQL                | (Leaf, Server +  | Internal CA      | (Phase 1)        | Administrator    | ISSUED           |
|    | billing-srv-01        | Client Auth)     |                  |                  |                  | Phase 1          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 11 | Internal PKI         | ROOT CA          | MedDefense       | Unknown          | Security Team    | UNKNOWN          |
|    | Root Certificate     | (Self-Signed)    | Internal         | (Must be 10+     |                  | MUST AUDIT       |
|    | Authority             |                  |                  | years)           |                  |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 12 | Internal PKI         | INTERMEDIATE CA  | MedDefense       | Unknown          | Security Team    | UNKNOWN          |
|    | Issuing CA           |                  | Internal Root CA | (Must be 5+      |                  | MUST AUDIT       |
|    | Certificate           |                  |                  | years)           |                  |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 13 | NAS-01 Web Admin     | PRIVATE TLS      | Unknown          | Unknown          | Server           | UNKNOWN          |
|    | Interface            | (Self-Signed ?)  | (Self-Signed ?)  |                  | Administrator    | MUST AUDIT       |
|    | nas-admin.meddefense  |                  |                  |                  |                  |                  |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 14 | BD Alaris Pump       | PRIVATE TLS      | Unknown          | Unknown          | Clinical         | UNKNOWN          |
|    | Management Console   | (Self-Signed ?)  | (Self-Signed ?)  |                  | Engineering      | MUST AUDIT       |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+
| 15 | Code Signing         | CODE SIGNING     | Not Yet Issued   | Not Yet Issued   | Security Team    | NOT YET          |
|    | (Internal Apps)      |                  | (Internal CA)    | (Phase 2)        |                  | ISSUED           |
|    |                      |                  |                  |                  |                  | Phase 2          |
+----+----------------------+------------------+------------------+------------------+------------------+------------------+

STATUS SUMMARY:
- CRITICAL (expiring < 30 days):  1  (ID-01: Patient Portal)
- UNKNOWN (must audit):           7  (IDs 02, 03, 04, 05, 11, 12, 13, 14)
- NOT YET ISSUED (planned):       6  (IDs 06, 07, 08, 09, 10, 15)
- TOTAL MANAGED CERTIFICATES:    15


================================================================================
PART 2: AUTO-RENEWAL STRATEGY
================================================================================

DECISION: MedDefense should deploy a HYBRID certificate strategy.

+------------------+--------------------------------------+--------------------------------------+
| Strategy         | ACME / Let's Encrypt                 | Commercial / Internal CA             |
+------------------+--------------------------------------+--------------------------------------+
| Use Case         | PUBLIC-FACING SERVICES:              | INTERNAL SERVICES, VPN, EMAIL:       |
|                  | - Patient Portal TLS                 | - EHR Internal Interface             |
|                  | - Any future public web service      | - VPN Gateways (3 sites)             |
|                  |                                      | - PACS DICOM TLS                     |
|                  |                                      | - Database TLS (PostgreSQL, MySQL)   |
|                  |                                      | - S/MIME Email Signing               |
|                  |                                      | - Code Signing (internal apps)       |
+------------------+--------------------------------------+--------------------------------------+
| Certificate      | 90 days                              | 1 year (365 days) for leaf certs     |
| Lifetime         |                                      | 5 years for Intermediate CA          |
|                  |                                      | 10 years for Root CA                 |
+------------------+--------------------------------------+--------------------------------------+
| Renewal Method   | AUTOMATED via certbot / acme.sh      | MANUAL with automation tools         |
|                  | - Fully unattended                   | - PowerShell, Ansible, or custom     |
|                  | - Runs as a cron job / systemd timer |   scripts                            |
|                  | - Pre-hook: stop service ?           | - Scheduled maintenance windows      |
|                  | - Post-hook: reload service, test    | - Manual verification step           |
+------------------+--------------------------------------+--------------------------------------+
| Cost             | FREE                                 | Commercial CA: $200-$1,500/year/cert |
|                  |                                      | Internal CA: FREE (labor cost only)  |
+------------------+--------------------------------------+--------------------------------------+
| Trust Model      | Publicly trusted by all browsers     | Must distribute Internal CA cert     |
|                  | via ISRG Root X1/X2                  | to all internal devices via GPO/MDM  |
+------------------+--------------------------------------+--------------------------------------+
| Revocation       | OCSP stapling built-in               | CRL distribution points required     |
|                  |                                      | OCSP responder (internal) needed     |
+------------------+--------------------------------------+--------------------------------------+


JUSTIFICATION FOR PATIENT PORTAL: ACME / LET'S ENCRYPT

The patient portal certificate (ID-01) is the most critical public-facing
certificate at MedDefense. The decision to use Let's Encrypt with ACME
automation is based on the following analysis:

FACTOR 1: CLINICAL IMPACT OF EXPIRATION
    Current certificate expires in 18 days. When it expires, 800 patients
    per day receive a browser warning (NET::ERR_CERT_DATE_INVALID or
    SEC_ERROR_EXPIRED_CERTIFICATE). The clinical impact is not just
    inconvenience — it is disruption of care:
    - Patients cannot view lab results.
    - Patients cannot request prescription refills.
    - Patients cannot message their providers.
    - Administrative staff must handle 800+ phone calls/day.
    An expiration is not an IT problem. It is a patient safety problem.

FACTOR 2: 90-DAY LIFECYCLE FORCES AUTOMATION
    The 90-day Let's Encrypt certificate lifetime is a FEATURE, not a bug.
    A 1-year certificate from a commercial CA provides a false sense of
    security: "We just renewed it last year, we have plenty of time."
    Then 11 months pass, nobody remembers, and the emergency repeats.
    A 90-day certificate with mandatory automation ELIMINATES the human
    forgetfulness factor. The automation either works (and the certificate
    is always valid) or fails (and we get an alert 30 days before expiry).

FACTOR 3: COST
    Let's Encrypt is free. MedDefense's $120,000 security budget should
    not be spent on certificate fees that can be eliminated. Commercial
    OV/EV certificates provide no additional cryptographic security over
    a DV Let's Encrypt certificate for a patient portal. The "green bar"
    EV indicator is deprecated in modern browsers.

FACTOR 4: OPERATIONAL MATURITY
    Let's Encrypt is the largest CA in the world by volume. ACME is an
    IETF standard (RFC 8555). The client ecosystem (certbot, acme.sh,
    lego, win-acme) is mature and well-documented. Integration with
    nginx, Apache, and HAProxy is trivial.

DECISION: Deploy Let's Encrypt via certbot on patient-portal-srv-01 with
fully automated renewal. Monitor renewal success via the alerting system
defined in Part 3. This decision is MANDATORY given the 18-day deadline.


================================================================================
PART 3: MONITORING AND ALERTING
================================================================================

Monitoring System: MedDefense shall deploy a centralized certificate
monitoring system. Two options, based on budget and complexity:

OPTION A (RECOMMENDED): Open-source + Internal
    Tool: Uptime Kuma + custom cert-expiry-check.sh script
    - Uptime Kuma monitors HTTPS endpoints and tracks certificate expiry.
    - A daily cron job runs cert-expiry-check.sh on all internal servers
      to check non-HTTPS certificates (VPN, databases, LDAPS).
    - Alerts sent to Microsoft Teams channel #security-alerts and email
      to the certificate owner.

OPTION B (ENHANCED): Commercial SaaS
    Tool: Let's Encrypt + Certificate Transparency monitoring, or a
    commercial platform (e.g., Keyfactor, Venafi, AppViewX).
    - For a 50,000-patient healthcare organization, a dedicated CLM
      (Certificate Lifecycle Management) platform may be justified in
      Phase 2 when the certificate inventory exceeds 50 certificates.

ALERTING THRESHOLDS:

+------------------+------------------+------------------+--------------------------------------+
| Threshold        | Alert Level      | Recipients       | Action Required                      |
+------------------+------------------+------------------+--------------------------------------+
| 90 DAYS          | INFO             | Certificate      | - Log the upcoming expiry in the     |
| before expiry    | (Automated       | Owner only       |   certificate inventory.             |
|                  | email)           |                  | - Verify auto-renewal is configured  |
|                  |                  |                  |   and tested (for ACME certs).       |
|                  |                  |                  | - Begin manual renewal process if    |
|                  |                  |                  |   not automated.                     |
+------------------+------------------+------------------+--------------------------------------+
| 60 DAYS          | WARNING          | Certificate      | - Escalate if renewal has not        |
| before expiry    | (Email +         | Owner +          |   started.                           |
|                  | Teams channel)   | Security Team    | - Open a ticket in the ITSM system   |
|                  |                  |                  |   with a 30-day SLA.                 |
+------------------+------------------+------------------+--------------------------------------+
| 30 DAYS          | HIGH             | Certificate      | - Immediate action required.         |
| before expiry    | (Email + Teams   | Owner +          | - Renewal must be completed within   |
|                  | + SMS/PagerDuty) | Security Team +  |   7 days.                            |
|                  |                  | IT Manager       | - Manager escalation.                |
+------------------+------------------+------------------+--------------------------------------+
| 7 DAYS           | CRITICAL         | Certificate      | - ALL HANDS. Certificate renewal     |
| before expiry    | (Email + Teams   | Owner +          |   is the #1 priority for the IT      |
|                  | + SMS + Phone    | Security Team +  |   department until resolved.         |
|                  | Call)            | IT Manager +     | - Daily standup meetings on status.  |
|                  |                  | CISO             | - Pre-approval for after-hours       |
|                  |                  |                  |   change window if needed.           |
+------------------+------------------+------------------+--------------------------------------+
| EXPIRED          | INCIDENT         | All above +      | - INCIDENT RESPONSE TRIGGERED.       |
|                  | (PagerDuty       | Executive Team   | - Patient portal: activate emergency |
|                  | Incident Alert)  | (CIO, CEO)       |   communication plan for patients.   |
|                  |                  |                  | - Internal services: activate IT     |
|                  |                  |                  |   incident response procedure.       |
|                  |                  |                  | - Post-incident RCA required within  |
|                  |                  |                  |   5 business days.                   |
+------------------+------------------+------------------+--------------------------------------+

MONITORING FREQUENCY:
    - Public certificates: Hourly (via Uptime Kuma or monitoring service)
    - Internal certificates: Daily (via cron job / scheduled task)
    - Auto-renewal success: Post-renewal hook reports status to monitoring

ALERT CONTENT (Minimum Required Information):
    - Certificate Common Name (CN) and Subject Alternative Names (SANs)
    - Service/Server name
    - Expiration date and days remaining
    - Issuer CA
    - Responsible owner
    - Link to renewal procedure documentation
    - Ticket number (if already created)


================================================================================
PART 4: CERTIFICATE POLICY
================================================================================

POLICY RULE 1: NO SELF-SIGNED CERTIFICATES IN PRODUCTION
    All production services (internal and external) must use certificates
    signed by the MedDefense Internal Certificate Authority (CA) or a
    trusted public CA. Self-signed certificates are prohibited in any
    production environment. Exceptions require written approval from the
    CISO, must be time-limited (maximum 90 days), and must be registered
    in the certificate inventory with a remediation plan.
    Rationale: Self-signed certificates train staff to click through
    browser warnings, enabling man-in-the-middle attacks (see CRYPTO-005,
    Attack Surface Finding 5). The compromised print-srv-01 demonstrates
    that an internal attacker can exploit this trust erosion.

POLICY RULE 2: MANDATORY AUTOMATED RENEWAL FOR PUBLIC-FACING SERVICES
    All public-facing TLS certificates (patient portal, patient API,
    future patient mobile app endpoints) must use ACME-based automated
    renewal with a maximum certificate lifetime of 90 days. Manual
    renewal of public-facing certificates is prohibited. The automation
    must include a post-renewal validation step that confirms the new
    certificate is being served correctly before the old certificate
    expires (staple OCSP response, verify with external monitoring).
    Rationale: The 18-day emergency (ID-01) must never recur. Automation
    is the only reliable solution. Manual processes fail at scale.

POLICY RULE 3: CERTIFICATE INVENTORY IS THE SOURCE OF TRUTH
    Every TLS certificate in use at MedDefense — public, internal,
    self-signed (temporary exceptions only), code signing, S/MIME, and
    client certificates — must be registered in the Certificate Inventory
    within 24 hours of issuance or discovery. The inventory must include,
    at minimum: Subject CN, SANs, Issuer, Serial Number, Expiration Date,
    Service Owner (role), Server/Hostname, and Renewal Method (automated
    or manual). Certificates not in the inventory within 30 days of this
    policy's effective date shall be treated as unauthorized and must be
    revoked or replaced.
    Rationale: You cannot manage what you do not track. Seven certificates
    are currently "UNKNOWN" in the inventory. This is the root cause of
    the patient portal emergency.

POLICY RULE 4: SEPARATION OF DUTIES FOR INTERNAL CA
    The MedDefense Internal Certificate Authority (Root CA and Issuing CA)
    shall operate under a separation-of-duties model:
    - CA Administrators (Security Team, maximum 3 individuals) are
      authorized to issue and revoke certificates.
    - Certificate Owners (Application Admins, Network Engineers, DBAs)
      may request certificates via a standardized CSR process but may
      NOT issue or revoke them.
    - Audit Logs of all certificate issuance, renewal, and revocation
      events must be retained for a minimum of 3 years and reviewed
      quarterly by the Security Team.
    The Root CA private key must be stored OFFLINE (air-gapped) on a
    hardware token (HSM or FIPS 140-2 Level 2 USB key) in a physical
    safe with dual-control access (Security Director + CISO). It shall
    never be connected to a network-connected system.
    Rationale: The Internal CA is the cryptographic root of trust for
    all internal services. Compromise of the Root CA key invalidates the
    entire internal PKI and requires re-issuance of every internal
    certificate. Separation of duties and offline storage limit this risk.

POLICY RULE 5: ALGORITHM AND KEY STRENGTH STANDARDS
    All certificates issued after the effective date of this policy
    (regardless of issuer) must comply with the following minimum
    cryptographic standards:
    - Publicly Trusted TLS Certificates: ECDSA with P-256 curve OR RSA
      with 2048-bit key minimum. SHA-256 signature algorithm. No SHA-1.
    - Internal TLS Certificates: ECDSA P-256 or RSA 2048-bit minimum.
      SHA-256 signature algorithm.
    - S/MIME and Code Signing Certificates: RSA 2048-bit or ECDSA P-256.
      SHA-256 signature algorithm.
    - Internal CA (Root): RSA 4096-bit or ECDSA P-384. SHA-384 signature.
      Validity: 10 years. Offline storage (see Policy Rule 4).
    - Internal CA (Issuing): RSA 4096-bit or ECDSA P-384. SHA-384
      signature. Validity: 5 years.
    Certificates using RSA keys smaller than 2048 bits, ECDSA keys on
    curves smaller than P-256, or SHA-1 signature algorithms must be
    revoked and replaced within 90 days of policy effective date. No
    new certificates with these weak algorithms may be issued.
    Rationale: The T6 Algorithm Analysis, T10 TLS Audit, and T16 Attack
    Surface assessment all confirm that SHA-1, RSA < 2048, and weak ECDSA
    curves are exploitable (see Birthday Attack, Collision Attack). This
    policy codifies the cryptographic baseline recommended across all
    crypto tasks.


================================================================================
PART 5: IMPLEMENTATION ROADMAP
================================================================================

IMMEDIATE (0-18 DAYS): PATIENT PORTAL EMERGENCY
    Day 0-2:  Install certbot on patient-portal-srv-01.
    Day 2-3:  Request Let's Encrypt certificate for patient-portal.meddefense.com
              (ECDSA P-256, automated renewal via systemd timer).
    Day 3-4:  Deploy to production. Test with SSL Labs (aiming for A+).
    Day 4:    Verify automated renewal is functioning (simulate with
              `certbot renew --dry-run`).
    Day 5:    Register certificate in inventory (ID-01 updated).
              Configure monitoring (90/60/30/7 day alerts).

PHASE 1 (WEEKS 1-12): INTERNAL PKI AND INVENTORY
    Week 1-2:  Audit all UNKNOWN certificates (IDs 02, 03, 04, 05, 11, 12,
               13, 14). Add to inventory or revoke unauthorized.
    Week 2-4:  Set up Internal CA (if not already properly configured).
               Store Root CA offline. Issue Issuing CA cert.
    Week 4-6:  Issue certificates for DICOM TLS (IDs 06, 07), Database
               TLS (IDs 09, 10), and VPN (IDs 03, 04, 05 if needed).
    Week 6-8:  Deploy monitoring system (Uptime Kuma or commercial CLM).
    Week 8-12: Issue S/MIME certificates for clinical staff (ID-08).

PHASE 2 (MONTHS 3-6): MATURITY
    Month 3-4:  Evaluate commercial CLM platform if inventory exceeds
                50 certificates.
    Month 4-5:  Issue code signing certificates (ID-15).
    Month 5-6:  First quarterly audit of certificate inventory and CA
                audit logs. Report to CISO.


================================================================================
PART 6: ROLES AND RESPONSIBILITIES
================================================================================

+----------------------------+----------------------------------------------+
| Role                       | Responsibility                              |
+----------------------------+----------------------------------------------+
| Security Team (CA Admins)  | - Issue and revoke internal certificates    |
| (max 3 individuals)        | - Maintain Internal CA infrastructure       |
|                            | - Quarterly CA audit log review             |
|                            | - Policy compliance monitoring              |
+----------------------------+----------------------------------------------+
| Certificate Owner          | - Request certificates via CSR              |
| (App Admin, Net Eng, DBA)  | - Ensure automated renewal is functional    |
|                            | - Respond to expiry alerts within SLA       |
|                            | - Report compromised keys immediately       |
+----------------------------+----------------------------------------------+
| IT Manager                 | - Escalation point for 30-day alerts        |
|                            | - Resource allocation for manual renewals   |
|                            | - Budget approval for commercial certs      |
+----------------------------+----------------------------------------------+
| CISO                       | - Policy approval and exception sign-off    |
|                            | - Critical alert recipient (7-day, expired) |
|                            | - Incident response oversight              |
+----------------------------+----------------------------------------------+


================================================================================
REFERENCES
================================================================================

- NIST SP 800-57 Part 3: Application and Management of Cryptographic Keys
- CAB Forum Baseline Requirements for TLS Certificates
- RFC 8555: Automatic Certificate Management Environment (ACME)
- Let's Encrypt: Integration Guide
- T10 TLS Configuration Task
- T11 PKI Audit Task
- T15 Crypto Posture Audit (CRYPTO-002: Patient Portal TLS)
- 1x02-F005: TLS Certificate Expiring


================================================================================
END OF CERTIFICATE LIFECYCLE MANAGEMENT PLAN
================================================================================
