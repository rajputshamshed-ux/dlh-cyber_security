================================================================================
                    72-HOUR EMERGENCY RESPONSE PLAN
                    MEDDEFENSE HEALTH SYSTEMS
                    Task 3: The 72-Hour Plan
================================================================================

Exercise: Task 3 - The 72-Hour Plan
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Design an emergency response plan prioritizing the actions
          MedDefense must take in the next 72 hours to reduce exposure
          to the Crimson Tide ransomware campaign. Maximum risk reduction,
          minimum time, with available resources.

Constraints:
  - Sarah Park + 2 IT staff available tonight
  - FortiGate firmware requires support contract renewal ($2,400)
  - Network segmentation requires 2-3 days minimum
  - Backup isolation possible tonight (physical disconnect)
  - AD Kerberos changes require maintenance window (auth risk)
  - Hospital C (45 miles) in active containment

Sources: 1x05 T0 Advisory Analysis, 1x05 T1 CVE Deep Dive, 1x05 T2 Kill Chain
         Overlay, 1x03 Security Strategy, 1x04 T20 Implementation Playbook


================================================================================
RESOURCE INVENTORY (AS OF NOW)
================================================================================

PERSONNEL AVAILABLE:
  - James Chen (CISO) - Strategic authority, Board liaison
  - Sarah Park (Security Team Lead) - Technical, AD/FortiGate expertise
  - IT Staff #1 (Network focus) - Firewall, switches, VPN
  - IT Staff #2 (Systems focus) - Servers, databases, backups
  - You (Security Analyst) - Crypto, assessment, documentation

BUDGET:
  - $120,000 approved (1x03 Board meeting) but NOT YET ALLOCATED
  - Emergency spend authority: James Chen up to $5,000 without Board
  - FortiGate support renewal: $2,400 (within emergency spend)
  - AWS KMS HSM: $18/year (negligible, operational expense)

SYSTEMS:
  - fw-meddefense-01 (FortiGate 100E, FortiOS 7.0.9) - VULNERABLE
  - ehr-db-01 (PostgreSQL 15.2) - PLAINTEXT PATIENT DATA
  - nas-01 (Synology NAS) - PLAINTEXT BACKUPS, NETWORK-ACCESSIBLE
  - dc01, dc02 (Domain Controllers) - DES/RC4 KERBEROS ENABLED
  - patient-portal-srv-01 - TLS 1.0, CERT EXPIRING 18 DAYS
  - pacs-srv-01 - UNENCRYPTED DICOM

TIME:
  - Hospital C in active containment NOW
  - Crimson Tide actively targeting healthcare in region
  - FortiGate CVE-2023-27997 CVSS 9.8, public exploit, CISA KEV
  - 72 hours to maximum achievable risk reduction


================================================================================
TIER 1 - TONIGHT (0-12 HOURS)
================================================================================

Actions that can be taken IMMEDIATELY with NO budget approval, NO
procurement, and MINIMAL risk of service disruption. These are the
things you do before you sleep.

----------------------------------------------------------------------
ACTION T1-1: DISABLE SSL-VPN ON FORTIGATE (IMMEDIATE WORKAROUND)
----------------------------------------------------------------------

Action:             Disable the SSL-VPN service on fw-meddefense-01 on
                    ALL internet-facing interfaces. This closes the
                    CVE-2023-27997 attack vector completely. The
                    vulnerability exists ONLY in the SSL-VPN daemon;
                    disabling it removes the attack surface.

Phase Blocked:      PHASE 1 - Initial Access (CVE-2023-27997 exploit)
                    This is the SINGLE MOST EFFECTIVE action to prevent
                    initial compromise.

Owner:              Sarah Park + IT Staff #1 (Network)

Prerequisites:      - Verify IPsec site-to-site VPNs do NOT depend on
                      SSL-VPN (they use IPsec/IKE, separate service).
                    - Identify all remote VPN users who use SSL-VPN for
                      remote access. (Estimate: 15-25 clinical staff,
                      IT administrators).
                    - Prepare communication to remote users about
                      alternative access method or downtime.

Steps:
  1. Sarah logs into FortiGate admin console.
  2. Navigate to VPN > SSL-VPN Settings.
  3. Uncheck "Enable SSL-VPN" on ALL interfaces (WAN1, WAN2 if present).
  4. Apply changes.
  5. Verify SSL-VPN is no longer listening:
     From external network: nmap -p 443,8443 <FortiGate-public-IP>
     Expected: Port closed or filtered (no SSL-VPN response).
  6. Document the change in change management (post-deployment).

Risk of Action:     Remote VPN users lose access to internal systems.
                    Clinical staff working from home cannot access EHR.
                    IT staff on call cannot remote in.
                    MITIGATION: Communicate before disabling. If critical
                    remote access is needed, coordinate with specific
                    users to come on-site or use alternative method.

Risk of Inaction:   CVE-2023-27997 remains exploitable. Any attacker on
                    the internet can achieve unauthenticated RCE on the
                    FortiGate. Crimson Tide is actively scanning for this
                    exact vulnerability in the healthcare sector. Hospital
                    C is in active containment. The risk of inaction is
                    CATASTROPHIC COMPROMISE TONIGHT.

Time to Complete:   15 minutes.

----------------------------------------------------------------------
ACTION T1-2: PHYSICALLY ISOLATE NAS-01 BACKUPS FROM NETWORK
----------------------------------------------------------------------

Action:             Disconnect nas-01 from the network. If the NAS is
                    physically accessible, unplug the Ethernet cable.
                    If it's a VM, remove the virtual network adapter.
                    This prevents ransomware (if it enters) from
                    encrypting the backups. The NAS stores ALL MedDefense
                    backup data.

Phase Blocked:      PHASE 7 - Impact (Ransomware encryption of backups)
                    Without backups, MedDefense cannot recover from
                    ransomware without paying the ransom.

Owner:              IT Staff #2 (Systems) + You (verification)

Prerequisites:      - Verify no active backup jobs are running.
                    - Verify no restore operations are in progress.
                    - Notify IT Manager that backups will be offline
                      until further notice (no restores possible during
                      isolation).

Steps:
  1. IT Staff #2 accesses NAS-01 (physically or via hypervisor).
  2. Disconnect Ethernet cable(s) from NAS-01.
  3. If VM: remove/disable vNIC in hypervisor settings.
  4. Verify NAS is no longer reachable:
     ping nas-01.meddefense.local
     Expected: Request timed out.
  5. You document: time of disconnection, state of last backup job,
     list of systems that depend on NAS-01 for backup/restore.
  6. Place sign on NAS-01: "ISOLATED PER SECURITY INCIDENT - DO NOT
     RECONNECT WITHOUT CISO AUTHORIZATION."

Risk of Action:     NO BACKUPS during isolation period. If a system
                    fails (disk crash, corruption) during isolation,
                    it cannot be restored from NAS-01. No new backups
                    can be written.
                    MITIGATION: This is a TEMPORARY measure (24-48 hours
                    max). Critical systems should be identified. If a
                    critical system requires a backup during isolation,
                    a one-time manual backup to external USB drive can
                    be performed (verify USB drive is clean before
                    connecting).

Risk of Inaction:   NAS-01 is on the same flat network as every other
                    device. If ransomware enters (via FortiGate exploit
                    or any other vector), it WILL encrypt the NAS-01
                    backups. All backup data is destroyed. MedDefense
                    has NO recovery capability. Ransom payment becomes
                    the only option. Risk of inaction: TOTAL LOSS OF
                    DISASTER RECOVERY CAPABILITY.

Time to Complete:   10 minutes.

----------------------------------------------------------------------
ACTION T1-3: ENABLE ENHANCED LOGGING ON ALL CRITICAL SYSTEMS
----------------------------------------------------------------------

Action:             Increase logging verbosity on Domain Controllers,
                    FortiGate, and ehr-db-01. Forward logs to a
                    temporary syslog collector (even a laptop with
                    syslog-ng running). The goal is to preserve forensic
                    evidence. If MedDefense is ALREADY compromised
                    (unknown at this point), increased logging helps
                    detect and investigate.

Phase Blocked:      PHASE 5 - Defense Evasion (makes it harder to hide)
                    PHASE 2 - Credential Access (logs suspicious activity)
                    This is a DETECTION control, not prevention.

Owner:              Sarah Park (DC logs) + IT Staff #1 (FortiGate logs) +
                    IT Staff #2 (ehr-db-01 logs) + You (syslog collector
                    setup)

Prerequisites:      - Identify a machine with sufficient disk space to
                      act as temporary syslog collector (any Linux VM
                      or Windows workstation with 100GB+ free).
                    - Install syslog-ng (Linux) or use built-in Windows
                      Event Forwarding.

Steps:
  1. You: Set up temporary syslog collector on available Linux VM.
     sudo apt-get install syslog-ng -y
     Configure to accept remote syslog on UDP/514.
     Allocate 200GB partition for logs.

  2. Sarah: On dc01, enable advanced audit policy:
     auditpol /set /category:"Account Logon" /success:enable /failure:enable
     auditpol /set /category:"Account Management" /success:enable /failure:enable
     auditpol /set /category:"DS Access" /success:enable /failure:enable
     Forward Windows Event Logs to syslog collector.

  3. IT Staff #1: On FortiGate, increase logging to DEBUG for SSL-VPN
     (even though disabled - historical logs), firewall policy denies,
     and admin access. Forward syslog to collector.

  4. IT Staff #2: On ehr-db-01, enable PostgreSQL connection logging:
     ALTER SYSTEM SET log_connections = 'on';
     ALTER SYSTEM SET log_disconnections = 'on';
     ALTER SYSTEM SET log_statement = 'ddl';
     SELECT pg_reload_conf();

Risk of Action:     Increased logging consumes disk space. If logs fill
                    available disk on critical systems, services may
                    crash. MITIGATION: Monitor disk usage every hour.
                    Set alerts at 80% capacity.

Risk of Inaction:   If MedDefense is already compromised, there is NO
                    forensic trail to investigate the scope, timeline,
                    and data exfiltrated. Breach notification (HIPAA)
                    requires a forensic assessment of what was accessed.
                    Without logs, this is impossible to determine.
                    Risk of inaction: UNINVESTIGATABLE BREACH.

Time to Complete:   45 minutes (syslog setup) + 30 minutes (policy config).

----------------------------------------------------------------------
ACTION T1-4: COMPROMISE ASSESSMENT - CHECK FOR INDICATORS OF INTRUSION
----------------------------------------------------------------------

Action:             Check critical systems for IoCs (Indicators of
                    Compromise) consistent with Crimson Tide's known
                    TTPs. Focus on: unknown VPN accounts, new domain
                    admin accounts, unusual outbound connections.

Phase Addressed:    PHASE 1-7 ALL (determines if attack has already
                    occurred). This is SITUATIONAL AWARENESS.

Owner:              You + Sarah Park (analysis) + IT Staff #1 (FortiGate)

Prerequisites:      - Access to FortiGate admin console and logs.
                    - Domain Admin access to dc01.
                    - List of known VPN user accounts.

Steps:
  1. FortiGate - Check SSL-VPN connections last 30 days:
     In FortiGate CLI:
     get vpn ssl monitor
     execute log display category event
     Look for: VPN connections from unknown public IPs, connections
     at unusual hours (01:00-05:00 local), multiple failed then
     successful connections.

  2. Active Directory - Check for new accounts (last 30 days):
     On dc01 PowerShell:
     Get-ADUser -Filter {Created -gt (Get-Date).AddDays(-30)} -Properties Created
     Look for: Accounts you don't recognize. "svc_" accounts you
     didn't create. Accounts with Domain Admin group membership
     added in last 30 days.

  3. Active Directory - Check for DCSync or NTDS.dit access:
     On dc01 Event Viewer > Security:
     Filter for Event ID 4662 (Directory Service Access).
     Look for: Access to "CN=Configuration,DC=meddefense,DC=local"
     or NTDS.dit by non-DC computer accounts.

  4. Check ehr-db-01 for suspicious connections:
     SELECT client_addr, count(*) FROM pg_stat_activity
     GROUP BY client_addr ORDER BY count(*) DESC;
     Look for: IP addresses outside 10.10.10.0/24, connections at
     unusual hours, connections from print-srv-01 (10.10.10.100).

Risk of Action:     LOW. This is read-only analysis. No configuration
                    changes are made.

Risk of Inaction:   MedDefense may ALREADY be compromised and not know it.
                    Crimson Tide dwell time is unknown (advisory suggests
                    days to weeks between initial access and ransomware
                    deployment). MedDefense could be in the dwell period
                    RIGHT NOW. Not checking means missing the window to
                    evict the attacker before ransomware deploys.
                    Risk of inaction: ATTACKER REMAINS UNDETECTED.

Time to Complete:   1-2 hours.

----------------------------------------------------------------------
ACTION T1-5: EMERGENCY COMMUNICATION TO ALL STAFF
----------------------------------------------------------------------

Action:             Send an organization-wide communication about the
                    active threat. This is NOT a technical control, but
                    it reduces the risk of phishing and social engineering
                    (which Crimson Tide may use as a secondary vector).

Phase Addressed:    PHASE 1 - Initial Access (alternative: phishing)
                    Reduces risk of secondary compromise vectors.

Owner:              James Chen (CISO) - drafts and approves
                    Sarah Park - technical content
                    You - assist with threat details

Prerequisites:      - James Chen approval.
                    - Email distribution list for all staff.
                    - Draft message prepared.

Message Template:
  "URGENT SECURITY ALERT: MedDefense Health Systems is aware of an
   active ransomware campaign targeting healthcare organizations in
   our region. Hospital C is currently affected.

   ALL STAFF: Do not open unexpected email attachments. Do not click
   links in emails from unknown senders. Report suspicious emails
   to IT Help Desk immediately. Do not connect personal devices to
   the MedDefense network. Do not insert unknown USB drives.

   IT is implementing emergency security measures tonight. Some
   remote access services will be temporarily unavailable.

   This is not a drill. Your vigilance is critical.

   Questions: Contact IT Help Desk at x5555."

Risk of Action:     LOW. Some staff may panic. Some may misinterpret
                    and think MedDefense is already compromised.
                    MITIGATION: Be clear that this is PREVENTIVE, not
                    reactive. Frame as "we are protecting ourselves
                    against a regional threat."

Risk of Inaction:   Staff unaware of threat. More susceptible to
                    phishing. If Crimson Tide sends targeted phishing
                    emails to MedDefense staff (common in healthcare
                    campaigns), unprepared staff may click and provide
                    a secondary access vector. Risk of inaction: HUMAN
                    VULNERABILITY REMAINS UNMITIGATED.

Time to Complete:   20 minutes (draft + approval + send).


================================================================================
TIER 1 SUMMARY - TONIGHT (0-12 HOURS)
================================================================================

+-------+------------------+----------+----------+----------+----------+
| ACTION| DESCRIPTION      | PHASE    | OWNER    | TIME     | RISK OF  |
|       |                  | BLOCKED  |          | TO DO    | ACTION   |
+-------+------------------+----------+----------+----------+----------+
| T1-1  | Disable SSL-VPN  | Phase 1  | Sarah +  | 15 min   | Remote   |
|       | on FortiGate     | (STOP)   | IT #1    |          | VPN down |
+-------+------------------+----------+----------+----------+----------+
| T1-2  | Physically       | Phase 7  | IT #2 +  | 10 min   | No       |
|       | isolate NAS-01   | (STOP)   | You      |          | backups  |
+-------+------------------+----------+----------+----------+----------+
| T1-3  | Enhanced logging | Phase 5  | All team | 75 min   | Disk     |
|       | on all critical  | (DETECT) |          |          | space    |
+-------+------------------+----------+----------+----------+----------+
| T1-4  | Compromise       | Phase 1-7| You +    | 1-2 hrs  | LOW      |
|       | assessment       | (DETECT) | Sarah    |          |          |
+-------+------------------+----------+----------+----------+----------+
| T1-5  | Emergency comms  | Phase 1  | James +  | 20 min   | Staff    |
|       | to all staff     | (alt vec)| Sarah    |          | concern  |
+-------+------------------+----------+----------+----------+----------+

TOTAL TIER 1 TIME: ~3 hours. All actions completable by midnight if
started immediately. After Tier 1, MedDefense has:
- Closed the primary attack vector (SSL-VPN disabled) ✓
- Protected backups from ransomware encryption ✓
- Established enhanced detection capability ✓
- Assessed whether compromise has already occurred ✓
- Alerted all staff to the threat ✓

THE TEAM CAN SLEEP AFTER TIER 1 IS COMPLETE. Set rotation: one person
on call monitoring logs. 6 hours sleep minimum for each team member.
We need the team sharp for Tier 2.


================================================================================
TIER 2 - TOMORROW (12-36 HOURS)
================================================================================

Actions that require some coordination, possibly a brief service window,
and may need emergency budget approval. These are the things you do
tomorrow morning.

----------------------------------------------------------------------
ACTION T2-1: RENEW FORTIGATE SUPPORT CONTRACT AND PATCH FIRMWARE
----------------------------------------------------------------------

Action:             Renew the FortiGate support contract ($2,400),
                    download FortiOS 7.0.12 (or 7.2.6), and patch
                    fw-meddefense-01. This is the PERMANENT fix for
                    Phase 1. After patching, SSL-VPN can be re-enabled.

Phase Blocked:      PHASE 1 - Initial Access (PERMANENT FIX)

Owner:              James Chen (budget approval) + IT Staff #1 (download,
                    patch) + Sarah Park (verify)

Prerequisites:      - James Chen approves $2,400 emergency spend
                      (within $5,000 delegated authority).
                    - FortiGate support contract renewed and active.
                    - FortiOS 7.0.12 firmware downloaded and SHA-256
                      checksum verified against Fortinet published hash.
                    - Current FortiGate configuration backed up.
                    - Maintenance window: 05:00-07:00 local time
                      (lowest traffic, before clinical staff arrive).

Steps:
  1. James Chen: Approve $2,400 via corporate credit card. Renew
     support contract on Fortinet support portal. (30 min)
  2. IT Staff #1: Download FortiOS 7.0.12 firmware. Verify checksum.
     Copy to FortiGate via TFTP or admin console upload. (15 min)
  3. IT Staff #1: Backup current configuration:
     execute backup config tftp <backup-server> <filename>
  4. During maintenance window (05:00-07:00):
     - Notify all sites: "Firewall maintenance, VPN and internet
       may be intermittent."
     - Apply firmware update: execute restore image tftp <filename>
     - FortiGate reboots automatically.
     - Verify FortiGate boots correctly.
     - Verify IPsec VPN tunnels to all 3 sites re-establish.
     - Verify internet access restored.
     - Verify SSL-VPN service is still DISABLED (we re-enable later,
       after testing).
  5. Post-upgrade validation:
     get system status | grep Version
     Expected: FortiOS 7.0.12 or higher.

Risk of Action:     MEDIUM. Firmware upgrade on a single point of
                    failure. If the upgrade fails or the FortiGate is
                    bricked, all 3 sites lose VPN connectivity and
                    internet access. No vendor support during upgrade
                    (contract just renewed but support engineer not
                    engaged). MITIGATION: Have the previous firmware
                    image available for rollback. Have the physical
                    console cable connected for emergency recovery.

Risk of Inaction:   SSL-VPN remains disabled (acceptable temporarily)
                    but the vulnerability remains unpatched. Any
                    misconfiguration or accidental re-enablement of
                    SSL-VPN re-exposes MedDefense. Cannot re-enable
                    remote access for VPN users. FortiGate remains on
                    unsupported, vulnerable firmware for all other
                    services (not just SSL-VPN).

Time to Complete:   2 hours (including maintenance window).

----------------------------------------------------------------------
ACTION T2-2: DEPLOY KERBEROS AES-256 ENFORCEMENT (AD HARDENING)
----------------------------------------------------------------------

Action:             Disable DES, RC4-HMAC, and (optionally) AES128 in
                    Kerberos encryption types. Enforce AES256 only.
                    Per T20 Implementation Playbook Action #2.

Phase Blocked:      PHASE 2 - Credential Access (Kerberoasting becomes
                    infeasible). PHASE 4 - Lateral Movement (harder to
                    pivot with cracked service accounts).

Owner:              Sarah Park (Domain Admin) + IT Staff #2 (service
                    account verification)

Prerequisites:      - T1-4 Compromise Assessment COMPLETE. If MedDefense
                      is already compromised, changing Kerberos may
                      alert the attacker and trigger premature ransomware
                      deployment. CONFIRM NO ACTIVE COMPROMISE before
                      this change. If compromise IS detected, skip this
                      action and follow Incident Response procedures.
                    - All service accounts documented.
                    - Test user account ready for validation.
                    - Maintenance window: Sunday 03:00-05:00
                      (same as T20 Playbook Action #2).

Steps:              Execute T20 Implementation Playbook Action #2 in full.
                    Key steps: Disable DES/RC4/AES128 in GPO, force
                    replication, verify AES256 only.

Risk of Action:     MEDIUM-HIGH. If legacy applications or devices
                    (medical devices, old printers) rely on RC4 or DES
                    Kerberos, they will FAIL authentication. This could
                    disrupt clinical operations.
                    MITIGATION: Before enforcing, run a Kerberos audit
                    log query (Event ID 4769) to identify any systems
                    currently using RC4 or DES. Contact those system
                    owners. If critical medical device uses RC4 (e.g.,
                    BD Alaris pump management console), isolate it on
                    a separate VLAN with restricted access instead of
                    blocking its Kerberos globally.

Risk of Inaction:   Kerberoasting remains trivially exploitable. Any
                    domain user can request TGS tickets encrypted with
                    RC4, crack them offline, and obtain Domain Admin
                    within hours. This is the Phase 2 attack path.
                    Without this fix, all other controls are bypassed
                    via credential theft.

Time to Complete:   2 hours (during maintenance window) + 2 hours
                    preparation.

----------------------------------------------------------------------
ACTION T2-3: BEGIN POSTGRESQL TDE DEPLOYMENT ON ehr-db-01
----------------------------------------------------------------------

Action:             Deploy PostgreSQL Transparent Data Encryption with
                    AES-256-GCM and AWS KMS key management. Per T20
                    Implementation Playbook Action #3.

Phase Blocked:      PHASE 3 - Data Collection (data is encrypted at rest,
                    useless if exfiltrated). PHASE 7 - Double Extortion
                    (leaked data is encrypted, extortion has no leverage).

Owner:              IT Staff #2 (database) + You (KMS configuration,
                    encryption verification)

Prerequisites:      - AWS KMS CMK created (requires AWS account access;
                      MedDefense has existing AWS infrastructure per
                      1x03 roadmap).
                    - IAM role for ehr-db-01 with KMS permissions.
                    - pg_tde extension available (install if needed).
                    - FULL DATABASE BACKUP verified restorable.
                    - Maintenance window: Sunday 01:00-05:00 (4 hours
                      per T20 Playbook).

Steps:              Execute T20 Implementation Playbook Action #3 in full.
                    Key steps: KMS key creation, pg_tde installation,
                    tablespace migration to encrypted tablespace,
                    application verification.

Risk of Action:     MEDIUM. Database encryption carries risk of data
                    corruption if interrupted (power failure, disk full).
                    Performance impact on clinical applications (3-8%
                    overhead on AES-NI capable CPUs).
                    MITIGATION: Full backup before starting. Monitor
                    disk space and query performance during and after.
                    Rollback plan: Move tables back to unencrypted
                    tablespace.

Risk of Inaction:   Patient database remains PLAINTEXT. If attacker
                    enters (via any vector, now or in the future),
                    50,000 records are immediately readable and
                    exfiltratable. This is the HIPAA $24.95M ALE risk.
                    The CISA advisory explicitly states 4/5 victims had
                    unencrypted databases. MedDefense is currently in
                    that cohort.

Time to Complete:   4 hours (maintenance window) + 3 hours preparation.

----------------------------------------------------------------------
ACTION T2-4: PROCURE AND BEGIN NETWORK SEGMENTATION PLANNING
----------------------------------------------------------------------

Action:             Begin the procurement and design phase for network
                    segmentation. This CANNOT be fully implemented in
                    72 hours, but procurement and design can be
                    completed so deployment starts immediately after
                    the 72-hour window.

Phase Blocked:      PHASE 4 - Lateral Movement (future state)
                    PHASE 7 - Ransomware spread containment

Owner:              James Chen (procurement approval, vendor contact) +
                    IT Staff #1 (network design)

Prerequisites:      - Quote for managed switches with VLAN support
                      (if current switches don't support VLANs).
                    - Network topology diagram (from 1x00) updated
                      with proposed VLAN segmentation.
                    - 1x03 budget allocation for CG-001.

Steps:
  1. James Chen: Contact existing hardware vendor (CDW, SHI, or
     similar). Request quote for VLAN-capable switches if needed.
     Estimated cost: $15,000-$25,000 for 3-site deployment.
     Approve from $120,000 budget (CG-001 allocation).
  2. IT Staff #1: Produce VLAN segmentation plan:
     VLAN 10: Clinical Devices (MRI, PACS, patient monitors)
     VLAN 20: Servers (ehr-db-01, dc01, file servers)
     VLAN 30: User Workstations (clinical staff PCs)
     VLAN 40: Guest/Untrusted (BYOD, patient Wi-Fi)
     VLAN 50: Management (iDRAC, iLO, switch management)
     Define ACL rules between VLANs (deny by default, allow specific).
  3. Schedule deployment for next week (post-72-hour window).

Risk of Action:     LOW (planning only, no production changes).

Risk of Inaction:   Flat network persists. Lateral movement remains
                    unrestricted. Even with Phases 1-3 blocked, an
                    attacker who enters via ANY vector (phishing,
                    compromised vendor, insider) has unrestricted
                    access to all systems.

Time to Complete:   4 hours (procurement + design).

----------------------------------------------------------------------
ACTION T2-5: EMERGENCY BOARD BRIEFING (VIRTUAL)
----------------------------------------------------------------------

Action:             Convene an emergency virtual Board briefing to
                    inform leadership of the Crimson Tide threat,
                    actions taken, and any additional budget or
                    authority needed for Tier 3.

Phase Addressed:    All phases (enables all other actions through
                    leadership support and resource allocation).

Owner:              James Chen (presents) + You (technical briefing) +
                    Sarah Park (operational update)

Prerequisites:      - T1 actions complete (have results to present).
                    - T2 actions planned (present the plan).
                    - Any compromise assessment results (present findings).

Agenda:
  1. Situation: CISA Crimson Tide advisory, Hospital C active
     containment, CVE-2023-27997 on our FortiGate (CVSS 9.8).
  2. Actions Taken (Tier 1): SSL-VPN disabled, NAS isolated, enhanced
     logging, compromise assessment findings.
  3. Actions Planned (Tier 2-3): FortiGate patch, AD hardening,
     database encryption, network segmentation planning.
  4. Budget Status: $2,400 spent on FortiGate support (emergency
     spend). Additional procurement for network segmentation
     ($15K-$25K) from approved $120K budget.
  5. Risk: If we do nothing, 50,000 patient records at risk of
     exfiltration and public release (double extortion).
  6. Request: Confirmation of support for emergency actions. Authority
     for James Chen to continue directing resources.

Risk of Action:     LOW. Briefing is informational and authorization-
                    seeking.

Risk of Inaction:   Board unaware of active threat. Potential for
                    leadership surprise if incident escalates. Lack
                    of documented Board awareness could have legal/
                    fiduciary implications.

Time to Complete:   45 minutes (briefing).


================================================================================
TIER 2 SUMMARY - TOMORROW (12-36 HOURS)
================================================================================

+-------+------------------+----------+----------+----------+----------+
| ACTION| DESCRIPTION      | PHASE    | OWNER    | TIME     | RISK OF  |
|       |                  | BLOCKED  |          | TO DO    | ACTION   |
+-------+------------------+----------+----------+----------+----------+
| T2-1  | Renew support +  | Phase 1  | James +  | 2 hrs    | MEDIUM   |
|       | patch FortiGate  | (PERM)   | IT #1    |          | (SPOF)   |
+-------+------------------+----------+----------+----------+----------+
| T2-2  | Kerberos AES-256 | Phase 2  | Sarah +  | 4 hrs    | MED-HIGH |
|       | enforcement      | (STOP)   | IT #2    |          | (legacy) |
+-------+------------------+----------+----------+----------+----------+
| T2-3  | PostgreSQL TDE   | Phase 3  | IT #2 +  | 7 hrs    | MEDIUM   |
|       | on ehr-db-01     | Phase 7  | You      |          | (perf)   |
+-------+------------------+----------+----------+----------+----------+
| T2-4  | Network seg.     | Phase 4  | James +  | 4 hrs    | LOW      |
|       | planning + proc. | Phase 7  | IT #1    |          | (plan)   |
+-------+------------------+----------+----------+----------+----------+
| T2-5  | Emergency Board  | ALL      | James +  | 45 min   | LOW      |
|       | briefing         |          | All      |          |          |
+-------+------------------+----------+----------+----------+----------+

TOTAL TIER 2 TIME: ~18 person-hours across the team. Achievable in
one day with parallel execution.


================================================================================
TIER 3 - THIS WEEK (36-72 HOURS)
================================================================================

Actions that require procurement, vendor involvement, or configuration
changes that need testing before production deployment.

----------------------------------------------------------------------
ACTION T3-1: DEPLOY LUKS ENCRYPTION ON NAS-01 AND RE-ENABLE BACKUPS
----------------------------------------------------------------------

Action:             NAS-01 has been physically isolated (T1-2). Before
                    reconnecting, encrypt the backup volume with LUKS2
                    AES-256-XTS. Then re-enable backups to the encrypted
                    volume. Per T20 Implementation Playbook Action #4.

Phase Blocked:      PHASE 7 - Impact (backups survive ransomware because
                    they are encrypted at rest AND on isolated network
                    post-segmentation).

Owner:              IT Staff #2 + You

Prerequisites:      - T1-2 NAS isolation still in effect.
                    - LUKS2 tools verified on NAS-01.
                    - Maintenance window scheduled (requires backup
                      destruction and re-seeding).
                    - Post-encryption backup jobs defined.

Steps:              Execute T20 Implementation Playbook Action #4.
                    Key steps: Unmount, luksFormat, luksOpen, mkfs,
                    mount, re-seed backups.

Risk of Action:     MEDIUM. All existing backups destroyed during
                    encryption setup. If encryption fails or passphrase
                    is lost, backups are unrecoverable.
                    MITIGATION: Passphrase stored in password manager
                    AND physical safe (dual control). Test restore
                    immediately after encryption.

Risk of Inaction:   NAS-01 remains offline (no backups during this
                    period) OR is reconnected unencrypted (backups
                    still vulnerable to ransomware encryption).

Time to Complete:   6-8 hours (including backup re-seeding).

----------------------------------------------------------------------
ACTION T3-2: ENABLE TLS 1.3 ON PATIENT PORTAL WITH AUTOMATED CERT RENEWAL
----------------------------------------------------------------------

Action:             The patient portal certificate expires in 18 days.
                    Deploy TLS 1.3 with Let's Encrypt automated renewal.
                    Per T20 Implementation Playbook Action #1.

Phase Blocked:      PHASE 6 - Data Exfiltration (stronger encryption on
                    legitimate traffic; doesn't directly block attacker
                    but improves overall security posture).
                    Also addresses 1x02-F001 (TLS 1.0) and prevents
                    certificate expiry outage.

Owner:              IT Staff #1 + You

Prerequisites:      - Certbot installed on patient-portal-srv-01.
                    - DNS verified.
                    - Maintenance window: Sunday 02:00-04:00.

Steps:              Execute T20 Implementation Playbook Action #1.
                    Key steps: certbot, nginx config update, reload,
                    SSL Labs validation.

Risk of Action:     LOW. Standard web server certificate renewal.
                    Service impact minimal (seconds of reload).

Risk of Inaction:   Certificate expires in 18 days. Patient portal
                    becomes inaccessible to 800+ patients/day. TLS 1.0
                    remains exploitable. This is a separate emergency
                    from Crimson Tide but equally time-critical.

Time to Complete:   2 hours.

----------------------------------------------------------------------
ACTION T3-3: DEPLOY IMMUTABLE/OFFLINE BACKUP SOLUTION
----------------------------------------------------------------------

Action:             Implement an additional backup tier that is
                    immutable (WORM) or physically offline (air-gapped).
                    This could be cloud-based (AWS S3 with Object Lock
                    in compliance mode) or a physical external drive
                    rotated offline.

Phase Blocked:      PHASE 7 - Impact (immutable backups survive
                    ransomware; enables recovery without ransom).

Owner:              James Chen (procurement/contract) + IT Staff #2
                    (technical implementation)

Prerequisites:      - AWS S3 bucket with Object Lock enabled (requires
                      AWS account and appropriate permissions).
                    - Or: external USB drives (2-4 TB) for physical
                      rotation.
                    - Backup software configured to write to new target.

Steps:
  1. James Chen: Approve AWS S3 Object Lock configuration or purchase
     external drives (~$500 for 2x 4TB drives).
  2. IT Staff #2: Configure backup job to write to S3 bucket with
     Object Lock in COMPLIANCE mode (retention: 30 days minimum,
     cannot be deleted even by root account).
  3. Alternative: Manual backup to external drive, physically
     disconnect and store in fireproof safe. Rotate weekly.
  4. Test restore from immutable backup.

Risk of Action:     LOW for cloud option. MEDIUM for physical option
                    (human error in rotation). Cloud option has ongoing
                    storage costs ($0.023/GB/month for S3 Standard).

Risk of Inaction:   MedDefense has no ransomware-resilient backups.
                    Even with NAS-01 encrypted (T3-1), the NAS is still
                    network-accessible and could be encrypted by
                    ransomware. Immutable backups are the only guarantee
                    of recovery.

Time to Complete:   4 hours (setup) + ongoing backup time.

----------------------------------------------------------------------
ACTION T3-4: ENABLE DICOM TLS BETWEEN MRI AND PACS
----------------------------------------------------------------------

Action:             Encrypt DICOM traffic between MRI workstation and
                    PACS server. Per T20 Implementation Playbook Action #5.
                    Requires internal CA certificates.

Phase Blocked:      PHASE 6 - Data Exfiltration (attacker cannot sniff
                    DICOM images in transit on flat network).

Owner:              IT Staff #2 + Sarah Park (certificates)

Prerequisites:      - Internal CA operational.
                    - Server and client certificates issued.
                    - Vendor documentation for DICOM TLS on specific
                      PACS/MRI models.
                    - Maintenance window (Wednesday 20:00-22:00).

Steps:              Execute T20 Implementation Playbook Action #5.

Risk of Action:     MEDIUM. Medical imaging is clinical-critical. If
                    DICOM TLS breaks image transmission, radiology
                    workflow is disrupted. MITIGATION: Rollback to
                    unencrypted DICOM if issues occur.

Risk of Inaction:   DICOM images with embedded PHI continue flowing
                    unencrypted on flat network. Any attacker on the
                    network can passively capture medical images.

Time to Complete:   2 hours (maintenance window) + 2 hours preparation.

----------------------------------------------------------------------
ACTION T3-5: BEGIN 24/7 SECURITY MONITORING (MSSP ENGAGEMENT)
----------------------------------------------------------------------

Action:             MedDefense has no SIEM and no 24/7 SOC. In the
                    short term, engage a Managed Security Service
                    Provider (MSSP) for 24/7 monitoring of the
                    enhanced logs enabled in T1-3.

Phase Addressed:    PHASE 5 - Defense Evasion (detected by SOC)
                    PHASE 2 - Credential Access (detected by SOC)

Owner:              James Chen (contract, procurement) + Sarah Park
                    (technical integration)

Prerequisites:      - T1-3 enhanced logging operational.
                    - MSSP identified and engaged (use existing vendor
                      relationships or CISA-recommended providers).
                    - Log forwarding configured to MSSP collector.

Steps:
  1. James Chen: Contact MSSP vendors for emergency engagement.
     Request: 24/7 log monitoring, threat detection, alerting.
     Expected cost: $3,000-$8,000/month for initial deployment.
     Approve from $120,000 budget (CG-005 SIEM allocation).
  2. IT Staff #1: Configure syslog forwarding from FortiGate, DCs,
     and critical servers to MSSP collector.
  3. MSSP: Onboard MedDefense logs, configure detection rules for
     Crimson Tide IOCs, begin monitoring.

Risk of Action:     LOW. MSSP provides monitoring without production
                    changes. Cost is within budget.

Risk of Inaction:   MedDefense has no 24/7 detection capability.
                    Enhanced logging (T1-3) generates data but nobody
                    is watching it overnight or on weekends. An attack
                    during off-hours goes undetected until Monday
                    morning.

Time to Complete:   4-8 hours (contract + onboarding).


================================================================================
TIER 3 SUMMARY - THIS WEEK (36-72 HOURS)
================================================================================

+-------+------------------+----------+----------+----------+----------+
| ACTION| DESCRIPTION      | PHASE    | OWNER    | TIME     | RISK OF  |
|       |                  | BLOCKED  |          | TO DO    | ACTION   |
+-------+------------------+----------+----------+----------+----------+
| T3-1  | LUKS encrypt     | Phase 7  | IT #2 +  | 6-8 hrs  | MEDIUM   |
|       | NAS-01 + backups |          | You      |          |          |
+-------+------------------+----------+----------+----------+----------+
| T3-2  | TLS 1.3 on       | Phase 6  | IT #1 +  | 2 hrs    | LOW      |
|       | patient portal   | (cert)   | You      |          |          |
+-------+------------------+----------+----------+----------+----------+
| T3-3  | Immutable backup | Phase 7  | James +  | 4 hrs    | LOW-MED  |
|       | solution         |          | IT #2    |          |          |
+-------+------------------+----------+----------+----------+----------+
| T3-4  | DICOM TLS        | Phase 6  | IT #2 +  | 4 hrs    | MEDIUM   |
|       | MRI to PACS      |          | Sarah    |          |          |
+-------+------------------+----------+----------+----------+----------+
| T3-5  | MSSP 24/7        | Phase 5  | James +  | 4-8 hrs  | LOW      |
|       | monitoring       | Phase 2  | Sarah    |          |          |
+-------+------------------+----------+----------+----------+----------+

TOTAL TIER 3 TIME: ~24 person-hours across the team. Achievable
within the 36-72 hour window with parallel execution.


================================================================================
RESOURCE CONFLICT ASSESSMENT
================================================================================

CONFLICTS IDENTIFIED:

1. SARAH PARK - OVERALLOCATED
   Tasks: T1-1 (SSL-VPN), T1-3 (DC logs), T1-4 (compromise assessment),
          T2-2 (Kerberos), T3-4 (DICOM TLS certs), T3-5 (MSSP)
   Conflict: Sarah is required for too many simultaneous tasks,
            especially in Tier 1 (T1-1 and T1-3 and T1-4).
   Resolution: T1-1 (SSL-VPN disable) is QUICKEST (15 min). Sarah does
               this FIRST. T1-3 (DC logs) can be partially automated
               with a PowerShell script Sarah writes and IT Staff #2
               executes. T1-4 (compromise assessment) is led by YOU
               with Sarah consulting on AD analysis.

2. IT STAFF #1 (NETWORK) - SEQUENCING CONFLICT
   Tasks: T1-1 (SSL-VPN), T1-3 (FortiGate logs), T2-1 (patch FortiGate),
          T2-4 (network design), T3-2 (TLS portal)
   Conflict: T1-1 and T2-1 are on the SAME SYSTEM (FortiGate).
            T1-1 disables SSL-VPN; T2-1 patches firmware.
            If T1-1 is done, T2-1 MUST follow within 24 hours because
            remote VPN users are disconnected.
   Resolution: SEQUENCE these. T1-1 tonight (disable), T2-1 tomorrow
               (patch). This is not a conflict; it's a dependency.
               IT Staff #1 owns the FortiGate end-to-end.

3. IT STAFF #2 (SYSTEMS) - CONCURRENT MAINTENANCE CONFLICT
   Tasks: T1-2 (NAS isolation), T2-3 (PostgreSQL TDE), T3-1 (NAS LUKS),
          T3-4 (DICOM TLS)
   Conflict: T2-3 (TDE) and T3-1 (NAS LUKS) both require multi-hour
            maintenance windows. They CANNOT be done simultaneously
            because IT Staff #2 is the only DBA/storage person.
   Resolution: SEQUENCE these. T2-3 (database TDE) takes PRIORITY over
               T3-1 (NAS LUKS) because the database contains LIVE
               patient data. NAS encryption follows on Day 3.
               DICOM TLS (T3-4) can be done in parallel with NAS LUKS
               prep if DICOM is a separate system.

4. YOU (SECURITY ANALYST) - CONTEXT SWITCHING
   Tasks: T1-2 (verify NAS), T1-3 (syslog setup), T1-4 (compromise
          assessment lead), T2-3 (KMS + crypto verify), T3-1 (LUKS
          verify), T3-2 (TLS verify)
   Conflict: You are involved in nearly every task for verification
            and documentation. Cannot be in multiple places.
   Resolution: You are the FLOATER. You assist with setup and then
               move to the next task. Your primary value is in the
               crypto-specific tasks (KMS, LUKS, TLS verification)
               and the compromise assessment (analysis). Delegate
               syslog setup to IT Staff #1 or use a pre-built script.

5. EHR MAINTENANCE WINDOW CONFLICT
   Tasks: T2-3 (PostgreSQL TDE) requires 4-hour EHR downtime.
          T2-2 (Kerberos) requires authentication testing.
          These should NOT overlap because if Kerberos breaks during
          the EHR maintenance window, you cannot distinguish whether
          the EHR outage is from TDE or from Kerberos.
   Resolution: STAGGER maintenance windows. Kerberos (T2-2) first
               (Sunday 03:00-05:00). Verify all authentication works.
               Then TDE (T2-3) (Sunday 05:00-09:00, extended from
               T20 Playbook to account for Kerberos window).
               This extends the total EHR downtime but provides clean
               change isolation.

CONFLICT RESOLUTION SUMMARY:
+------------------+------------------+------------------+------------------+
| CONFLICT         | RESOLUTION       | IMPACT           | ACCEPTABLE?      |
+------------------+------------------+------------------+------------------+
| Sarah overalloc. | You lead T1-4    | Sarah available  | YES              |
|                  | with her consult | for critical     |                  |
|                  |                  | FortiGate/AD     |                  |
+------------------+------------------+------------------+------------------+
| IT #1 FortiGate  | Sequence: T1-1   | Remote VPN down  | YES              |
| sequencing       | tonight, T2-1    | 24 hrs. Accept-  | (acceptable      |
|                  | tomorrow         | able risk given  | trade-off)       |
|                  |                  | threat.          |                  |
+------------------+------------------+------------------+------------------+
| IT #2 maintenance| Database TDE     | NAS remains      | YES              |
| windows overlap  | FIRST (T2-3),    | isolated until   |                  |
|                  | NAS LUKS (T3-1)  | Day 3. Backups   |                  |
|                  | after.           | offline 48+ hrs. |                  |
+------------------+------------------+------------------+------------------+
| You context      | You float.       | You may be a     | YES              |
| switching        | Prioritize crypto| bottleneck on    |                  |
|                  | tasks. Delegate  | documentation.   |                  |
|                  | syslog to IT #1. | Doc can be post. |                  |
+------------------+------------------+------------------+------------------+
| EHR maintenance  | Kerberos first,  | EHR downtime     | YES              |
| window overlap   | then TDE. Clean  | extended 2 hrs.  | (clean change    |
|                  | separation.      | Clinical impact  | control > speed) |
|                  |                  | managed.         |                  |
+------------------+------------------+------------------+------------------+


================================================================================
72-HOUR OUTCOME TARGET
================================================================================

After 72 hours, the following should be achieved:

SECURITY POSTURE:
  - Phase 1 (Initial Access): CLOSED (SSL-VPN disabled + FortiGate patched)
  - Phase 2 (Credential Access): BLOCKED (AES-256 Kerberos enforced)
  - Phase 3 (Data Collection): ENCRYPTED (PostgreSQL TDE deployed,
    patient data unreadable if exfiltrated)
  - Phase 4 (Lateral Movement): PLANNED (Network segmentation procured,
    deployment next week)
  - Phase 5 (Defense Evasion): DETECTABLE (Enhanced logging + MSSP 24/7)
  - Phase 6 (Data Exfiltration): IMPROVED (TLS 1.3 portal, DICOM TLS,
    encrypted DB reduces value of exfiltrated data)
  - Phase 7 (Impact): RESILIENT (NAS encrypted, immutable backups ordered,
    can recover without ransom)

RISK REDUCTION: From 7/7 phases EXPOSED (T0 assessment) to an estimated
1-2/7 phases EXPOSED (residual risk: advanced exfiltration channels,
ransomware encryption of production systems if network segmentation
not yet deployed).


================================================================================
REFERENCES
================================================================================

- 1x05 T0 CISA Advisory Analysis (7-Phase Crimson Tide Chain)
- 1x05 T1 CVE Deep Dive (CVE-2023-27997)
- 1x05 T2 Kill Chain Overlay (Control Interception Map)
- 1x04 T20 Implementation Playbook (All 5 technical actions)
- 1x03 Security Strategy (Control Roadmap CG-001 through CG-010)
- 1x02 Vulnerability Findings
- 1x00 Network Topology & Asset Registry


================================================================================
END OF 72-HOUR EMERGENCY RESPONSE PLAN
================================================================================
