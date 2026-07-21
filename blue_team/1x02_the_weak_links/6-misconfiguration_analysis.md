================================================================================
                    MISCONFIGURATION ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 6: The Misconfiguration Findings
================================================================================

Exercise: Task 6 - The Misconfiguration Findings
Analyst: shamshed rajput
Date: 21/07/2026
Objective: Analyze vulnerabilities that have no CVE identifier and understand
          why they are equally dangerous.

Source: meddefense-vulnerability-scan.txt
Cross-References: 1x00 Task 3 (Walk-through), Task 5 (Control Gaps), Task 7 (Network Scan)


================================================================================
MISCONFIGURATION FINDING 1: POSTGRESQL UNRESTRICTED NETWORK ACCESS
================================================================================

FINDING ID: 003
Host: 10.10.2.11 (ehr-db-01)
Misconfiguration: PostgreSQL is configured to accept connections from ANY IP
                  address on the internal network (pg_hba.conf allows 10.10.0.0/16).
                  No firewall or network ACL restricts access to port 5432.
                  listen_addresses = '*'
Why No CVE: This is a configuration error, not a software bug. The PostgreSQL
            software functions as designed. The administrator chose to bind to
            all interfaces and allow all network connections. The vulnerability
            exists because of how the system was configured, not because the
            software has a flaw.
Severity Assessment: CRITICAL - The EHR database contains PHI for 50,000+
                      patients. Any compromised host on the flat network can
                      connect directly to the database. This bypasses all
                      application-level authentication controls.
Cross-Reference 1x00: GAP-003 (Flat Network - No Segmentation). Marcus noted:
                      "PostgreSQL is accessible from the entire 10.10.0.0/16
                      range. Should be restricted to ehr-srv-01 only."
Comparable CVE Risk: CVE-2021-44790 (CVSS 9.8) on billing-srv-01. This
                      misconfiguration is equally dangerous because it
                      provides direct access to the EHR database without
                      authentication or application-layer controls, whereas
                      the CVE requires exploitation of a software bug first.


================================================================================
MISCONFIGURATION FINDING 2: SSH PASSWORD AUTHENTICATION ENABLED
================================================================================

FINDING ID: 009
Host: 10.10.2.15 (billing-srv-01)
Misconfiguration: SSH on this host allows password-based authentication.
                  Combined with no account lockout policy on the Linux system,
                  this permits brute-force attacks. SSH key-only authentication
                  is recommended. Other Linux servers also allow password auth
                  except ehr-srv-01.
Why No CVE: This is a configuration choice, not a software vulnerability.
            OpenSSH provides both password and key-based authentication. The
            administrator chose to leave password authentication enabled even
            though key-only is more secure.
Severity Assessment: HIGH - SSH is a critical access point. Password
                      authentication combined with weak passwords and no
                      account lockout makes brute-force attacks feasible.
                      However, it requires the attacker to guess credentials
                      first.
Cross-Reference 1x00: C-005 (SSH Hardening - ehr-srv-01 only). Marcus
                      migrated ehr-srv-01 to key-only auth before leaving.
                      All other Linux servers still have PasswordAuthentication
                      set to 'yes'.
Comparable CVE Risk: CVE-2019-0211 (CVSS 7.8) on billing-srv-01. While the
                      CVE is a software bug, this misconfiguration enables
                      attackers to obtain credentials that can then be used
                      with the CVE to gain root access. The two work together.


================================================================================
MISCONFIGURATION FINDING 3: MYSQL UNRESTRICTED NETWORK BINDING
================================================================================

FINDING ID: 006
Host: 10.10.2.15 (billing-srv-01)
Misconfiguration: MySQL is bound to 0.0.0.0 (all interfaces), accepting
                  connections from any IP on the internal network. It should
                  be bound to localhost (127.0.0.1) or restricted to specific
                  application servers.
Why No CVE: This is a configuration error. MySQL's bind-address parameter
            defaults to 0.0.0.0. The administrator did not restrict it. The
            software works as designed; the configuration creates the exposure.
Severity Assessment: HIGH - The billing database contains financial records
                      and patient billing data. Any compromised host on the
                      flat network can attempt to connect to the database.
                      Combined with weak credentials, this could lead to data
                      exfiltration.
Cross-Reference 1x00: GAP-003 (Flat Network). The billing server's MySQL
                      database is accessible network-wide. The Apache
                      vulnerabilities (Finding 001/002) provide a path to
                      exploit this misconfiguration.
Comparable CVE Risk: CVE-2021-44790 (CVSS 9.8). While the CVE provides RCE,
                      this misconfiguration provides direct database access.
                      An attacker who exploits the CVE can then use this
                      misconfiguration to exfiltrate billing data easily.


================================================================================
MISCONFIGURATION FINDING 4: WINDOWS XP (EOL) ON NETWORK
================================================================================

FINDING ID: 004
Host: 10.10.1.70 (WS-RAD-01 - MRI Workstation)
Misconfiguration: Windows XP is on the same subnet (10.10.1.0/24) as all
                  other workstations with no VLAN isolation. Ports 445 (SMB)
                  and 3389 (RDP) are open. This is a legacy system with no
                  compensating controls.
Why No CVE: The EOL status itself is not a CVE. The CVEs (2017-0144,
            2019-0708, 2008-4250) are the vulnerabilities. The misconfiguration
            is the decision to keep an EOL system on the network without
            isolation, patching, or compensating controls.
Severity Assessment: CRITICAL - The MRI runs Windows XP (EOL 2014) with
                      weaponized exploits (EternalBlue, BlueKeep). It is on
                      the flat network. An attacker can exploit this system
                      and pivot to the EHR, billing, and AD.
Cross-Reference 1x00: GAP-007 (No Compensating Controls for MRI). GAP-003
                      (Flat Network). This is exactly the scenario described
                      in the walk-through (Observation 4 - Medical IoT) and
                      the Legacy Dilemma (Task 6).
Comparable CVE Risk: CVE-2017-0144 (CVSS 8.1) - EternalBlue. The
                      misconfiguration makes this CVE exploitable. Without
                      the misconfiguration (i.e., network isolation),
                      EternalBlue would be much harder to exploit.


================================================================================
MISCONFIGURATION FINDING 5: SYNOLOGY NAS MANAGEMENT INTERFACE ACCESSIBLE
================================================================================

FINDING ID: 015
Host: 10.10.2.41 (NAS-01 - Backup Storage)
Misconfiguration: The Synology NAS management interface (DSM) is accessible
                  from the entire internal network on ports 5000 and 5001.
                  Management interfaces should be restricted to administrative
                  IPs only. Backup data is stored unencrypted.
Why No CVE: This is a configuration choice. The NAS DSM interface is designed
            to be accessible; the administrator did not restrict it to
            administrative IPs. This is not a software vulnerability.
Severity Assessment: HIGH - The NAS contains all backup data for MedDefense
                      servers. If an attacker compromises the NAS management
                      interface, they can delete backups, making recovery
                      impossible. The NAS is co-located with servers (C-009
                      weakness).
Cross-Reference 1x00: C-009 weakness (Backups on same network). Artifact 5
                      (Backup Configuration) notes: "NAS is on the same
                      network and in the same room as the servers. If we
                      lose the room, we lose both."
Comparable CVE Risk: CVE-2021-44790 (CVSS 9.8). While the Apache CVE provides
                      RCE, this misconfiguration provides the ability to
                      delete ALL backups, which is equally catastrophic for
                      recovery operations.


================================================================================
MISCONFIGURATION FINDING 6: DICOM SERVICE WITHOUT ENCRYPTION
================================================================================

FINDING ID: 024
Host: 10.10.2.12 (pacs-srv-01)
Misconfiguration: The PACS server exposes DICOM services (ports 4242 and 11112)
                  without TLS encryption. DICOM traffic contains patient
                  identifiers and medical images. Traffic between the MRI
                  workstation, radiology workstations, and the PACS server
                  traverses the network in cleartext.
Why No CVE: This is a configuration choice. DICOM supports TLS encryption but
            it was not enabled. The software works as designed; encryption is
            available but was not configured.
Severity Assessment: HIGH - Medical images contain PHI. Anyone on the flat
                      network can intercept and view patient images. This
                      violates HIPAA requirements for encryption of PHI in
                      transit. Additionally, the MRI workstation runs
                      Windows XP (Finding 004), making interception easy.
Cross-Reference 1x00: Data Map (Task 9) - Data in Transit: Internal traffic
                      is NOT encrypted. GAP-003 (Flat Network) enables
                      sniffing.
Comparable CVE Risk: CVE-2014-3566 (POODLE, CVSS 7.4) on web-srv-01. Both
                      involve weak/unencrypted transmission of sensitive data.
                      This misconfiguration is equally dangerous because it
                      exposes medical images (PHI) to anyone on the network,
                      with no exploit required.


================================================================================
DANGEROUS FALSE ASSURANCE
================================================================================

+----------------------------------------------------------------------------+
| WHY "OUR CVE SCAN SHOWS NOTHING CRITICAL, WE ARE SECURE" IS FALSE ASSURANCE |
|                                                                             |
| The statement "Our CVE scan shows nothing critical, we are secure" provides |
| dangerous false assurance because it ignores an entire category of         |
| vulnerabilities that are equally or more dangerous than CVEs:              |
| MISCONFIGURATIONS.                                                         |
|                                                                             |
| The six misconfigurations analyzed above expose MedDefense to:             |
| - Direct database access (Finding 003, 006) - no exploit needed          |
| - Brute-force attacks (Finding 009) - no software vulnerability            |
| - EOL systems on the network (Finding 004) - weaponized exploits          |
| - Backup deletion (Finding 015) - complete recovery failure               |
| - PHI exposure in transit (Finding 024) - HIPAA violation                  |
|                                                                             |
| A CVE scan only identifies known software vulnerabilities. It cannot       |
| identify:                                                                  |
| - Misconfigurations (wrong settings, default credentials)                  |
| - Architectural weaknesses (flat network, EOL systems)                    |
| - Operational failures (no encryption, no access controls)                |
| - Procedural gaps (no offboarding, no monitoring)                         |
|                                                                             |
| The MongoDB Ransomware Wave of 2017 affected 28,000 databases. Not one    |
| had a CVE. The Capital One breach (2019) exposing 100 million records     |
| was a misconfiguration. These incidents prove that the most devastating   |
| breaches often exploit misconfigurations, not CVEs.                       |
|                                                                             |
| For MedDefense, a CVE-free scan would still leave:                         |
| - PostgreSQL accessible to anyone on the network                         |
| - MySQL accessible to anyone on the network                              |
| - SSH password auth vulnerable to brute force                            |
| - Windows XP MRI with EternalBlue on the flat network                    |
| - NAS management accessible to anyone                                    |
| - DICOM images transmitted in cleartext                                   |
|                                                                             |
| None of these would appear in a CVE scan. Yet each is a direct path to    |
| compromise. This is why vulnerability assessment must include             |
| misconfiguration analysis alongside CVE analysis.                        |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| Finding  | Host             | Misconfiguration                       | Severity         | Cross-Reference 1x00                    |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 003      | ehr-db-01        | PostgreSQL unrestricted network        | CRITICAL         | GAP-003 (Flat Network)                   |
|          |                  | access                                 |                  |                                          |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 009      | billing-srv-01   | SSH password auth enabled              | HIGH             | C-005 (SSH Hardening only on ehr-srv-01) |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 006      | billing-srv-01   | MySQL unrestricted network binding     | HIGH             | GAP-003 (Flat Network)                   |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 004      | MRI Workstation  | Windows XP on network w/o isolation    | CRITICAL         | GAP-007 (No Compensating Controls)       |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 015      | NAS-01           | NAS management interface accessible    | HIGH             | C-009 (Co-located backups)               |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+
| 024      | pacs-srv-01      | DICOM without encryption               | HIGH             | Data Map - Data in Transit               |
+----------+------------------+----------------------------------------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt
- Asset Registry (1x00 Task 7)
- Gap Analysis (1x00 Task 12)
- Walk-through Observations (1x00 Task 3)
- Control Matrix (1x00 Task 10)
- Data Map (1x00 Task 9)
- MongoDB Ransomware Wave 2017
- Capital One Breach 2019

Cross-References to Project 1x01:
- Threat Actor Matrix (Task 6): Ransomware Groups (#1)
- Kill Chains (Task 10): KC #1, KC #2, KC #4


================================================================================
END OF MISCONFIGURATION ANALYSIS REPORT
================================================================================
