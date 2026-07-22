================================================================================
                    NOISE FILTER - MEDDEFENSE HEALTH SYSTEMS
                    Task 16: The Noise Filter
================================================================================

Exercise: Task 16 - The Noise Filter
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Triage every finding in the scan report into action categories to
          separate signal from noise.

Source: meddefense-vulnerability-scan.txt

Categories:
- AC = Actionable Critical (Immediate remediation 24-48h)
- AS = Actionable Standard (Scheduled remediation 7-30 days)
- I = Informational (Document and monitor)
- FP = False Positive (Document and dismiss)


================================================================================
FULL TRIAGE (ALL 31 FINDINGS)
================================================================================

Finding 001 | CVSS 9.8 | billing-srv-01 | Category: AC | Reason: Remote code execution on billing server (CVE-2021-44790) with public PoC. Chains with Finding 002 for full system compromise.

Finding 002 | CVSS 7.8 | billing-srv-01 | Category: AC | Reason: CISA KEV listed privilege escalation (CVE-2019-0211). Chains with Finding 001 for full system compromise. Actively exploited.

Finding 003 | N/A (Critical) | ehr-db-01 | Category: AC | Reason: PostgreSQL unrestricted network access on EHR database. Any compromised host can access 50,000+ patient records directly.

Finding 004 | N/A (Critical) | MRI Workstation | Category: AC | Reason: Windows XP EOL with weaponized exploits (EternalBlue, BlueKeep, MS08-067). Permanent backdoor on the flat network.

Finding 005 | HIGH | web-srv-01 | Category: AS | Reason: TLS 1.0 support (POODLE/BEAST) on internet-facing patient portal. TLS 1.2 is supported, so not critical but should be addressed.

Finding 006 | HIGH | billing-srv-01 | Category: AC | Reason: MySQL unrestricted network binding allows database access from any compromised host on the flat network.

Finding 007 | HIGH | ad-dc-01 | Category: AC | Reason: LDAP signing not required allows relay attacks on Domain Controller. Domain compromise risk.

Finding 008 | HIGH | print-srv-01 | Category: AS | Reason: Windows Server 2012 R2 EOL with PrintNightmare. Print server is LOW criticality, but EOL system should be migrated.

Finding 009 | HIGH | billing-srv-01 | Category: AC | Reason: SSH password authentication enabled with no account lockout. Brute-force attacks possible on critical billing server.

Finding 010 | HIGH | BD Alaris Pumps | Category: AC | Reason: Default credentials (admin/admin) on 7 life-safety infusion pumps. Direct patient safety risk.

Finding 011 | HIGH | billing-srv-01 | Category: AC | Reason: Ubuntu 18.04 EOL without ESM. No security patches for OS-level vulnerabilities.

Finding 012 | MEDIUM | web-srv-01 | Category: AS | Reason: Missing HTTP security headers (XSS, CSP, HSTS). Defense-in-depth issue on internet-facing portal.

Finding 013 | MEDIUM | web-srv-01 | Category: AS | Reason: SSL certificate expires in 23 days. Patient portal will become inaccessible if not renewed.

Finding 014 | MEDIUM | Westside Router | Category: AS | Reason: Consumer-grade Netgear router at Westside. Not enterprise-grade. Should be replaced with proper firewall.

Finding 015 | MEDIUM | NAS-01 | Category: AC | Reason: NAS management interface accessible network-wide. Attacker can delete all backups.

Finding 016 | MEDIUM | Philips Monitors | Category: AS | Reason: Medical device web interfaces accessible on flat network. Should be isolated (GAP-003).

Finding 017 | MEDIUM | ehr-srv-01 | Category: I | Reason: Tomcat version disclosure only. Led to manual discovery of Ghostcat (Finding 031).

Finding 018 | MEDIUM | ad-dc-01/02 | Category: AS | Reason: Weak Kerberos encryption types (DES, RC4) enabled. Upgrade encryption.

Finding 019 | MEDIUM | Multiple (RDP) | Category: AS | Reason: RDP enabled on 5 workstations. Common attack vector but NLA is enabled (mitigation).

Finding 020 | MEDIUM | backup-srv-01 | Category: FP | Reason: CVE-2023-38408 requires ssh-agent forwarding to attacker-controlled host. Not present in this environment (SecurePoint flagged as potential FP).

Finding 021 | MEDIUM | web-srv-01 | Category: AS | Reason: HTTP TRACE method enabled. Low risk but should be disabled.

Finding 022 | LOW | ehr-srv-01 | Category: I | Reason: System clock skew 47 seconds. Operational issue, not security vulnerability.

Finding 023 | LOW | Multiple (Workstations) | Category: AS | Reason: USB mass storage not restricted. Data exfiltration risk. Address via GPO.

Finding 024 | LOW | pacs-srv-01 | Category: AS | Reason: DICOM services without encryption. Medical images (PHI) transmitted in cleartext.

Finding 025 | LOW | ad-dc-01 | Category: AS | Reason: DNS zone transfer enabled. Reconnaissance risk.

Finding 026 | LOW | billing-srv-01 | Category: AC | Reason: Kernel version outdated with 47 known CVEs. Ubuntu 18.04 EOL without ESM.

Finding 027 | INFORMATIONAL | Workstations | Category: I | Reason: 15 workstations have inactive Sophos agent. Monitor and remediate.

Finding 028 | INFORMATIONAL | Unknown Linux | Category: AC | Reason: Unidentified shadow IT device on server subnet (Jupyter Notebook, Cockpit). Investigate immediately.

Finding 029 | INFORMATIONAL | Unknown Linux (Westside) | Category: AC | Reason: Unidentified shadow IT device with Grafana 8.2.0 (vulnerable to CVE-2021-43798). Investigate immediately.

Finding 030 | INFORMATIONAL | ehr-srv-01 | Category: I | Reason: TLS certificate common name mismatch. Operational issue, not security.

Finding 031 | CVSS 9.8 | ehr-srv-01 | Category: AC | Reason: Ghostcat (CVE-2020-1938) on EHR application server. AJP connector allows file read including database credentials.


================================================================================
TRIAGE SUMMARY
================================================================================

+------------------+---------------------+------------------------------------------+
| Category         | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| AC - Actionable  | 12                  | 38.7%                                    |
| Critical         |                     |                                          |
+------------------+---------------------+------------------------------------------+
| AS - Actionable  | 11                  | 35.5%                                    |
| Standard         |                     |                                          |
+------------------+---------------------+------------------------------------------+
| I - Informational| 4                   | 12.9%                                    |
+------------------+---------------------+------------------------------------------+
| FP - False       | 1                   | 3.2%                                     |
| Positive         |                     |                                          |
+------------------+---------------------+------------------------------------------+
| TOTAL            | 31                  | 100%                                     |
+------------------+---------------------+------------------------------------------+


================================================================================
ACTIONABLE FINDINGS LIST (SORTED BY PRIORITY)
================================================================================

ACTIONABLE CRITICAL (AC) - 12 FINDINGS (24-48 HOURS)
----------------------------------------------------
+----------+------------------+----------------------------------------+------------------------------------------+
| Priority | Finding ID       | Host                                   | Reason                                   |
+----------+------------------+----------------------------------------+------------------------------------------+
| #1       | 004              | MRI Workstation                        | Windows XP EOL with weaponized exploits  |
|          |                  |                                        | (EternalBlue, BlueKeep) on flat network  |
+----------+------------------+----------------------------------------+------------------------------------------+
| #2       | 031              | ehr-srv-01                             | Ghostcat (CVE-2020-1938) on EHR          |
|          |                  |                                        | application server - read credentials    |
+----------+------------------+----------------------------------------+------------------------------------------+
| #3       | 003              | ehr-db-01                              | PostgreSQL unrestricted - direct access  |
|          |                  |                                        | to 50,000+ patient records               |
+----------+------------------+----------------------------------------+------------------------------------------+
| #4       | 010              | BD Alaris Pumps                        | Default credentials (admin/admin) on     |
|          |                  |                                        | life-safety infusion pumps               |
+----------+------------------+----------------------------------------+------------------------------------------+
| #5       | 001              | billing-srv-01                         | Apache RCE (CVE-2021-44790) with PoC     |
+----------+------------------+----------------------------------------+------------------------------------------+
| #6       | 002              | billing-srv-01                         | Apache privilege escalation (CISA KEV)   |
+----------+------------------+----------------------------------------+------------------------------------------+
| #7       | 006              | billing-srv-01                         | MySQL unrestricted binding               |
+----------+------------------+----------------------------------------+------------------------------------------+
| #8       | 007              | ad-dc-01                               | LDAP signing not required - relay attacks|
+----------+------------------+----------------------------------------+------------------------------------------+
| #9       | 015              | NAS-01                                 | NAS management accessible - backup       |
|          |                  |                                        | deletion risk                            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #10      | 009              | billing-srv-01                         | SSH password auth with no lockout        |
+----------+------------------+----------------------------------------+------------------------------------------+
| #11      | 011 + 026        | billing-srv-01                         | Ubuntu 18.04 EOL without ESM + outdated  |
|          |                  |                                        | kernel (47 CVEs)                         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #12      | 028 + 029        | Unknown Linux devices                  | Shadow IT devices - investigate           |
|          |                  | (Shadow IT)                            | immediately                               |
+----------+------------------+----------------------------------------+------------------------------------------+

ACTIONABLE STANDARD (AS) - 11 FINDINGS (7-30 DAYS)
---------------------------------------------------
+----------+------------------+----------------------------------------+------------------------------------------+
| Priority | Finding ID       | Host                                   | Reason                                   |
+----------+------------------+----------------------------------------+------------------------------------------+
| #1       | 005              | web-srv-01                             | TLS 1.0 support on patient portal        |
+----------+------------------+----------------------------------------+------------------------------------------+
| #2       | 012              | web-srv-01                             | Missing HTTP security headers             |
+----------+------------------+----------------------------------------+------------------------------------------+
| #3       | 013              | web-srv-01                             | SSL certificate expires in 23 days       |
+----------+------------------+----------------------------------------+------------------------------------------+
| #4       | 014              | Westside Router                        | Consumer-grade router at Westside        |
+----------+------------------+----------------------------------------+------------------------------------------+
| #5       | 016              | Philips Monitors                       | Medical device web interfaces accessible  |
+----------+------------------+----------------------------------------+------------------------------------------+
| #6       | 018              | ad-dc-01/02                            | Weak Kerberos encryption types            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #7       | 019              | Multiple (RDP)                         | RDP enabled on 5 workstations            |
+----------+------------------+----------------------------------------+------------------------------------------+
| #8       | 021              | web-srv-01                             | HTTP TRACE method enabled                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #9       | 023              | Multiple Workstations                  | USB mass storage not restricted           |
+----------+------------------+----------------------------------------+------------------------------------------+
| #10      | 024              | pacs-srv-01                            | DICOM services without encryption         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #11      | 025              | ad-dc-01                               | DNS zone transfer enabled                 |
+----------+------------------+----------------------------------------+------------------------------------------+


================================================================================
SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| TRIAGE SUMMARY                                                             |
|                                                                             |
| Of 31 findings:                                                            |
| - 12 are ACTIONABLE CRITICAL (38.7%) - must be addressed within 24-48h   |
| - 11 are ACTIONABLE STANDARD (35.5%) - schedule within 7-30 days          |
| - 4 are INFORMATIONAL (12.9%) - document and monitor                     |
| - 1 is FALSE POSITIVE (3.2%) - dismiss                                   |
|                                                                             |
| The flat network (GAP-003) is the PRIMARY AMPLIFIER. Without             |
| segmentation, every vulnerability is network-wide.                        |
|                                                                             |
| billing-srv-01 has the MOST findings (6) and is the most exposed         |
| critical server.                                                          |
|                                                                             |
| The MRI Windows XP (Finding 004) is the SINGLE MOST DANGEROUS finding.    |
|                                                                             |
| Ghostcat (Finding 031) on ehr-srv-01 is the most urgent application-     |
| level vulnerability.                                                      |
|                                                                             |
| Default credentials on medical devices (Finding 010) is the most urgent   |
| patient safety finding.                                                   |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt (all 31 findings)
- Gap Analysis (1x00 Task 12): GAP-003, GAP-007
- Kill Chains (1x01 Task 10): KC #1, KC #2, KC #3, KC #4
- Asset Registry (1x00 Task 7): All assets


================================================================================
END OF NOISE FILTER REPORT
================================================================================
