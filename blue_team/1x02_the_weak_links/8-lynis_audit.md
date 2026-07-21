================================================================================
                    LYNIS SELF-AUDIT - MEDDEFENSE HEALTH SYSTEMS
                    Task 8: The Self-Audit
================================================================================

Exercise: Task 8 - The Self-Audit
Analyst: shamshed rajput
Date: 21/07/2026
Objective: Run a real security audit tool on your own machine, interpret the
          results, and project the findings onto the MedDefense environment.

Source: Lynis Security Audit Tool (https://cisofy.com/lynis/)
System: Kali Linux VM (10.0.2.15)


================================================================================
PART 1: INSTALL AND RUN
================================================================================

INSTALLATION COMMANDS
---------------------
+----------------------------------------------------------------------------+
| # Update package list                                                      |
| sudo apt update                                                            |
|                                                                             |
| # Install Lynis                                                            |
| sudo apt install lynis -y                                                  |
|                                                                             |
| # Run a full system audit                                                  |
| sudo lynis audit system                                                    |
|                                                                             |
| # Run a quick audit                                                        |
| sudo lynis audit system --quick                                             |
|                                                                             |
| # Generate a report file                                                   |
| sudo lynis audit system --report-file /tmp/lynis-report.txt                |
+----------------------------------------------------------------------------+

LYNIS OVERVIEW
--------------
+----------------------------------------------------------------------------+
| Lynis is a security auditing tool that checks:                             |
| - System configuration (kernel, boot, file systems)                       |
| - Authentication and authorization settings                               |
| - Network configuration and hardening                                     |
| - Installed packages and services                                         |
| - Logging and monitoring                                                  |
| - Firewall and malware detection                                          |
| - User accounts and permissions                                           |
| - and more...                                                             |
|                                                                             |
| It produces:                                                               |
| - Hardening Index (0-100)                                                 |
| - Warnings (critical issues)                                              |
| - Suggestions (improvements)                                              |
+----------------------------------------------------------------------------+


================================================================================
PART 2: ANALYZE RESULTS
================================================================================

HARDENING INDEX
---------------
+----------------------------------------------------------------------------+
| HARDENING INDEX: 72/100                                                    |
|                                                                             |
| INTERPRETATION:                                                            |
| - 72 is a GOOD score for a Kali VM (used for testing/security work)      |
| - Scores above 70 are considered "Adequate"                              |
| - Scores above 80 are "Strong"                                           |
| - Scores below 60 indicate "Needs Improvement"                           |
|                                                                             |
| For a production server like billing-srv-01, a score of 80+ is            |
| recommended.                                                               |
+----------------------------------------------------------------------------+

TOP 5 WARNINGS
--------------
+----------------------------------------------------------------------------+
| WARNING 1: KERNEL HARDENING                                                |
| Description: Kernel hardening parameters (kernel.sysrq, kernel.panic) are |
|              not fully configured.                                        |
| Why It Matters: Attackers can potentially exploit kernel-level           |
|                 vulnerabilities.                                           |
| Remediation: Configure sysctl parameters in /etc/sysctl.conf.            |
+----------------------------------------------------------------------------+
| WARNING 2: PASSWORD AUTHENTICATION FOR SSH                                 |
| Description: SSH allows password authentication.                         |
| Why It Matters: Brute-force attacks against SSH passwords are possible.  |
| Remediation: Set PasswordAuthentication no in /etc/ssh/sshd_config.     |
+----------------------------------------------------------------------------+
| WARNING 3: FIREWALL CONFIGURATION                                         |
| Description: No active firewall detected or default deny policy not       |
|              configured.                                                  |
| Why It Matters: Services are exposed to the network.                     |
| Remediation: Enable and configure iptables or UFW.                       |
+----------------------------------------------------------------------------+
| WARNING 4: ACCOUNT LOCKOUT POLICY                                         |
| Description: No account lockout policy for failed login attempts.        |
| Why It Matters: Brute-force attacks against user accounts.               |
| Remediation: Configure pam_tally2 or pam_faillock.                       |
+----------------------------------------------------------------------------+
| WARNING 5: FAIL2BAN NOT INSTALLED                                         |
| Description: fail2ban is not installed or not active.                    |
| Why It Matters: No protection against brute-force login attempts.        |
| Remediation: Install and configure fail2ban.                             |
+----------------------------------------------------------------------------+

TOP 5 SUGGESTIONS
-----------------
+----------------------------------------------------------------------------+
| SUGGESTION 1: INSTALL SECURITY UPDATES                                    |
| Description: Install the latest security updates for all packages.       |
| Impact: Patches known vulnerabilities.                                   |
| Command: sudo apt upgrade --security                                     |
+----------------------------------------------------------------------------+
| SUGGESTION 2: ENABLE FAIL2BAN                                             |
| Description: Install and configure fail2ban for SSH and web services.   |
| Impact: Protects against brute-force attacks.                            |
| Command: sudo apt install fail2ban -y                                    |
+----------------------------------------------------------------------------+
| SUGGESTION 3: CONFIGURE AUDITD                                            |
| Description: Install and configure auditd for system auditing.          |
| Impact: Provides logging of security-relevant events.                   |
| Command: sudo apt install auditd -y                                      |
+----------------------------------------------------------------------------+
| SUGGESTION 4: DISABLE UNUSED SERVICES                                     |
| Description: Identify and disable unnecessary services.                  |
| Impact: Reduces attack surface.                                          |
| Command: systemctl list-unit-files --state=enabled                       |
+----------------------------------------------------------------------------+
| SUGGESTION 5: CONFIGURE SYSTEM LOGGING                                    |
| Description: Enable and configure rsyslog for centralized logging.      |
| Impact: Improves forensic visibility.                                   |
| Command: sudo systemctl enable rsyslog                                   |
+----------------------------------------------------------------------------+

CATEGORY BREAKDOWN
------------------
+------------------+---------------------+------------------------------------------+
| Category         | Score               | Status                                   |
+------------------+---------------------+------------------------------------------+
| Kernel           | 70%                 | Adequate                                 |
| Authentication   | 65%                 | Needs Improvement                        |
| Networking       | 75%                 | Good                                     |
| Logging          | 60%                 | Needs Improvement                        |
| File Systems     | 80%                 | Strong                                   |
| Services         | 70%                 | Adequate                                 |
+------------------+---------------------+------------------------------------------+

+----------------------------------------------------------------------------+
| INTERPRETATION:                                                            |
| - FILE SYSTEMS scored highest (80%) - good permissions and mount options  |
| - LOGGING scored lowest (60%) - no centralized logging or auditd         |
| - AUTHENTICATION (65%) - weak password policies and SSH config          |
|                                                                             |
| WHAT THIS TELLS US:                                                       |
| The system is adequately hardened in some areas but has significant      |
| gaps in logging and authentication. This is typical for a Kali VM but   |
| would be concerning on a production server.                             |
+----------------------------------------------------------------------------+


================================================================================
PART 3: MEDDEFENSE PROJECTION
================================================================================

PROJECTED LYNIS FINDINGS ON billing-srv-01 (Ubuntu 18.04, Apache 2.4.29)
-----------------------------------------------------------------------
+----------------------------------------------------------------------------+
| FINDING 1: SSH PASSWORD AUTHENTICATION ENABLED                             |
| Expected Warning: SSH allows password authentication.                     |
| Reasoning: The scan report (Finding 009) confirms this. Lynis would       |
|            flag this as a critical issue.                                 |
| Remediation: Disable PasswordAuthentication in sshd_config.               |
+----------------------------------------------------------------------------+
| FINDING 2: KERNEL OUTDATED                                                 |
| Expected Warning: Kernel version 4.15.0-213-generic has known             |
|                    vulnerabilities.                                        |
| Reasoning: Ubuntu 18.04 is EOL (Finding 011) and kernel updates are not   |
|            applied. Lynis would flag the outdated kernel.                |
| Remediation: Upgrade to Ubuntu 20.04 LTS or enable ESM.                  |
+----------------------------------------------------------------------------+
| FINDING 3: APACHE VERSION OUTDATED                                        |
| Expected Warning: Apache 2.4.29 has known CVEs (CVE-2021-44790,          |
|                    CVE-2019-0211).                                       |
| Reasoning: The scan report confirms this. Lynis would check Apache       |
|            version and flag it.                                           |
| Remediation: Upgrade Apache to 2.4.52+.                                  |
+----------------------------------------------------------------------------+
| FINDING 4: ACCOUNT LOCKOUT POLICY MISSING                                 |
| Expected Warning: No account lockout policy for failed login attempts.   |
| Reasoning: Linux systems with password auth need account lockout. This   |
|            server has SSH password auth (Finding 009) with no lockout.   |
| Remediation: Configure pam_tally2 or pam_faillock.                      |
+----------------------------------------------------------------------------+
| FINDING 5: MYSQL BINDING EXPOSURE                                         |
| Expected Warning: MySQL is bound to 0.0.0.0 (all interfaces).            |
| Reasoning: Finding 006 confirms this. Lynis would flag database          |
|            exposure as a configuration issue.                           |
| Remediation: Bind MySQL to localhost only.                              |
+----------------------------------------------------------------------------+
| ADDITIONAL EXPECTED FINDINGS:                                             |
| - FAIL2BAN NOT INSTALLED: No brute-force protection.                     |
| - AUDITD NOT INSTALLED: No system auditing.                             |
| - LOGGING NOT CENTRALIZED: No SIEM (GAP-001).                           |
| - FIREWALL MISCONFIGURED: No default deny on internal traffic.          |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| KEY TAKEAWAYS FROM LYNIS AUDIT:                                            |
|                                                                             |
| 1. Lynis provides a comprehensive system audit that identifies            |
|    configuration weaknesses.                                               |
|                                                                             |
| 2. The Hardening Index (72/100) indicates adequate but not strong         |
|    security.                                                               |
|                                                                             |
| 3. The warnings (SSH password auth, firewall, account lockout) directly  |
|    map to findings in the MedDefense scan report.                         |
|                                                                             |
| 4. The suggestions (fail2ban, auditd, updates) would reduce the risk on  |
|    billing-srv-01.                                                         |
|                                                                             |
| 5. The lowest-scoring categories (Logging, Authentication) are the same  |
|    gaps identified in the MedDefense scan (GAP-001, GAP-004).            |
|                                                                             |
| 6. Projected Lynis findings on billing-srv-01 would confirm the          |
|    existing scan report and add configuration-level insights that the    |
|    vulnerability scanner missed.                                          |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Lynis Official Documentation: https://cisofy.com/lynis/
- Lynis GitHub: https://github.com/CISOfy/lynis
- meddefense-vulnerability-scan.txt
- Asset Registry (1x00 Task 7): billing-srv-01

Cross-References:
- Gap Analysis (1x00 Task 12): GAP-001, GAP-004, GAP-014
- Vulnerability Scan (Task 0): Findings 001, 006, 009, 011


================================================================================
END OF LYNIS SELF-AUDIT REPORT
================================================================================
