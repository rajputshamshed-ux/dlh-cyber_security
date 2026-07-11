================================================================================
                    SYMPTOM TRAP ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 2: The Symptom Trap
================================================================================

Exercise: Task 2 - The Symptom Trap
Analyst: shamshed rajput
Date: 11/07/2026

[Objective: Develop analytical reflex to look beyond visible symptoms and
          identify root causes in security events.

Source: billing-srv-01_diagnostics.txt
Server: billing-srv-01 (Ubuntu 18.04 LTS)
Issue: Recurring CPU saturation (94.2%)


================================================================================
1. INCIDENT ANALYSIS
================================================================================

1.1 THE VISIBLE SYMPTOM
-----------------------
+----------------------------------------------------------------------------+
| SYMPTOM: Recurring CPU saturation on billing-srv-01 (94.2% CPU usage)      |
| Sysadmin Diagnosis: "Hardware undersized for billing workload."            |
| Recommended Solution: Hardware upgrade or migration to more powerful VM    |
+----------------------------------------------------------------------------+

1.2 THE ACTUAL FINDING
----------------------
+----------------------------------------------------------------------------+
| FINDING: Crypto-miner (Monero) installed and running on billing-srv-01     |
| Process: ./kworker (disguised as legitimate kernel worker)                 |
| User: www-data (unexpected - should be root for kernel processes)         |
| CPU Consumption: 94.2%                                                    |
| Connection: stratum+tcp://pool.monero.org:4443 (pool.mining)              |
+----------------------------------------------------------------------------+

top - 14:22:07 up 12 days, 3:47, 2 users
PID    USER      PR  NI  %CPU  %MEM    COMMAND
8834   www-data  20   0  94.2   3.1    ./kworker -o stratum+tcp://pool.monero.org:4443
1102   root      20   0   2.1   8.4    /usr/sbin/apache2 -k start
1455   mysql     20   0   1.3  12.6    /usr/sbin/mysqld

Active Internet connections:
Proto  Local Address      Foreign Address        State
tcp    10.10.2.15:45892   185.243.115.89:4443    ESTABLISHED
tcp    10.10.2.15:45901   91.121.87.10:8080      ESTABLISHED
tcp    10.10.2.15:80      10.10.1.0/24:*         LISTEN


1.3 KEY ELEMENTS INTERPRETED
----------------------------
+------------------+----------------------------------------------------------+
| Element          | Interpretation                                           |
+------------------+----------------------------------------------------------+
| ./kworker        | Legitimate name spoofed. Real kworker is a kernel        |
|                  | process, not a userland binary executed by www-data.     |
+------------------+----------------------------------------------------------+
| www-data         | Process running under web server user. Indicates         |
|                  | compromise via web application vulnerability.            |
+------------------+----------------------------------------------------------+
| 94.2% CPU        | Crypto-miner consuming almost all CPU resources.         |
+------------------+----------------------------------------------------------+
| stratum+tcp://   | Protocol used by cryptocurrency miners to connect to     |
| pool.monero.org  | mining pools. Monero is a privacy-focused cryptocurrency.|
+------------------+----------------------------------------------------------+
| :4443            | Non-standard port. Attacker uses unusual port to avoid   |
|                  | detection and bypass firewall restrictions.              |
+------------------+----------------------------------------------------------+
| 185.243.115.89   | Foreign IP address (likely attacker's mining pool        |
| 91.121.87.10     | server). Two established connections.                   |
+------------------+----------------------------------------------------------+


================================================================================
2. CIA TRIAD CLASSIFICATION
================================================================================

2.1 THE SYMPTOM TRAP
--------------------
+----------------------------------------------------------------------------+
| The sysadmin sees: CPU at 94.2% → Availability problem                     |
| The sysadmin concludes: Hardware undersized                                 |
| The sysadmin recommends: Upgrade hardware                                  |
|                                                                             |
| THIS IS A SYMPTOM. THE ROOT CAUSE IS A SECURITY COMPROMISE.                |
+----------------------------------------------------------------------------+

2.2 CORRECT CIA CLASSIFICATION (Chronological Order)
---------------------------------------------------
+----------+---------------------+--------------------------------------------------+
| Order    | CIA Pillar          | Explanation                                      |
+----------+---------------------+--------------------------------------------------+
| 1        | Confidentiality     | Attacker gained unauthorized access to server.   |
|          |                     | (NIST SP 800-12: protecting info from            |
|          |                     | unauthorized access)                            |
+----------+---------------------+--------------------------------------------------+
| 2        | Integrity           | Attacker installed crypto-miner (./kworker) on   |
|          |                     | server. Modified system without authorization.   |
|          |                     | (NIST SP 800-12: protecting against              |
|          |                     | unauthorized modification)                       |
+----------+---------------------+--------------------------------------------------+
| 3        | Availability        | Crypto-miner consumes 94.2% CPU. Legitimate      |
| (Visible)|                     | users cannot use system. (NIST SP 800-12:        |
|          |                     | ensuring timely and reliable access)             |
+----------+---------------------+--------------------------------------------------+

2.3 WHY THE SYMPTOM TRAP IS DANGEROUS
-------------------------------------
+----------------------------------------------------------------------------+
| The visible symptom (Availability) is the LAST pillar affected.           |
|                                                                             |
| Confidentiality (breached) → Integrity (modified) → Availability (impacted)|
|         ↑                                                      ↑           |
|         |                                                      |           |
|    Root cause                                           Visible symptom   |
+----------------------------------------------------------------------------+


================================================================================
3. WHY HARDWARE UPGRADE FAILS
================================================================================

3.1 THE FAULTY SOLUTION
-----------------------
+------------------+----------------------------------------------------------+
| Proposed         | "Upgrade hardware or migrate to more powerful VM."        |
| Solution         |                                                           |
+------------------+----------------------------------------------------------+
| Why it Fails     | The attacker's crypto-miner will simply consume whatever |
|                  | resources are available. A more powerful server means     |
|                  | more CPU for the miner, more revenue for the attacker.    |
+------------------+----------------------------------------------------------+

3.2 SCENARIO COMPARISON
-----------------------
+------------------+---------------------------+------------------------------+
| Aspect           | Current Server            | After Hardware Upgrade       |
+------------------+---------------------------+------------------------------+
| CPU Available    | 100%                      | 200% (more powerful)         |
| Miner CPU Usage  | 94.2%                     | ~94% (still saturated)       |
| Business Impact  | Critical billing system   | Critical billing system      |
|                  | severely degraded          | still severely degraded      |
| Attacker Revenue | Mining Monero             | Mining MORE Monero           |
+------------------+---------------------------+------------------------------+

3.3 CONCLUSION
--------------
+----------------------------------------------------------------------------+
| The hardware upgrade treats the symptom (lack of CPU resources) not the   |
| root cause (presence of unauthorized crypto-miner).                       |
|                                                                             |
| THE SECURITY PROBLEM DOES NOT GO AWAY.                                    |
| MedDefense would pay for hardware that benefits the attacker.             |
+----------------------------------------------------------------------------+


================================================================================
4. CONNECTION TO JANUARY INCIDENT
================================================================================

4.1 INCIDENT TIMELINE
---------------------
+----------------------------------------------------------------------------+
| January    : Ransomware incident on billing-srv-01                        |
|             Response: Ad-hoc recovery (improvised over 4 days)            |
|             Action taken: Server "rebuilt"                                |
|                                                                             |
| Post-January: Performance issues observed by Marcus                       |
|             Sticky note: "Check billing-srv-01, something is wrong"       |
|                                                                             |
| Last 2 months: CPU saturation flagged 3 times by IT team                  |
|             Sysadmin: restarts server (temporary fix)                     |
|                                                                             |
| Now         : Crypto-miner discovered running on billing-srv-01           |
+----------------------------------------------------------------------------+

4.2 WHAT THIS SUGGESTS
----------------------
+----------------------------------------------------------------------------+
| The same server (billing-srv-01) was compromised in January (ransomware) |
| and is compromised again now (crypto-miner).                              |
|                                                                             |
| POSSIBLE EXPLANATIONS:                                                     |
| 1. The server was never fully cleaned after the ransomware.               |
|    The attacker left a backdoor.                                         |
|                                                                             |
| 2. The "rebuild" was incomplete. The same vulnerability that allowed      |
|    initial compromise was never fixed.                                   |
|                                                                             |
| 3. The initial compromise vector was never identified and remediated.     |
|                                                                             |
| 4. The attacker maintained persistence and re-entered after the           |
|    "rebuild."                                                             |
+----------------------------------------------------------------------------+

4.3 THE CRITICAL QUESTION
-------------------------
+----------------------------------------------------------------------------+
| THE QUESTION YOU MUST ASK:                                                 |
|                                                                             |
| "How did the attacker gain access to billing-srv-01 in January?"          |
|                                                                             |
| AND ITS CONSEQUENCE:                                                       |
|                                                                             |
| "Has that vulnerability been identified, patched, or otherwise            |
|  eliminated?"                                                              |
|                                                                             |
| Until this question is answered, ANY "fix" is temporary.                  |
| The attacker will return.                                                 |
+----------------------------------------------------------------------------+


================================================================================
5. RECOMMENDED CORRECTIVE ACTIONS
================================================================================

5.1 IMMEDIATE ACTIONS (0-24 hours)
----------------------------------
+----------+------------------+--------------------------------------------------+
| Priority | Action           | Justification                                    |
+----------+------------------+--------------------------------------------------+
| 1        | Isolate          | Take billing-srv-01 offline. The server is       |
|          | billing-srv-01   | compromised and actively mining Monero.          |
+----------+------------------+--------------------------------------------------+
| 2        | Capture          | Create forensic image of the server before       |
|          | Forensic Image   | any changes. This preserves evidence.            |
+----------+------------------+--------------------------------------------------+
| 3        | Block Outbound   | Block outbound connections to the foreign IPs    |
|          | Connections      | (185.243.115.89 and 91.121.87.10) at firewall.   |
+----------+------------------+--------------------------------------------------+
| 4        | Disable          | Disable malicious process (PID 8834) and remove  |
|          | Malicious        | any cron jobs/systemd services.                  |
|          | Process          |                                                  |
+----------+------------------+--------------------------------------------------+

5.2 ROOT CAUSE REMEDIATION (1-3 days)
-------------------------------------
+----------+------------------+--------------------------------------------------+
| Priority | Action           | Justification                                    |
+----------+------------------+--------------------------------------------------+
| 1        | Identify Initial | Perform thorough web application security        |
|          | Attack Vector    | review. Find how attacker gained initial access. |
+----------+------------------+--------------------------------------------------+
| 2        | Patch            | Patch identified vulnerability (web app code,    |
|          | Vulnerability   | OS, third-party libraries).                      |
+----------+------------------+--------------------------------------------------+
| 3        | Clean Rebuild   | Perform CLEAN rebuild from known-good media.     |
|          |                  | Do NOT restore from potentially compromised      |
|          |                  | backups.                                          |
+----------+------------------+--------------------------------------------------+
| 4        | Change All       | Change all passwords, API keys, and secrets      |
|          | Credentials      | that were on compromised server.                 |
+----------+------------------+--------------------------------------------------+

5.3 MEDIUM-TERM IMPROVEMENTS (1-2 weeks)
----------------------------------------
+----------+------------------+--------------------------------------------------+
| Priority | Action           | Justification                                    |
+----------+------------------+--------------------------------------------------+
| 1        | Implement EDR   | Deploy Endpoint Detection and Response to        |
|          |                  | detect and block malicious processes.            |
+----------+------------------+--------------------------------------------------+
| 2        | Network          | Implement network segmentation. Ensure           |
|          | Segmentation     | billing-srv-01 cannot communicate unnecessarily. |
+----------+------------------+--------------------------------------------------+
| 3        | Centralized      | Deploy centralized logging to secure SIEM.       |
|          | Logging          |                                                  |
+----------+------------------+--------------------------------------------------+
| 4        | Alerting         | Configure alerts for high CPU usage, unusual     |
|          |                  | outbound connections, new processes under        |
|          |                  | www-data, failed login attempts.                 |
+----------+------------------+--------------------------------------------------+

5.4 LONG-TERM IMPROVEMENTS (1 month+)
-------------------------------------
+----------+------------------+--------------------------------------------------+
| Priority | Action           | Justification                                    |
+----------+------------------+--------------------------------------------------+
| 1        | MFA Implementation| No MFA is currently in place (except James).    |
|          |                  | Implement MFA for all privileged access.         |
+----------+------------------+--------------------------------------------------+
| 2        | Principle of     | Review all user privileges. Remove unnecessary   |
|          | Least Privilege  | permissions.                                    |
+----------+------------------+--------------------------------------------------+
| 3        | Vulnerability    | Implement regular vulnerability scanning for     |
|          | Scanning         | all servers.                                     |
+----------+------------------+--------------------------------------------------+
| 4        | BCP/DR Plan      | Document and test business continuity and        |
|          |                  | disaster recovery plans.                         |
+----------+------------------+--------------------------------------------------+


================================================================================
6. KEY TAKEAWAYS
================================================================================

1. Never treat symptoms without investigating root causes.
   The "Symptom Trap" is a common security failure.

2. CPU saturation is often a symptom of compromise, not hardware failure.

3. Security incidents follow a sequence: Confidentiality → Integrity → Availability.
   Availability is usually the last and most visible pillar impacted.

4. A hardware upgrade does NOT solve a security problem.
   It gives the attacker more resources.

5. A single server compromised multiple times (ransomware + crypto-miner)
   indicates the root cause was never addressed.

6. The critical question is always: "How did the attacker gain access?"
   Without answering this, any "fix" is temporary.

7. www-data running a crypto-miner suggests web application compromise.

8. Document and learn from incidents. The January ransomware response was
   ad-hoc with no lessons learned.


================================================================================
7. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls
- CIS Controls v8: Critical Security Controls
- HHS HICP: Healthcare Cybersecurity Practices
- CISA Healthcare and Public Health Sector Guide


================================================================================
END OF SYMPTOM TRAP ANALYSIS REPORT
================================================================================
