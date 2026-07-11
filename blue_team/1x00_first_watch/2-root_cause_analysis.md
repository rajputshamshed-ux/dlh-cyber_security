================================================================================
                    SYMPTOM TRAP ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 2: The Symptom Trap
================================================================================

Exercise: Task 2 - The Symptom Trap
Analyst: shamshed rajput
Date: 11/07/2026

Objective: Develop analytical reflex to look beyond visible symptoms and
          identify root causes in security events.

Methodology References:
- NIST SP 800-12 Rev.1: CIA Triad (Chapters 2-3) - Foundational framework
- NIST SP 800-30: Threat, Vulnerability, Risk definitions (Chapter 2)
- NIST SP 800-53 Rev.5: Control Families (taxonomy context)
- CIS Controls v8: Critical controls (top-level understanding)
- NIST CSF 2.0: Identify Function (asset context)
- CISA Healthcare Guide: Healthcare threat context
- ISO 27001 Gap Analysis: Structured assessment methodology
- HHS HICP: Healthcare security practices

Source: billing-srv-01_diagnostics.txt
Server: billing-srv-01 (Ubuntu 18.04 LTS)
Issue: Recurring CPU saturation (94.2%)


================================================================================
1. INCIDENT ANALYSIS - NIST SP 800-12 & NIST SP 800-30 FRAMEWORK
================================================================================

1.1 THE VISIBLE SYMPTOM (NIST SP 800-30 - Impact Assessment)
------------------------------------------------------------
+----------------------------------------------------------------------------+
| SYMPTOM: Recurring CPU saturation on billing-srv-01 (94.2% CPU usage)      |
| Sysadmin Diagnosis: "Hardware undersized for billing workload."            |
| Recommended Solution: Hardware upgrade or migration to more powerful VM    |
+----------------------------------------------------------------------------+

NIST SP 800-30 (Chapter 2 - The Fundamentals):
- The sysadmin is only observing the IMPACT (Availability loss)
- The sysadmin is misidentifying the ROOT CAUSE (hardware vs. compromise)
- This is a classic failure to decompose the incident into risk components

1.2 THE ACTUAL FINDING - NIST SP 800-30 Risk Components
-------------------------------------------------------
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


1.3 NIST SP 800-30 RISK COMPONENTS DECOMPOSED
---------------------------------------------
+------------------+----------------------------------------------------------+
| Component        | Analysis                                                 |
+------------------+----------------------------------------------------------+
| THREAT           | Threat Actor: Cybercriminal                              |
| (NIST SP 800-30) | Motivation: Financial gain (cryptocurrency mining)      |
|                  | Capability: Exploited web application vulnerability      |
|                  | (based on process running under www-data)               |
+------------------+----------------------------------------------------------+
| VULNERABILITY    | Unpatched web application vulnerability                  |
| (NIST SP 800-30) | Weak access controls (www-data can execute arbitrary    |
|                  | binaries)                                                |
|                  | No EDR/AV to detect the crypto-miner                     |
|                  | No network monitoring to detect outbound connections     |
+------------------+----------------------------------------------------------+
| LIKELIHOOD       | HIGH (server has been compromised twice in 6 months)     |
| (NIST SP 800-30) | Attacker has established persistence and is actively     |
|                  | exploiting the server                                     |
+------------------+----------------------------------------------------------+
| IMPACT           | Availability: CPU saturation (94.2% usage)               |
| (NIST SP 800-30) | Confidentiality: Data potentially exfiltrated            |
|                  | Integrity: System modified (malware installed)           |
+------------------+----------------------------------------------------------+
| RISK             | RISK = Threat x Vulnerability x Impact                   |
| (NIST SP 800-30) | HIGH (Critical billing server compromised, likely        |
|                  | impacting patient billing operations)                     |
+------------------+----------------------------------------------------------+


1.4 NIST SP 800-12 CIA TRIAD CLASSIFICATION (Chronological Order)
-----------------------------------------------------------------
+----------+---------------------+--------------------------------------------------+
| Order    | CIA Pillar          | Explanation                                      |
|          | (NIST SP 800-12)    |                                                  |
+----------+---------------------+--------------------------------------------------+
| 1        | Confidentiality     | Attacker gained unauthorized access to server.   |
|          | (NIST SP 800-12     | "Preserving authorized restrictions on           |
|          |  Ch 2)              | information access and disclosure."             |
+----------+---------------------+--------------------------------------------------+
| 2        | Integrity           | Attacker installed crypto-miner (./kworker).     |
|          | (NIST SP 800-12     | "Guarding against improper information           |
|          |  Ch 2)              | modification or destruction."                    |
+----------+---------------------+--------------------------------------------------+
| 3        | Availability        | Crypto-miner consumes 94.2% CPU. Legitimate      |
| (Visible)| (NIST SP 800-12     | users cannot use system. "Ensuring timely and    |
|          |  Ch 2)              | reliable access to information."                |
+----------+---------------------+--------------------------------------------------+

NIST SP 800-12 (Ch 2): "Information security is the protection of
information and information systems from unauthorized access, use,
disclosure, disruption, modification, or destruction."

The sysadmin only sees the "disruption" (Availability) but misses the
"unauthorized access" (Confidentiality) and "modification" (Integrity)
that preceded it.


================================================================================
2. NIST SP 800-53 & CIS CONTROLS MAPPING
================================================================================

2.1 CONTROLS THAT SHOULD HAVE PREVENTED THIS INCIDENT
-----------------------------------------------------
+------------------+---------------------+----------------------------------------+
| Control Family   | Control ID          | Why It Failed                          |
| (NIST SP 800-53) |                     |                                        |
+------------------+---------------------+----------------------------------------+
| Access Control   | AC-3                | www-data should not execute binaries.  |
| (AC)             | Access Enforcement  | Principle of least privilege violated. |
+------------------+---------------------+----------------------------------------+
| Identification   | IA-2                | No MFA means attacker used stolen      |
| and              | Identification and  | credentials or exploited vulnerability.|
| Authentication   | Authentication      |                                        |
| (IA)             | (Organizational)    |                                        |
+------------------+---------------------+----------------------------------------+
| System and       | SI-3                | Sophos installed but failed to detect  |
| Information      | Malicious Code      | the crypto-miner. Unknown if current   |
| Integrity (SI)   | Protection          | on all machines.                       |
+------------------+---------------------+----------------------------------------+
| System and       | SI-4                | No alert for 94.2% CPU or unusual      |
| Information      | Information System  | outbound connections to 185.243.115.89.|
| Integrity (SI)   | Monitoring          |                                        |
+------------------+---------------------+----------------------------------------+
| Configuration    | CM-3                | Server "rebuilt" but vulnerability     |
| Management (CM)  | Change Control      | not fixed. Untested rebuild.           |
+------------------+---------------------+----------------------------------------+
| Incident         | IR-4                | January ransomware handled ad-hoc. No  |
| Response (IR)    | Incident Handling   | proper investigation or lessons        |
|                  |                     | learned.                               |
+------------------+---------------------+----------------------------------------+

2.2 CIS CONTROLS V8 MAPPING
---------------------------
+------------------+---------------------+----------------------------------------+
| CIS Control      | Description         | Why It Failed                          |
+------------------+---------------------+----------------------------------------+
| CIS Control 1    | Inventory and       | Server asset known. No complete        |
|                  | Control of          | endpoint inventory exists.             |
|                  | Enterprise Assets   |                                        |
+------------------+---------------------+----------------------------------------+
| CIS Control 7    | Continuous          | No vulnerability assessment performed. |
|                  | Vulnerability       | Web application vulnerability unknown. |
|                  | Management          |                                        |
+------------------+---------------------+----------------------------------------+
| CIS Control 10  | Malware Defenses    | Sophos installed but failed to detect  |
|                  |                     | the crypto-miner.                      |
+------------------+---------------------+----------------------------------------+
| CIS Control 12  | Network             | Server on flat network (10.10.0.0/16). |
|                  | Infrastructure      | No segmentation to limit lateral       |
|                  | Management          | movement.                              |
+------------------+---------------------+----------------------------------------+
| CIS Control 13  | Network Monitoring  | No monitoring of outbound connections  |
|                  | and Defense         | to foreign IPs.                        |
+------------------+---------------------+----------------------------------------+
| CIS Control 17  | Incident Response   | No formal IR plan. January incident    |
|                  | Management          | was handled ad-hoc.                    |
+------------------+---------------------+----------------------------------------+


================================================================================
3. WHY HARDWARE UPGRADE FAILS - NIST CSF 2.0 & NIST SP 800-30
================================================================================

3.1 THE FAULTY SOLUTION (NIST CSF 2.0 - Identify Function Failure)
------------------------------------------------------------------
+------------------+----------------------------------------------------------+
| Proposed         | "Upgrade hardware or migrate to more powerful VM."        |
| Solution         |                                                           |
+------------------+----------------------------------------------------------+
| Why it Fails     | The attacker's crypto-miner will simply consume whatever |
| (NIST SP 800-30) | resources are available. A more powerful server means     |
|                  | more CPU for the miner, more revenue for the attacker.    |
+------------------+----------------------------------------------------------+

NIST CSF 2.0 - Identify Function:
The organization failed to IDENTIFY the root cause of the incident.
They only identified the symptom (CPU saturation) and proposed a solution
that does not address the actual risk.

NIST CSF 2.0 Core: IDENTIFY (ID) - "The organization's current capabilities
and its ability to manage cybersecurity risk."

The sysadmin's recommendation demonstrates a failure to:
- ID.RA-1: Identify threats and vulnerabilities
- ID.RA-2: Identify risks
- ID.RA-3: Identify risk response options

3.2 SCENARIO COMPARISON (NIST SP 800-30 Impact Assessment)
----------------------------------------------------------
+------------------+---------------------------+------------------------------+
| Aspect           | Current Server            | After Hardware Upgrade       |
+------------------+---------------------------+------------------------------+
| CPU Available    | 100%                      | 200% (more powerful)         |
| Miner CPU Usage  | 94.2%                     | ~94% (still saturated)       |
| Business Impact  | Critical billing system   | Critical billing system      |
|                  | severely degraded          | still severely degraded      |
| Attacker Revenue | Mining Monero             | Mining MORE Monero           |
| Risk Remains     | HIGH                      | HIGH (unchanged)             |
+------------------+---------------------------+------------------------------+

3.3 NIST SP 800-30 RISK TREATMENT CONCLUSION
--------------------------------------------
+----------------------------------------------------------------------------+
| NIST SP 800-30 Risk Treatment Options:                                     |
|                                                                             |
| ✓ MITIGATE: Eliminate the crypto-miner and fix the vulnerability           |
| ✗ TRANSFER: Not applicable (insurance won't help)                         |
| ✗ ACCEPT: Accepting the risk would mean accepting crypto-mining on        |
|            critical servers (unacceptable)                                 |
| ✗ AVOID: Avoiding would mean shutting down the billing system             |
|            (not possible)                                                  |
|                                                                             |
| CORRECT APPROACH: MITIGATE by addressing the root cause                    |
|                                                                             |
| THE SECURITY PROBLEM DOES NOT GO AWAY WITH HARDWARE UPGRADE.              |
| Hardware upgrade is not a valid risk treatment strategy.                   |
+----------------------------------------------------------------------------+


================================================================================
4. CONNECTION TO JANUARY INCIDENT - NIST SP 800-12 & HHS HICP
================================================================================

4.1 INCIDENT TIMELINE (HHS HICP - Incident Response Context)
------------------------------------------------------------
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

4.2 HHS HICP - Healthcare Cybersecurity Practices Context
---------------------------------------------------------
+----------------------------------------------------------------------------+
| HHS HICP - Threat Overview:                                                |
| - Healthcare organizations are prime targets for cybercriminals           |
| - Ransomware is the #1 threat to healthcare organizations                |
| - Cryptocurrency mining is a growing threat                               |
| - Incident response is critical for healthcare organizations              |
|                                                                             |
| MedDefense failed on multiple HICP practices:                              |
| 1. No formal incident response plan                                       |
| 2. No post-incident investigation (January ransomware)                    |
| 3. No vulnerability identification after initial compromise              |
| 4. No lessons learned or improvements implemented                         |
+----------------------------------------------------------------------------+

4.3 WHAT THIS SUGGESTS (NIST SP 800-30 Vulnerability Analysis)
---------------------------------------------------------------
+----------------------------------------------------------------------------+
| The same server (billing-srv-01) was compromised in January (ransomware) |
| and is compromised again now (crypto-miner).                              |
|                                                                             |
| NIST SP 800-30 Vulnerability Analysis:                                     |
|                                                                             |
| POSSIBLE VULNERABILITIES:                                                   |
| 1. The server was never fully cleaned after the ransomware.               |
|    The attacker left a backdoor (persistence mechanism).                  |
|                                                                             |
| 2. The "rebuild" was incomplete. The same vulnerability that allowed      |
|    initial compromise was never identified or fixed.                      |
|                                                                             |
| 3. The initial compromise vector (web application vulnerability) was     |
|    never identified and remediated.                                       |
|                                                                             |
| 4. The attacker maintained persistence (cron job, systemd service,        |
|    SSH key) and re-entered after the "rebuild."                          |
+----------------------------------------------------------------------------+

4.4 THE CRITICAL QUESTION (NIST SP 800-12 Risk Assessment)
----------------------------------------------------------
+----------------------------------------------------------------------------+
| NIST SP 800-12 Ch 3 (Roles): "Risk assessment is the process of           |
| analyzing threats to and vulnerabilities of an information system."       |
|                                                                             |
| THE QUESTION YOU MUST ASK:                                                 |
|                                                                             |
| "How did the attacker gain access to billing-srv-01 in January?"          |
|                                                                             |
| AND ITS CONSEQUENCE:                                                       |
|                                                                             |
| "Has that vulnerability been identified, patched, or otherwise            |
|  eliminated?"                                                              |
|                                                                             |
| Without answering this, the NIST SP 800-12 risk assessment is            |
| incomplete and any "fix" is temporary.                                    |
+----------------------------------------------------------------------------+


================================================================================
5. ISO 27001 GAP ANALYSIS - CONTROLS STATUS
================================================================================

5.1 ISO 27001 CONTROL GAP ASSESSMENT
------------------------------------
+------------------+---------------------+----------------------------------------+
| ISO 27001        | Status              | Gap Description                        |
| Control          |                     |                                        |
+------------------+---------------------+----------------------------------------+
| A.5.1            | NOT IN PLACE        | No incident response plan.             |
| Policies for     |                     | January ransomware handled ad-hoc.    |
| Information      |                     |                                        |
| Security         |                     |                                        |
+------------------+---------------------+----------------------------------------+
| A.8.1            | PARTIAL             | Sophos installed but status unknown.   |
| Malware          |                     | Crypto-miner evaded detection.         |
| Protection       |                     |                                        |
+------------------+---------------------+----------------------------------------+
| A.8.2            | NOT IN PLACE        | No vulnerability assessments           |
| Vulnerability    |                     | performed. Web app vulnerability       |
| Management       |                     | unknown.                               |
+------------------+---------------------+----------------------------------------+
| A.9.2            | NOT IN PLACE        | www-data should not run arbitrary      |
| Access Control   |                     | binaries. Principle of least           |
|                  |                     | privilege violated.                    |
+------------------+---------------------+----------------------------------------+
| A.12.4           | NOT IN PLACE        | No monitoring of outbound connections. |
| Logging and      |                     | CPU alerts not configured.             |
| Monitoring       |                     |                                        |
+------------------+---------------------+----------------------------------------+
| A.12.6           | NOT IN PLACE        | No technical vulnerability management  |
| Technical        |                     | program.                               |
| Vulnerability    |                     |                                        |
| Management       |                     |                                        |
+------------------+---------------------+----------------------------------------+
| A.16.1           | NOT IN PLACE        | No formal incident response plan.      |
| Incident         |                     | No post-incident analysis.             |
| Management       |                     |                                        |
+------------------+---------------------+----------------------------------------+


================================================================================
6. RECOMMENDED CORRECTIVE ACTIONS - MAPPED TO FRAMEWORKS
================================================================================

6.1 IMMEDIATE ACTIONS (0-24 hours)
----------------------------------
+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| 1        | Isolate          | Server compromised. Cannot be trusted. | NIST SP 800-53   |
|          | billing-srv-01   |                                        | CP-10            |
+----------+------------------+----------------------------------------+------------------+
| 2        | Capture          | Preserve evidence for investigation.   | NIST SP 800-61   |
|          | Forensic Image   |                                        | (IR-4)           |
+----------+------------------+----------------------------------------+------------------+
| 3        | Block Outbound   | Block connections to 185.243.115.89    | NIST SP 800-53   |
|          | Connections      | and 91.121.87.10 at firewall.          | SC-7             |
+----------+------------------+----------------------------------------+------------------+
| 4        | Disable          | Disable PID 8834. Remove cron/systemd. | NIST SP 800-53   |
|          | Malicious        |                                        | SI-3             |
|          | Process          |                                        |                  |
+----------+------------------+----------------------------------------+------------------+

6.2 ROOT CAUSE REMEDIATION (1-3 days)
-------------------------------------
+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| 1        | Identify Attack  | Review web logs. Find initial access.  | NIST SP 800-61   |
|          | Vector           |                                        | IR-4             |
+----------+------------------+----------------------------------------+------------------+
| 2        | Patch            | Fix web application vulnerability.     | NIST SP 800-53   |
|          | Vulnerability   |                                        | SI-3             |
+----------+------------------+----------------------------------------+------------------+
| 3        | Clean Rebuild   | Rebuild from known-good media.         | NIST SP 800-53   |
|          |                  | DO NOT use compromised backups.        | CM-3             |
+----------+------------------+----------------------------------------+------------------+
| 4        | Change All       | Change passwords, API keys, secrets.   | NIST SP 800-53   |
|          | Credentials      |                                        | AC-2             |
+----------+------------------+----------------------------------------+------------------+

6.3 MEDIUM-TERM IMPROVEMENTS (1-2 weeks)
----------------------------------------
+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| 1        | Implement EDR   | Detect and block malicious processes.  | NIST SP 800-53   |
|          |                  |                                        | SI-3             |
+----------+------------------+----------------------------------------+------------------+
| 2        | Network          | Isolate billing-srv-01 from other      | NIST SP 800-53   |
|          | Segmentation     | servers.                               | SC-7 / CIS 12    |
+----------+------------------+----------------------------------------+------------------+
| 3        | Centralized      | Send logs to secure SIEM.              | NIST SP 800-53   |
|          | Logging          |                                        | AU-6             |
+----------+------------------+----------------------------------------+------------------+
| 4        | Alerting         | Alert on high CPU, unusual outbound,   | NIST SP 800-53   |
|          |                  | new www-data processes.                | SI-4             |
+----------+------------------+----------------------------------------+------------------+

6.4 LONG-TERM IMPROVEMENTS (1 month+)
-------------------------------------
+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| 1        | MFA              | Implement MFA for all privileged       | NIST SP 800-53   |
|          | Implementation   | access.                                | IA-2             |
+----------+------------------+----------------------------------------+------------------+
| 2        | Least Privilege  | Review user permissions. Remove        | NIST SP 800-53   |
|          |                  | unnecessary privileges.                | AC-6             |
+----------+------------------+----------------------------------------+------------------+
| 3        | Vulnerability    | Regular vulnerability scanning for     | NIST SP 800-53   |
|          | Scanning         | all servers.                           | RA-5 / CIS 7     |
+----------+------------------+----------------------------------------+------------------+
| 4        | BCP/DR Plan      | Document and test BCP/DR plans.        | NIST SP 800-53   |
|          |                  |                                        | CP-2             |
+----------+------------------+----------------------------------------+------------------+
| 5        | Incident         | Create formal IR plan. Test with       | NIST SP 800-53   |
|          | Response Plan    | tabletop exercises.                    | IR-8             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
7. EXECUTIVE SUMMARY - NIST CSF 2.0 & HHS HICP
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
+----------------------------------------------------------------------------+
|                                                                             |
| NIST CSF 2.0 - IDENTIFY FUNCTION (IDENTIFY)                                |
|                                                                             |
| THE PROBLEM:                                                               |
| billing-srv-01 is not suffering from hardware limitations. It is           |
| compromised by a crypto-miner that is using 94.2% of CPU resources.        |
|                                                                             |
| THE DIAGNOSIS ERROR:                                                       |
| The sysadmin is treating a symptom (CPU saturation) as the root cause.    |
| This is the "Symptom Trap" - a common security failure.                    |
|                                                                             |
| NIST CSF 2.0 - ID.RA-1: "Identified threats and vulnerabilities"          |
| The sysadmin failed to identify the threat (crypto-miner) and               |
| vulnerability (unpatched web application).                                 |
|                                                                             |
| HHS HICP - Threat Overview:                                                 |
| Healthcare organizations are prime targets. Ransomware and crypto-mining   |
| are active threats. Incident response is critical.                         |
|                                                                             |
| NIST SP 800-30 - Risk Components:                                          |
| Threat: Cybercriminal (financial gain)                                    |
| Vulnerability: Web application vulnerability, weak access controls         |
| Impact: Availability loss for critical billing system                     |
| Risk: HIGH                                                                 |
|                                                                             |
| THE JANUARY CONNECTION:                                                    |
| The same server was compromised by ransomware in January. The root        |
| cause was never identified or fixed. This crypto-miner is the result.     |
|                                                                             |
| THE CRITICAL QUESTION:                                                     |
| "How did the attacker gain access in January?"                            |
| "Has that vulnerability been addressed?"                                  |
|                                                                             |
| RECOMMENDATION:                                                            |
| Do NOT upgrade hardware. Isolate the server, perform a forensic           |
| investigation, identify the root cause, and remediate the security        |
| vulnerability. THEN rebuild from known-good media.                        |
+----------------------------------------------------------------------------+


================================================================================
8. KEY TAKEAWAYS - MAPPED TO FRAMEWORKS
================================================================================

1. Never treat symptoms without investigating root causes.
   (NIST SP 800-30: Risk = Threat x Vulnerability x Impact)

2. CPU saturation is often a symptom of compromise, not hardware failure.
   (NIST SP 800-12: CIA Triad - Availability is often the last affected)

3. Security incidents follow a sequence: Confidentiality → Integrity → Availability.
   (NIST SP 800-12 Ch 2: CIA pillars are interdependent)

4. A hardware upgrade does NOT solve a security problem.
   (NIST SP 800-30: Risk treatment - MITIGATE requires addressing root cause)

5. A single server compromised multiple times indicates the root cause was
   never addressed. (NIST SP 800-61: Incident response requires post-incident
   analysis and lessons learned)

6. The critical question is always: "How did the attacker gain access?"
   (NIST SP 800-30: Without identifying the vulnerability, risk remains)

7. www-data running a crypto-miner suggests web application compromise.
   (NIST SP 800-53: AC-6 Principle of Least Privilege violated)

8. Document and learn from incidents.
   (HHS HICP: Healthcare organizations must have incident response plans)

9. Controls that failed: AC-3 (Access Control), SI-3 (Malware Protection),
   SI-4 (Monitoring), IR-4 (Incident Handling), CM-3 (Change Control)
   (NIST SP 800-53 Control Families)

10. CIS Controls that failed: 7 (Vulnerability Management), 10 (Malware
    Defenses), 12 (Network Infrastructure), 13 (Network Monitoring),
    17 (Incident Response Management)
    (CIS Controls v8)


================================================================================
9. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - Control Families (AC, IA, SI, CM, IR)
- NIST SP 800-61 Rev.2: Incident Handling - IR-4
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function (ID.RA-1, ID.RA-2, ID.RA-3)
- CISA Healthcare and Public Health Sector Guide
- ISO 27001 Gap Analysis: Methodology (A.5, A.8, A.9, A.12, A.16)
- HHS HICP: Health Industry Cybersecurity Practices (Threat Overviews)


================================================================================
END OF SYMPTOM TRAP ANALYSIS REPORT
================================================================================
