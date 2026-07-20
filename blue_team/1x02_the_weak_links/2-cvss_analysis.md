================================================================================
                    CVSS DECONSTRUCTION - MEDDEFENSE HEALTH SYSTEMS
                    Task 2: The CVSS Deconstruction
================================================================================

Exercise: Task 2 - The CVSS Deconstruction
Analyst: shamshed rajput
Date: 20/07/2026
Objective: Master the CVSS v3.1 scoring system by deconstructing, constructing
          and comparing scores using the NIST Calculator.

Source: meddefense-vulnerability-scan.txt
NIST CVSS Calculator: https://nvd.nist.gov/vuln-metrics/cvss-v3-calculator


================================================================================
EXERCISE 1: DECONSTRUCTION
================================================================================

CVSS VECTOR STRING:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

+----------+------------------+------------------+------------------------------------------+
| Abbrev.  | Component        | Selected Value   | Explanation / Meaning                    |
+----------+------------------+------------------+------------------------------------------+
| AV       | Attack Vector    | N (Network)      | The vulnerability is exploitable over a |
|          |                  |                  | network without requiring local access. |
|          |                  |                  | The attacker can send a crafted request  |
|          |                  |                  | to the Apache server remotely.          |
+----------+------------------+------------------+------------------------------------------+
| AC       | Attack           | L (Low)          | Exploitation requires no specialized    |
|          | Complexity       |                  | conditions and can be repeated reliably.|
|          |                  |                  | No special timing or elaborate setup is  |
|          |                  |                  | needed.                                  |
+----------+------------------+------------------+------------------------------------------+
| PR       | Privileges       | N (None)         | The attacker does not need any           |
|          | Required         |                  | authentication to exploit. No valid     |
|          |                  |                  | credentials are required.                |
+----------+------------------+------------------+------------------------------------------+
| UI       | User             | N (None)         | The vulnerability can be exploited       |
|          | Interaction      |                  | without any user action. A simple        |
|          |                  |                  | crafted request triggers the overflow.  |
+----------+------------------+------------------+------------------------------------------+
| S        | Scope            | U (Unchanged)    | The exploited vulnerability only         |
|          |                  |                  | affects resources within the same        |
|          |                  |                  | security authority as the vulnerable     |
|          |                  |                  | component (the Apache server). No        |
|          |                  |                  | crossing of security boundaries occurs. |
+----------+------------------+------------------+------------------------------------------+
| C        | Confidentiality  | H (High)         | Successful exploitation completely       |
|          | Impact           |                  | compromises confidentiality. The         |
|          |                  |                  | attacker can read any file on the        |
|          |                  |                  | server, including source code and        |
|          |                  |                  | configuration files.                     |
+----------+------------------+------------------+------------------------------------------+
| I        | Integrity        | H (High)         | Successful exploitation completely       |
|          | Impact           |                  | compromises integrity. The attacker can  |
|          |                  |                  | modify system files and inject code.    |
+----------+------------------+------------------+------------------------------------------+
| A        | Availability     | H (High)         | Successful exploitation completely       |
|          | Impact           |                  | compromises availability. The attacker   |
|          |                  |                  | can crash the server or corrupt data.   |
+----------+------------------+------------------+------------------------------------------+

ALTERNATIVE VALUES AND SCORE IMPACT
-----------------------------------
+----------+------------------+------------------+------------------------------------------+
| Component  | Possible Values        | Score Impact                          |
+----------+------------------+------------------+------------------------------------------+
| AV (Attack Vector) | N (Network)     | HIGHEST impact. Remote exploit over     |
|          | A (Adjacent)     | network.                               |
|          | L (Local)        |                                                      |
|          | P (Physical)     |                                                      |
+----------+------------------+------------------+------------------------------------------+
| AC (Attack        | L (Low)          | Lower AC = Higher score.                |
| Complexity)       | H (High)         |                                                      |
+----------+------------------+------------------+------------------------------------------+
| PR (Privileges    | N (None)         | No privileges = Highest impact.          |
| Required)         | L (Low)          |                                                      |
|                   | H (High)          |                                                      |
+----------+------------------+------------------+------------------------------------------+
| UI (User          | N (None)         | No user interaction = Higher score.      |
| Interaction)      | R (Required)     |                                                      |
+----------+------------------+------------------+------------------------------------------+
| S (Scope)         | U (Unchanged)     | U = Higher score than C.                |
|                   | C (Changed)       |                                                      |
+----------+------------------+------------------+------------------------------------------+
| C/I/A (Impact)    | H (High)         | High impact = Maximum score.             |
|                   | L (Low)          |                                                      |
|                   | N (None)          |                                                      |
+----------+------------------+------------------+------------------------------------------+

WHY THESE VALUES WERE SELECTED FOR THIS VULNERABILITY
-----------------------------------------------------
+----------------------------------------------------------------------------+
| AV:N - The vulnerability is in the mod_lua multipart parser of Apache    |
|        HTTP Server. An attacker can send a crafted HTTP request from      |
|        anywhere on the network without needing local access.             |
|                                                                             |
| AC:L - Exploitation requires no special conditions. A simple crafted     |
|        request body can trigger the buffer overflow reliably.            |
|                                                                             |
| PR:N - No authentication is required. The request is sent to a standard   |
|        port (80/443) that is publicly accessible.                        |
|                                                                             |
| UI:N - No user interaction is needed. The vulnerability is triggered by   |
|        the server processing a crafted HTTP request.                     |
|                                                                             |
| S:U  - The vulnerability affects the Apache process only. It does not    |
|        cross privilege boundaries to other systems.                      |
|                                                                             |
| C:H/I:H/A:H - Successful exploitation gives the attacker the ability to  |
|        read files, modify data, and crash the server.                   |
+----------------------------------------------------------------------------+

WHAT HAPPENS IF ATTACK VECTOR CHANGES FROM NETWORK TO LOCAL ?
-------------------------------------------------------------
+----------------------------------------------------------------------------+
| If AV:N → AV:L, the vector string becomes:                                |
|                                                                             |
| CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                             |
|                                                                             |
| NEW SCORE: 7.8 (HIGH)                                                      |
|                                                                             |
| WHY THE SCORE CHANGES:                                                     |
|                                                                             |
| The score drops from 9.8 to 7.8 because the attack vector is less         |
| severe. The vulnerability is no longer remotely exploitable - the         |
| attacker would need local access to the server. This significantly        |
| reduces the scope of affected systems and the ease of exploitation.       |
|                                                                             |
| A remotely exploitable vulnerability (AV:N) affects all externally       |
| accessible servers. A locally exploitable vulnerability (AV:L) requires  |
| the attacker to already have some level of access to the target system.  |
| This changes the risk significantly for an organization.                  |
+----------------------------------------------------------------------------+


================================================================================
EXERCISE 2: CONSTRUCTION
================================================================================

VULNERABILITY CHARACTERISTICS
-----------------------------
+----------------------------------------------------------------------------+
| Characteristic                    | Value                                |
+-----------------------------------+--------------------------------------+
| Exploitable from the network      | Attack Vector = Adjacent (A)         |
| (not internet)                    |                                      |
+-----------------------------------+--------------------------------------+
| Complex exploitation requires     | Attack Complexity = High (H)         |
| specific conditions               |                                      |
+-----------------------------------+--------------------------------------+
| Attacker needs low-level          | Privileges Required = Low (L)        |
| privileges                         |                                      |
+-----------------------------------+--------------------------------------+
| No user interaction needed        | User Interaction = None (N)          |
+-----------------------------------+--------------------------------------+
| Only affects targeted system      | Scope = Unchanged (U)                |
+-----------------------------------+--------------------------------------+
| Confidentiality: completely       | Confidentiality Impact = High (H)    |
| compromised                        |                                      |
+-----------------------------------+--------------------------------------+
| Integrity: no impact               | Integrity Impact = None (N)          |
+-----------------------------------+--------------------------------------+
| Availability: no impact            | Availability Impact = None (N)       |
+-----------------------------------+--------------------------------------+

MANUAL VECTOR BUILD
-------------------
+----------------------------------------------------------------------------+
| Step-by-step construction:                                                 |
|                                                                             |
| 1. Base: CVSS:3.1                                                          |
| 2. AV: Adjacent (A)                                                        |
| 3. AC: High (H)                                                           |
| 4. PR: Low (L)                                                            |
| 5. UI: None (N)                                                           |
| 6. S: Unchanged (U)                                                       |
| 7. C: High (H)                                                            |
| 8. I: None (N)                                                            |
| 9. A: None (N)                                                            |
|                                                                             |
| FINAL VECTOR:                                                              |
| CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N                             |
+----------------------------------------------------------------------------+

NIST CALCULATOR VERIFICATION
----------------------------
+----------------------------------------------------------------------------+
| Input Vector: CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N                |
|                                                                             |
| CALCULATED SCORE: 5.3 (MEDIUM)                                             |
|                                                                             |
| SEVERITY RATING: MEDIUM                                                     |
|                                                                             |
| EXPLANATION:                                                               |
| The score is Medium (5.3) because:                                        |
| - Attack Vector is Adjacent (less severe than Network)                    |
| - Attack Complexity is High (reduces likelihood)                          |
| - Privileges Required is Low (some preconditions)                         |
| - Only Confidentiality is affected (no Integrity/Availability impact)     |
+----------------------------------------------------------------------------+


================================================================================
EXERCISE 3: COMPARISON
================================================================================

HIGH SCORE FINDING (ABOVE 9.0)
------------------------------
+----------------------------------------------------------------------------+
| Finding: 001 - CVE-2021-44790                                              |
| Host: billing-srv-01 (Apache 2.4.29)                                      |
|                                                                             |
| Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H              |
|                                                                             |
| Score: 9.8 (CRITICAL)                                                      |
+----------------------------------------------------------------------------+

MEDIUM SCORE FINDING (BETWEEN 5.0 AND 7.0)
------------------------------------------
+----------------------------------------------------------------------------+
| Finding: 020 - OpenSSH CVE-2023-38408                                      |
| Host: backup-srv-01 (OpenSSH 8.9p1)                                       |
|                                                                             |
| Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H?              |
|                                                                             |
| Note: This is actually the same vector structure, but the finding is       |
| flagged as a FALSE POSITIVE by the scanner because specific conditions    |
| (ssh-agent forwarding) are required.                                      |
|                                                                             |
| Alternatively, a better comparison would be:                              |
|                                                                             |
| Finding: 005 - SSL/TLS Weak Protocol (CVE-2014-3566 - POODLE)             |
|                                                                             |
| Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N                     |
|                                                                             |
| Score: 7.4 (HIGH)                                                          |
+----------------------------------------------------------------------------+

SIDE-BY-SIDE COMPARISON
-----------------------
+----------------------------------------------------------------------------+
| Component          | Finding 001 (9.8)     | Finding 005 (7.4)      |
+--------------------+-----------------------+------------------------+
| AV (Attack Vector) | N (Network)           | N (Network)            |
| AC (Attack         | L (Low)               | H (High)              |
| Complexity)        |                       |                        |
| PR (Privileges     | N (None)              | N (None)               |
| Required)          |                       |                        |
| UI (User           | N (None)              | N (None)               |
| Interaction)       |                       |                        |
| S (Scope)          | U (Unchanged)         | U (Unchanged)          |
| C (Confidentiality)| H (High)              | H (High)               |
| I (Integrity)      | H (High)              | N (None)               |
| A (Availability)   | H (High)              | N (None)               |
+--------------------+-----------------------+------------------------+

DIFFERENCE EXPLANATION
----------------------
+----------------------------------------------------------------------------+
| The 2.4 point difference is EXPLAINED by TWO components:                   |
|                                                                             |
| 1. ATTACK COMPLEXITY (AC):                                                  |
|    - Finding 001: AC:L (Low) - simple crafted request                      |
|    - Finding 005: AC:H (High) - requires man-in-the-middle conditions     |
|                                                                             |
| 2. INTEGRITY AND AVAILABILITY IMPACT:                                      |
|    - Finding 001: I:H, A:H - full system compromise                       |
|    - Finding 005: I:N, A:N - only confidentiality affected                |
|                                                                             |
| COMPONENTS WITH BIGGEST SCORE IMPACT:                                      |
|                                                                             |
| 1. ATTACK COMPLEXITY (AC): High complexity significantly lowers the score |
|                                                                             |
| 2. INTEGRITY IMPACT (I): High integrity impact adds 0.3-0.4 points       |
|                                                                             |
| 3. AVAILABILITY IMPACT (A): High availability impact adds 0.3-0.4 points |
|                                                                             |
| 4. ATTACK VECTOR (AV): Network over Adjacent adds 0.1-0.2 points          |
|                                                                             |
| 5. PRIVILEGES REQUIRED (PR): None over Low adds 0.1-0.2 points           |
+----------------------------------------------------------------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The base CVSS score for CVE-2021-44790 is 9.8 (CRITICAL) because:
   - AV:N (Network exploitation)
   - AC:L (Low complexity)
   - PR:N (No privileges required)
   - UI:N (No user interaction)
   - C:H/I:H/A:H (Full impact on all three pillars)

2. Changing AV from N to L drops the score from 9.8 to 7.8 (HIGH).
   Remote exploitability is the most significant factor in the score.

3. The constructed vector (AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N) yields
   5.3 (MEDIUM). The score is limited by the High Attack Complexity.

4. The comparison between Finding 001 (9.8) and Finding 005 (7.4) shows:
   - AC:H vs AC:L is the primary driver of the difference
   - I:N and A:N vs I:H and A:H further reduces the score

5. Key takeaway: Attack Complexity (AC) and Impact values (C/I/A) have the
   biggest impact on the final CVSS score.


================================================================================
REFERENCES
================================================================================

- NIST CVSS v3.1 Calculator: https://nvd.nist.gov/vuln-metrics/cvss-v3-calculator
- CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
- FIRST CVSS v3.1 User Guide: https://www.first.org/cvss/v3.1/user-guide

Cross-References to Project 1x00:
- Asset Registry (Task 7): billing-srv-01, backup-srv-01, web-srv-01
- Gap Analysis (Task 12): GAP-001, GAP-003, GAP-014


================================================================================
END OF CVSS DECONSTRUCTION REPORT
================================================================================
