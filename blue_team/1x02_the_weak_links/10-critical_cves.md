================================================================================
                    CRITICAL CVES - MEDDEFENSE HEALTH SYSTEMS
                    Task 10: The Critical CVEs
================================================================================

Exercise: Task 10 - The Critical CVEs
Analyst: shamshed rajput
Date: 21/07/2026
Objective: Conduct a comprehensive deep analysis of the 5 most critical
          findings from the scan report.

Source: meddefense-vulnerability-scan.txt
Cross-References: Tasks 0-9, 1x00 Asset Registry, 1x01 Threat Actor Matrix


================================================================================
CRITICAL FINDING #1: MRI WINDOWS XP WITH WEAPONIZED EXPLOITS
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 004                                              |
+------------------+--------------------------------------------------+
| CVE              | CVE-2017-0144 (EternalBlue), CVE-2019-0708      |
|                  | (BlueKeep), CVE-2008-4250 (MS08-067)            |
+------------------+--------------------------------------------------+
| Host             | 10.10.1.70 (WS-RAD-01 - MRI Workstation)        |
+------------------+--------------------------------------------------+
| Asset Role       | Siemens MAGNETOM MRI Scanner Control            |
|                  | Workstation (from 1x00 Asset Registry SRV-013)  |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - Patient safety, diagnostic imaging    |
|                  | (45 MRI studies/day)                            |
|                  | CIA: Integrity (patient data), Availability     |
|                  | (imaging services), Confidentiality (PHI)       |
+------------------+--------------------------------------------------+

TECHNICAL ANALYSIS
------------------
+----------------------------------------------------------------------------+
| Vulnerability   | Windows XP SP3 (EOL April 2014) with multiple   |
| Description     | weaponized exploits:                             |
|                  | - CVE-2017-0144 (EternalBlue/MS17-010)          |
|                  |   SMB Remote Code Execution. Weaponized.        |
|                  |   Used in WannaCry ransomware.                  |
|                  | - CVE-2019-0708 (BlueKeep)                     |
|                  |   Remote Desktop Protocol RCE. Weaponized.     |
|                  | - CVE-2008-4250 (MS08-067)                     |
|                  |   Windows Server Service RCE. Weaponized.      |
|                  | All require NO authentication.                  |
+----------------------------------------------------------------------------+
| CVSS Base Score  | CVE-2017-0144: 8.1 (HIGH)                      |
|                  | CVE-2019-0708: 9.8 (CRITICAL)                  |
|                  | CVE-2008-4250: 10.0 (CRITICAL - CVSSv2)       |
+----------------------------------------------------------------------------+
| Exploit          | 5/5 - WEAPONIZED. All three have public,       |
| Availability     | weaponized exploits. EternalBlue has a         |
|                  | Metasploit module. CISA KEV listed.           |
+----------------------------------------------------------------------------+
| CISA KEV Status  | YES - CVE-2017-0144 (EternalBlue) is listed    |
|                  | YES - CVE-2019-0708 (BlueKeep) is listed      |
+----------------------------------------------------------------------------+
| CWE              | CWE-119 - Improper Restriction of Operations   |
|                  | within the Bounds of a Memory Buffer           |
+----------------------------------------------------------------------------+

CONTEXTUAL ANALYSIS
-------------------
+----------------------------------------------------------------------------+
| Network          | Ports 445 (SMB) and 3389 (RDP) are OPEN on     |
| Exposure         | this host. It is on the same subnet           |
|                  | (10.10.1.0/24) as all other workstations.      |
|                  | The flat network means ANY compromised system  |
|                  | can reach this host.                           |
+----------------------------------------------------------------------------+
| Kill Chain       | KC #4 (MRI → EHR) - Steps 1-5                 |
| Position         | This finding appears in Kill Chain #4:         |
|                  | "Windows XP MRI → Pivot to EHR"                |
|                  | Step 1: Initial access via Windows XP         |
|                  | Step 2: Establish foothold on MRI workstation |
|                  | Step 3: Lateral movement to EHR               |
+----------------------------------------------------------------------------+
| Threat Actor     | Ransomware Groups (#1) - Weaponized exploits  |
|                  | are actively used in ransomware campaigns.    |
|                  | Unskilled/Opportunistic (#6) - Automated      |
|                  | scanners actively target EternalBlue.         |
+----------------------------------------------------------------------------+
| Related          | - Finding 003 (PostgreSQL unrestricted):      |
| Findings         |   MRI can connect to EHR database             |
|                  | - Finding 024 (DICOM unencrypted):            |
|                  |   MRI images transmitted in cleartext        |
|                  | - Finding 015 (NAS accessible):               |
|                  |   Backups can be targeted from MRI           |
+----------------------------------------------------------------------------+

ADJUSTED PRIORITY
-----------------
+------------------+--------------------------------------------------+
| Priority         | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | This is a PERMANENT, UNPATCHABLE BACKDOOR into  |
|                  | MedDefense's network. Windows XP EOL 2014 with  |
|                  | THREE weaponized exploits, ALL listed in CISA  |
|                  | KEV. Ports 445 and 3389 are OPEN. The flat     |
|                  | network means any compromised system can reach  |
|                  | it. A compromise leads to:                      |
|                  | - Full control of the MRI workstation          |
|                  | - Lateral movement to EHR, billing, AD        |
|                  | - Ransomware deployment                        |
|                  | - Patient safety risk (imaging disruption)     |
|                  | This is the #1 priority. Breach 3 (Task 13)   |
|                  | validated this exact scenario with $40M+      |
|                  | recovery costs.                                 |
+------------------+--------------------------------------------------+


================================================================================
CRITICAL FINDING #2: APACHE MOD_LUA REMOTE CODE EXECUTION
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 001                                              |
+------------------+--------------------------------------------------+
| CVE              | CVE-2021-44790                                   |
+------------------+--------------------------------------------------+
| Host             | 10.10.2.15 (billing-srv-01)                     |
+------------------+--------------------------------------------------+
| Asset Role       | Billing/Claims Processing Server (from 1x00     |
|                  | Asset Registry SRV-004)                          |
+------------------+--------------------------------------------------+
| Asset Criticality| HIGH - Financial data, revenue cycle            |
|                  | CIA: Confidentiality (billing data),           |
|                  | Integrity (financial records), Availability    |
|                  | (claims processing)                             |
+------------------+--------------------------------------------------+

TECHNICAL ANALYSIS
------------------
+----------------------------------------------------------------------------+
| Vulnerability   | Buffer overflow vulnerability in Apache HTTP   |
| Description     | Server mod_lua module (CVE-2021-44790).        |
|                  | Remote unauthenticated attacker can send a     |
|                  | crafted request to trigger buffer overflow    |
|                  | and execute arbitrary code. Apache 2.4.29     |
|                  | (billing-srv-01) is vulnerable.                |
+----------------------------------------------------------------------------+
| CVSS Base Score  | 9.8 (CRITICAL)                                   |
+----------------------------------------------------------------------------+
| Exploit          | 3/5 - PoC exists but exploitation may require  |
| Availability     | specific conditions. Not in CISA KEV.          |
+----------------------------------------------------------------------------+
| CISA KEV Status  | NO                                               |
+----------------------------------------------------------------------------+
| CWE              | CWE-119 - Improper Restriction of Operations   |
|                  | within the Bounds of a Memory Buffer           |
+----------------------------------------------------------------------------+

CONTEXTUAL ANALYSIS
-------------------
+----------------------------------------------------------------------------+
| Network          | billing-srv-01 is on the server subnet        |
| Exposure         | (10.10.2.0/24). Apache port 80 is accessible  |
|                  | from the internal network. Combined with the  |
|                  | flat network, ANY compromised host can reach  |
|                  | it. The billing application is also accessible |
|                  | to external partners (potentially internet).   |
+----------------------------------------------------------------------------+
| Kill Chain       | KC #1 (Ransomware through Unpatched VPN) -     |
| Position         | Step 2: Establish foothold                     |
|                  | KC #5 (Supply Chain) - Step 1: Initial access |
+----------------------------------------------------------------------------+
| Threat Actor     | Ransomware Groups (#1) - Use this as entry    |
|                  | point for ransomware deployment.              |
|                  | Unskilled/Opportunistic (#6) - Automated      |
|                  | scanners actively target Apache 2.4.29.      |
+----------------------------------------------------------------------------+
| Related          | - Finding 002 (Apache Privilege Escalation):  |
| Findings         |   CVE-2021-44790 + CVE-2019-0211 chain        |
|                  |   for FULL SYSTEM COMPROMISE                  |
|                  | - Finding 006 (MySQL unrestricted):           |
|                  |   Exfiltrate billing data                     |
|                  | - Finding 009 (SSH password auth):            |
|                  |   Brute-force access after foothold          |
+----------------------------------------------------------------------------+

ADJUSTED PRIORITY
-----------------
+------------------+--------------------------------------------------+
| Priority         | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | This vulnerability provides REMOTE CODE          |
|                  | EXECUTION on billing-srv-01. Combined with       |
|                  | CVE-2019-0211 (Finding 002), an attacker can     |
|                  | achieve FULL SYSTEM COMPROMISE (www-data →      |
|                  | root). billing-srv-01 has already been          |
|                  | compromised twice (crypto-miner, ransomware).   |
|                  | This is the most exposed critical server.       |
|                  | CVSS 9.8. Public PoC available.                |
+------------------+--------------------------------------------------+


================================================================================
CRITICAL FINDING #3: POSTGRESQL UNRESTRICTED NETWORK ACCESS
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 003                                              |
+------------------+--------------------------------------------------+
| CVE              | N/A (Misconfiguration)                           |
+------------------+--------------------------------------------------+
| Host             | 10.10.2.11 (ehr-db-01)                          |
+------------------+--------------------------------------------------+
| Asset Role       | EHR Database (from 1x00 Asset Registry SRV-002)  |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - PHI for 50,000+ patients             |
|                  | CIA: Confidentiality (PHI), Integrity (patient  |
|                  | data), Availability (clinical operations)       |
+------------------+--------------------------------------------------+

TECHNICAL ANALYSIS
------------------
+----------------------------------------------------------------------------+
| Vulnerability   | PostgreSQL configured with pg_hba.conf allowing  |
| Description     | connections from the entire internal network    |
|                  | (10.10.0.0/16). listen_addresses = '*'         |
|                  | No firewall or network ACL restricts access.    |
+----------------------------------------------------------------------------+
| CVSS Base Score  | N/A (Misconfiguration - no CVE)                 |
+----------------------------------------------------------------------------+
| Exploit          | N/A (No exploit needed - direct access)        |
| Availability     |                                                  |
+----------------------------------------------------------------------------+
| CISA KEV Status  | N/A                                               |
+----------------------------------------------------------------------------+
| CWE              | CWE-284 - Improper Access Control                |
+----------------------------------------------------------------------------+

CONTEXTUAL ANALYSIS
-------------------
+----------------------------------------------------------------------------+
| Network          | PostgreSQL on port 5432 is accessible from the  |
| Exposure         | ENTIRE flat network (10.10.0.0/16). Any         |
|                  | compromised host can connect directly to the    |
|                  | EHR database.                                    |
+----------------------------------------------------------------------------+
| Kill Chain       | KC #2 (Phishing → EHR) - Step 4: Connect to    |
| Position         | PostgreSQL                                       |
|                  | KC #4 (MRI → EHR) - Step 4: Access EHR         |
+----------------------------------------------------------------------------+
| Threat Actor     | ANY actor on the network. Insider (#3/#4):     |
|                  | Direct access to PHI. Ransomware Groups (#1):  |
|                  | Encrypt database. Unskilled (#6): Automate     |
|                  | database connections.                           |
+----------------------------------------------------------------------------+
| Related          | - Finding 001/002 (Apache RCE): Use to access  |
| Findings         |   the database                                   |
|                  | - Finding 004 (Windows XP): MRI can connect    |
|                  | - Finding 006 (MySQL): Same pattern            |
+----------------------------------------------------------------------------+

ADJUSTED PRIORITY
-----------------
+------------------+--------------------------------------------------+
| Priority         | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | This is a DIRECT path to 50,000 patient records. |
|                  | No authentication required beyond network       |
|                  | access. ANY compromised host on the flat        |
|                  | network can query the EHR database. Marcus      |
|                  | noted: "Should be restricted to ehr-srv-01     |
|                  | only." This is a CRITICAL misconfiguration      |
|                  | that bypasses all application-level controls.  |
+------------------+--------------------------------------------------+


================================================================================
CRITICAL FINDING #4: APACHE PRIVILEGE ESCALATION
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 002                                              |
+------------------+--------------------------------------------------+
| CVE              | CVE-2019-0211                                   |
+------------------+--------------------------------------------------+
| Host             | 10.10.2.15 (billing-srv-01)                     |
+------------------+--------------------------------------------------+
| Asset Role       | Billing/Claims Processing Server (SRV-004)      |
+------------------+--------------------------------------------------+
| Asset Criticality| HIGH - Financial data, revenue cycle            |
+------------------+--------------------------------------------------+

TECHNICAL ANALYSIS
------------------
+----------------------------------------------------------------------------+
| Vulnerability   | Apache HTTP Server privilege escalation         |
| Description     | (CVE-2019-0211). Allows low-privilege user     |
|                  | (www-data) to escalate to root via scoreboard   |
|                  | manipulation. Affects Apache 2.4.17-2.4.38.   |
+----------------------------------------------------------------------------+
| CVSS Base Score  | 7.8 (HIGH)                                       |
+----------------------------------------------------------------------------+
| Exploit          | 5/5 - WEAPONIZED. Listed in CISA KEV. Active   |
| Availability     | exploitation. PoC widely available.             |
+----------------------------------------------------------------------------+
| CISA KEV Status  | YES - Added 2021-11-03, Due Date 2022-05-03    |
+----------------------------------------------------------------------------+
| CWE              | CWE-269 - Improper Privilege Management         |
+----------------------------------------------------------------------------+

CONTEXTUAL ANALYSIS
-------------------
+----------------------------------------------------------------------------+
| Network          | Same as Finding 001 - billing-srv-01 on the    |
| Exposure         | server subnet. Accessible after initial        |
|                  | foothold.                                       |
+----------------------------------------------------------------------------+
| Kill Chain       | KC #1 (Ransomware) - Step 4: Privilege         |
| Position         | escalation                                       |
+----------------------------------------------------------------------------+
| Threat Actor     | Ransomware Groups (#1) - Use this to gain root |
|                  | and deploy ransomware via Group Policy.        |
+----------------------------------------------------------------------------+
| Related          | Finding 001 (Apache RCE): CHAINS with this to  |
| Findings         | achieve FULL SYSTEM COMPROMISE                 |
|                  | Finding 009 (SSH password auth): Brute-force  |
|                  | access after escalation                        |
+----------------------------------------------------------------------------+

ADJUSTED PRIORITY
-----------------
+------------------+--------------------------------------------------+
| Priority         | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | This vulnerability CHAINS with Finding 001 to   |
|                  | provide FULL SYSTEM COMPROMISE. CVE-2021-44790 |
|                  | gives RCE as www-data, and CVE-2019-0211 gives |
|                  | privilege escalation to root. CVE-2019-0211    |
|                  | is in CISA KEV with active exploitation.       |
|                  | Together, they provide complete control over   |
|                  | billing-srv-01.                                 |
+------------------+--------------------------------------------------+


================================================================================
CRITICAL FINDING #5: TOMCAT GHOSTCAT (AJP CONNECTOR)
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 031 (Manual verification of Finding 017)         |
+------------------+--------------------------------------------------+
| CVE              | CVE-2020-1938 (Ghostcat)                         |
+------------------+--------------------------------------------------+
| Host             | 10.10.2.10 (ehr-srv-01)                         |
+------------------+--------------------------------------------------+
| Asset Role       | EHR Application Server (from 1x00 Asset         |
|                  | Registry SRV-001)                                |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - Patient data, clinical operations    |
|                  | CIA: Confidentiality (PHI), Integrity (patient  |
|                  | data), Availability (patient care)              |
+------------------+--------------------------------------------------+

TECHNICAL ANALYSIS
------------------
+----------------------------------------------------------------------------+
| Vulnerability   | Apache Tomcat AJP Connector File Read           |
| Description     | (CVE-2020-1938 - Ghostcat). Allows an attacker  |
|                  | to read ANY file on the server via the AJP     |
|                  | connector on port 8009. Can read configuration  |
|                  | files containing database credentials.          |
+----------------------------------------------------------------------------+
| CVSS Base Score  | 9.8 (CRITICAL)                                   |
+----------------------------------------------------------------------------+
| Exploit          | 3/5 - PoC available. Metasploit auxiliary       |
| Availability     | module exists. Not in CISA KEV.                |
+----------------------------------------------------------------------------+
| CISA KEV Status  | NO                                               |
+----------------------------------------------------------------------------+
| CWE              | CWE-22 - Improper Limitation of a Pathname to   |
|                  | a Restricted Directory (Path Traversal)         |
+----------------------------------------------------------------------------+

CONTEXTUAL ANALYSIS
-------------------
+------------------+--------------------------------------------------+
| Network          | ehr-srv-01 is on the server subnet (10.10.2.0/24)|
| Exposure         | AJP connector on port 8009 is accessible from   |
|                  | the flat network. Any compromised host can      |
|                  | reach it.                                        |
+----------------------------------------------------------------------------+
| Kill Chain       | KC #2 (Phishing → EHR) - Step 5: Access EHR    |
| Position         | server                                           |
+----------------------------------------------------------------------------+
| Threat Actor     | Ransomware Groups (#1) - Read credentials to   |
|                  | access EHR database. Unskilled (#6) - Use      |
|                  | automated scanners for Ghostcat.               |
+----------------------------------------------------------------------------+
| Related          | Finding 017 (Tomcat info disclosure): Reveals  |
| Findings         | Tomcat version                                  |
|                  | Finding 003 (PostgreSQL): Read credentials to  |
|                  | access database                                 |
+----------------------------------------------------------------------------+

ADJUSTED PRIORITY
-----------------
+------------------+--------------------------------------------------+
| Priority         | HIGH                                             |
+------------------+--------------------------------------------------+
| Justification    | CVSS 9.8 on the EHR APPLICATION SERVER. The    |
|                  | AJP connector can read configuration files     |
|                  | containing database credentials, leading to    |
|                  | direct access to the EHR database (Finding 003).|
|                  | While not in CISA KEV, PoC is public and easy  |
|                  | to execute. This is a HIGH priority because    |
|                  | it provides a path to the EHR database.        |
+------------------+--------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+------------------+
| Rank     | Finding          | CVE              | Host             | CVSS             | Priority         |
+----------+------------------+------------------+------------------+------------------+------------------+
| #1       | 004              | Multiple (XP)    | MRI Workstation  | 9.8 / 8.1 / 10.0 | CRITICAL         |
|          |                  | EOL/Weaponized   |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+
| #2       | 001              | CVE-2021-44790   | billing-srv-01   | 9.8              | CRITICAL         |
+----------+------------------+------------------+------------------+------------------+------------------+
| #3       | 003              | N/A (Misconfig)  | ehr-db-01        | N/A              | CRITICAL         |
+----------+------------------+------------------+------------------+------------------+------------------+
| #4       | 002              | CVE-2019-0211    | billing-srv-01   | 7.8              | CRITICAL         |
|          |                  |                  |                  |                  | (CISA KEV)       |
+----------+------------------+------------------+------------------+------------------+------------------+
| #5       | 031              | CVE-2020-1938    | ehr-srv-01       | 9.8              | HIGH             |
+----------+------------------+------------------+------------------+------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The MRI Windows XP (Finding 004) is the SINGLE MOST CRITICAL finding.
   Permanent, unpatched backdoor with weaponized exploits. #1 priority.

2. Findings 001 and 002 on billing-srv-01 FORM A CHAIN:
   - CVE-2021-44790 (RCE as www-data) → CVE-2019-0211 (Priv Esc to root)
   - Combined = FULL SYSTEM COMPROMISE

3. Finding 003 (PostgreSQL) is a CRITICAL misconfiguration that provides
   direct access to PHI without authentication.

4. Finding 031 (Ghostcat) on ehr-srv-01 allows reading of database
   credentials. Combined with Finding 003, provides access to EHR data.

5. The flat network (GAP-003) ENABLES ALL of these findings by allowing
   lateral movement from any compromised system to any other.

6. The 5 critical findings are interconnected. A single compromise can
   chain through multiple findings to reach the EHR database.


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt (Findings 001, 002, 003, 004, 031)
- NVD: https://nvd.nist.gov (CVE-2021-44790, CVE-2019-0211, CVE-2020-1938)
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Exploit-DB: https://www.exploit-db.com
- Asset Registry (1x00 Task 7): SRV-001, SRV-002, SRV-004, SRV-013
- Criticality Assessment (1x00 Task 8): Top 5 Critical Assets
- Kill Chains (1x01 Task 10): KC #1, KC #2, KC #4, KC #5


================================================================================
END OF CRITICAL CVES REPORT
================================================================================
