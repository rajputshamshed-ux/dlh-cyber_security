================================================================================
                    WEB EXPOSURE - MEDDEFENSE HEALTH SYSTEMS
                    Task 13: The Web Exposure
================================================================================

Exercise: Task 13 - The Web Exposure
Analyst: shamshed rajput
Date: 21/07/2026
Objective: Analyze web-facing vulnerabilities with specific attention to
          internet-exposed vs internal-only exposure.

Source: meddefense-vulnerability-scan.txt
Cross-References: 1x00 Asset Registry, 1x01 Kill Chains


================================================================================
HOST 1: web-srv-01 (PATIENT PORTAL) - 10.10.2.50
================================================================================

HOST OVERVIEW
-------------
+------------------+--------------------------------------------------+
| Host             | web-srv-01 (10.10.2.50)                          |
+------------------+--------------------------------------------------+
| Asset Role       | Public Website + Patient Portal                  |
|                  | (from 1x00 Asset Registry SRV-010)              |
+------------------+--------------------------------------------------+
| Asset Criticality| HIGH - Patient access, PHI in portal             |
+------------------+--------------------------------------------------+
| Exposure         | INTERNET-FACING                                  |
+------------------+--------------------------------------------------+

WEB FINDINGS
------------
+----------+------------------+-----------------+------------------------------------------+
| Finding  | CVE              | Severity        | Description                              |
+----------+------------------+-----------------+------------------------------------------+
| 005      | N/A (TLS 1.0)    | HIGH            | SSL/TLS Weak Protocol (TLS 1.0)         |
|          |                  |                 | POODLE/BEAST vulnerable                  |
+----------+------------------+-----------------+------------------------------------------+
| 012      | N/A              | MEDIUM          | HTTP Security Headers Missing            |
|          |                  |                 | XSS, Clickjacking protection missing    |
+----------+------------------+-----------------+------------------------------------------+
| 013      | N/A              | MEDIUM          | SSL Certificate Expiration (23 days)    |
+----------+------------------+-----------------+------------------------------------------+
| 021      | N/A              | MEDIUM          | HTTP TRACE Method Enabled (XST risk)    |
+----------+------------------+-----------------+------------------------------------------+

COMBINED RISK
-------------
+----------------------------------------------------------------------------+
| AGGREGATE RISK: HIGH                                                       |
|                                                                             |
| While no single finding is catastrophic alone, the COMBINATION creates    |
| significant risk:                                                          |
|                                                                             |
| 1. TLS 1.0 + TRACE Method = Man-in-the-middle + Credential Theft          |
| 2. Missing Security Headers = Increased XSS/Clickjacking risk            |
| 3. Certificate Expiring = Loss of patient trust and access               |
|                                                                             |
| This is an internet-facing system, so these findings are visible to      |
| ANY external attacker scanning MedDefense's public presence.              |
+----------------------------------------------------------------------------+

ATTACK SCENARIO
---------------
+----------------------------------------------------------------------------+
| Kill Chain: Patient Portal Compromise                                      |
|                                                                             |
| Step 1: Attacker scans web-srv-01 and discovers:                          |
|         - TLS 1.0 support (vulnerable to downgrade attacks)              |
|         - TRACE method enabled (XST vulnerability)                       |
|         - Missing security headers                                          |
|                                                                             |
| Step 2: Attacker performs a Man-in-the-Middle attack, forcing TLS 1.0    |
|         downgrade and intercepting session cookies.                       |
|                                                                             |
| Step 3: Attacker uses captured session tokens to access the patient      |
|         portal as legitimate patients.                                   |
|                                                                             |
| Step 4: Attacker exfiltrates patient data (PHI) - names, DOBs,          |
|         lab results, medications.                                          |
|                                                                             |
| Step 5: HIPAA breach notification required.                              |
+----------------------------------------------------------------------------+

PRIORITY
--------
+------------------+--------------------------------------------------+
| Priority         | HIGH - Second priority among web hosts          |
+------------------+--------------------------------------------------+
| Justification    | This is internet-facing, meaning ANY attacker   |
|                  | can probe it. However, exploitation requires    |
|                  | active MITM conditions. The certificate         |
|                  | expiration is urgent (23 days). Should be      |
|                  | addressed after ehr-srv-01 (Ghostcat).         |
+------------------+--------------------------------------------------+


================================================================================
HOST 2: ehr-srv-01 (EHR APPLICATION SERVER) - 10.10.2.10
================================================================================

HOST OVERVIEW
-------------
+------------------+--------------------------------------------------+
| Host             | ehr-srv-01 (10.10.2.10)                          |
+------------------+--------------------------------------------------+
| Asset Role       | EHR Application Server                           |
|                  | (from 1x00 Asset Registry SRV-001)              |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - Patient data, clinical operations     |
+------------------+--------------------------------------------------+
| Exposure         | INTERNAL (but flat network accessible)           |
+------------------+--------------------------------------------------+

WEB FINDINGS
------------
+----------+------------------+-----------------+------------------------------------------+
| Finding  | CVE              | Severity        | Description                              |
+----------+------------------+-----------------+------------------------------------------+
| 017      | N/A              | MEDIUM          | Tomcat Error Page Information Disclosure|
|          |                  |                 | Reveals Tomcat 9.0.31 version            |
+----------+------------------+-----------------+------------------------------------------+
| 031      | CVE-2020-1938    | CRITICAL        | Ghostcat AJP File Read (CVSS 9.8)       |
|          | (Manual verify)  |                 | AJP connector active on port 8009       |
+----------+------------------+-----------------+------------------------------------------+

COMBINED RISK
-------------
+----------------------------------------------------------------------------+
| AGGREGATE RISK: CRITICAL                                                   |
|                                                                             |
| Finding 017 is a MEDIUM (information disclosure) that LED to Finding 031, |
| a CRITICAL vulnerability. The chain is:                                   |
|                                                                             |
| 1. Tomcat version is disclosed (Finding 017)                              |
| 2. Attacker looks up CVE-2020-1938 (Ghostcat) for Tomcat 9.0.31          |
| 3. AJP connector is CONFIRMED open on port 8009 (Finding 031)            |
| 4. Attacker can read ANY file on ehr-srv-01, including database          |
|    credentials                                                             |
|                                                                             |
| This is on the EHR APPLICATION SERVER - the most critical system at      |
| MedDefense.                                                                |
+----------------------------------------------------------------------------+

ATTACK SCENARIO
---------------
+----------------------------------------------------------------------------+
| Kill Chain: Ghostcat → EHR Database Compromise                            |
|                                                                             |
| Step 1: Attacker discovers Tomcat 9.0.31 via error page (Finding 017)    |
|                                                                             |
| Step 2: Attacker queries NVD and finds CVE-2020-1938 (Ghostcat)          |
|                                                                             |
| Step 3: Attacker exploits Ghostcat via AJP connector (Finding 031)       |
|                                                                             |
| Step 4: Attacker reads configuration files (e.g., context.xml,          |
|         server.xml) containing database credentials                       |
|                                                                             |
| Step 5: Attacker connects to ehr-db-01 (Finding 003 - PostgreSQL         |
|         unrestricted) using stolen credentials                            |
|                                                                             |
| Step 6: Attacker exfiltrates ALL patient data (50,000+ records)          |
|                                                                             |
| Kill Chain #2 (Phishing → EHR) - Step 4-5: Connect to PostgreSQL        |
+----------------------------------------------------------------------------+

PRIORITY
--------
+------------------+--------------------------------------------------+
| Priority         | #1 PRIORITY - CRITICAL                           |
+------------------+--------------------------------------------------+
| Justification    | This is the EHR APPLICATION SERVER - the most   |
|                  | critical asset at MedDefense. Ghostcat (CVSS    |
|                  | 9.8) allows reading of database credentials.   |
|                  | Combined with Finding 003 (PostgreSQL           |
|                  | unrestricted), this provides DIRECT access to  |
|                  | 50,000 patient records.                         |
+------------------+--------------------------------------------------+


================================================================================
HOST 3: NAS-01 (BACKUP STORAGE) - 10.10.2.41
================================================================================

HOST OVERVIEW
-------------
+------------------+--------------------------------------------------+
| Host             | NAS-01 (10.10.2.41)                             |
+------------------+--------------------------------------------------+
| Asset Role       | Backup Storage (from 1x00 Asset Registry DTA-001) |
+------------------+--------------------------------------------------+
| Asset Criticality| HIGH - All backup data                           |
+------------------+--------------------------------------------------+
| Exposure         | INTERNAL (flat network accessible)               |
+------------------+--------------------------------------------------+

WEB FINDINGS
------------
+----------+------------------+-----------------+------------------------------------------+
| Finding  | CVE              | Severity        | Description                              |
+----------+------------------+-----------------+------------------------------------------+
| 015      | N/A              | MEDIUM          | Synology DSM Web Interface Accessible    |
|          |                  |                 | Ports 5000/5001 open network-wide        |
+----------+------------------+-----------------+------------------------------------------+

COMBINED RISK
-------------
+----------------------------------------------------------------------------+
| AGGREGATE RISK: HIGH                                                       |
|                                                                             |
| The NAS management interface is accessible from ANY system on the flat    |
| network. The NAS stores ALL backup data. If an attacker compromises ANY   |
| system, they can reach the NAS management interface.                      |
|                                                                             |
| Combined with the co-located backup issue (C-009 weakness), this is a    |
| SINGLE POINT OF FAILURE for recovery.                                     |
+----------------------------------------------------------------------------+

ATTACK SCENARIO
---------------
+----------------------------------------------------------------------------+
| Kill Chain: Backup Deletion                                                |
|                                                                             |
| Step 1: Attacker compromises ANY system on the flat network              |
|         (phishing, VPN, or Apache exploit)                                |
|                                                                             |
| Step 2: Attacker discovers NAS-01 management interface on port 5000      |
|                                                                             |
| Step 3: Attacker connects to management interface                        |
|                                                                             |
| Step 4: Attacker uses default credentials or brute force to access DSM   |
|                                                                             |
| Step 5: Attacker DELETES ALL backups                                      |
|                                                                             |
| Step 6: Ransomware deployment means NO recovery possible                  |
|                                                                             |
| This appears in Kill Chain #1 (VPN Ransomware) - Step 4: Backup          |
| neutralization                                                             |
+----------------------------------------------------------------------------+

PRIORITY
--------
+------------------+--------------------------------------------------+
| Priority         | HIGH - Third priority among web hosts            |
+------------------+--------------------------------------------------+
| Justification    | The NAS is critical for recovery, but the risk   |
|                  | is ACCESS (not directly exploitable without     |
|                  | credentials). Ghostcat (ehr-srv-01) is more     |
|                  | urgent because it provides access to PHI.       |
+------------------+--------------------------------------------------+


================================================================================
HOST 4: BD ALARIS PUMPS (MEDICAL IOT) - 10.10.3.40-46
================================================================================

HOST OVERVIEW
-------------
+------------------+--------------------------------------------------+
| Host             | BD Alaris Pumps (10.10.3.40-46)                  |
+------------------+--------------------------------------------------+
| Asset Role       | Medical IoT - Infusion Pumps                     |
|                  | (from 1x00 Asset Registry IOT-002)              |
+------------------+--------------------------------------------------+
| Asset Criticality| CRITICAL - Life-safety devices                    |
+------------------+--------------------------------------------------+
| Exposure         | INTERNAL (flat network accessible)               |
+------------------+--------------------------------------------------+

WEB FINDINGS
------------
+----------+------------------+-----------------+------------------------------------------+
| Finding  | CVE              | Severity        | Description                              |
+----------+------------------+-----------------+------------------------------------------+
| 010      | CVE-2020-25165   | HIGH            | BD Alaris Pumps with default credentials |
|          |                  |                 | (admin/admin) on 7/7 pumps               |
+----------+------------------+-----------------+------------------------------------------+
| 016      | N/A              | MEDIUM          | Medical Device HTTP Interfaces Accessible|
|          |                  |                 | Web management on ports 80/443           |
+----------+------------------+-----------------+------------------------------------------+

COMBINED RISK
-------------
+----------------------------------------------------------------------------+
| AGGREGATE RISK: CRITICAL                                                   |
|                                                                             |
| The pumps have DEFAULT CREDENTIALS (admin/admin) and open web             |
| interfaces accessible from the ENTIRE flat network. An attacker who       |
| compromises ANY system can:                                               |
|                                                                             |
| 1. Connect to pump management interfaces                                 |
| 2. Login with admin/admin credentials                                    |
| 3. Modify medication dosages                                              |
| 4. Disable alarms                                                         |
|                                                                             |
| This is a DIRECT PATIENT SAFETY RISK.                                     |
+----------------------------------------------------------------------------+

ATTACK SCENARIO
---------------
+----------------------------------------------------------------------------+
| Kill Chain: IoT Patient Safety (Kill Chain #3)                            |
|                                                                             |
| Step 1: Attacker compromises a workstation (phishing or VPN)             |
|                                                                             |
| Step 2: Attacker scans flat network and discovers BD Alaris pumps        |
|                                                                             |
| Step 3: Attacker connects to pump web interface (port 80/443)            |
|                                                                             |
| Step 4: Attacker logs in with default credentials (admin/admin)          |
|                                                                             |
| Step 5: Attacker modifies medication dosages or disables alarms          |
|                                                                             |
| Step 6: PATIENT SAFETY INCIDENT                                            |
|                                                                             |
| Kill Chain #3 (Default Creds → IoT Patient Safety)                       |
+----------------------------------------------------------------------------+

PRIORITY
--------
+------------------+--------------------------------------------------+
| Priority         | #2 PRIORITY - CRITICAL                           |
+------------------+--------------------------------------------------+
| Justification    | This is a DIRECT PATIENT SAFETY RISK. The       |
|                  | flat network (GAP-003) and default credentials  |
|                  | (GAP-007) make this trivial to exploit. It is   |
|                  | the #2 priority after Ghostcat on ehr-srv-01.  |
+------------------+--------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Host     | Hostname         | Exposure         | Combined Risk    | Priority         |
+----------+------------------+------------------+------------------+------------------+
| #1       | ehr-srv-01       | Internal (flat)  | CRITICAL         | #1 PRIORITY      |
|          |                  |                  | (Ghostcat + DB)  |                  |
+----------+------------------+------------------+------------------+------------------+
| #2       | BD Alaris Pumps  | Internal (flat)  | CRITICAL         | #2 PRIORITY      |
|          |                  |                  | (Patient Safety) |                  |
+----------+------------------+------------------+------------------+------------------+
| #3       | web-srv-01       | Internet-facing  | HIGH             | #3 PRIORITY      |
|          |                  |                  | (PHI exposure)   |                  |
+----------+------------------+------------------+------------------+------------------+
| #4       | NAS-01           | Internal (flat)  | HIGH             | #4 PRIORITY      |
|          |                  |                  | (Backup deletion)|                  |
+----------+------------------+------------------+------------------+------------------+


================================================================================
VALUE OF INVESTIGATING "MEDIUM" FINDINGS
================================================================================

+----------------------------------------------------------------------------+
| FINDING 017 → FINDING 031 CASE STUDY                                       |
|                                                                             |
| Finding 017 (Tomcat information disclosure) was rated MEDIUM by the       |
| scanner. It revealed:                                                      |
| - Tomcat version: 9.0.31                                                 |
| - Internal path information                                              |
| - Stack traces                                                           |
|                                                                             |
| SecurePoint investigated this MEDIUM finding and DISCOVERED Finding 031: |
| - AJP connector on port 8009 is ACTIVE                                   |
| - CVE-2020-1938 (Ghostcat) - CVSS 9.8                                   |
| - File read vulnerability on ehr-srv-01                                 |
|                                                                             |
| WHAT THIS TELLS US:                                                       |
|                                                                             |
| 1. "Medium" findings can be EARLY WARNING INDICATORS of CRITICAL         |
|    vulnerabilities.                                                       |
|                                                                             |
| 2. Information disclosure findings (version numbers, error messages,     |
|    stack traces) are often the FIRST STEP in an attacker's              |
|    reconnaissance.                                                        |
|                                                                             |
| 3. Automated scanners often miss LOW/MEDIUM findings because they       |
|    don't connect the dots. Version information alone is not a           |
|    vulnerability, but it points to potential vulnerabilities.            |
|                                                                             |
| 4. ATTACKERS LOOK FOR VERSION INFORMATION. They use it to identify       |
|    vulnerable software versions. NVD is public - attackers use it.       |
|                                                                             |
| 5. MANUAL INVESTIGATION is essential. The scanner would have reported    |
|    Finding 017 and stopped. The analyst investigated and found           |
|    Ghostcat.                                                              |
|                                                                             |
| 6. In vulnerability assessment, the chain is:                            |
|    - Disclosure → Reconnaissance → Exploitation                         |
|    Finding 017 is the "Disclosure" link in this chain.                  |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt (Findings 005, 010, 012, 013, 015, 016,
  017, 021, 031)
- Asset Registry (1x00 Task 7): SRV-001, SRV-010, DTA-001, IOT-002
- Gap Analysis (1x00 Task 12): GAP-003, GAP-007
- Kill Chains (1x01 Task 10): KC #2, KC #3, KC #4


================================================================================
END OF WEB EXPOSURE REPORT
================================================================================
