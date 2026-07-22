================================================================================
                    CVSS CONTEXTUALIZER - MEDDEFENSE HEALTH SYSTEMS
                    Task 17: The CVSS Contextualizer
================================================================================

Exercise: Task 17 - The CVSS Contextualizer
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Recalculate CVSS scores with environmental metrics to produce
          threat-informed, business-contextualized priorities.

Source: meddefense-vulnerability-scan.txt
NIST CVSS Calculator: https://nvd.nist.gov/vuln-metrics/cvss-v3-calculator
Cross-References: 1x00 Criticality Matrix, 1x01 Kill Chains, T4 Exploitability


================================================================================
FINDING 004: MRI WINDOWS XP WITH WEAPONIZED EXPLOITS
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 004 - Windows XP EOL (EternalBlue, BlueKeep,    |
|                  | MS08-067)                                        |
+------------------+--------------------------------------------------+
| CVSS Base Score  | 9.8 (CRITICAL) - CVE-2019-0708 (BlueKeep)       |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: MRI Workstation (SRV-013)                                          |
| CIA Rating: CRITICAL - Patient safety, diagnostic imaging, 45 studies/day |
| Criticality Impact: RAISES URGENCY - This is a life-safety system        |
| directly impacting patient care. Any compromise risks patient harm.      |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #4 (MRI → EHR)                              |
| Chain Role: Initial access point AND pivot point                         |
| Kill Chain Impact: RAISES URGENCY - This is the ENTRY POINT for a       |
| complete network compromise. The MRI can pivot to the EHR database.      |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 5/5 (WEAPONIZED)                                   |
| CISA KEV: YES - CVE-2017-0144 (EternalBlue) and CVE-2019-0708            |
| (BlueKeep) are listed                                                    |
| Exploit Impact: RAISES URGENCY - Weaponized exploits with active        |
| exploitation in the wild. Attackers are using these TODAY.              |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE in place. Proposed in 1x00 T6:                   |
| - Network Segmentation (C-015 - Proposed)                                |
| - Application Whitelisting (C-016 - Proposed)                           |
| Control Impact: NONE - No controls are currently implemented.           |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                           |
| - CIA: High/High/High (unchanged - patient safety, data integrity,      |
|   imaging availability)                                                  |
| - Modified Attack Vector: Network (N) - remains network accessible      |
|   via flat network                                                      |
| Adjusted Score: 9.8 (CRITICAL)                                          |
+----------------------------------------------------------------------------+

FINAL PRIORITY: CRITICAL
+----------------------------------------------------------------------------+
| Justification: This is the SINGLE MOST DANGEROUS finding. Windows XP   |
| EOL with THREE weaponized exploits (EternalBlue, BlueKeep, MS08-067)   |
| on the flat network. The MRI is a CRITICAL life-safety asset with 45   |
| studies/day. It appears in Kill Chain #4 as the entry point to the     |
| EHR. Exploits are WEAPONIZED and in CISA KEV. NO compensating           |
| controls are in place. This is an EMERGENCY.                            |
+----------------------------------------------------------------------------+


================================================================================
FINDING 031: GHOSTCAT (TOMCAT AJP FILE READ)
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 031 - CVE-2020-1938 (Ghostcat)                   |
+------------------+--------------------------------------------------+
| CVSS Base Score  | 9.8 (CRITICAL)                                   |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: ehr-srv-01 (EHR Application Server - SRV-001)                      |
| CIA Rating: CRITICAL - Patient data, clinical operations, 50,000+        |
| patients                                                                  |
| Criticality Impact: RAISES URGENCY - This is the #1 critical asset.      |
| Compromise means patient records at risk.                                 |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #2 (Phishing → EHR)                         |
| Chain Role: Initial access to EHR server                                 |
| Kill Chain Impact: RAISES URGENCY - This is the access point to the      |
| EHR application server.                                                  |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 3/5 (PoC available)                                |
| CISA KEV: NO                                                              |
| Exploit Impact: MODERATE RAISE - PoC is public and easy to execute,      |
| but not currently in KEV.                                                |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE for AJP connector.                               |
| C-005: SSH Hardening (does not apply)                                   |
| Control Impact: NONE - No controls for the AJP port.                    |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (patient data, integrity, availability)            |
| - Modified Attack Vector: Adjacent (A) - only accessible from flat      |
|   network, not internet                                                  |
| Adjusted Score: 8.4 (HIGH)                                               |
+----------------------------------------------------------------------------+

FINAL PRIORITY: CRITICAL
+----------------------------------------------------------------------------+
| Justification: Ghostcat on the EHR application server allows reading     |
| ANY file including database credentials. Combined with Finding 003      |
| (PostgreSQL unrestricted), this provides direct access to 50,000+       |
| patient records. While not in CISA KEV, the PoC is public and easy to   |
| execute. The EHR server is the #1 critical asset. This is an            |
| EMERGENCY.                                                               |
+----------------------------------------------------------------------------+


================================================================================
FINDING 003: POSTGRESQL UNRESTRICTED NETWORK ACCESS
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 003 - PostgreSQL Unrestricted Network Access     |
+------------------+--------------------------------------------------+
| CVSS Base Score  | N/A (Misconfiguration)                           |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: ehr-db-01 (EHR Database - SRV-002)                                  |
| CIA Rating: CRITICAL - PHI for 50,000+ patients                           |
| Criticality Impact: RAISES URGENCY - This is the EHR DATABASE. Direct    |
| access means ALL patient data.                                            |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #2, KC #4                                    |
| Chain Role: Final target (data exfiltration)                              |
| Kill Chain Impact: RAISES URGENCY - This is where attackers want to go. |
| It enables data exfiltration.                                             |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: N/A - Misconfiguration, not a CVE                   |
| CISA KEV: N/A                                                             |
| Exploit Impact: RAISES URGENCY - No exploit needed. ANY compromised      |
| host can connect directly.                                                |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE for database access.                             |
| C-014: AD Logging (does not apply)                                      |
| Control Impact: NONE - Database is openly accessible.                   |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (PHI, patient data integrity, clinical             |
|   availability)                                                           |
| - Modified Attack Vector: Adjacent (A) - accessible from flat network   |
| Adjusted Score: 9.8 (CRITICAL)                                           |
+----------------------------------------------------------------------------+

FINAL PRIORITY: CRITICAL
+----------------------------------------------------------------------------+
| Justification: This is a DIRECT path to 50,000 patient records. No      |
| exploit needed. ANY compromised host on the flat network can connect    |
| directly to the EHR database. Marcus noted: "Should be restricted to    |
| ehr-srv-01 only." This is a CRITICAL misconfiguration that bypasses     |
| all application-level controls.                                          |
+----------------------------------------------------------------------------+


================================================================================
FINDING 010: BD ALARIS DEFAULT CREDENTIALS
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 010 - BD Alaris Pumps Default Credentials         |
+------------------+--------------------------------------------------+
| CVSS Base Score  | N/A (Misconfiguration)                           |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: BD Alaris Infusion Pumps (IOT-002)                                  |
| CIA Rating: CRITICAL - Life-safety devices, 120 units                     |
| Criticality Impact: RAISES URGENCY - This is PATIENT SAFETY. Direct      |
| impact on patients.                                                       |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #3 (IoT Patient Safety)                      |
| Chain Role: Final target (patient harm)                                   |
| Kill Chain Impact: RAISES URGENCY - This is a direct patient safety      |
| incident waiting to happen.                                               |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 2/5 (Theoretical - CVE-2020-25165)                  |
| CISA KEV: NO                                                              |
| Exploit Impact: RAISES URGENCY - No exploit needed. Default credentials  |
| (admin/admin) are well-known.                                             |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE.                                                 |
| C-007: Shared Account Policy (not enforced)                              |
| Control Impact: NONE - Default credentials remain unchanged.            |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (patient safety, medication data integrity,        |
|   availability for dosing)                                                |
| - Modified Attack Vector: Adjacent (A) - accessible from flat network   |
| Adjusted Score: 9.8 (CRITICAL)                                           |
+----------------------------------------------------------------------------+

FINAL PRIORITY: CRITICAL
+----------------------------------------------------------------------------+
| Justification: 7 life-safety infusion pumps have DEFAULT CREDENTIALS    |
| (admin/admin) on the flat network. ANY compromised host can connect and  |
| modify medication dosages. This is a DIRECT PATIENT SAFETY RISK.        |
| Kill Chain #3 describes this exact scenario. This is an EMERGENCY.      |
+----------------------------------------------------------------------------+


================================================================================
FINDING 001: APACHE MOD_LUA RCE (CVE-2021-44790)
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 001 - CVE-2021-44790 (Apache mod_lua RCE)        |
+------------------+--------------------------------------------------+
| CVSS Base Score  | 9.8 (CRITICAL)                                   |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: billing-srv-01 (Billing Server - SRV-004)                           |
| CIA Rating: HIGH - Financial data, revenue cycle                         |
| Criticality Impact: MODERATE RAISE - Billing is important but not        |
| patient safety.                                                           |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #1, KC #5                                    |
| Chain Role: Initial access point                                         |
| Kill Chain Impact: RAISES URGENCY - This is the ENTRY POINT for          |
| ransomware attacks.                                                       |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 3/5 (PoC available)                                |
| CISA KEV: NO                                                              |
| Exploit Impact: MODERATE RAISE - PoC exists but not in KEV.             |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE for Apache.                                     |
| Control Impact: NONE - Apache is exposed.                               |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (billing data integrity, availability)             |
| - Modified Attack Vector: Adjacent (A) - accessible from flat network   |
|   but not internet                                                       |
| Adjusted Score: 8.4 (HIGH)                                               |
+----------------------------------------------------------------------------+

FINAL PRIORITY: HIGH
+----------------------------------------------------------------------------+
| Justification: This is the entry point for the most damaging attacks.   |
| While billing-srv-01 is not a patient safety asset, it has been         |
| compromised twice before (crypto-miner, ransomware). Combined with      |
| Finding 002, it enables full system compromise. Not in CISA KEV but    |
| PoC is available. High priority.                                        |
+----------------------------------------------------------------------------+


================================================================================
FINDING 002: APACHE PRIVILEGE ESCALATION (CVE-2019-0211)
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 002 - CVE-2019-0211 (Apache Privilege Escalation) |
+------------------+--------------------------------------------------+
| CVSS Base Score  | 7.8 (HIGH)                                       |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: billing-srv-01 (Billing Server - SRV-004)                           |
| CIA Rating: HIGH - Financial data                                        |
| Criticality Impact: MODERATE RAISE                                        |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #1, KC #5                                    |
| Chain Role: Privilege escalation (www-data → root)                       |
| Kill Chain Impact: RAISES URGENCY - This is what makes initial RCE      |
| catastrophic.                                                             |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 5/5 (WEAPONIZED)                                   |
| CISA KEV: YES - Added 2021-11-03                                         |
| Exploit Impact: RAISES URGENCY - Weaponized exploit in CISA KEV.        |
| Actively exploited.                                                       |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE.                                                |
| Control Impact: NONE                                                    |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (full system compromise)                           |
| - Modified Attack Vector: Adjacent (A)                                  |
| Adjusted Score: 7.8 (HIGH)                                               |
+----------------------------------------------------------------------------+

FINAL PRIORITY: HIGH
+----------------------------------------------------------------------------+
| Justification: This vulnerability CHAINS with Finding 001 for FULL      |
| SYSTEM COMPROMISE. While the base CVSS is 7.8, it is in CISA KEV and    |
| actively exploited. It makes the Apache RCE catastrophic. High          |
| priority.                                                                |
+----------------------------------------------------------------------------+


================================================================================
FINDING 015: NAS MANAGEMENT INTERFACE ACCESSIBLE
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 015 - NAS Management Interface Accessible        |
+------------------+--------------------------------------------------+
| CVSS Base Score  | N/A (Misconfiguration)                           |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: NAS-01 (Backup Storage - DTA-001)                                   |
| CIA Rating: HIGH - All backup data                                       |
| Criticality Impact: RAISES URGENCY - No backups = no recovery          |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): KC #1, KC #5                                    |
| Chain Role: Final target (backup deletion)                                |
| Kill Chain Impact: RAISES URGENCY - Attackers target backups first.      |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: N/A - Misconfiguration                              |
| CISA KEV: N/A                                                             |
| Exploit Impact: MODERATE RAISE - No exploit needed, just network        |
| access.                                                                   |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE.                                                |
| C-009: Veeam Backups (backup process exists but NAS is exposed)         |
| Control Impact: NONE - NAS is accessible.                               |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: High/High/High (loss of backups affects all data)                 |
| - Modified Attack Vector: Adjacent (A)                                  |
| Adjusted Score: 8.4 (HIGH)                                               |
+----------------------------------------------------------------------------+

FINAL PRIORITY: HIGH
+----------------------------------------------------------------------------+
| Justification: The NAS stores ALL backup data. Management interface is   |
| accessible network-wide. An attacker can delete all backups, making     |
| recovery impossible. Combined with co-located backups (C-009 weakness), |
| this is a single point of failure. High priority.                       |
+----------------------------------------------------------------------------+


================================================================================
FINDING 008: WINDOWS SERVER 2012 R2 EOL (PRINT SERVER)
================================================================================

+------------------+--------------------------------------------------+
| Finding          | 008 - Windows Server 2012 R2 EOL                  |
+------------------+--------------------------------------------------+
| CVSS Base Score  | N/A (EOL)                                        |
+------------------+--------------------------------------------------+

FACTOR 1: ASSET CRITICALITY
+----------------------------------------------------------------------------+
| Asset: print-srv-01 (Print Server - SRV-008)                               |
| CIA Rating: LOW - Printing services                                       |
| Criticality Impact: LOWERS URGENCY - Print server is not critical.       |
+----------------------------------------------------------------------------+

FACTOR 2: KILL CHAIN POSITION
+----------------------------------------------------------------------------+
| Appears in Kill Chain(s): None                                           |
| Chain Role: Not a kill chain asset                                       |
| Kill Chain Impact: NEUTRAL - Not a key attack target.                   |
+----------------------------------------------------------------------------+

FACTOR 3: EXPLOITABILITY
+----------------------------------------------------------------------------+
| Exploitability Score: 4/5 (PrintNightmare - CVE-2021-34527)               |
| CISA KEV: YES                                                             |
| Exploit Impact: MODERATE RAISE - Weaponized but on LOW criticality      |
| asset.                                                                    |
+----------------------------------------------------------------------------+

FACTOR 4: COMPENSATING CONTROLS
+----------------------------------------------------------------------------+
| Existing Controls: NONE.                                                |
| Control Impact: NONE.                                                   |
+----------------------------------------------------------------------------+

ENVIRONMENTAL CVSS
+----------------------------------------------------------------------------+
| Environmental Metrics Applied:                                            |
| - CIA: Low/Low/Medium (printing only)                                    |
| - Modified Attack Vector: Adjacent (A)                                  |
| - Modified Impact: Low/Low/Medium                                        |
| Adjusted Score: 5.3 (MEDIUM)                                             |
+----------------------------------------------------------------------------+

FINAL PRIORITY: MEDIUM
+----------------------------------------------------------------------------+
| Justification: This is an EOL system but on a LOW criticality asset.    |
| The print server does not contain PHI or financial data. While          |
| PrintNightmare is weaponized, the impact is limited to printing         |
| services. Should be migrated but not an emergency. Medium priority.     |
+----------------------------------------------------------------------------+


================================================================================
PRIORITY COMPARISON TABLE
================================================================================

+----------+------------------+-----------------+-----------------+------------------+
| Finding  | CVSS Base Score  | Adjusted Priority| Change Direction | Key Factor       |
+----------+------------------+-----------------+-----------------+------------------+
| 004      | 9.8 (CRITICAL)   | CRITICAL        | SAME            | Weaponized       |
| (MRI XP) |                  |                 |                 | exploits + CISA  |
|          |                  |                 |                 | KEV              |
+----------+------------------+-----------------+-----------------+------------------+
| 031      | 9.8 (CRITICAL)   | CRITICAL        | SAME            | EHR server +     |
| (Ghostcat|                  |                 |                 | PoC available    |
+----------+------------------+-----------------+-----------------+------------------+
| 003      | N/A              | CRITICAL        | UPGRADED        | Direct PHI       |
| (Post-   |                  |                 |                 | exposure         |
| greSQL)  |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| 010      | N/A              | CRITICAL        | UPGRADED        | Patient safety   |
| (Alaris) |                  |                 |                 | + default creds  |
+----------+------------------+-----------------+-----------------+------------------+
| 001      | 9.8 (CRITICAL)   | HIGH            | DOWNGRADED      | PoC not KEV,     |
| (Apache  |                  |                 |                 | billing asset   |
| RCE)     |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| 002      | 7.8 (HIGH)       | HIGH            | SAME            | CISA KEV but     |
| (Apache  |                  |                 |                 | billing asset    |
| PrivEsc) |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| 015      | N/A              | HIGH            | UPGRADED        | Backup deletion  |
| (NAS)    |                  |                 |                 | risk             |
+----------+------------------+-----------------+-----------------+------------------+
| 008      | N/A              | MEDIUM          | DOWNGRADED      | LOW criticality  |
| (Print   |                  |                 |                 | asset            |
| Server)  |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+


================================================================================
REFERENCES
================================================================================

- NIST CVSS Calculator: https://nvd.nist.gov/vuln-metrics/cvss-v3-calculator
- meddefense-vulnerability-scan.txt
- Criticality Assessment (1x00 Task 8)
- Kill Chains (1x01 Task 10)
- Exploit Hunt (T4)


================================================================================
END OF CVSS CONTEXTUALIZER REPORT
================================================================================
