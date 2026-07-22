================================================================================
                    NETWORK POSTURE - MEDDEFENSE HEALTH SYSTEMS
                    Task 14: The Network Posture
================================================================================

Exercise: Task 14 - The Network Posture
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Quantify how the flat network architecture amplifies the effective
          risk of every individual vulnerability.

Source: meddefense-vulnerability-scan.txt
Cross-References: 1x00 Gap Analysis (GAP-003), 1x01 Kill Chains


================================================================================
CVE ANALYSIS 1: APACHE MOD_LUA RCE (CVE-2021-44790)
================================================================================

CVE: CVE-2021-44790
Host: billing-srv-01 (10.10.2.15)
Asset Role: Billing/Claims Processing Server (SRV-004)
CVSS Base Score: 9.8 (CRITICAL)

Scenario A: Current (flat network)
----------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ANY system on the 10.10.0.0/16 network. This includes:                    |
| - All clinical workstations (~320)                                       |
| - All servers (EHR, PACS, AD, backup)                                   |
| - All medical devices (monitors, pumps, MRI)                            |
| - All network infrastructure (firewall, switches)                       |
| - Guest WiFi (if isolation is not working)                              |
| - Shadow IT devices (Raspberry Pi, unknown Linux)                       |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| The ENTIRE network. After gaining root on billing-srv-01 (combined with  |
| Finding 002), the attacker can:                                          |
| - Access ehr-db-01 via port 5432 (Finding 003)                         |
| - Access AD and deploy ransomware via Group Policy (Kill Chain #1)      |
| - Access medical devices (monitors, pumps)                             |
| - Delete backups on NAS-01 (Finding 015)                               |
| - Exfiltrate billing data via MySQL (Finding 006)                     |
|                                                                          |
| Impact Radius: ENTIRE ORGANIZATION                                      |
| Effective Risk: CRITICAL                                                 |
+----------------------------------------------------------------------------+

Scenario B: Hypothetical (segmented network)
--------------------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ONLY systems in the same VLAN as billing-srv-01. Ideally:               |
| - Billing application servers                                           |
| - Database servers (if in same segment)                                |
| - Authorized administrative workstations                               |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| ONLY systems in the billing VLAN. The attacker would need to:          |
| - Bypass a firewall between VLANs                                      |
| - Exploit a separate vulnerability to pivot                           |
| - Or use compromised credentials (harder without AD access)           |
|                                                                          |
| Systems OUT OF REACH:                                                  |
| - EHR database (ehr-db-01) would be on a different VLAN              |
| - AD would be on a different VLAN                                     |
| - Medical devices would be on isolated IoT VLAN                      |
| - Backups would be on isolated storage VLAN                          |
|                                                                          |
| Impact Radius: BILLING SEGMENT ONLY                                   |
| Effective Risk: HIGH (contained)                                      |
+----------------------------------------------------------------------------+

Risk Amplification Factor:
+----------------------------------------------------------------------------+
| THE FLAT NETWORK MULTIPLIES THIS RISK BY A FACTOR OF 5-10X              |
|                                                                          |
| This vulnerability goes from a contained billing system compromise to  |
| a NETWORK-WIDE BREACH. Without segmentation, a single RCE on           |
| billing-srv-01 becomes:                                                |
| - EHR compromise                                                      |
| - AD compromise                                                       |
| - IoT compromise                                                      |
| - Backup deletion                                                     |
|                                                                          |
| The flat network turns a "billing system" vulnerability into a        |
| "network-wide" vulnerability.                                          |
+----------------------------------------------------------------------------+


================================================================================
CVE ANALYSIS 2: POSTGRESQL UNRESTRICTED ACCESS (MISCONFIGURATION)
================================================================================

CVE: N/A (Misconfiguration)
Host: ehr-db-01 (10.10.2.11)
Asset Role: EHR Database (SRV-002) - PHI for 50,000+ patients
CVSS Base Score: N/A (but effectively CRITICAL)

Scenario A: Current (flat network)
----------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ANY system on the 10.10.0.0/16 network. This includes:                    |
| - All clinical workstations (~320)                                       |
| - ALL servers (any compromised system)                                  |
| - Medical devices (monitors, pumps, MRI)                                |
| - Guest WiFi (if not isolated)                                          |
| - Shadow IT devices (Raspberry Pi, unknown Linux)                       |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| The EHR database contains PHI for 50,000+ patients. Direct access means: |
| - Exfiltrate ALL patient records (names, DOBs, SSNs, diagnoses)         |
| - Modify patient data (Integrity violation)                            |
| - Encrypt the database (ransomware)                                    |
| - Use credentials from the database to access other systems            |
|                                                                          |
| This is a DIRECT path to the most sensitive data at MedDefense.       |
|                                                                          |
| Impact Radius: ENTIRE ORGANIZATION + PATIENT DATA                     |
| Effective Risk: CRITICAL                                                |
+----------------------------------------------------------------------------+

Scenario B: Hypothetical (segmented network)
--------------------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ONLY systems in the same VLAN as ehr-db-01. Ideally:                   |
| - EHR application server (ehr-srv-01)                                 |
| - Authorized administrative workstations (limited IPs)                |
| - Backup servers (if in same segment)                                 |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| ONLY the EHR segment. The attacker would need to:                     |
| - Compromise ehr-srv-01 FIRST (which is separate)                    |
| - Then connect to the database                                       |
| - Cannot access from clinical workstations directly                  |
|                                                                          |
| Systems OUT OF REACH:                                                 |
| - Clinical workstations (on different VLAN)                         |
| - Billing server (on different VLAN)                                |
| - AD (on different VLAN)                                            |
|                                                                          |
| Impact Radius: EHR SEGMENT ONLY                                      |
| Effective Risk: HIGH (but requires prior access)                    |
+----------------------------------------------------------------------------+

Risk Amplification Factor:
+----------------------------------------------------------------------------+
| THE FLAT NETWORK MULTIPLIES THIS RISK BY A FACTOR OF 10-20X             |
|                                                                          |
| This misconfiguration is the SINGLE MOST AMPLIFIED finding in the scan.|
| In a flat network, ANY compromised system can access the EHR database. |
| In a segmented network, only systems in the EHR segment can reach it. |
|                                                                          |
| The difference is between:                                            |
| - ANY breach = EHR breach (flat network)                              |
| - EHR segment breach = EHR breach (segmented)                        |
|                                                                          |
| The flat network makes this misconfiguration a NETWORK-WIDE problem.  |
+----------------------------------------------------------------------------+


================================================================================
CVE ANALYSIS 3: BD ALARIS DEFAULT CREDENTIALS (MISCONFIGURATION)
================================================================================

CVE: N/A (Misconfiguration)
Host: BD Alaris Pumps (10.10.3.40-46)
Asset Role: Medical IoT - Infusion Pumps (IOT-002) - Life-Safety Devices
CVSS Base Score: N/A (but effectively CRITICAL)

Scenario A: Current (flat network)
----------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ANY system on the 10.10.0.0/16 network. This includes:                    |
| - All clinical workstations (~320)                                       |
| - ANY compromised system                                                 |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| The attacker can log in to the pump management console and:              |
| - Modify medication dosages                                              |
| - Disable alarms                                                         |
| - View patient names and medication information                         |
| - Use the pumps as a pivot point to other systems                       |
|                                                                          |
| This is a DIRECT PATIENT SAFETY RISK.                                   |
|                                                                          |
| Impact Radius: PATIENT SAFETY + NETWORK                                 |
| Effective Risk: CRITICAL                                                |
+----------------------------------------------------------------------------+

Scenario B: Hypothetical (segmented network)
--------------------------------------------
Who can reach this vulnerability:
+----------------------------------------------------------------------------+
| ONLY systems in the same IoT VLAN. Ideally:                             |
| - Clinical workstations that need to monitor patients                  |
| - Authorized biomedical engineering workstations                       |
| - No access from general workstations                                 |
+----------------------------------------------------------------------------+

What the attacker can reach AFTER exploitation:
+----------------------------------------------------------------------------+
| ONLY the IoT VLAN. The attacker would need to:                        |
| - First compromise a system in the IoT VLAN                          |
| - Cannot access from a compromised clinical workstation              |
|                                                                          |
| Systems OUT OF REACH:                                                 |
| - General clinical workstations (on different VLAN)                 |
| - Servers (on different VLAN)                                       |
| - AD (on different VLAN)                                            |
|                                                                          |
| Impact Radius: IOT SEGMENT ONLY                                      |
| Effective Risk: MEDIUM (only if IoT segment is compromised)         |
+----------------------------------------------------------------------------+

Risk Amplification Factor:
+----------------------------------------------------------------------------+
| THE FLAT NETWORK MULTIPLIES THIS RISK BY A FACTOR OF 5-8X               |
|                                                                          |
| In a flat network, ANY compromised workstation can reach the pumps.    |
| In a segmented network, only compromised IoT devices can reach them.  |
|                                                                          |
| The difference:                                                         |
| - Flat: 320 workstations + servers + any system = access to pumps     |
| - Segmented: only compromised IoT VLAN systems = access to pumps     |
|                                                                          |
| This is the difference between a patient safety incident and a        |
| contained IoT device compromise.                                       |
+----------------------------------------------------------------------------+


================================================================================
NETWORK POSTURE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| NETWORK POSTURE SUMMARY                                                    |
|                                                                             |
| The flat network is the SINGLE MOST CONSEQUENTIAL ARCHITECTURAL           |
| DECISION in MedDefense's vulnerability posture. It turns EVERY            |
| vulnerability into a network-wide vulnerability.                          |
|                                                                             |
| AGGREGATE RISK AMPLIFICATION:                                              |
|                                                                             |
| Across the entire scan report, the flat network AMPLIFIES EVERY          |
| vulnerability by a factor of 3-20X.                                        |
|                                                                             |
| Examples:                                                                  |
| - billing-srv-01 RCE (CVE-2021-44790): 5-10X amplification              |
| - PostgreSQL unrestricted (ehr-db-01): 10-20X amplification             |
| - BD Alaris default credentials: 5-8X amplification                     |
|                                                                             |
| WHY NETWORK SEGMENTATION IS MORE IMPACTFUL THAN PATCHING ANY SINGLE CVE: |
|                                                                             |
| 1. Patching a single CVE fixes ONE vulnerability on ONE system.          |
|    Segmentation fixes ALL vulnerabilities on ALL systems by limiting     |
|    their blast radius.                                                    |
|                                                                             |
| 2. When you patch a CVE, you are still vulnerable to the NEXT one.      |
|    When you segment the network, you reduce the impact of EVERY          |
|    vulnerability - current, future, and unknown.                         |
|                                                                             |
| 3. The flat network is the ENABLER of lateral movement. Without it,     |
|    Kill Chain #1 (VPN Ransomware) stops at the perimeter.               |
|                                                                             |
| 4. Segmentation provides defense in depth even when patches are not     |
|    available (EOL systems like Windows XP MRI).                         |
|                                                                             |
| 5. The cost of segmentation (firewall reconfiguration, VLAN setup) is    |
|    LOW compared to the cost of a single breach ($5M+).                  |
|                                                                             |
| THE BOTTOM LINE:                                                          |
|                                                                             |
| Investing in network segmentation provides more risk reduction per      |
| dollar than patching any single CVE. It is the SINGLE MOST EFFECTIVE    |
| control MedDefense can implement.                                         |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+-----------------+-----------------+------------------+
| CVE      | Host             | CVSS            | Amplification   | Impact           |
|          |                  |                 | Factor          |                  |
+----------+------------------+-----------------+-----------------+------------------+
| CVE-2021-| billing-srv-01   | 9.8             | 5-10X           | Network-wide     |
| 44790    |                  |                 |                 | compromise       |
+----------+------------------+-----------------+-----------------+------------------+
| N/A      | ehr-db-01        | N/A (Critical)  | 10-20X          | EHR data         |
| (Post-   |                  |                 |                 | exposure         |
| greSQL)  |                  |                 |                 |                  |
+----------+------------------+-----------------+-----------------+------------------+
| N/A      | BD Alaris Pumps  | N/A (Critical)  | 5-8X            | Patient safety   |
| (Default)|                  |                 |                 | risk             |
+----------+------------------+-----------------+-----------------+------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt
- Gap Analysis (1x00 Task 12): GAP-003
- Kill Chains (1x01 Task 10): KC #1, KC #2, KC #3
- Asset Registry (1x00 Task 7): SRV-001, SRV-004, IOT-002


================================================================================
END OF NETWORK POSTURE REPORT
================================================================================
