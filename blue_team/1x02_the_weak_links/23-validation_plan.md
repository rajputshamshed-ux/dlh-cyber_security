================================================================================
                    VALIDATION PLAN - MEDDEFENSE HEALTH SYSTEMS
                    Task 23: The Validation Plan
================================================================================

Exercise: Task 23 - The Validation Plan
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Design a post-remediation validation and continuous monitoring
          strategy.

Sources: Tasks 19-22, 1x00 Gap Analysis, 1x01 Threat Landscape


================================================================================
1. POST-PATCH VERIFICATION (IMMEDIATE REMEDIATIONS)
================================================================================

REMEDIATION 1: MRI WINDOWS XP COMPENSATING CONTROLS (FINDING 004)
------------------------------------------------------------------
+----------------------------------------------------------------------------+
| TEST 1: Network Segmentation                                               |
| Method: Confirm MRI is on isolated VLAN                                   |
| Command: nmap -sn 10.10.1.0/24 (verify MRI not responding from other     |
|          subnets)                                                         |
| Success: MRI responds only from authorized IPs within the isolated VLAN. |
| Owner: IT Network Team                                                   |
+----------------------------------------------------------------------------+
| TEST 2: Host-Based Firewall                                                |
| Method: Confirm ports 445 (SMB) and 3389 (RDP) are BLOCKED on MRI        |
|          workstation                                                      |
| Command: nmap -p445,3389 10.10.1.70                                      |
| Success: Ports 445 and 3389 show "filtered" or "closed"                 |
| Owner: IT Security Team                                                  |
+----------------------------------------------------------------------------+
| TEST 3: Application Whitelisting                                           |
| Method: Confirm only approved applications are allowed to run            |
| Check: Verify MRI control software and PACS client are allowed;          |
|          attempt to run a test application (should be blocked)            |
| Success: Unauthorized applications cannot execute                        |
| Owner: IT Security Team                                                  |
+----------------------------------------------------------------------------+


REMEDIATION 2: GHOSTCAT ON EHR APPLICATION SERVER (FINDING 031)
----------------------------------------------------------------
+----------------------------------------------------------------------------+
| TEST 1: AJP Connector Verification                                         |
| Method: Confirm AJP connector is disabled OR upgraded                    |
| Command: nmap -p8009 10.10.2.10                                          |
| Success: Port 8009 shows "closed" or "filtered"                         |
| Owner: IT Systems Team                                                   |
+----------------------------------------------------------------------------+
| TEST 2: Tomcat Version Verification                                       |
| Method: Confirm Tomcat is upgraded to 9.0.43+                           |
| Command: curl -I http://10.10.2.10:8080 | grep Server                   |
| Success: Server header shows Apache Tomcat/9.0.43 or later              |
| Owner: IT Systems Team                                                   |
+----------------------------------------------------------------------------+
| TEST 3: Ghostcat Exploit Attempt                                           |
| Method: Run Ghostcat PoC against ehr-srv-01 (in isolated environment)   |
| Check: Confirm exploit no longer works                                     |
| Success: Exploit fails; file read is blocked                            |
| Owner: IT Security Team                                                  |
+----------------------------------------------------------------------------+


REMEDIATION 3: POSTGRESQL RESTRICTED ACCESS (FINDING 003)
----------------------------------------------------------
+----------------------------------------------------------------------------+
| TEST 1: pg_hba.conf Verification                                           |
| Method: Confirm PostgreSQL only accepts connections from ehr-srv-01     |
| Command: SELECT * FROM pg_hba_file_rules;                                |
| Success: Only 10.10.2.10/32 is allowed                                   |
| Owner: IT Database Administrator                                          |
+----------------------------------------------------------------------------+
| TEST 2: Connection Test from Unauthorized Hosts                           |
| Method: Attempt PostgreSQL connection from ehr-db-01 to ehr-db-01       |
| Command: psql -h 10.10.2.11 -U ehr_user -d ehr_db                       |
| Success: Connection fails with "no pg_hba.conf entry"                  |
| Owner: IT Database Administrator                                          |
+----------------------------------------------------------------------------+
| TEST 3: Connection Test from Authorized Host                              |
| Method: Confirm ehr-srv-01 can still connect                            |
| Command: psql -h 10.10.2.11 -U ehr_user -d ehr_db (from ehr-srv-01)    |
| Success: Connection succeeds; EHR application functions normally       |
| Owner: IT Database Administrator                                          |
+----------------------------------------------------------------------------+


REMEDIATION 4: BD ALARIS DEFAULT CREDENTIALS (FINDING 010)
-----------------------------------------------------------
+----------------------------------------------------------------------------+
| TEST 1: Credential Change Verification                                     |
| Method: Attempt login with default credentials (admin/admin)             |
| Command: curl -X POST http://10.10.3.40/login -d "user=admin&pass=admin" |
| Success: Login fails with "invalid credentials"                         |
| Owner: Biomedical Engineering + IT                                        |
+----------------------------------------------------------------------------+
| TEST 2: New Credential Verification                                       |
| Method: Confirm new credentials work for authorized staff               |
| Check: Biomed staff can access pump management console                   |
| Success: Authorized login succeeds with new credentials                  |
| Owner: Biomedical Engineering                                             |
+----------------------------------------------------------------------------+


================================================================================
2. COMPENSATING CONTROL VALIDATION
================================================================================

MRI COMPENSATING CONTROLS
-------------------------
+----------------------------------------------------------------------------+
| VALIDATION METHOD:                                                         |
|                                                                             |
| 1. VLAN Confirmation:                                                      |
|    - Use nmap to confirm MRI is no longer reachable from clinical        |
|      workstations                                                          |
|    - Verify PACS communication still works (essential for clinical       |
|      operations)                                                           |
|                                                                             |
| 2. Firewall Rule Confirmation:                                             |
|    - Review FortiGate rules for MRI VLAN                                  |
|    - Confirm ONLY necessary PACS traffic is allowed                       |
|    - Log traffic to detect violations                                     |
|                                                                             |
| 3. Whitelisting Confirmation:                                              |
|    - Review AppLocker logs for blocked applications                      |
|    - Confirm MRI software still functions correctly                       |
|                                                                             |
| 4. Monitoring Confirmation:                                                |
|    - Verify IDS/IPS alerts are configured for MRI VLAN                   |
|    - Test with a simulated attack (in controlled environment)            |
+----------------------------------------------------------------------------+

MEDICAL IOT COMPENSATING CONTROLS
---------------------------------
+----------------------------------------------------------------------------+
| VALIDATION METHOD:                                                         |
|                                                                             |
| 1. IoT VLAN Confirmation:                                                  |
|    - Confirm ALL medical IoT devices are on the dedicated IoT VLAN       |
|    - Verify clinical workstations can still access necessary devices     |
|      (monitors, pumps)                                                    |
|                                                                             |
| 2. Firewall Rule Confirmation:                                             |
|    - Review firewall rules between IoT VLAN and clinical VLAN            |
|    - Confirm ONLY necessary traffic is allowed (monitoring data)          |
|                                                                             |
| 3. Default Credential Audit:                                               |
|    - Verify ALL IoT devices have changed default credentials             |
|    - Use credential scanning tool to confirm                              |
+----------------------------------------------------------------------------+


================================================================================
3. RESCAN SCHEDULE
================================================================================

+----------------------------------------------------------------------------+
| RECOMMENDED FREQUENCY:                                                     |
|                                                                             |
| 1. FULL VULNERABILITY SCAN: MONTHLY                                       |
|    - Complete scan of all 10.10.0.0/16 assets                            |
|    - Schedule during off-peak hours (2 AM - 6 AM)                        |
|    - Use authenticated scans where credentials are available             |
|    - Owner: IT Security Team                                              |
|                                                                             |
| 2. CRITICAL ASSET SCAN: WEEKLY                                            |
|    - Scan EHR, billing, AD, and medical IoT devices                      |
|    - Focus on high-priority assets identified in Task 8                  |
|    - Owner: IT Security Team                                              |
|                                                                             |
| 3. NEW CVE SCAN: WITHIN 48 HOURS OF CISA KEV ADDITION                    |
|    - Check for newly weaponized vulnerabilities                          |
|    - Prioritize based on asset criticality                               |
|    - Owner: IT Security Team + Deputy CISO                               |
|                                                                             |
| 4. POST-PATCH VERIFICATION SCAN: WITHIN 24 HOURS OF PATCHING            |
|    - Verify findings are closed                                          |
|    - Confirm no new issues introduced                                     |
|    - Owner: IT Systems Team                                               |
+----------------------------------------------------------------------------+

JUSTIFICATION
-------------
+----------------------------------------------------------------------------+
| Monthly scanning is the industry standard for mid-size organizations      |
| (NIST CSF recommends continuous monitoring). Weekly scanning for          |
| critical assets provides early detection of new vulnerabilities. The     |
| CISA KEV 48-hour response ensures MedDefense addresses actively          |
| weaponized vulnerabilities before they are exploited.                    |
+----------------------------------------------------------------------------+


================================================================================
4. CONTINUOUS INTELLIGENCE
================================================================================

+----------------------------------------------------------------------------+
| CONTINUOUS INTELLIGENCE INTEGRATION                                        |
|                                                                             |
| 1. CISA KEV ALERTS:                                                        |
|    - Subscribe to CISA KEV RSS feed                                      |
|    - Check weekly for new additions                                       |
|    - Immediate action for KEV vulnerabilities affecting critical assets  |
|    - Owner: IT Security Team                                              |
|                                                                             |
| 2. VENDOR ADVISORIES:                                                      |
|    - Subscribe to:                                                         |
|      - Fortinet PSIRT (FortiGate)                                        |
|      - Microsoft Security Response Center (O365, Windows)                |
|      - Apache Security (web servers)                                     |
|      - Synology Security (NAS)                                           |
|      - BD Security Alerts (medical devices)                              |
|    - Review weekly                                                       |
|    - Owner: IT Systems Team                                               |
|                                                                             |
| 3. THREAT FEED UPDATES:                                                    |
|    - Monitor CISA healthcare advisories                                  |
|    - Review HC3 analyst notes                                            |
|    - Track ransomware trends in healthcare sector                        |
|    - Owner: Deputy CISO                                                   |
|                                                                             |
| 4. INTEGRATION PROCESS:                                                   |
|    - Weekly: Review all intelligence sources                            |
|    - Identify: Which vulnerabilities affect MedDefense                   |
|    - Prioritize: Using asset criticality + exploit availability          |
|    - Act: Add to remediation plan                                        |
|    - Owner: Deputy CISO + IT Security Team                               |
+----------------------------------------------------------------------------+


================================================================================
5. VULNERABILITY MANAGEMENT LIFECYCLE DIAGRAM
================================================================================

+----------------------------------------------------------------------------+
| VULNERABILITY MANAGEMENT LIFECYCLE (TEXT REPRESENTATION)                  |
|                                                                             |
|                    ┌─────────────────────────────────────────┐             |
|                    │        1. SCAN (Monthly/Weekly)        │             |
|                    │   IT Security Team runs OpenVAS scan   │             |
|                    │   Identifies new vulnerabilities       │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │       2. TRIAGE (24-48 hours)          │             |
|                    │   IT Security Team reviews findings    │             |
|                    │   Separates FPs from true findings    │             |
|                    │   Categorizes by severity              │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │      3. PRIORITIZE (48-72 hours)       │             |
|                    │   Deputy CISO + IT Security Team       │             |
|                    │   Cross-references:                     │             |
|                    │   - Asset criticality (1x00)          │             |
|                    │   - Threat landscape (1x01)           │             |
|                    │   - Exploit availability (CISA KEV)   │             |
|                    │   Creates remediation plan             │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │       4. REMEDIATE (Timeline)          │             |
|                    │   IT Operations / Vendors execute      │             |
|                    │   Immediate: Security Team directs     │             |
|                    │   Scheduled: IT Ops coordinates        │             |
|                    │   Long-term: Architecture changes      │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │       5. VALIDATE (24 hours)           │             |
|                    │   IT Security Team verifies            │             |
|                    │   Rescan affected systems              │             |
|                    │   Confirm vulnerability is closed      │             |
|                    │   Document results                     │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │        6. REPORT (Monthly)             │             |
|                    │   IT Security Team reports to:          │             |
|                    │   - Deputy CISO (technical)           │             |
|                    │   - CEO/Board (executive)             │             |
|                    │   Tracks progress against KPIs         │             |
|                    └──────────────┬──────────────────────────┘             |
|                                   │                                       |
|                                   ▼                                       |
|                    ┌─────────────────────────────────────────┐             |
|                    │   LOOP BACK TO STEP 1 (Continuous)     │             |
|                    └─────────────────────────────────────────┘             |
+----------------------------------------------------------------------------+

RESPONSIBILITY MATRIX
---------------------
+----------+------------------+------------------------------------------+
| Step     | Owner            | Role                                     |
+----------+------------------+------------------------------------------+
| Scan     | IT Security Team | Run scans, identify findings             |
+----------+------------------+------------------------------------------+
| Triage   | IT Security Team | Review findings, separate FP from TP     |
+----------+------------------+------------------------------------------+
| Prioritize| Deputy CISO      | Cross-reference with 1x00 and 1x01      |
+----------+------------------+------------------------------------------+
| Remediate | IT Ops / Vendor  | Execute patches and configuration changes|
+----------+------------------+------------------------------------------+
| Validate  | IT Security Team | Verify remediation was successful        |
+----------+------------------+------------------------------------------+
| Report   | Deputy CISO      | Report to CEO/Board                     |
+----------+------------------+------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. Post-patch verification is ESSENTIAL. A patch that fails silently is
   worse than no patch at all because everyone thinks the problem is fixed.

2. Compensating controls require active monitoring and validation.
   Segmentation and whitelisting must be regularly verified.

3. Monthly full scans + weekly critical asset scans = industry best practice.

4. Continuous intelligence (CISA KEV, vendor advisories) is essential for
   identifying new threats between scheduled scans.

5. The vulnerability management lifecycle is CONTINUOUS. It never ends.
   New vulnerabilities are discovered every day.


================================================================================
REFERENCES
================================================================================

- NIST CSF: PR.DS-1, DE.AE-1, RS.AN-1
- CIS Controls v8: Control 1, 7, 8
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- meddefense-vulnerability-scan.txt

Cross-References:
- Priority Matrix (T20)
- Patch Briefing (T22)


================================================================================
END OF VALIDATION PLAN REPORT
================================================================================
