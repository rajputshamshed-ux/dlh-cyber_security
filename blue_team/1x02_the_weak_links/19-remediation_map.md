================================================================================
                    REMEDIATION MAP - MEDDEFENSE HEALTH SYSTEMS
                    Task 19: The Remediation Map
================================================================================

Exercise: Task 19 - The Remediation Map
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Design specific remediation actions for each prioritized
          vulnerability, considering operational constraints and risks of
          the remediation itself.

Source: meddefense-vulnerability-scan.txt
Cross-References: Tasks 16-18, 1x00 Gap Analysis, 1x01 Kill Chains


================================================================================
REMEDIATION PLAN 1: FINDING 004 - MRI WINDOWS XP (EternalBlue, BlueKeep)
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 004                                              |
+------------------+--------------------------------------------------+
| Response Type    | COMPENSATING CONTROL                             |
+------------------+--------------------------------------------------+

CONTROL DESCRIPTION
+----------------------------------------------------------------------------+
| 1. Network Segmentation: Isolate MRI on dedicated VLAN with strict       |
|    firewall rules allowing ONLY necessary traffic (PACS communication).   |
|                                                                             |
| 2. Application Whitelisting: Implement Windows XP AppLocker to allow     |
|    ONLY approved applications (MRI control software, PACS client).       |
|                                                                             |
| 3. Host-Based Firewall: Configure Windows Firewall to block ALL inbound  |
|    connections except from authorized PACS server IPs.                   |
|                                                                             |
| 4. Network Monitoring: Deploy IDS/IPS on the MRI VLAN to detect          |
|    anomalous traffic.                                                     |
+----------------------------------------------------------------------------+

RESIDUAL RISK
+----------------------------------------------------------------------------+
| Residual risk remains because the OS itself is still vulnerable. If an   |
| attacker can bypass whitelisting or firewall rules, they can still       |
| exploit the system. The MRI cannot be patched, so the risk can only be   |
| REDUCED, not ELIMINATED. Long-term solution is virtualizing the MRI     |
| control workstation or replacing the device.                            |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| Phase 1 (Immediate - 48h): Network Segmentation                         |
| Phase 2 (7 days): Host-Based Firewall + App Whitelisting                |
| Phase 3 (30 days): Network Monitoring + IDS/IPS                        |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| Phase 1: IT/Network Team                                                |
| Phase 2: Security Team                                                  |
| Phase 3: Security Team + IT                                            |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $10,000 - $15,000 (firewall configuration + VLAN setup + monitoring)   |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 2: FINDING 031 - GHOSTCAT (CVE-2020-1938)
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 031                                              |
+------------------+--------------------------------------------------+
| Response Type    | PATCH + CONFIGURATION CHANGE                     |
+------------------+--------------------------------------------------+

PATCH SOURCE
+----------------------------------------------------------------------------+
| Vendor Advisory: Apache Tomcat 9.0.31 → 9.0.43 or later                   |
| URL: https://tomcat.apache.org/security-9.html                           |
| Fix: Upgrade Tomcat to 9.0.43+ OR disable AJP connector if not used.    |
+----------------------------------------------------------------------------+

PREREQUISITES
+----------------------------------------------------------------------------+
| - Test upgrade in isolated environment first                           |
| - Schedule maintenance window (off-hours)                             |
| - Backup ehr-srv-01 and configuration files                           |
| - Document current configuration (ports, connectors)                  |
| - Validate application compatibility with newer Tomcat version         |
+----------------------------------------------------------------------------+

ROLLBACK PLAN
+----------------------------------------------------------------------------+
| 1. Restore Tomcat backup (previous version + configs)                 |
| 2. Restart Tomcat service                                              |
| 3. Verify EHR application functionality                                |
| 4. Rollback time: 15-30 minutes                                       |
+----------------------------------------------------------------------------+

OPERATIONAL RISK
+----------------------------------------------------------------------------+
| Risk: EHR application may break with newer Tomcat version.             |
| Mitigation: Test in staging environment first. Schedule during         |
| lowest clinical activity (2-4 AM). Have rollback plan ready.          |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| 48 hours (Immediate)                                                    |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team + Application Vendor (MedTech Solutions)                       |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $1,000 - $3,000 (maintenance window, testing, coordination)            |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 3: FINDING 003 - POSTGRESQL UNRESTRICTED ACCESS
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 003                                              |
+------------------+--------------------------------------------------+
| Response Type    | CONFIGURATION CHANGE                             |
+------------------+--------------------------------------------------+

CHANGE DESCRIPTION
+----------------------------------------------------------------------------+
| 1. Edit pg_hba.conf to restrict connections:                             |
|    # Replace: host all all 10.10.0.0/16 md5                            |
|    # With: host all all 10.10.2.10/32 md5  (only ehr-srv-01)          |
|                                                                             |
| 2. Set listen_addresses = 'localhost,10.10.2.11' in postgresql.conf    |
|                                                                             |
| 3. Configure host-based firewall to drop all other connections to       |
|    port 5432.                                                           |
+----------------------------------------------------------------------------+

IMPACT ASSESSMENT
+----------------------------------------------------------------------------+
| EHR application will continue to function normally. Only connections   |
| from unauthorized hosts will be blocked. No clinical impact.            |
|                                                                             |
| Verification: Confirm ehr-srv-01 can still connect to ehr-db-01.       |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| 24 hours (Immediate)                                                    |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team (Database Administrator)                                        |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $0 - $500 (configuration only)                                         |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 4: FINDING 010 - BD ALARIS DEFAULT CREDENTIALS
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 010                                              |
+------------------+--------------------------------------------------+
| Response Type    | COMPENSATING CONTROL + CONFIGURATION CHANGE      |
+------------------+--------------------------------------------------+

CONTROL DESCRIPTION
+----------------------------------------------------------------------------+
| 1. IMMEDIATE: Change default credentials on ALL 7 pumps.                |
|    (admin/admin → strong unique passwords)                             |
|                                                                             |
| 2. Network Segmentation: Isolate all medical IoT devices on dedicated  |
|    VLAN (Implementation Priority #2 from T16).                         |
|                                                                             |
| 3. Vendor Update: Coordinate with BD to apply firmware v12.1.2         |
|    (under FDA review - requires formal scheduling through BD)         |
+----------------------------------------------------------------------------+

RESIDUAL RISK
+----------------------------------------------------------------------------+
| Even with changed credentials, the pumps remain on the flat network    |
| until segmentation is implemented. A compromised system can still      |
| reach the pumps, but cannot log in without credentials. Risk is        |
| reduced but not eliminated.                                             |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| Phase 1 (24 hours): Change default credentials                         |
| Phase 2 (7 days): Network Segmentation (IoT VLAN)                     |
| Phase 3 (30 days): Vendor firmware update (BD coordination)           |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| Phase 1: IT / Biomedical Engineering                                  |
| Phase 2: IT/Network Team                                              |
| Phase 3: BD Vendor + Biomedical Engineering                          |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $5,000 - $10,000 (vendor coordination + network reconfiguration)      |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 5: FINDING 001 - APACHE RCE (CVE-2021-44790)
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 001                                              |
+------------------+--------------------------------------------------+
| Response Type    | PATCH                                             |
+------------------+--------------------------------------------------+

PATCH SOURCE
+----------------------------------------------------------------------------+
| Vendor Advisory: Apache HTTP Server 2.4.29 → 2.4.52+                   |
| URL: https://httpd.apache.org/security/vulnerabilities_24.html         |
| Fix: Upgrade Apache to 2.4.52 or later                                |
| Package: sudo apt install apache2=2.4.52                              |
+----------------------------------------------------------------------------+

PREREQUISITES
+----------------------------------------------------------------------------+
| - Test Apache upgrade in staging environment                         |
| - Schedule maintenance window (off-hours)                           |
| - Back up /etc/apache2/ configuration files                         |
| - Validate PHP/application compatibility with new Apache version    |
| - Note: This is a production billing server - requires careful testing |
+----------------------------------------------------------------------------+

ROLLBACK PLAN
+----------------------------------------------------------------------------+
| 1. Restore Apache configuration files from backup                    |
| 2. Revert to previous Apache version:                                |
|    sudo apt install apache2=2.4.29                                  |
| 3. Restart Apache service                                            |
| 4. Verify billing application functionality                         |
+----------------------------------------------------------------------------+

OPERATIONAL RISK
+----------------------------------------------------------------------------+
| Risk: Billing application may break with newer Apache version.       |
| Mitigation: Test in isolated environment first. Schedule during      |
| lowest activity period. Have rollback plan ready.                  |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| 7 days (Testing + Scheduled maintenance)                              |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team + Application Vendor (billing application)                    |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $1,000 - $3,000 (testing + maintenance window)                       |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 6: FINDING 002 - APACHE PRIVILEGE ESCALATION (CVE-2019-0211)
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 002                                              |
+------------------+--------------------------------------------------+
| Response Type    | PATCH (same as Finding 001)                       |
+------------------+--------------------------------------------------+

PATCH SOURCE
+----------------------------------------------------------------------------+
| Same as Finding 001 - Apache HTTP Server 2.4.29 → 2.4.39+             |
| URL: https://httpd.apache.org/security/vulnerabilities_24.html         |
| Note: This CVE is fixed in Apache 2.4.39 or later.                    |
+----------------------------------------------------------------------------+

PREREQUISITES
+----------------------------------------------------------------------------+
| Same as Finding 001 - This vulnerability is patched by the SAME        |
| upgrade. This is part of the same patch cycle.                         |
+----------------------------------------------------------------------------+

ROLLBACK PLAN
+----------------------------------------------------------------------------+
| Same as Finding 001 - Rollback to previous Apache version.             |
+----------------------------------------------------------------------------+

OPERATIONAL RISK
+----------------------------------------------------------------------------+
| Same as Finding 001 - Same upgrade, same risk.                        |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| 7 days (Testing + Scheduled maintenance)                              |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team + Application Vendor (billing application)                    |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $0 - Combined with Finding 001 (no additional cost)                  |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 7: FINDING 015 - NAS MANAGEMENT INTERFACE ACCESSIBLE
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 015                                              |
+------------------+--------------------------------------------------+
| Response Type    | CONFIGURATION CHANGE + COMPENSATING CONTROL      |
+------------------+--------------------------------------------------+

CHANGE DESCRIPTION
+----------------------------------------------------------------------------+
| 1. Configure Synology DSM firewall to restrict management interface     |
|    (ports 5000/5001) to administrative IPs only.                       |
|                                                                             |
| 2. Enable MFA for all DSM administrative accounts.                     |
|                                                                             |
| 3. Change all default DSM credentials to strong unique passwords.      |
|                                                                             |
| 4. Implement immutable/offsite backups (cloud S3 or external storage). |
+----------------------------------------------------------------------------+

IMPACT ASSESSMENT
+----------------------------------------------------------------------------+
| Administrative access will be restricted. Backup operations will       |
| continue to function normally. No clinical impact.                    |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| Phase 1 (7 days): Firewall restriction + MFA + Credential Change     |
| Phase 2 (30 days): Offsite/Immutable backups                        |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team (Backup Administrator)                                        |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $5,000 - $15,000 (offsite backups implementation)                     |
+----------------------------------------------------------------------------+


================================================================================
REMEDIATION PLAN 8: FINDING 008 - WINDOWS SERVER 2012 R2 EOL (PRINT SERVER)
================================================================================

+------------------+--------------------------------------------------+
| Finding ID       | 008                                              |
+------------------+--------------------------------------------------+
| Response Type    | EXCEPTION                                         |
+------------------+--------------------------------------------------+

JUSTIFICATION
+----------------------------------------------------------------------------+
| The print server is a LOW criticality asset. Migration to a newer OS   |
| is recommended but not urgent. Extended Security Updates (ESU) can be  |
| purchased from Microsoft for up to 3 years to receive patches.         |
|                                                                             |
| Alternatively, decommission the print server and migrate printing       |
| services to a supported cloud solution or a new Windows Server VM.     |
+----------------------------------------------------------------------------+

REVIEW DATE
+----------------------------------------------------------------------------+
| 90 days - Reassess migration feasibility and ESU cost                 |
+----------------------------------------------------------------------------+

MONITORING
+----------------------------------------------------------------------------+
| Continue to monitor for exploitation attempts targeting                |
| PrintNightmare (CVE-2021-34527) and other print spooler vulnerabilities. |
| Implement network monitoring for unusual SMB/RPC traffic.              |
+----------------------------------------------------------------------------+

TIMELINE
+----------------------------------------------------------------------------+
| 90 days (Exception + Monitoring)                                       |
+----------------------------------------------------------------------------+

OWNER
+----------------------------------------------------------------------------+
| IT Team (Print Services)                                               |
+----------------------------------------------------------------------------+

COST ESTIMATE
+----------------------------------------------------------------------------+
| $0 - $5,000 (if ESU purchased)                                        |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Finding  | Response Type    | Timeline         | Owner            | Cost Estimate    |
+----------+------------------+------------------+------------------+------------------+
| 004      | Compensating     | Immediate - 30d  | IT + Security    | $10K - $15K      |
| (MRI XP) | Control          |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 031      | Patch + Config   | 48 hours         | IT + Vendor      | $1K - $3K        |
| (Ghostcat|                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 003      | Configuration    | 24 hours         | IT (DBA)         | $0 - $500        |
| (Post-   | Change           |                  |                  |                  |
| greSQL)  |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 010      | Config +         | 24h - 30d        | IT + Vendor      | $5K - $10K       |
| (Alaris) | Compensating     |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 001      | Patch            | 7 days           | IT + Vendor      | $1K - $3K        |
| (Apache  |                  |                  |                  |                  |
| RCE)     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 002      | Patch            | 7 days           | IT + Vendor      | $0 (combined)    |
| (Apache  |                  |                  |                  |                  |
| PrivEsc) |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 015      | Config +         | 7-30 days        | IT               | $5K - $15K       |
| (NAS)    | Compensating     |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| 008      | Exception        | 90 days          | IT               | $0 - $5K         |
| (Print   |                  |                  |                  |                  |
| Server)  |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt
- Apache Security: https://httpd.apache.org/security/
- Apache Tomcat Security: https://tomcat.apache.org/security.html
- PostgreSQL Documentation: https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
- Synology DSM: https://www.synology.com/en-us/knowledgebase/DSM
- BD Alaris: https://www.bd.com/en-us/support/security-bulletin

Cross-References:
- Noise Filter (T16)
- CVSS Contextualizer (T17)
- Threat-Vulnerability Correlation (T18)


================================================================================
END OF REMEDIATION MAP REPORT
================================================================================

