================================================================================
                    QUICK WINS - MEDDEFENSE HEALTH SYSTEMS
                    Task 13: The Quick Wins
================================================================================

Exercise: Task 13 - The Quick Wins
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Identify and design 5 security improvements that can be
          implemented within 2 weeks at zero or minimal cost.

Sources: 1x00 Gap Analysis, 1x01 Kill Chains, 1x02 Vulnerability Scan,
         1x03 Risk Register (T10), 1x03 Control Selection (T11)

Principles:
- Zero or minimal cost (< $500)
- No major infrastructure changes
- Implementable within 2 weeks
- Uses existing resources and contracts


================================================================================
QUICK WIN #1: DISABLE DEFAULT CREDENTIALS ON BD ALARIS PUMPS
================================================================================

+------------------+--------------------------------------------------+
| Quick Win        | Disable Default Credentials on BD Alaris Pumps   |
+------------------+--------------------------------------------------+
| Risk Addressed   | RISK-005 (Medical IoT Compromise)                |
+------------------+--------------------------------------------------+
| Action           | 1. Identify all 7 BD Alaris pumps on the network  |
|                  | 2. Log in to each pump's management interface     |
|                  | 3. Change credentials from admin/admin to strong, |
|                  |    unique passwords                               |
|                  | 4. Document new credentials in a secure password  |
|                  |    manager                                        |
|                  | 5. Test clinical functionality after changes     |
+------------------+--------------------------------------------------+
| Owner            | Biomedical Engineering + IT Security Team        |
+------------------+--------------------------------------------------+
| Timeline         | 3 days                                            |
+------------------+--------------------------------------------------+
| Cost             | $0 (already have access)                          |
+------------------+--------------------------------------------------+
| Risk Reduction   | Disrupts Kill Chain #3 (IoT Patient Safety) at   |
|                  | Step 2 (Establish Foothold). Default credentials |
|                  | are a common entry point for attackers. This     |
|                  | removes the easiest path to compromise.         |
+------------------+--------------------------------------------------+
| Verification     | 1. Confirm login with default credentials fails  |
|                  | 2. Confirm authorized staff can log in with new  |
|                  |    credentials                                    |
|                  | 3. Update asset registry with credential status  |
+------------------+--------------------------------------------------+


================================================================================
QUICK WIN #2: DISABLE SSH PASSWORD AUTHENTICATION ON LINUX SERVERS
================================================================================

+------------------+--------------------------------------------------+
| Quick Win        | Disable SSH Password Authentication on Linux     |
|                  | Servers                                           |
+------------------+--------------------------------------------------+
| Risk Addressed   | RISK-001 (Data Breach), RISK-003 (Ransomware)    |
+------------------+--------------------------------------------------+
| Action           | 1. Identify all Linux servers (billing-srv-01,   |
|                  |    ehr-srv-01, ehr-db-01, backup-srv-01,        |
|                  |    web-srv-01)                                   |
|                  | 2. For each server, edit /etc/ssh/sshd_config:  |
|                  |    set PasswordAuthentication no                 |
|                  | 3. Reload SSH service: systemctl reload sshd     |
|                  | 4. Verify key-based authentication is working    |
|                  | 5. Document the change                           |
+------------------+--------------------------------------------------+
| Owner            | IT Systems Team + Security Analyst               |
+------------------+--------------------------------------------------+
| Timeline         | 5 days                                            |
+------------------+--------------------------------------------------+
| Cost             | $0 (configuration change only)                    |
+------------------+--------------------------------------------------+
| Risk Reduction   | Disrupts Kill Chain #1 (Ransomware via VPN) and  |
|                  | Kill Chain #2 (Phishing → EHR) at Step 4        |
|                  | (Credential Access). SSH password auth is a     |
|                  | primary target for brute-force attacks. This    |
|                  | eliminates credential theft via SSH.           |
+------------------+--------------------------------------------------+
| Verification     | 1. Confirm sshd_config shows                     |
|                  |    PasswordAuthentication no                     |
|                  | 2. Attempt password login (should fail)         |
|                  | 3. Confirm SSH key login works                  |
+------------------+--------------------------------------------------+


================================================================================
QUICK WIN #3: RESTRICT POSTGRESQL TO EHR APPLICATION SERVER ONLY
================================================================================

+------------------+--------------------------------------------------+
| Quick Win        | Restrict PostgreSQL to ehr-srv-01 Only           |
+------------------+--------------------------------------------------+
| Risk Addressed   | RISK-001 (Data Breach)                           |
+------------------+--------------------------------------------------+
| Action           | 1. On ehr-db-01, edit /etc/postgresql/*/main/   |
|                  |    pg_hba.conf                                   |
|                  | 2. Replace: host all all 10.10.0.0/16 md5      |
|                  |    With: host all all 10.10.2.10/32 md5         |
|                  | 3. Reload PostgreSQL: systemctl reload           |
|                  |    postgresql                                     |
|                  | 4. Test connection from ehr-srv-01 works        |
|                  | 5. Test connection from other hosts (should     |
|                  |    fail)                                          |
+------------------+--------------------------------------------------+
| Owner            | Database Administrator + IT Security Team       |
+------------------+--------------------------------------------------+
| Timeline         | 1 day                                             |
+------------------+--------------------------------------------------+
| Cost             | $0 (configuration change only)                    |
+------------------+--------------------------------------------------+
| Risk Reduction   | Disrupts Kill Chain #2 (Phishing → EHR) at      |
|                  | Step 5 (Connect to PostgreSQL). Direct access   |
|                  | to the EHR database is eliminated. ANY          |
|                  | compromised host cannot reach the database.     |
+------------------+--------------------------------------------------+
| Verification     | 1. Confirm pg_hba.conf shows only 10.10.2.10/32 |
|                  | 2. Confirm ehr-srv-01 can connect               |
|                  | 3. Confirm other hosts cannot connect           |
+------------------+--------------------------------------------------+


================================================================================
QUICK WIN #4: ENABLE SCREEN LOCK ON CLINICAL WORKSTATIONS
================================================================================

+------------------+--------------------------------------------------+
| Quick Win        | Enable Screen Lock on Clinical Workstations      |
+------------------+--------------------------------------------------+
| Risk Addressed   | RISK-004 (Insider Data Theft)                    |
+------------------+--------------------------------------------------+
| Action           | 1. Configure Group Policy Object (GPO) for       |
|                  |    clinical workstations                         |
|                  | 2. Set screen lock timeout to 5 minutes         |
|                  | 3. Enable screen saver with password protection  |
|                  | 4. Deploy GPO to all Windows 10 workstations    |
|                  | 5. Remove the sign at nurse station that says   |
|                  |    "For efficiency, please do not log out       |
|                  |    between shifts"                              |
+------------------+--------------------------------------------------+
| Owner            | IT Systems Team + Nursing Leadership            |
+------------------+--------------------------------------------------+
| Timeline         | 7 days                                            |
+------------------+--------------------------------------------------+
| Cost             | $0 (existing AD/GPO infrastructure)              |
+------------------+--------------------------------------------------+
| Risk Reduction   | Disrupts Kill Chain #2 (Phishing → EHR) and    |
|                  | Insider threats. Unlocked sessions are the      |
|                  | easiest way for unauthorized individuals to     |
|                  | access PHI. This removes that exposure.        |
+------------------+--------------------------------------------------+
| Verification     | 1. Confirm GPO is applied to clinical           |
|                  |    workstations                                  |
|                  | 2. Test that screen locks after 5 minutes      |
|                  | 3. Confirm password required to unlock         |
+------------------+--------------------------------------------------+


================================================================================
QUICK WIN #5: CONDUCT SECURITY AWARENESS EMAIL (PHISHING AWARENESS)
================================================================================

+------------------+--------------------------------------------------+
| Quick Win        | Conduct Phishing Awareness Campaign              |
+------------------+--------------------------------------------------+
| Risk Addressed   | RISK-002 (VPN Compromise), RISK-004 (Insider    |
|                  | Data Theft)                                      |
+------------------+--------------------------------------------------+
| Action           | 1. Send an email to ALL employees with:          |
|                  |    - Common phishing red flags                  |
|                  |    - Examples of real phishing attempts        |
|                  |    - Instructions for reporting suspicious      |
|                  |      emails                                      |
|                  | 2. Include a link to a short (5-minute) online   |
|                  |    security awareness module (use existing      |
|                  |    training platform)                           |
|                  | 3. Ask managers to discuss phishing risks in    |
|                  |    team meetings                                 |
|                  | 4. Track email open rates and module completion |
|                  | 5. Schedule a follow-up phishing simulation     |
|                  |    for next month                               |
+------------------+--------------------------------------------------+
| Owner            | Security Analyst + HR Department                |
+------------------+--------------------------------------------------+
| Timeline         | 3 days                                            |
+------------------+--------------------------------------------------+
| Cost             | $0 (existing O365 email and training platform)   |
+------------------+--------------------------------------------------+
| Risk Reduction   | Disrupts Kill Chain #2 (Phishing → EHR) at      |
|                  | Step 1 (Initial Access). Phishing is the #1    |
|                  | entry vector for credential theft. This raises  |
|                  | awareness and reduces the likelihood of         |
|                  | successful phishing attempts.                   |
+------------------+--------------------------------------------------+
| Verification     | 1. Confirm email sent to all employees          |
|                  | 2. Track email open rates (>80% target)        |
|                  | 3. Track module completion rates (>60% target) |
+------------------+--------------------------------------------------+


================================================================================
QUICK WINS SUMMARY TABLE
================================================================================

+----------+------------------+------------------------------------------+------------------+------------------+
| Quick    | Title            | Risk Addressed                           | Timeline         | Cost             |
| Win #    |                  |                                          |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+
| #1       | Disable Default  | RISK-005 (Medical IoT Compromise)        | 3 days           | $0               |
|          | Credentials      |                                          |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+
| #2       | Disable SSH      | RISK-001 (Data Breach), RISK-003         | 5 days           | $0               |
|          | Password Auth    | (Ransomware)                             |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+
| #3       | Restrict         | RISK-001 (Data Breach)                   | 1 day            | $0               |
|          | PostgreSQL       |                                          |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+
| #4       | Enable Screen    | RISK-004 (Insider Data Theft)            | 7 days           | $0               |
|          | Lock             |                                          |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+
| #5       | Phishing         | RISK-002 (VPN Compromise), RISK-004      | 3 days           | $0               |
|          | Awareness        | (Insider Data Theft)                     |                  |                  |
+----------+------------------+------------------------------------------+------------------+------------------+

TOTAL COST: $0
TOTAL TIMELINE: 7 days (parallel execution)
TOTAL RISKS ADDRESSED: 4 of 10 (40%)


================================================================================
QUICK WINS - ORGANIZATIONAL PURPOSE
================================================================================

+----------------------------------------------------------------------------+
| WHY QUICK WINS MATTER BEYOND IMMEDIATE RISK REDUCTION                      |
|                                                                             |
| Quick wins serve a crucial organizational purpose in the first month of a   |
| security program. They demonstrate momentum and build credibility with    |
| the Board, showing that MedDefense is taking action while the longer-term   |
| initiatives are being planned. They signal that security is not just a     |
| theoretical exercise but a practical, operational priority. They also      |
| build trust with employees, showing that security improvements are         |
| achievable without disrupting clinical workflows. Finally, they create     |
| a foundation of "security hygiene" that makes later, more complex          |
| investments more effective. A program that starts with quick wins is       |
| one that stakeholders believe in - and that belief is essential for        |
| sustaining funding and organizational buy-in over the long term.          |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Risk Register (1x03 T10)
- Control Selection (1x03 T11)
- Kill Chains (1x01 T10)
- Gap Analysis (1x00 Task 12)
- Vulnerability Scan (1x02)


================================================================================
END OF QUICK WINS REPORT
================================================================================
