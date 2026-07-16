================================================================================
                    VECTOR-TO-ASSET MATRIX - MEDDEFENSE HEALTH SYSTEMS
                    Task 9: The Vector-to-Asset Matrix
================================================================================

Exercise: Task 9 - The Vector-to-Asset Matrix
Analyst: shamshed rajput 
Date: 16/07/2026
Objective: Produce a systematic cross-reference showing which attack vectors
          can reach which critical assets, creating a complete threat
          exposure map.

Methodology References:
- NIST SP 800-30: Attack path analysis
- MITRE ATT&CK: Tactics and techniques
- Security+ 2.2: Attack vectors
- CIS Controls v8: Control 1, 7, 12

Cross-References to Project 1x00:
- Criticality Assessment (Task 8): Top 5 Critical Assets
- Asset Registry (Task 7): Medical IoT, Active Directory
- Gap Analysis (Task 12): All Gap IDs
- Attack Surface Map (Task 7): External, Internal, Human
- Technical Vectors (Task 8): All technical vectors
- Social Engineering Analysis (Task 4): Human vectors


================================================================================
1. CRITICAL ASSETS (COLUMNS)
================================================================================

+----------+------------------+--------------------------------------------------+
| Column   | Asset            | Criticality Rating                               |
+----------+------------------+--------------------------------------------------+
| C1       | EHR System       | CRITICAL - Patient data for 50,000+ patients    |
|          | (ehr-srv-01/     |                                                  |
|          | ehr-db-01)       |                                                  |
+----------+------------------+--------------------------------------------------+
| C2       | Medical IoT      | CRITICAL - Life-safety devices (monitors,       |
|          | (Monitors,       | pumps)                                           |
|          | Pumps, MRI)      |                                                  |
+----------+------------------+--------------------------------------------------+
| C3       | PACS/Imaging     | CRITICAL - Diagnostic images, MRI runs Windows   |
|          | System           | XP                                                |
|          | (pacs-srv-01,    |                                                  |
|          | MRI, CT)         |                                                  |
+----------+------------------+--------------------------------------------------+
| C4       | Active Directory | CRITICAL - Authentication backbone               |
|          | (ad-dc-01/02)    |                                                  |
+----------+------------------+--------------------------------------------------+
| C5       | Billing System   | HIGH - Financial data, revenue cycle             |
|          | (billing-srv-01) |                                                  |
+----------+------------------+--------------------------------------------------+
| C6       | Network Core     | CRITICAL - Connectivity, perimeter, VPN          |
|          | (FortiGate,      |                                                  |
|          | Core Switch)     |                                                  |
+----------+------------------+--------------------------------------------------+
| C7       | Backup &         | HIGH - Recovery capability                        |
|          | Recovery         |                                                  |
|          | (NAS-01,         |                                                  |
|          | backup-srv-01)   |                                                  |
+----------+------------------+--------------------------------------------------+


================================================================================
2. ATTACK VECTORS (ROWS)
================================================================================

+----------+--------------------------------------------------+
| Row      | Vector                                           |
+----------+--------------------------------------------------+
| V1       | Phishing / Spear Phishing                        |
+----------+--------------------------------------------------+
| V2       | VPN Exploit                                      |
+----------+--------------------------------------------------+
| V3       | Default / Shared Credentials                     |
+----------+--------------------------------------------------+
| V4       | Vulnerable Software Exploit (Apache, etc.)      |
+----------+--------------------------------------------------+
| V5       | Supply Chain Compromise (Vendor)                |
+----------+--------------------------------------------------+
| V6       | Insider (Malicious)                              |
+----------+--------------------------------------------------+
| V7       | Insider (Negligent)                              |
+----------+--------------------------------------------------+
| V8       | Physical Access                                  |
+----------+--------------------------------------------------+


================================================================================
3. VECTOR-TO-ASSET MATRIX
================================================================================

+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
|          | C1: EHR System   | C2: Medical IoT  | C3: PACS/Imaging | C4: Active       | C5: Billing      | C6: Network      | C7: Backup &     |
|          | (ehr-srv-01/     | (Monitors,       | System (pacs-    | Directory        | System           | Core             | Recovery (NAS)   |
|          | ehr-db-01)       | Pumps, MRI)      | srv-01, MRI)     | (ad-dc-01/02)    | (billing-srv-01) | (FortiGate,      |                  |
|          |                  |                  |                  |                  |                  | Core Switch)     |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V1:      | Phishing →       | Phishing →       | Phishing →       | Phishing →       | Phishing →       | Phishing →       | Phishing →       |
| Phishing | clinician        | clinician        | clinician        | IT admin         | finance staff    | IT admin         | IT admin         |
| / Spear  | credentials →    | credentials →    | credentials →    | credentials →    | credentials →    | credentials →    | credentials →    |
| Phishing | flat network →   | flat network →   | flat network →   | flat network →   | flat network →   | flat network →   | flat network →   |
|          | PostgreSQL 5432  | reach IoT        | PACS workstation | AD admin access  | MySQL 3306       | FortiGate admin  | NAS admin        |
|          | open →           | devices →        | → PACS data      | → Domain         | open →           | access →         | access →         |
|          | ehr-db-01        | manipulate       | exfiltration     | compromise       | billing data     | firewall         | backup           |
|          | patient data     | patient          |                  |                  | exfiltration     | reconfigure      | deletion         |
|          |                  | monitors/pumps   |                  |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V2:      | VPN exploit →    | VPN exploit →    | VPN exploit →    | VPN exploit →    | VPN exploit →    | VPN exploit →    | VPN exploit →    |
| VPN      | access to flat   | access to flat   | access to flat   | access to flat   | access to flat   | access to flat   | access to flat   |
| Exploit  | network →        | network →        | network →        | network →        | network →        | network →        | network →        |
|          | PostgreSQL 5432  | reach IoT        | PACS workstation | AD admin access  | MySQL 3306       | FortiGate admin  | NAS admin        |
|          | open →           | devices →        | → PACS data      | → Domain         | open →           | access →         | access →         |
|          | ehr-db-01        | manipulate       | exfiltration     | compromise       | billing data     | firewall         | backup           |
|          | patient data     | patient          |                  |                  | exfiltration     | reconfigure      | deletion         |
|                  |                  | monitors/pumps   |                  |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V3:      | Default PACS     | Default IoT      | Default PACS     | Default          | Default          | Default switch   | Default NAS      |
| Default  | credentials →    | credentials      | credentials →    | credentials      | credentials on   | credentials →    | credentials →    |
| / Shared | PACS workstation | (admin/admin) →  | PACS workstation | on PACS          | billing-srv-01   | switch           | NAS admin        |
| Creds    | → access to EHR  | infusion pump    | → PACS data      | workstation      | → MySQL 3306     | management       | access →         |
|          | via flat network | management →     | exfiltration     | → lateral        | open →           | → network        | backup           |
|          | → PostgreSQL     | alter medication |                  | movement to AD   | billing data     | reconfigure      | deletion         |
|          | 5432 open →      | dosages          |                  | → Domain         | exfiltration     |                  |                  |
|          | ehr-db-01        |                  |                  | compromise       |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V4:      | Apache RCE on    | Windows XP       | Windows XP       | Apache RCE on    | Apache 2.4.29    | Apache RCE on    | NAS firmware     |
| Vulner.  | billing-srv-01   | exploit on MRI   | exploit on MRI   | billing-srv-01   | RCE on billing-  | web-srv-01 →     | exploit →        |
| Software | → pivot to       | workstation →    | workstation →    | → pivot to AD    | srv-01 →         | pivot to Forti-  | NAS admin        |
| Exploit  | PostgreSQL 5432  | pivot to EHR     | PACS server →    | → Domain         | MySQL 3306       | Gate admin       | access →         |
|          | open →           | via flat network | PACS data        | compromise       | open →           | → firewall       | backup           |
|          | ehr-db-01        | → PostgreSQL     | exfiltration     |                  | billing data     | reconfigure      | deletion         |
|          | patient data     | 5432 open        |                  |                  | exfiltration     |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V5:      | MedTech vendor   | Siemens vendor   | Siemens vendor   | MedTech vendor   | MedTech vendor   | Fortinet         | Veeam vendor     |
| Supply   | credentials →    | credentials →    | credentials →    | credentials →    | credentials →    | support          | credentials →    |
| Chain    | direct access    | MRI workstation  | MRI workstation  | EHR server →     | billing-srv-01   | credentials →    | NAS admin        |
| Comprom. | to ehr-srv-01    | → Windows XP     | → PACS server    | pivot to AD      | → MySQL 3306     | FortiGate        | access →         |
|          | → ehr-db-01      | exploit →       | → PACS data      | → Domain         | open →           | admin access     | backup           |
|          | patient data     | pivot to EHR    | exfiltration     | compromise       | billing data     | → firewall       | deletion         |
|          |                  | via flat network |                  |                  | exfiltration     | reconfigure      |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V6:      | Malicious        | Malicious        | Malicious        | Malicious        | Malicious        | Malicious        | Malicious        |
| Insider  | employee with    | employee with    | employee with    | IT admin with    | finance employee | IT admin with    | IT admin with    |
| (Malic.) | EHR access →     | IoT access →     | PACS access →    | AD admin access  | billing access   | network admin    | backup admin     |
|          | exfiltrate       | alter patient    | exfiltrate       | → create         | → exfiltrate     | access →         | access →         |
|          | patient PHI      | monitor          | imaging data     | backdoor,        | billing data     | reconfigure      | delete backups   |
|          |                  | readings or      |                  | deploy           |                  | network,         | → no recovery    |
|          |                  | pump dosages     |                  | ransomware       |                  | install          |                  |
|          |                  |                  |                  |                  |                  | backdoor         |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V7:      | Negligent        | Negligent        | Negligent        | Negligent IT     | Negligent        | Negligent        | Negligent        |
| Insider  | employee leaves  | staff leave      | radiology        | admin stores     | staff leave      | staff leave      | admin leaves     |
| (Neglig.)| EHR session      | IoT session      | staff leave      | credentials in   | billing session  | network closet   | backup NAS       |
|          | unlocked →       | unlocked →       | PACS session     | plaintext →      | unlocked →       | unlocked →       | unplugged →      |
|          | passerby views   | passerby alters  | unlocked →       | attacker finds   | passerby views   | attacker gains   | backups not      |
|          | or modifies PHI  | patient data     | passerby views   | → AD compromise  | billing data     | network access   | taken            |
|          |                  |                  | imaging data     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+
| V8:      | Physical access  | Physical access  | Physical access  | Physical access  | Physical access  | Physical access  | Physical access  |
| Physical | to server room   | to patient room  | to radiology     | to server room   | to server room   | to network       | to server room   |
| Access   | → server theft   | → device         | department →     | → AD server      | → billing        | closet →         | → NAS theft      |
|          | or hardware      | manipulation     | PACS server      | theft or         | server theft     | switch           | or destruction   |
|          | keylogger        | (disconnect,     | theft or         | hardware         | or hardware      | manipulation     | → no recovery    |
|          | installation     | alter settings)  | hardware         | keylogger        | keylogger        | (disconnect,     |                  |
|          | → complete       | → patient        | keylogger        | installation     | installation     | tap into         |                  |
|          | data compromise  | safety risk      | installation     | → complete       | → billing data   | network) →       |                  |
|          |                  |                  | → imaging data   | system           | compromise       | complete         |                  |
|          |                  |                  | compromise       | compromise       |                  | network          |                  |
|          |                  |                  |                  |                  |                  | compromise       |                  |
+----------+------------------+------------------+------------------+------------------+------------------+------------------+------------------+


================================================================================
4. CELL COUNT SUMMARY
================================================================================

+----------+------------------------------------------+------------------+
| Row      | Vector                                   | Cells Filled     |
+----------+------------------------------------------+------------------+
| V1       | Phishing / Spear Phishing                | 7 of 7           |
+----------+------------------------------------------+------------------+
| V2       | VPN Exploit                              | 7 of 7           |
+----------+------------------------------------------+------------------+
| V3       | Default / Shared Credentials             | 7 of 7           |
+----------+------------------------------------------+------------------+
| V4       | Vulnerable Software Exploit              | 7 of 7           |
+----------+------------------------------------------+------------------+
| V5       | Supply Chain Compromise                  | 7 of 7           |
+----------+------------------------------------------+------------------+
| V6       | Insider (Malicious)                      | 7 of 7           |
+----------+------------------------------------------+------------------+
| V7       | Insider (Negligent)                      | 7 of 7           |
+----------+------------------------------------------+------------------+
| V8       | Physical Access                          | 7 of 7           |
+----------+------------------------------------------+------------------+

+------------------+------------------------------------------+------------------+
| Column           | Asset                                    | Cells Filled     |
+------------------+------------------------------------------+------------------+
| C1               | EHR System                               | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C2               | Medical IoT                              | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C3               | PACS/Imaging System                      | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C4               | Active Directory                         | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C5               | Billing System                           | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C6               | Network Core                             | 8 of 8           |
+------------------+------------------------------------------+------------------+
| C7               | Backup & Recovery                        | 8 of 8           |
+------------------+------------------------------------------+------------------+

TOTAL CELLS FILLED: 56 of 56 (100%)


================================================================================
5. MOST CONNECTED ASSETS (REACHABLE BY MOST VECTORS)
================================================================================

+----------+------------------+------------------+------------------------------------------+
| Rank     | Asset            | Vectors Reaching | Justification                            |
+----------+------------------+------------------+------------------------------------------+
| #1       | EHR System       | 8 of 8 (100%)    | The EHR is reachable by EVERY vector.   |
|          |                  |                  | Phishing, VPN, default creds, software   |
|          |                  |                  | exploits, supply chain, insider,         |
|          |                  |                  | physical - ALL paths lead to the EHR.   |
|          |                  |                  | This is the organization's most          |
|          |                  |                  | exposed and most valuable asset.         |
+----------+------------------+------------------+------------------------------------------+
| #2       | Active Directory | 8 of 8 (100%)    | AD is reachable by EVERY vector. The    |
|          |                  |                  | "keys to the kingdom" can be obtained   |
|          |                  |                  | through any attack path. This is why    |
|          |                  |                  | AD is a CRITICAL asset.                  |
+----------+------------------+------------------+------------------------------------------+
| #3       | Backup &         | 8 of 8 (100%)    | Backups are reachable by EVERY vector.  |
|          | Recovery (NAS)   |                  | Attackers consistently target backups   |
|          |                  |                  | first (BlackReef playbook). The          |
|          |                  |                  | co-located NAS is vulnerable to          |
|          |                  |                  | physical access, network access, and    |
|          |                  |                  | insider threats.                         |
+----------+------------------+------------------+------------------------------------------+


================================================================================
6. MOST VERSATILE VECTORS (REACH MOST ASSETS)
================================================================================

+----------+------------------+------------------+------------------------------------------+
| Rank     | Vector           | Assets Reached  | Justification                            |
+----------+------------------+------------------+------------------------------------------+
| #1       | Phishing /       | 7 of 7 (100%)    | Phishing reaches EVERY asset. A single   |
|          | Spear Phishing   |                  | successful email can lead to EHR, AD,    |
|          |                  |                  | billing, IoT, backups, and network core. |
|          |                  |                  | This is the most versatile vector        |
|          |                  |                  | because it targets the HUMAN surface.   |
+----------+------------------+------------------+------------------------------------------+
| #2       | Insider          | 7 of 7 (100%)    | Malicious insiders can reach EVERY       |
|          | (Malicious)      |                  | asset because they already have          |
|          |                  |                  | legitimate access. An IT admin can       |
|          |                  |                  | access AD, EHR, backups, and network     |
|          |                  |                  | core. A clinician can access EHR and     |
|          |                  |                  | IoT.                                     |
+----------+------------------+------------------+------------------------------------------+
| #3       | VPN Exploit      | 7 of 7 (100%)    | VPN exploit reaches EVERY asset. Once   |
|          |                  |                  | inside the flat network, ANY asset is   |
|          |                  |                  | reachable. This is the most dangerous    |
|          |                  |                  | external vector because it bypasses     |
|          |                  |                  | the perimeter entirely.                  |
+----------+------------------+------------------+------------------------------------------+


================================================================================
7. HIGHEST-PRIORITY INTERSECTIONS
================================================================================

+----------+------------------------------------------+------------------------------------------+
| Priority | Intersection                             | Justification                            |
+----------+------------------------------------------+------------------------------------------+
| #1       | Phishing → EHR System                    | Phishing is the #1 most versatile        |
|          |                                          | vector. EHR is the #1 most connected    |
|          |                                          | asset. This intersection represents the  |
|          |                                          | highest probability + highest impact    |
|          |                                          | combination. MedDefense has NO MFA      |
|          |                                          | (GAP-004) and NO SIEM (GAP-001).        |
+----------+------------------------------------------+------------------------------------------+
| #2       | VPN Exploit → Active Directory           | VPN exploit provides direct network      |
|          |                                          | access. Active Directory is the "keys   |
|          |                                          | to the kingdom." The 280-bed regional   |
|          |                                          | hospital case (File 4) started exactly  |
|          |                                          | this way. MedDefense has unpatched VPN  |
|          |                                          | (GAP-014) and NO MFA (GAP-004).         |
+----------+------------------------------------------+------------------------------------------+
| #3       | Default Credentials → Medical IoT        | Default credentials on IoT devices       |
|          |                                          | (GAP-007) provide direct access to      |
|          |                                          | life-safety equipment. Breach 3 (Task   |
|          |                                          | 13) was exactly this scenario. This     |
|          |                                          | intersection represents the highest     |
|          |                                          | patient safety risk.                    |
+----------+------------------------------------------+------------------------------------------+


================================================================================
8. KEY FINDINGS
================================================================================

1. 100% of cells are filled (56 of 56). EVERY vector can reach EVERY asset.
   This is the consequence of the FLAT NETWORK (GAP-003) and NO
   SEGMENTATION. There are no internal barriers to stop any attack path.

2. The EHR System and Active Directory are reachable by ALL 8 vectors.
   They are the most exposed and most critical assets. The EHR contains
   PHI for 50,000 patients. AD provides control over ALL systems.

3. Phishing / Spear Phishing is the MOST VERSATILE vector (reaches 100%
   of assets). This is because it targets the human surface (GAP-013)
   and credentials are reused across systems (GAP-004).

4. The FLAT NETWORK is the PRIMARY ENABLER of all attack paths.
   Without segmentation, EVERY vector reaches EVERY asset.

5. The 3 highest-priority intersections are:
   - Phishing → EHR (highest probability + highest impact)
   - VPN Exploit → AD (most critical external vector → most critical asset)
   - Default Credentials → Medical IoT (highest patient safety risk)

6. The matrix demonstrates that MedDefense's architecture is fundamentally
   brittle. A single successful attack can reach any asset in the
   organization.


================================================================================
9. REFERENCES
================================================================================

- NIST SP 800-30: Attack path analysis
- MITRE ATT&CK: Tactics and techniques
- Security+ 2.2: Attack vectors
- CIS Controls v8: Control 1, 7, 12

Cross-References to Project 1x00:
- Criticality Assessment (Task 8): Top 5 Critical Assets
- Asset Registry (Task 7): Medical IoT, Active Directory
- Gap Analysis (Task 12): All Gap IDs
- Attack Surface Map (Task 7): External, Internal, Human
- Technical Vectors (Task 8): All technical vectors
- Social Engineering Analysis (Task 4): Human vectors


================================================================================
END OF VECTOR-TO-ASSET MATRIX
================================================================================
