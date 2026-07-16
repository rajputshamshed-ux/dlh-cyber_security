================================================================================
                    THREAT LANDSCAPE REPORT
                    MEDDEFENSE HEALTH SYSTEMS
================================================================================

Document Title:  Threat Landscape Report - MedDefense Health Systems
Prepared For:    Board of Directors, MedDefense Health Systems
Prepared By:     shamshed rajput, Junior Security Analyst
Approved By:     James Chen, Deputy CISO
Date:            16/07/2026
Classification:  CONFIDENTIAL - Internal Use Only

Companion Document: Security Posture Assessment (Project 0x00)


================================================================================
1. EXECUTIVE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
|                                                                             |
| THE THREAT LANDSCAPE:                                                      |
| MedDefense operates in a sector that is the #1 target for ransomware in   |
| the United States. Healthcare organizations are targeted because of       |
| clinical urgency (hospitals pay ransoms to avoid patient harm), high-     |
| value data (patient records sell for $250-$1,000 on dark web markets),   |
| and legacy systems (unpatchable medical devices provide permanent entry  |
| points). Three regional hospitals within 200 miles have been hit by      |
| ransomware in the past 8 months.                                          |
|                                                                             |
| THE SINGLE MOST DANGEROUS THREAT:                                          |
| Ransomware through unpatched perimeter devices. MedDefense's VPN has no   |
| patch management program and no multi-factor authentication. An attacker  |
| exploiting a known VPN vulnerability would gain access to the flat        |
| network, move to the Domain Controller, and deploy ransomware to ALL      |
| systems via Group Policy. The 280-bed hospital case study (File 4) is    |
| virtually identical to MedDefense - 11-day EHR downtime, $5M recovery    |
| costs, ambulance diversions, and CEO resignation.                         |
|                                                                             |
| TOP 3 RECOMMENDATIONS:                                                    |
| 1. IMMEDIATELY segment medical IoT devices on an isolated VLAN            |
|    ($22,000, 1 week) - addresses patient safety risk                     |
| 2. IMPLEMENT multi-factor authentication for all remote access and        |
|    critical systems ($8,000-$10,000, 1 month) - prevents credential theft |
| 3. DEPLOY a SIEM (Wazuh open-source) for detection capability            |
|    ($5,000, 1 month) - stops blind operations                            |
|                                                                             |
| BUDGET IMPLICATION:                                                       |
| The top 7 priorities can be addressed within the $120,000 annual budget  |
| ($42,000 allocated to immediate actions).                                |
|                                                                             |
| WITHOUT INVESTMENT:                                                       |
| MedDefense faces a CRITICAL likelihood of a ransomware attack within the  |
| next 12 months - based on sector statistics, regional incidents, and     |
| the gaps identified in the Security Posture Assessment.                   |
+----------------------------------------------------------------------------+


================================================================================
2. SCOPE AND METHODOLOGY
================================================================================

2.1 INTELLIGENCE SOURCES
------------------------
+----------------------------------------------------------------------------+
| INTELLIGENCE SOURCES REVIEWED:                                             |
|                                                                             |
| 1. CISA Advisory AA24-131A: "Ransomware Trends Targeting Healthcare"      |
|    - Sector-wide ransomware statistics and trends                         |
|                                                                             |
| 2. HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare"       |
|    - Actor profiles and motivations specific to healthcare               |
|                                                                             |
| 3. HHS Breach Portal Statistics (Marcus's Excel summary)                  |
|    - 24 months of healthcare breach data                                  |
|                                                                             |
| 4. Ransomware Incident Case Summary - 280-bed regional hospital           |
|    - Real-world attack sequence virtually identical to MedDefense       |
|                                                                             |
| 5. Article - "The Economics of Healthcare Ransomware"                    |
|    - Financial motivations and attack economics                          |
|                                                                             |
| 6. BlackReef Ransomware Profile                                           |
|    - RaaS operational model and TTPs                                     |
|                                                                             |
| 7. Marcus Webb's Threat Intelligence Collection                           |
|    - Annotated intelligence files from predecessor                       |
+----------------------------------------------------------------------------+

2.2 ANALYTICAL FRAMEWORKS
-------------------------
+----------------------------------------------------------------------------+
| FRAMEWORKS APPLIED:                                                       |
|                                                                             |
| 1. MITRE ATT&CK Enterprise Framework                                      |
|    - Used to map attack steps to tactics and techniques                  |
|                                                                             |
| 2. STRIDE Threat Modeling                                                 |
|    - Applied to EHR system (12 threats, 6 categories)                    |
|    - Applied to PACS, AD, and Network Infrastructure (surface analysis)  |
|                                                                             |
| 3. Kill Chain Analysis                                                    |
|    - 5 complete attack chains from initial access to impact              |
|                                                                             |
| 4. NIST SP 800-30 Risk Assessment                                         |
|    - Threat, vulnerability, likelihood, impact decomposition             |
|                                                                             |
| 5. Security+ 2.1 Threat Actor Framework                                   |
|    - Six actor categories with attributes and motivations                |
|                                                                             |
| 6. CIS Controls v8                                                        |
|    - Control mapping and gap identification                              |
+----------------------------------------------------------------------------+

2.3 CONNECTION TO SECURITY POSTURE ASSESSMENT
---------------------------------------------
+----------------------------------------------------------------------------+
| This report is the COMPANION DOCUMENT to the Security Posture Assessment  |
| (Project 0x00). The Posture Assessment identified what MedDefense has,    |
| what protects it, and where the gaps are. This Threat Landscape Report   |
| identifies WHO would exploit those gaps, HOW, and WHY.                   |
|                                                                             |
| Together, they form the complete picture: internal vulnerabilities and   |
| external threats. Every threat referenced in this report is connected    |
| to a specific gap from the Posture Assessment.                           |
|                                                                             |
| KEY CONNECTIONS:                                                          |
| - GAP-003 (Flat Network) enables lateral movement in ALL kill chains    |
| - GAP-004 (No MFA) enables credential theft in ALL kill chains          |
| - GAP-001 (No SIEM) enables undetected operation in ALL kill chains     |
| - GAP-014 (No Patch Management) enables VPN exploitation in #1 threat   |
| - GAP-007 (MRI Windows XP) enables life-safety compromise               |
+----------------------------------------------------------------------------+


================================================================================
3. HEALTHCARE SECTOR THREAT OVERVIEW
================================================================================

3.1 WHY HEALTHCARE IS TARGETED
------------------------------
+----------------------------------------------------------------------------+
| Healthcare is the MOST TARGETED critical infrastructure sector for       |
| ransomware, accounting for 25% of all reported incidents across 16       |
| sectors (CISA Advisory AA24-131A). The reasons:                          |
|                                                                             |
| 1. CLINICAL URGENCY: "When a manufacturing plant goes down, it loses     |
|    money. When a hospital goes down, patients may die." Healthcare       |
|    organizations pay ransoms at a higher rate than any other sector      |
|    (60% vs 46% cross-industry average).                                  |
|                                                                             |
| 2. PATIENT DATA VALUE: Patient records sell for $250-$1,000 on dark web  |
|    markets (vs $5-$50 for credit cards). They contain everything needed  |
|    for identity theft AND insurance fraud: name, date of birth, SSN,     |
|    insurance policy number, medical history.                             |
|                                                                             |
| 3. LEGACY SYSTEMS: Healthcare consistently runs older, unpatched         |
|    systems. Medical devices on legacy OS (Windows XP), servers running   |
|    EOL software, flat networks without segmentation. Initial access is   |
|    easier than in financial or technology sectors.                      |
|                                                                             |
| 4. INSURANCE COVERAGE: Most mid-size hospitals carry cyber insurance.   |
|    Attackers know this. Insurance companies often recommend payment if   |
|    recovery cost exceeds ransom amount.                                 |
|                                                                             |
| 5. REGULATORY PRESSURE: HIPAA breach notification requirements create    |
|    additional pressure to pay beyond operational urgency.               |
+----------------------------------------------------------------------------+

3.2 CURRENT TRENDS
------------------
+----------------------------------------------------------------------------+
| KEY TRENDS IN HEALTHCARE CYBERSECURITY:                                   |
|                                                                             |
| 1. RANSOMWARE ATTACKS ARE INCREASING:                                     |
|    Healthcare was the most-targeted critical infrastructure sector for   |
|    ransomware in 2023 and 2024 (25% of all incidents).                   |
|                                                                             |
| 2. DOUBLE EXTORTION IS THE STANDARD:                                      |
|    In 73% of healthcare ransomware incidents, threat actors exfiltrated  |
|    data before deploying encryption.                                     |
|                                                                             |
| 3. RANSOMWARE-AS-A-SERVICE HAS INDUSTRIALIZED ATTACKS:                   |
|    Developers build tools, Initial Access Brokers sell entry points      |
|    ($500-$10,000), affiliates deploy ransomware. It is a professional    |
|    supply chain.                                                         |
|                                                                             |
| 4. AVERAGE RANSOM DEMAND IS DOUBLING:                                     |
|    Between 2022 and 2024, average ransom demand for healthcare doubled   |
|    from $1.2M to $2.5M. Recovery costs average $2.7M.                   |
|                                                                             |
| 5. AI IS LOWERING THE SKILL FLOOR:                                        |
|    Automated exploit chains and AI-written phishing emails make          |
|    previously sophisticated attacks accessible to low-skill actors.     |
+----------------------------------------------------------------------------+

3.3 SECTOR STATISTICS
---------------------
+----------------------------------------------------------------------------+
| KEY STATISTICS:                                                            |
|                                                                             |
| - 25% of all ransomware incidents target healthcare (CISA Advisory)       |
| - 89% of healthcare organizations experienced a cyberattack in 12 months  |
|   (Ponemon Institute)                                                      |
| - 93% of healthcare organizations experienced a data breach in 3 years   |
|   (HHS Report)                                                             |
| - 35% of healthcare breaches involve insiders (Verizon DBIR)              |
| - 43% of breaches involve network servers; 27% involve email              |
|   (HHS Breach Portal)                                                     |
| - Average ransomware downtime for hospitals: 18 days (CISA Advisory)      |
| - Average total cost (recovery + lost revenue + regulatory): $2.7M       |
|   (CISA Advisory)                                                         |
| - Healthcare organizations pay ransoms at 60% vs 46% cross-industry      |
|   average (Industry Report)                                               |
| - The most common initial access vectors:                                 |
|   - Exploitation of public-facing applications (VPN, web portals): 38%   |
|   - Phishing with malicious attachments or links: 31%                    |
|   - Valid credentials (purchased or harvested): 22%                      |
|   - External remote services (RDP): 9%                                   |
+----------------------------------------------------------------------------+


================================================================================
4. MEDDEFENSE THREAT ACTOR PROFILES
================================================================================

4.1 ACTOR PROFILES SUMMARY
--------------------------
+----------+------------------+-----------------+------------------+------------------+
| Rank     | Actor Type       | Likelihood      | Primary          | Primary Target   |
|          |                  |                 | Motivation       |                  |
+----------+------------------+-----------------+------------------+------------------+
| #1       | Ransomware       | CRITICAL        | Financial Gain   | EHR, AD, Backup  |
|          | Groups (RaaS)    |                 |                  |                  |
+----------+------------------+-----------------+------------------+------------------+
| #2       | Insider          | HIGH            | Negligence       | ALL Data         |
|          | (Negligent)      |                 |                  |                  |
+----------+------------------+-----------------+------------------+------------------+
| #3       | Unskilled /      | HIGH            | Opportunistic    | Any Vulnerable   |
|          | Opportunistic    |                 | Financial Gain   | System           |
+----------+------------------+-----------------+------------------+------------------+
| #4       | Insider          | MEDIUM          | Financial Gain,  | EHR, PII         |
|          | (Malicious)      |                 | Revenge          |                  |
+----------+------------------+-----------------+------------------+------------------+
| #5       | Hacktivist       | LOW             | Political /      | Website, Portal  |
|          |                  |                 | Ideological      |                  |
+----------+------------------+-----------------+------------------+------------------+
| #6       | Nation-State     | LOW             | Espionage        | Research Data    |
|          | APT              |                 |                  | (if any)         |
+----------+------------------+-----------------+------------------+------------------+

4.2 TOP 3 ACTOR PROFILES
------------------------

RANK 1: RANSOMWARE GROUPS (ORGANIZED CRIME)
+------------------+--------------------------------------------------+
| Actor Type       | Ransomware Groups / Ransomware-as-a-Service      |
+------------------+--------------------------------------------------+
| Likelihood       | CRITICAL - 25% of all ransomware incidents       |
|                  | target healthcare. Three regional hospitals      |
|                  | within 200 miles hit in 8 months. MedDefense    |
|                  | matches the target profile exactly.             |
+------------------+--------------------------------------------------+
| Capability       | HIGH - RaaS model: developers, affiliates, IABs, |
|                  | negotiators. Professional supply chain. Access   |
|                  | purchased for $500-$10,000. Custom and          |
|                  | commercial tools. Double extortion capability.  |
+------------------+--------------------------------------------------+
| Motivation       | FINANCIAL GAIN - Ransom payments ($1M-$3M per   |
|                  | hospital). Patient data sold for $250-$1,000 per |
|                  | record.                                          |
+------------------+--------------------------------------------------+
| Preferred        | VPN/Perimeter Exploit (38% of healthcare        |
| Vector           | ransomware incidents) OR Phishing (31%).        |
|                  | Alternative: Purchased access from IABs.        |
+------------------+--------------------------------------------------+
| Primary Target   | EHR System (#1 CRITICAL), Active Directory (#4  |
|                  | CRITICAL), Billing, Backups                      |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-014 (No Patch Management), GAP-003 (Flat    |
| Exposure         | Network), GAP-004 (No MFA), GAP-001 (No SIEM)   |
+------------------+--------------------------------------------------+

RANK 2: INSIDER THREAT (NEGLIGENT)
+------------------+--------------------------------------------------+
| Actor Type       | Insider Threat (Negligent)                       |
+------------------+--------------------------------------------------+
| Likelihood       | HIGH - 35% of healthcare breaches involve        |
|                  | insiders. Conditions at MedDefense: shared      |
|                  | accounts, no automated offboarding, low         |
|                  | training completion, shadow IT.                 |
+------------------+--------------------------------------------------+
| Capability       | LOW - No technical sophistication. Caused by     |
|                  | carelessness, shortcuts, or lack of training.   |
+------------------+--------------------------------------------------+
| Motivation       | NEGLIGENCE / CONVENIENCE - Employees taking      |
|                  | shortcuts, bypassing controls, or unaware of    |
|                  | security implications.                           |
+------------------+--------------------------------------------------+
| Preferred        | Shadow IT, credential sharing, unlocked          |
| Vector           | sessions, misplaced data, weak passwords.       |
+------------------+--------------------------------------------------+
| Primary Target   | All data categories: PHI, PII, Financial,       |
|                  | Research                                         |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-009 (Shadow IT), GAP-010 (No Audits),       |
| Exposure         | GAP-011 (No Enforcement), GAP-007 (Shared       |
|                  | Accounts), GAP-013 (Low Training)               |
+------------------+--------------------------------------------------+

RANK 3: UNSKILLED / OPPORTUNISTIC
+------------------+--------------------------------------------------+
| Actor Type       | Unskilled / Opportunistic Attacker               |
+------------------+--------------------------------------------------+
| Likelihood       | HIGH - MedDefense is already being hit:          |
|                  | crypto-miner on billing-srv-01 proves scanning   |
|                  | is occurring. Unpatched public-facing services  |
|                  | are found by automated scanners.                 |
+------------------+--------------------------------------------------+
| Capability       | LOW - Automated tools, public exploits, AI-     |
|                  | assisted attacks. No targeting - they scan for  |
|                  | vulnerabilities across the internet.            |
+------------------+--------------------------------------------------+
| Motivation       | OPPORTUNISTIC FINANCIAL GAIN - Cryptocurrency    |
|                  | mining, selling access, low-effort exploitation. |
+------------------+--------------------------------------------------+
| Preferred        | Automated scanning for known vulnerabilities    |
| Vector           | (Apache, outdated services, default credentials).|
+------------------+--------------------------------------------------+
| Primary Target   | Any vulnerable system they find (billing-srv-01 |
|                  | is proof).                                       |
+------------------+--------------------------------------------------+
| MedDefense       | GAP-014 (No Patch Management), GAP-001 (No      |
| Exposure         | SIEM), GAP-016 (No Web App Security Testing)    |
+------------------+--------------------------------------------------+


================================================================================
5. ATTACK SURFACE ANALYSIS
================================================================================

5.1 EXTERNAL SURFACE (ACCESSIBLE FROM INTERNET)
-----------------------------------------------
+----------+------------------+------------------------------------------+------------------+
| Entry    | Asset            | Protection Exists                        | Key Gap          |
| Point    |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Patient  | web-srv-01       | C-001 Firewall Perimeter, C-009 Backups  | GAP-016 (No Web  |
| Portal   |                  |                                          | App Testing)     |
+----------+------------------+------------------------------------------+------------------+
| VPN      | FortiGate 100F   | C-001 Firewall Perimeter, C-003 VPN      | GAP-014 (No      |
| Endpoint |                  | Access                                   | Patch Mgt)       |
+----------+------------------+------------------------------------------+------------------+
| O365     | Microsoft O365   | C-006 Password Policy, C-013 Training    | GAP-013 (No      |
|          |                  |                                          | Email Security)  |
+----------+------------------+------------------------------------------+------------------+
| DNS      | meddefense.com   | Limited - DNS hosting provider security  | GAP-010 (No      |
|          |                  |                                          | Audits)          |
+----------+------------------+------------------------------------------+------------------+

5.2 INTERNAL SURFACE (ONCE INSIDE THE NETWORK)
----------------------------------------------
+----------+------------------+------------------------------------------+------------------+
| Entry    | Asset            | Exposure                                 | Key Gap          |
| Point    |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| PostgreSQL| ehr-db-01        | Port 5432 accessible from entire /16    | GAP-003 (Flat    |
|          |                  |                                          | Network)         |
+----------+------------------+------------------------------------------+------------------+
| MySQL    | billing-srv-01   | Port 3306 accessible from entire /16    | GAP-003 (Flat    |
|          |                  |                                          | Network)         |
+----------+------------------+------------------------------------------+------------------+
| Legacy   | MRI (Windows XP) | EOL 2014, known exploits (EternalBlue)  | GAP-007 (No      |
| Systems  |                  |                                          | Compensating)    |
+----------+------------------+------------------------------------------+------------------+
| IoT      | Monitors, Pumps  | Accessible from entire /16              | GAP-003 (Flat    |
|          |                  |                                          | Network)         |
+----------+------------------+------------------------------------------+------------------+
| Shadow   | Dr. Patel's NAS  | Unmanaged, default credentials          | GAP-009 (Shadow  |
| IT       | Raspberry Pi     |                                          | IT)              |
+----------+------------------+------------------------------------------+------------------+

5.3 HUMAN SURFACE (PEOPLE TARGETED)
-----------------------------------
+----------+------------------+------------------------------------------+------------------+
| Role     | Access Level     | Social Engineering                       | Key Gap          |
|          |                  | Vulnerability                            |                  |
+----------+------------------+------------------------------------------+------------------+
| Clinical | EHR, PACS, IoT   | Vishing, Phishing, Tailgating            | GAP-013 (Low     |
| Staff    |                  |                                          | Training)        |
+----------+------------------+------------------------------------------+------------------+
| IT Staff | ALL Systems      | Vishing (vendor impersonation), Phishing | GAP-004 (No MFA) |
+----------+------------------+------------------------------------------+------------------+
| Execs    | Financial,       | BEC (Business Email Compromise)          | GAP-004 (No MFA) |
|          | Strategic        |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Contracts| EHR (MedTech),   | Vendor impersonation, Supply Chain      | GAP-012 (No      |
| ors      | MRI (Siemens)    |                                          | Vendor Mgt)      |
+----------+------------------+------------------------------------------+------------------+


================================================================================
6. CRITICAL ATTACK PATHS (KILL CHAINS)
================================================================================

6.1 THE 5 KILL CHAINS
---------------------
+----------+------------------+------------------------------------------+------------------+
| Kill     | Title            | Target Asset(s)                          | Break Points     |
| Chain    |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| #1       | Ransomware via   | EHR + AD + Billing + Backup              | Patch Mgt, MFA,  |
|          | Unpatched VPN    |                                          | Segmentation,    |
|          |                  |                                          | SIEM, IR Plan    |
+----------+------------------+------------------------------------------+------------------+
| #2       | Phishing → EHR   | EHR (Patient Data)                       | MFA, SIEM,       |
|          | Data Exfil       |                                          | Segmentation,    |
|          |                  |                                          | Training,        |
|          |                  |                                          | Egress Filtering |
+----------+------------------+------------------------------------------+------------------+
| #3       | Default Creds →  | Medical IoT (Monitors, Pumps)            | Change Defaults, |
|          | IoT Patient      |                                          | Segmentation,    |
|          | Safety           |                                          | SIEM             |
+----------+------------------+------------------------------------------+------------------+
| #4       | Windows XP MRI   | MRI → EHR                                | Compensating     |
|          | → EHR            |                                          | Controls, MFA,   |
|          |                  |                                          | Segmentation,    |
|          |                  |                                          | SIEM             |
+----------+------------------+------------------------------------------+------------------+
| #5       | Supply Chain     | EHR + AD                                 | Vendor Mgt, MFA, |
|          | (MedTech) →      |                                          | Segmentation,    |
|          | EHR + AD         |                                          | SIEM, IR Plan    |
+----------+------------------+------------------------------------------+------------------+

6.2 THE CRITICAL THREE (MOST CONNECTED ASSETS)
----------------------------------------------
+----------+------------------+------------------+------------------------------------------+
| Rank     | Asset            | Vectors Reaching | Why                                      |
+----------+------------------+------------------+------------------------------------------+
| #1       | EHR System       | 8 of 8           | Reachable by EVERY vector. Contains PHI  |
|          |                  |                  | for 50,000+ patients.                    |
+----------+------------------+------------------+------------------------------------------+
| #2       | Active Directory | 8 of 8           | "Keys to the kingdom." Reachable by     |
|          |                  |                  | EVERY vector.                            |
+----------+------------------+------------------+------------------------------------------+
| #3       | Backup &         | 8 of 8           | Reachable by EVERY vector. Attackers     |
|          | Recovery (NAS)   |                  | target backups first (BlackReef playbook)|
+----------+------------------+------------------+------------------------------------------+

6.3 THE MOST VERSATILE VECTORS
------------------------------
+----------+------------------+------------------+------------------------------------------+
| Rank     | Vector           | Assets Reached  | Why                                      |
+----------+------------------+------------------+------------------------------------------+
| #1       | Phishing         | 7 of 7           | Targets the HUMAN surface. Single email  |
|          |                  |                  | can lead to ANY asset.                   |
+----------+------------------+------------------+------------------------------------------+
| #2       | Insider          | 7 of 7           | Already has legitimate access to         |
|          | (Malicious)      |                  | multiple systems.                        |
+----------+------------------+------------------+------------------------------------------+
| #3       | VPN Exploit      | 7 of 7           | Bypasses perimeter entirely. Once inside,|
|          |                  |                  | ANY asset is reachable.                  |
+----------+------------------+------------------+------------------------------------------+


================================================================================
7. STRIDE ANALYSIS SUMMARY
================================================================================

7.1 EHR SYSTEM (12 THREATS IDENTIFIED)
--------------------------------------
+----------+------------------+------------------------------------------+------------------+
| STRIDE   | Top Threat       | Impact                                   | Severity         |
| Category |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| S        | Phished physician | Unauthorized access to patient records   | HIGH             |
| SPOOFING | credentials      |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| T        | PostgreSQL       | Direct modification of patient data     | CRITICAL         |
| TAMPERING| database         | without audit trail                      |                  |
+----------+------------------+------------------------------------------+------------------+
| R        | Shared account   | No accountability for medical decisions  | MEDIUM           |
| REPUDIA- | prevents         |                                          |                  |
| TION     | accountability   |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| I        | PostgreSQL       | 50,000+ patient records exposed          | CRITICAL         |
| INFO     | exfiltration     |                                          |                  |
| DISCLOS. |                  |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| D        | Ransomware       | 11+ days EHR downtime, patient safety   | CRITICAL         |
| DOS      | encrypts EHR     | risk                                       |                  |
+----------+------------------+------------------------------------------+------------------+
| E        | Domain Admin     | Complete control over EHR system        | CRITICAL         |
| EOP      | access to EHR    |                                          |                  |
+----------+------------------+------------------------------------------+------------------+

7.2 PACS, AD, NETWORK SURFACE ANALYSIS
--------------------------------------
+----------+------------------+------------------------------------------+------------------+
| System   | Top Threat       | Severity                                 | Primary Gap      |
+----------+------------------+------------------------------------------+------------------+
| PACS /   | Information      | CRITICAL                                 | GAP-003, GAP-007 |
| Imaging  | Disclosure +     |                                          | Artifact 5 (No   |
|          | Denial of        |                                          | backup)          |
|          | Service          |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Active   | Elevation of     | CRITICAL                                 | GAP-004, GAP-001 |
| Directory| Privilege        |                                          |                  |
+----------+------------------+------------------------------------------+------------------+
| Network  | Information      | CRITICAL                                 | GAP-003, GAP-008 |
| Infra.   | Disclosure       |                                          |                  |
+----------+------------------+------------------------------------------+------------------+


================================================================================
8. THREAT SCENARIOS
================================================================================

8.1 SCENARIO SUMMARY
--------------------
+----------+------------------+------------------+------------------+------------------------------------------+
| Scenario | Actor            | Primary Vector   | Primary Target   | Business Impact                          |
+----------+------------------+------------------+------------------+------------------------------------------+
| S1       | RaaS Group       | VPN Exploit      | EHR + AD         | 11-day EHR downtime, $5M+ recovery      |
| External | (BlackReef)      |                  |                  | costs, ambulance diversions, CEO        |
|          |                  |                  |                  | resignation                              |
+----------+------------------+------------------+------------------+------------------------------------------+
| S2       | Malicious        | Legitimate       | EHR (PHI)        | $890K breach response costs, class      |
| Internal | Insider          | Access Abuse     |                  | action lawsuit, HIPAA fines             |
+----------+------------------+------------------+------------------+------------------------------------------+
| S3       | Supply Chain     | MedTech Vendor   | EHR + AD         | Direct vendor access bypasses ALL       |
| Third    | Attacker         | Compromise       |                  | perimeter controls, $2.5M+ ransom       |
| Party    |                  |                  |                  |                                          |
+----------+------------------+------------------+------------------+------------------------------------------+

8.2 BUSINESS IMPACT ASSESSMENT
------------------------------
+----------------------------------------------------------------------------+
| SCENARIO 1 (Ransomware):                                                    |
| Clinical: 11+ days EHR downtime, ambulance diversions, cancelled procedures |
| Financial: $2.5M+ ransom, $3.2M recovery, $1.8M lost revenue              |
| Regulatory: HHS investigation, HIPAA breach notification (50k+ patients)  |
| Reputational: CEO resignation, loss of patient trust, class action suits  |
+----------------------------------------------------------------------------+
| SCENARIO 2 (Insider):                                                       |
| Clinical: Patient identity theft risk, fraudulent medical bills           |
| Financial: $890K breach response, class action lawsuit, HIPAA fines       |
| Regulatory: HHS investigation, mandatory breach notification             |
| Reputational: Loss of patient trust, negative media coverage              |
+----------------------------------------------------------------------------+
| SCENARIO 3 (Supply Chain):                                                 |
| Clinical: 11+ days EHR downtime, patient safety risk                     |
| Financial: $2.5M+ ransom, $3M+ recovery, loss of vendor contract ($145K)  |
| Regulatory: HHS investigation, HIPAA breach notification (50k+ patients)  |
| Reputational: Loss of trust in vendors, damage to vendor relationships   |
+----------------------------------------------------------------------------+


================================================================================
9. GAP-THREAT CORRELATION
================================================================================

9.1 RE-PRIORITIZED GAP LIST (THREAT-INFORMED)
----------------------------------------------
+----------+------------------+----------------------------------------+------------------------------------------+
| New      | Gap ID           | Gap Title                              | Updated Risk Level                       |
| Rank     |                  |                                        |                                          |
+----------+------------------+----------------------------------------+------------------------------------------+
| #1       | GAP-001          | No SIEM or Log Monitoring              | CRITICAL (UPGRADED)                      |
+----------+------------------+----------------------------------------+------------------------------------------+
| #2       | GAP-003          | Medical IoT on Flat Network            | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #3       | GAP-004          | No MFA Anywhere                        | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #4       | GAP-007          | No Compensating Controls for MRI       | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #5       | GAP-014          | No Patch Management                    | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #6       | GAP-008          | No Egress Filtering                    | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #7       | GAP-012          | No Vendor Account Management           | CRITICAL                                 |
+----------+------------------+----------------------------------------+------------------------------------------+
| #8       | GAP-002          | No Incident Response Plan              | HIGH (DOWNGRADED)                        |
+----------+------------------+----------------------------------------+------------------------------------------+
| #9       | GAP-015          | No Automated Offboarding               | HIGH (DOWNGRADED)                        |
+----------+------------------+----------------------------------------+------------------------------------------+
| #10      | GAP-009          | Shadow IT Systems                      | HIGH (unchanged)                         |
+----------+------------------+----------------------------------------+------------------------------------------+
| #11      | GAP-013          | No Email Security                      | HIGH                                     |
+----------+------------------+----------------------------------------+------------------------------------------+
| #12      | GAP-006          | No Backup for PACS                     | HIGH                                     |
+----------+------------------+----------------------------------------+------------------------------------------+
| #13      | GAP-010          | No Administrative Detective Controls   | MEDIUM (DOWNGRADED)                      |
+----------+------------------+----------------------------------------+------------------------------------------+
| #14      | GAP-011          | No Administrative Deterrent Controls   | MEDIUM                                   |
+----------+------------------+----------------------------------------+------------------------------------------+
| #15      | GAP-005          | Unrestricted Physical Access           | MEDIUM (DOWNGRADED)                      |
+----------+------------------+----------------------------------------+------------------------------------------+

9.2 THE CRITICAL THREE
----------------------
+----------------------------------------------------------------------------+
| THE CRITICAL THREE                                                         |
|                                                                             |
| These are the 3 gaps that appear most frequently across kill chains and    |
| scenarios. Closing these gaps would disrupt the GREATEST number of         |
| attack paths.                                                               |
|                                                                             |
| RANK 1: GAP-001 - No SIEM or Log Monitoring                                |
| Appears in ALL 5 kill chains and ALL 3 scenarios. Without detection,       |
| every attack proceeds unseen until impact.                                |
|                                                                             |
| RANK 2: GAP-003 - Medical IoT on Flat Network - No Segmentation           |
| Appears in 4 of 5 kill chains. The flat network is the PRIMARY ENABLER    |
| of lateral movement.                                                       |
|                                                                             |
| RANK 3: GAP-004 - No MFA Anywhere                                         |
| Appears in ALL 5 kill chains. Credential theft is the #1 entry vector      |
| across ALL threat actor types.                                             |
+----------------------------------------------------------------------------+

9.3 THE SURPRISE
----------------
+----------------------------------------------------------------------------+
| THE SURPRISE: GAP-009 - Shadow IT Systems                                  |
|                                                                             |
| Original Rating: HIGH                                                      |
| Threat-Informed Rating: HIGH (unchanged but for different reasons)        |
|                                                                             |
| Why this is a surprise:                                                   |
|                                                                             |
| Shadow IT is not just an "asset management" problem. It is an ACTIVE       |
| ATTACK SURFACE. The Raspberry Pi with default credentials provides a      |
| PERFECT pivot point for attackers. An attacker on a shadow IT device      |
| can move to the EHR without detection. The threat analysis reveals that   |
| shadow IT appears in 2 kill chains (KC #2 and KC #3) as a pivot point.   |
|                                                                             |
| The crypto-miner on billing-srv-01 proves that MedDefense is already      |
| being scanned. A device like the Raspberry Pi is exactly what attackers   |
| look for.                                                                  |
+----------------------------------------------------------------------------+


================================================================================
10. PRIORITIZED RECOMMENDATIONS
================================================================================

10.1 TOP 5 THREATS WITH RECOMMENDED ACTIONS
--------------------------------------------
+----------+------------------+------------------------------------------+------------------+
| Rank     | Threat           | Recommended Action                       | Cost / Effort    |
+----------+------------------+------------------------------------------+------------------+
| #1       | VPN Ransomware   | Patch Management Program for ALL         | $2,000 /         |
|          |                  | network devices. Apply patches within    | Quick Win        |
|          |                  | 48 hours of CVE release.                 |                  |
+----------+------------------+------------------------------------------+------------------+
| #2       | Credential Theft | MFA for ALL remote access (VPN), admin   | $8,000-$10,000 / |
|          | → EHR            | accounts (AD), and critical systems      | Short-term       |
|          |                  | (EHR). Phased deployment.                |                  |
+----------+------------------+------------------------------------------+------------------+
| #3       | IoT Patient      | IMMEDIATELY segment IoT devices to       | $12,000 /        |
|          | Safety           | isolated VLAN. Strict firewall rules     | Quick Win        |
|          |                  | between IoT VLAN and internal network.  |                  |
+----------+------------------+------------------------------------------+------------------+
| #4       | Supply Chain     | MFA for ALL vendor accounts. Inventory   | $3,000 /         |
|          | Compromise       | ALL vendor accounts and access levels.  | Short-term       |
|          |                  | Review vendor access quarterly.         |                  |
+----------+------------------+------------------------------------------+------------------+
| #5       | Insider Data     | Automated account deactivation linked   | $3,000 /         |
|          | Exfiltration     | to HR termination data. Quarterly       | Short-term       |
|          |                  | review of active accounts.              |                  |
+----------+------------------+------------------------------------------+------------------+

10.2 STRATEGIC 2-INITIATIVE RECOMMENDATION
-------------------------------------------
+----------------------------------------------------------------------------+
| If MedDefense could only fund 2 defensive initiatives in the next quarter, |
| based on this threat analysis, they should be:                             |
|                                                                             |
| 1. NETWORK SEGMENTATION FOR IOT DEVICES ($12,000, 1 week)                  |
|                                                                             |
|    Addresses the most IMMEDIATE PATIENT SAFETY risk. Medical IoT devices   |
|    are on the same flat network as everything else. An attacker who       |
|    compromises ANY system can reach life-safety devices. The Breach 3     |
|    case validated that this exact scenario leads to $40M recovery costs.  |
|                                                                             |
| 2. MFA FOR ALL REMOTE ACCESS AND CRITICAL SYSTEMS ($8,000-$10,000, 1      |
|    month)                                                                  |
|                                                                             |
|    Addresses the #1 ENTRY VECTOR for attackers. Credential theft is the    |
|    primary vector across ALL threat actor types. Without MFA, a single    |
|    phished password provides access to the EHR, VPN, and AD.              |
|                                                                             |
| BOTTOM LINE:                                                               |
| These two initiatives address the HIGHEST LIKELIHOOD and HIGHEST IMPACT   |
| threats. They protect patient safety, reduce the #1 entry vector, and    |
| are both cost-effective and quick to implement.                           |
+----------------------------------------------------------------------------+

10.3 BUDGET ALLOCATION
----------------------
+----------------------------------------------------------------------------+
| TOP 7 PRIORITIES COST:                                                     |
|                                                                             |
| GAP-001 (SIEM):                     $5,000  (Short-term)                   |
| GAP-003 (IoT Segmentation):         $12,000 (Quick Win)                    |
| GAP-004 (MFA):                      $8,000-$10,000 (Short-term)            |
| GAP-007 (MRI Compensating):         $10,000 (Quick Win)                    |
| GAP-014 (Patch Management):         $2,000  (Quick Win)                    |
| GAP-008 (Egress Filtering):         $2,000  (Quick Win)                    |
| GAP-012 (Vendor Account Mgt):       $3,000  (Short-term)                   |
|                                                                             |
| TOTAL:                              $42,000 - $44,000                      |
|                                                                             |
| Remaining budget:                   $76,000 - $78,000                      |
+----------------------------------------------------------------------------+

10.4 CONNECTION TO NEXT PHASE: VULNERABILITY ASSESSMENT
-------------------------------------------------------
+----------------------------------------------------------------------------+
| This Threat Landscape Report (1x01) and the Security Posture Assessment   |
| (0x00) together provide the foundation for the Vulnerability Assessment   |
| (1x02).                                                                    |
|                                                                             |
| WHAT COMES NEXT:                                                           |
| 1. The Posture Assessment identified WHAT is vulnerable                  |
| 2. The Threat Report identified WHO would exploit it                     |
| 3. The Vulnerability Assessment will identify HOW to prioritize          |
|    remediation based on actual technical vulnerabilities found           |
|                                                                             |
| CONNECTION POINTS:                                                         |
| - Gaps prioritized in Section 9 will guide vulnerability scanning        |
| - Attack paths from Section 6 will guide penetration testing             |
| - Threat scenarios from Section 8 will guide scenario-based testing      |
|                                                                             |
| This Threat Landscape Report provides the THREAT CONTEXT for the         |
| Vulnerability Assessment. It answers: "What should we look for first ?"   |
+----------------------------------------------------------------------------+


================================================================================
11. KEY FINDINGS
================================================================================

1. Ransomware through unpatched VPN is the #1 threat. It combines HIGH
   likelihood (sector statistics, regional incidents) with CATASTROPHIC
   impact ($5M+ costs, patient safety risk).

2. The flat network (GAP-003) is the PRIMARY ENABLER of lateral movement.
   It appears in EVERY kill chain and turns a single compromise into a
   network-wide breach.

3. No MFA (GAP-004) makes credential theft the #1 entry vector across ALL
   threat actor types. This is the most cost-effective single control.

4. The MRI Windows XP (GAP-007) is a PERMANENT, UNPATCHABLE backdoor.
   Breach 3 validated that this exact scenario causes $40M recovery costs.

5. The Critical Three gaps (GAP-001, GAP-003, GAP-004) appear in ALL
   attack paths. Closing these three would disrupt the greatest number of
   attacks.

6. Shadow IT (GAP-009) is a SURPRISE - the threat analysis reveals that
   unmanaged devices provide PERFECT pivot points for attackers.

7. Supply chain risk is CRITICAL but often overlooked. MedTech Solutions
   has NO MFA, NO least privilege, and NO monitoring.

8. The 2-initiative recommendation (Segmentation + MFA) provides the
   greatest risk reduction per dollar.


================================================================================
12. REFERENCES
================================================================================

- CISA Advisory AA24-131A: "Ransomware Trends Targeting Healthcare" (File 1)
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)
- HHS Breach Portal Statistics (Excel summary) (File 3)
- Ransomware Incident Case Summary - 280-bed regional hospital (File 4)
- Article - "The Economics of Healthcare Ransomware" (File 5)
- Marcus Webb - MedDefense Threat Landscape DRAFT (File 6)
- BlackReef Ransomware Profile (File 7)
- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - Control Families
- MITRE ATT&CK Enterprise Framework
- Microsoft STRIDE Threat Model
- CIS Controls v8: Critical Security Controls
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices

Cross-References to Project 0x00 (Security Posture Assessment):
- Asset Registry (Task 7): All assets
- Criticality Assessment (Task 8): Top 5 Critical Assets
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Security Posture Assessment (Task 16): Complete posture


================================================================================
END OF THREAT LANDSCAPE REPORT
================================================================================
