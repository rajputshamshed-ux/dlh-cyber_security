================================================================================
                    THREAT ACTOR MATRIX - MEDDEFENSE HEALTH SYSTEMS
                    Task 6: The MedDefense Threat Actor Matrix
================================================================================

Exercise: Task 6 - The MedDefense Threat Actor Matrix
Analyst: shamshed rajput 
Date: 16/07/2026
Objective: Consolidate all threat actor analysis into a single prioritized
          reference matrix.

Methodology References:
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)
- CISA Advisory AA24-131A (File 1)
- BlackReef Ransomware Profile (File 7)
- Marcus Webb - Threat Landscape DRAFT (File 6)
- Security+ Threat Actor Framework

Cross-References to Project 1x00:
- Asset Registry (Task 7): Top 5 Critical Assets
- Criticality Assessment (Task 8): Asset criticality ratings
- Gap Analysis (Task 12): All Gap IDs
- Control Matrix (Task 10): Existing controls
- Walk-through Observations (Task 3): Physical security


================================================================================
1. THREAT ACTOR MATRIX
================================================================================

+----------------------------------------------------------------------------+
| ACTOR 1: RANSOMWARE GROUPS (ORGANIZED CRIME)                               |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | CRITICAL                                             |
|                    | 25% of all ransomware incidents target healthcare.  |
|                    | Three regional hospitals within 200 miles hit in 8  |
|                    | months. MedDefense matches the target profile       |
|                    | exactly: 350-bed regional hospital, limited         |
|                    | security budget, one security analyst.              |
|                    | Sources: CISA Advisory (File 1), HC3 (File 2),      |
|                    | BlackReef Profile                                   |
+------------------+------------------------------------------------------+
| CAPABILITY         | HIGH                                                 |
|                    | RaaS model: developers, affiliates, IABs,            |
|                    | negotiators. Professional supply chain. Access       |
|                    | purchased for $500-$10,000. Custom and commercial   |
|                    | tools. Double extortion capability.                  |
|                    | Sources: BlackReef Profile, HC3 (File 2)             |
+------------------+------------------------------------------------------+
| PRIMARY            | FINANCIAL GAIN                                       |
| MOTIVATION         | Ransom payments ($1M-$3M per hospital). Patient      |
|                    | data sold for $250-$1,000 per record.                |
|                    | Sources: Article - "The Economics of Healthcare      |
|                    | Ransomware" (File 5), BlackReef Profile              |
+------------------+------------------------------------------------------+
| PREFERRED          | VPN/Perimeter Exploit (38% of healthcare             |
| VECTOR             | ransomware incidents) OR Phishing (31%).             |
|                    | Alternative: Purchased access from IABs.             |
|                    | Sources: CISA Advisory (File 1), BlackReef Profile   |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | EHR System (#1 CRITICAL), Active Directory (#4       |
|                    | CRITICAL), Billing (#3 HIGH), Backups                |
|                    | Sources: Asset Registry (Task 7), Criticality        |
|                    | Assessment (Task 8)                                  |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-014: No Patch Management - VPN exploitation      |
| EXPOSURE           | GAP-003: Flat Network - Lateral movement             |
|                    | GAP-004: No MFA - Privilege escalation               |
|                    | GAP-001: No SIEM - Undetected operation              |
|                    | C-009 Weakness: Co-located Backups - Backup          |
|                    | neutralization                                       |
|                    | Sources: Gap Analysis (Task 12), Marcus (File 6)     |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| ACTOR 2: NATION-STATE APT                                                  |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | LOW                                                  |
|                    | MedDefense has no pharmaceutical research, vaccine   |
|                    | research, or clinical trials. Nation-state actors   |
|                    | primarily target healthcare R&D. However, if        |
|                    | MedDefense partners with a research university,     |
|                    | this assessment changes.                            |
|                    | Sources: HC3 (File 2), Marcus (File 6)               |
+------------------+------------------------------------------------------+
| CAPABILITY         | VERY HIGH                                            |
|                    | Custom malware, zero-day exploitation, prolonged     |
|                    | dwell times (months to years), significant funding   |
|                    | and personnel. Highest level of sophistication.     |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| PRIMARY            | ESPIONAGE / INTELLECTUAL PROPERTY THEFT              |
| MOTIVATION         | Theft of pharmaceutical research, vaccine formulas,  |
|                    | clinical trial data, genetic databases for           |
|                    | economic/strategic advantage.                        |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| PREFERRED          | Zero-day exploitation of public-facing systems OR    |
| VECTOR             | Spear-phishing targeting researchers.                |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | Clinical Trial / Research Data (if any) OR           |
|                    | potentially use MedDefense as a stepping stone to    |
|                    | partners with research programs.                     |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-014: No Patch Management - Zero-day              |
| EXPOSURE           | exploitation potential                               |
|                    | GAP-003: Flat Network - Lateral movement after       |
|                    | entry                                                |
|                    | GAP-001: No SIEM - Prolonged dwell time              |
|                    | undetected                                           |
|                    | Sources: Gap Analysis (Task 12)                      |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| ACTOR 3: INSIDER THREAT (MALICIOUS)                                        |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | MEDIUM                                               |
|                    | 35% of healthcare data breaches involve insiders     |
|                    | (Verizon DBIR). Conditions at MedDefense enable      |
|                    | malicious insider activity: no automated             |
|                    | offboarding, no DLP, no behavioral monitoring.       |
|                    | However, malicious intent is less common than        |
|                    | negligence.                                          |
|                    | Sources: HC3 (File 2), HHS Breach Portal (File 3),   |
|                    | Marcus (File 6)                                      |
+------------------+------------------------------------------------------+
| CAPABILITY         | LOW                                                  |
|                    | Malicious insiders already have authorized access.   |
|                    | No technical sophistication required. The            |
|                    | challenge is detection, not compromise.             |
|                    | Sources: HC3 (File 2), Insider Assessment (T3)        |
+------------------+------------------------------------------------------+
| PRIMARY            | FINANCIAL GAIN (selling patient data), REVENGE       |
| MOTIVATION         | (disgruntled employees), CURIOSITY                   |
|                    | (celebrity snooping).                                |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| PREFERRED          | Using legitimate credentials for unauthorized       |
| VECTOR             | access (insider has already access). Off-hours       |
|                    | access to circumvent detection.                      |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | Patient Records (EHR), PII, Financial Data           |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-015: No Automated Offboarding - Former           |
| EXPOSURE           | employees retain access                              |
|                    | GAP-001: No SIEM - Off-hours access undetected       |
|                    | GAP-010: No Audits - No detection of misuse          |
|                    | GAP-011: No Enforcement - No consequences            |
|                    | GAP-007: Shared Account Policy Not Enforced          |
|                    | Sources: Insider Assessment (T3), Gap Analysis       |
|                    | (Task 12)                                            |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| ACTOR 4: INSIDER THREAT (NEGLIGENT)                                        |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | HIGH                                                 |
|                    | Negligent insiders are more common than malicious.  |
|                    | Conditions at MedDefense: shared accounts, no       |
|                    | automated offboarding, low training completion,     |
|                    | shadow IT, unlocked sessions, credentials taped to  |
|                    | walls. Accidents are frequent.                      |
|                    | Sources: HC3 (File 2), Insider Assessment (T3),     |
|                    | Walk-through Observations (Task 3)                   |
+------------------+------------------------------------------------------+
| CAPABILITY         | LOW                                                  |
|                    | No technical sophistication. Caused by carelessness, |
|                    | shortcuts, or lack of training.                      |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| PRIMARY            | NEGLIGENCE / CONVENIENCE / LACK OF AWARENESS         |
| MOTIVATION         | Employees taking shortcuts, bypassing controls, or  |
|                    | unaware of security implications.                    |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| PREFERRED          | Shadow IT (unapproved devices), credential sharing,  |
| VECTOR             | unlocked sessions, misplaced data, weak passwords.  |
|                    | Sources: Insider Assessment (T3), Walk-through       |
|                    | Observations (Task 3)                                |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | All data categories: PHI, PII, Financial, Research   |
|                    | Sources: Insider Assessment (T3)                      |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-009: Shadow IT - Unmanaged devices              |
| EXPOSURE           | GAP-010: No Audits - No oversight                   |
|                    | GAP-011: No Enforcement - No consequences           |
|                    | GAP-007: Shared Account Policy Not Enforced         |
|                    | GAP-013: Training Completion (58-71%) - Low         |
|                    | awareness                                           |
|                    | Sources: Insider Assessment (T3), Gap Analysis      |
|                    | (Task 12)                                            |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| ACTOR 5: HACKTIVIST                                                       |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | LOW                                                  |
|                    | MedDefense has no political profile, no              |
|                    | controversial policies. Hacktivists target           |
|                    | organizations with ideological differences or       |
|                    | geopolitical conflicts. However, a DDoS on the      |
|                    | patient portal could cause disruption if targeted.  |
|                    | Sources: HC3 (File 2), Marcus (File 6)               |
+------------------+------------------------------------------------------+
| CAPABILITY         | LOW to MEDIUM                                        |
|                    | Primarily DDoS, website defacement, data leaks for  |
|                    | publicity. Limited technical sophistication.        |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| PRIMARY            | POLITICAL / IDEOLOGICAL                              |
| MOTIVATION         | Making a statement, exposing perceived wrongdoing,  |
|                    | or disrupting operations for publicity.             |
|                    | Sources: HC3 (File 2), Threat Actor Taxonomy (T1)    |
+------------------+------------------------------------------------------+
| PREFERRED          | Website defacement (CVE exploit in CMS) OR DDoS     |
| VECTOR             | attack.                                              |
|                    | Sources: Threat Actor Taxonomy (T1)                   |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | Public Website (web-srv-01) or Patient Portal       |
|                    | Sources: Threat Actor Taxonomy (T1), Asset Registry  |
|                    | (Task 7)                                             |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-016: No Web Application Security Testing -      |
| EXPOSURE           | Unpatched CMS vulnerabilities                        |
|                    | GAP-001: No SIEM - DDoS or defacement undetected    |
|                    | until user reports                                   |
|                    | Sources: Gap Analysis (Task 12), Marcus (File 6)    |
+------------------+------------------------------------------------------+


+----------------------------------------------------------------------------+
| ACTOR 6: UNSKILLED / OPPORTUNISTIC ATTACKER                               |
+----------------------------------------------------------------------------+
| LIKELIHOOD         | HIGH                                                 |
|                    | MedDefense is already being hit: crypto-miner on    |
|                    | billing-srv-01 proves scanning is occurring.        |
|                    | Unpatched public-facing services (Apache 2.4.29,    |
|                    | VPN) are found by automated scanners. The average   |
|                    | hospital is scanned thousands of times per day.    |
|                    | Sources: Marcus (File 6), Task 2 (Symptom Trap)     |
+------------------+------------------------------------------------------+
| CAPABILITY         | LOW                                                  |
|                    | Automated tools, public exploits, AI-assisted       |
|                    | attacks. No targeting - they scan for               |
|                    | vulnerabilities across the internet.                |
|                    | Sources: HC3 (File 2), Marcus (File 6)               |
+------------------+------------------------------------------------------+
| PRIMARY            | OPPORTUNISTIC FINANCIAL GAIN                         |
| MOTIVATION         | Cryptocurrency mining, selling access, low-effort   |
|                    | exploitation. Not targeting MedDefense               |
|                    | specifically - just looking for vulnerable systems. |
|                    | Sources: Marcus (File 6), Task 2 (Symptom Trap)     |
+------------------+------------------------------------------------------+
| PREFERRED          | Automated scanning for known vulnerabilities        |
| VECTOR             | (Apache, outdated services, default credentials).   |
|                    | Sources: Task 2 (Symptom Trap), Marcus (File 6)     |
+------------------+------------------------------------------------------+
| PRIMARY TARGET     | Any vulnerable system they find (billing-srv-01     |
|                    | is proof).                                           |
|                    | Sources: Task 2 (Symptom Trap)                       |
+------------------+------------------------------------------------------+
| MEDDEFENSE         | GAP-014: No Patch Management - Unpatched            |
| EXPOSURE           | vulnerabilities are exploitable                     |
|                    | GAP-001: No SIEM - Compromise undetected until      |
|                    | symptoms appear                                      |
|                    | GAP-016: No Web Application Security Testing -      |
|                    | Web vulnerabilities exploited                        |
|                    | Sources: Gap Analysis (Task 12), Task 2             |
+------------------+------------------------------------------------------+


================================================================================
2. TOP 3 PRIORITY RANKING
================================================================================

+----------------------------------------------------------------------------+
| RANK 1: RANSOMWARE GROUPS (ORGANIZED CRIME)                                |
+----------------------------------------------------------------------------+
| LIKELIHOOD  | CRITICAL                                            |
| IMPACT      | CRITICAL                                            |
| OVERALL     | #1 PRIORITY                                         |
+------------+------------------------------------------------------+
| JUSTIFICATION:                                                             |
|                                                                             |
| Ransomware groups represent the GREATEST threat to MedDefense. The         |
| organization matches the exact target profile that RaaS groups actively    |
| hunt: a 350-bed regional hospital with limited security budget, clinical   |
| urgency that creates payment pressure, and a flat network with no          |
| detection capability.                                                       |
|                                                                             |
| The convergence of factors is alarming:                                    |
| - 25% of all ransomware incidents target healthcare (sector-wide)         |
| - Three regional hospitals within 200 miles have been hit in 8 months     |
| - The 280-bed hospital case (File 4) is VIRTUALLY IDENTICAL to MedDefense |
| - Marcus annotated: "THIS IS US"                                          |
| - MedDefense has EVERY gap that ransomware groups exploit                 |
|                                                                             |
| The potential impact is catastrophic: 11-day EHR downtime, ambulance      |
| diversions, $5M+ recovery costs, CEO resignation. This is not             |
| theoretical - it happened to a hospital with the same profile.            |
|                                                                             |
| No other threat actor combines this level of LIKELIHOOD and IMPACT.       |
| This is the #1 priority.                                                  |
+----------------------------------------------------------------------------+


+----------------------------------------------------------------------------+
| RANK 2: INSIDER THREAT (NEGLIGENT)                                         |
+----------------------------------------------------------------------------+
| LIKELIHOOD  | HIGH                                                |
| IMPACT      | HIGH                                                |
| OVERALL     | #2 PRIORITY                                         |
+------------+------------------------------------------------------+
| JUSTIFICATION:                                                             |
|                                                                             |
| Negligent insiders represent the #2 threat because they are COMMON and     |
| the organization is actively ENABLING them. Conditions at MedDefense       |
| create a perfect environment for negligent insider incidents:             |
|                                                                             |
| - Shared accounts (radiology) with no accountability                      |
| - No automated offboarding (former employees retain access)              |
| - Low training completion (58-71% at some sites)                         |
| - Shadow IT (Dr. Patel's NAS, Marketing Google Drive)                    |
| - Unlocked sessions at nurse stations (Observation 3)                    |
| - Credentials taped to walls (Observation 2)                            |
| - No enforcement of security policies (GAP-011)                          |
|                                                                             |
| The impact of negligent insider incidents is often underestimated.        |
| Healthcare breaches from negligence account for approximately 35% of     |
| incidents (Verizon DBIR). A misdirected email with PHI, a lost device     |
| with patient data, or shared credentials being misused can trigger        |
| HIPAA breach notification, fines, and reputational damage.               |
|                                                                             |
| Unlike ransomware, negligent insider incidents are PREVENTABLE with       |
| administrative controls (training, enforcement, audits). The             |
| organization already has the tools to address this - they are not        |
| being used.                                                               |
+----------------------------------------------------------------------------+


+----------------------------------------------------------------------------+
| RANK 3: UNSKILLED / OPPORTUNISTIC ATTACKER                                |
+----------------------------------------------------------------------------+
| LIKELIHOOD  | HIGH                                                |
| IMPACT      | MEDIUM to HIGH                                      |
| OVERALL     | #3 PRIORITY                                         |
+------------+------------------------------------------------------+
| JUSTIFICATION:                                                             |
|                                                                             |
| Unskilled/opportunistic attackers represent the #3 threat because         |
| MedDefense is ALREADY BEING HIT by them. The crypto-miner on              |
| billing-srv-01 is proof: someone scanned for Apache 2.4.29 RCE across    |
| the internet, found MedDefense, and dropped a miner. No targeting, no    |
| sophistication - just opportunity.                                        |
|                                                                             |
| The likelihood is HIGH because:                                            |
| - Automated scanners find unpatched services quickly                      |
| - MedDefense has unpatched Apache, VPN, and potentially other services   |
| - AI-assisted attacks are lowering the skill floor                       |
| - The average hospital is scanned thousands of times per day             |
|                                                                             |
| The impact varies:                                                         |
| - Crypto-mining causes performance degradation (disruptive but not       |
|   catastrophic)                                                           |
| - Could escalate: the attacker could have deployed ransomware instead    |
| - Could lead to data exfiltration if they discover sensitive data        |
|                                                                             |
| The primary concern is that opportunistic attacks can become ransomware  |
| attacks. If the attacker had dropped ransomware instead of a miner,      |
| MedDefense would have faced the same impact as Rank 1. This is why they  |
| are #3.                                                                  |
+----------------------------------------------------------------------------+


================================================================================
3. FULL PRIORITY RANKING SUMMARY
================================================================================

+----------+------------------+-----------------+-----------------+------------------+
| Rank     | Actor Type       | Likelihood      | Impact          | Overall Priority |
+----------+------------------+-----------------+-----------------+------------------+
| #1       | Ransomware       | CRITICAL        | CRITICAL        | #1 PRIORITY      |
|          | (Organized Crime)|                 |                 |                   |
+----------+------------------+-----------------+-----------------+------------------+
| #2       | Insider          | HIGH            | HIGH            | #2 PRIORITY      |
|          | (Negligent)      |                 |                 |                   |
+----------+------------------+-----------------+-----------------+------------------+
| #3       | Unskilled /      | HIGH            | MEDIUM to HIGH  | #3 PRIORITY      |
|          | Opportunistic    |                 |                 |                   |
+----------+------------------+-----------------+-----------------+------------------+
| #4       | Insider          | MEDIUM          | HIGH            | #4 PRIORITY      |
|          | (Malicious)      |                 |                 |                   |
+----------+------------------+-----------------+-----------------+------------------+
| #5       | Hacktivist       | LOW             | MEDIUM          | #5 PRIORITY      |
+----------+------------------+-----------------+-----------------+------------------+
| #6       | Nation-State     | LOW             | HIGH            | #6 PRIORITY      |
|          | APT              | (unless         | (if targeted)   |                   |
|          |                  | research starts)|                 |                   |
+----------+------------------+-----------------+-----------------+------------------+


================================================================================
4. KEY FINDINGS
================================================================================

1. Ransomware groups are the #1 threat due to the convergence of HIGH
   likelihood (sector statistics, regional incidents) and CATASTROPHIC
   impact ($5M+ costs, patient safety risk).

2. Negligent insiders are the #2 threat because they are COMMON and the
   organization is actively ENABLING them through weak administrative
   controls (no enforcement, no audits, no training).

3. Unskilled/opportunistic attackers are actively hitting MedDefense TODAY
   (crypto-miner on billing-srv-01) and represent a credible threat.

4. Nation-state APT is LOW likelihood unless MedDefense begins research
   programs. This could change.

5. The top 3 threats (Ransomware, Negligent Insider, Opportunistic) are
   all HIGH or CRITICAL likelihood. This means MedDefense is facing
   multiple attack vectors that are LIKELY to be exploited.

6. The gaps that enable the top 3 threats are:
   - GAP-014 (No Patch Management) - enables ransomware and opportunistic
   - GAP-003 (Flat Network) - enables ransomware and opportunistic
   - GAP-004 (No MFA) - enables ransomware and malicious insider
   - GAP-001 (No SIEM) - enables ALL threats to go undetected
   - GAP-015 (No Offboarding) - enables malicious insider
   - GAP-011 (No Enforcement) - enables negligent insider


================================================================================
5. REFERENCES
================================================================================

- CISA Advisory AA24-131A (File 1)
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)
- HHS Breach Portal Statistics (File 3)
- Ransomware Incident Case Summary - 280-bed regional hospital (File 4)
- Article - "The Economics of Healthcare Ransomware" (File 5)
- Marcus Webb - MedDefense Threat Landscape DRAFT (File 6)
- BlackReef Ransomware Profile (File 7)

Cross-References to Project 1x00:
- Asset Registry (Task 7): Top 5 Critical Assets
- Criticality Assessment (Task 8): Asset criticality ratings
- Gap Analysis (Task 12): GAP-001, GAP-003, GAP-004, GAP-007, GAP-009,
  GAP-010, GAP-011, GAP-014, GAP-015, GAP-016
- Control Matrix (Task 10): C-001, C-005, C-006, C-008, C-009, C-010, C-013
- Walk-through Observations (Task 3): Physical security


================================================================================
END OF THREAT ACTOR MATRIX REPORT
================================================================================
