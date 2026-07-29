================================================================================
                    RISK REGISTER UPDATE - CRIMSON TIDE THREAT
                    Task 7: The Risk Register Update
================================================================================

Exercise: Task 7 - The Risk Register Update
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Update the MedDefense Risk Register with the Crimson Tide
          threat, demonstrating that a Risk Register is a living
          document that responds to new intelligence. Update existing
          ransomware entry and add new FortiGate vulnerability entry.

Sources: 1x03 T10 Risk Register, 1x03 T9 Governance Note, 1x05 T0 CISA
         Advisory Analysis, 1x05 T1 CVE Deep Dive, 1x05 T5 ALE Update,
         1x02 Vulnerability Findings


================================================================================
PART 1: UPDATE EXISTING ENTRY - RANSOMWARE RISK
================================================================================

----------------------------------------------------------------------
ORIGINAL ENTRY (from 1x03 T10 Risk Register)
----------------------------------------------------------------------

RISK ID:            RISK-001
Risk Title:         Ransomware Attack on Patient Database (ehr-db-01)
Date Identified:    22/07/2026
Risk Owner:         James Chen (CISO)
Category:           External Threat / Malware

Description:        A ransomware group gains access to the MedDefense
                    internal network, escalates privileges, exfiltrates
                    patient data from ehr-db-01, and encrypts production
                    systems and backups, demanding ransom payment for
                    decryption.

Threat Source:      Generic ransomware groups targeting healthcare
                    (Hive, LockBit, BlackCat based on 2023-2025 trends)

Vulnerabilities:    - 1x02-F004: PostgreSQL Database - No Encryption
                    - 1x02-F003: Backup Data Unencrypted on NAS
                    - 1x02-F001: Patient Portal TLS 1.0
                    - 1x00-GAP-001: Flat Network Topology

Likelihood:         4 - Likely (ARO: 0.25, once every 4 years)
Impact:             5 - Catastrophic (>$20M, patient data breach)
Risk Score:         20 (4 × 5) - CRITICAL

SLE:                $29,050,000
ARO:                0.25
ALE:                $7,262,500

Existing Controls:  - Windows Defender (built-in, no centralized mgmt)
                    - FortiGate firewall (perimeter, but firmware outdated)
                    - Tape backup (manual, inconsistent, on same network)

Treatment:          MITIGATE - Deploy encryption at rest (TDE + LUKS),
                    network segmentation, and hardened Active Directory
                    per 1x03 Security Strategy Phase 1.

Residual Risk:      Likelihood 3 (Possible), Impact 3 (Moderate)
                    Residual Score: 9 - MEDIUM
                    (After encryption: data exfiltrated is unreadable)

KRI:                - Number of ransomware attacks on US hospitals (monthly)
                    - Unusual SMB traffic on internal network
                    - Failed login attempts on ehr-db-01

Last Reviewed:      22/07/2026
Next Review:        22/10/2026 (Quarterly per governance schedule)

----------------------------------------------------------------------
UPDATED ENTRY (incorporating Crimson Tide intelligence)
----------------------------------------------------------------------

RISK ID:            RISK-001 (UPDATED)
Risk Title:         Crimson Tide Ransomware Attack on Patient Database
                    (ehr-db-01) - ACTIVE CAMPAIGN
Date Identified:    22/07/2026
Date Updated:       29/07/2026 (Trigger: CISA Advisory AA23-XXX)
Risk Owner:         James Chen (CISO)
Category:           External Threat / Malware / Named Threat Actor

Description:        The Crimson Tide (CT) ransomware group, currently
                    conducting an active campaign against U.S. healthcare
                    organizations, exploits CVE-2023-27997 (FortiOS
                    SSL-VPN) for initial access. After gaining Domain
                    Admin via Kerberoasting (RC4 Kerberos), they
                    exfiltrate unencrypted patient databases, deploy
                    ransomware on EHR, PACS, and backups, and employ
                    DOUBLE EXTORTION (payment for decryption AND payment
                    for non-release of exfiltrated data). 5 hospitals
                    hit in 10 days; 3 in MedDefense's region. Hospital C
                    (45 miles) in active containment.

Threat Source:       NAMED THREAT ACTOR: Crimson Tide (CT) ransomware group
                    - Active campaign: July 2026
                    - Targets: U.S. healthcare, specifically hospitals
                      with FortiOS SSL-VPN and unencrypted databases
                    - TTPs documented in CISA Advisory AA23-XXX
                    - CVE-2023-27997 exploitation (CISA KEV confirmed)
                    - Double extortion model

Vulnerabilities:    - CVE-2023-27997: FortiOS 7.0.9 SSL-VPN RCE (NEW,
                      CVSS 9.8, internet-facing, unpatched)
                    - 1x02-F004: PostgreSQL Database - No Encryption at
                      Rest (matches 4/5 CT victim profile)
                    - 1x02-F007: Kerberos Accepts DES and RC4-HMAC
                      (enables CT Phase 2 Kerberoasting)
                    - 1x02-F003: Backup Data Unencrypted on NAS
                      (CT Phase 7 encrypts backups)
                    - 1x00-GAP-001: Flat Network Topology
                      (enables CT Phase 4 lateral movement)

Likelihood:         5 - Almost Certain (ARO: 0.80, 80% probability/year)
                    UPDATED from 4 (Likely, 0.25 ARO)
                    BASIS: Active campaign + regional targeting +
                    matching vulnerability profile + CISA KEV
                    exploitation + Hospital C proximity.
                    (Full calculation in 1x05 T5 ALE Update)

Impact:             5 - Catastrophic (>$30M, patient data breach)
                    UPDATED SLE: $34,955,000 (from $29,050,000)
                    BASIS: Double extortion adds $700K ransom, class
                    action adds $3.5M, increased downtime and regulatory
                    penalties.
                    (Full calculation in 1x05 T5 ALE Update)

Risk Score:         25 (5 × 5) - CRITICAL (MAXIMUM)
                    UPDATED from 20 (4 × 5)
                    Score of 25 is the highest possible on the 5×5
                    matrix. This risk is at the theoretical maximum.

SLE:                $34,955,000 (UPDATED from $29,050,000)
ARO:                0.80 (UPDATED from 0.25)
ALE:                $27,964,000 (UPDATED from $7,262,500)

Existing Controls:  UNCHANGED (same inadequate controls as original):
                    - Windows Defender (built-in, no centralized mgmt)
                    - FortiGate firewall (perimeter, VULNERABLE firmware)
                    - Tape backup (manual, inconsistent, on same network)
                    ADDED TEMPORARY CONTROL (29/07/2026):
                    - SSL-VPN DISABLED on FortiGate (T1-1, temporary
                      workaround, disables remote VPN access)
                    - NAS-01 PHYSICALLY ISOLATED (T1-2, temporary,
                      no backups during isolation)

Treatment:          MITIGATE - URGENT (accelerated from Phase 1)
                    Original treatment decision STILL HOLDS but timeline
                    is compressed from 6 months to 72 hours.
                    
                    IMMEDIATE (0-12 hours):
                    - T1-1: SSL-VPN disabled (DONE)
                    - T1-2: NAS-01 isolated (DONE)
                    
                    TIER 2 (12-36 hours):
                    - T2-1: Renew FortiGate support + patch firmware
                    - T2-2: Enforce Kerberos AES-256, disable DES/RC4
                    - T2-3: Deploy PostgreSQL TDE on ehr-db-01
                    
                    TIER 3 (36-72 hours):
                    - T3-1: Deploy LUKS on NAS-01
                    - T3-3: Deploy immutable backups (S3 Object Lock)
                    - T3-5: Engage MSSP for 24/7 monitoring
                    
                    JUSTIFICATION: The treatment decision to MITIGATE
                    is unchanged but the URGENCY has escalated from
                    "Phase 1 (next 3 months)" to "IMMEDIATE (next 72
                    hours)." The cost-benefit still strongly favors
                    mitigation (ROI 285:1 per updated ALE).

Residual Risk:      After 72-Hour Emergency Plan completion:
                    Likelihood: 2 (Unlikely, ARO ~0.15)
                    Impact: 2 (Minor, encrypted data exfiltrated)
                    Residual Score: 4 - LOW
                    
                    UPDATED from original residual: 9 (MEDIUM)
                    The accelerated deployment of TDE + HSM means
                    exfiltrated data is AES-256 ciphertext, neutralizing
                    the double extortion threat. Network segmentation
                    planning reduces lateral movement. MSSP provides
                    detection.

NEW KRI (Crimson Tide Specific):

  KRI-001: CISA Advisory or KEV update referencing Crimson Tide or
           healthcare targeting.
  Source: CISA.gov, NVD, ISAC (Health-ISAC)
  Threshold: Any new advisory → immediate review.
  
  KRI-002: Hospital in MedDefense's state or adjacent state reports
           ransomware incident matching CT TTPs.
  Source: Local news, ISAC, personal network
  Threshold: 1 incident in state → escalate to CISO. 2 incidents →
  emergency Board briefing. (CURRENT STATUS: TRIGGERED - Hospital C)
  
  KRI-003: FortiGate IDS/IPS or firewall log detects exploit attempts
           targeting SSL-VPN (even though disabled, logs historical
           attempts or attempts against other services).
  Source: FortiGate syslog (forwarded to syslog collector per T1-3)
  Threshold: Any signature match for CVE-2023-27997 or FortiOS SSL-VPN
  exploit → IMMEDIATE INCIDENT RESPONSE.
  
  KRI-004: Unusual outbound HTTPS connections from internal servers
           (ehr-db-01, billing-srv-01) to unknown external IPs on
           non-standard ports or high data volumes.
  Source: FortiGate traffic logs, MSSP monitoring (T3-5)
  Threshold: Outbound data transfer >100MB from database server →
  investigate within 1 hour.

Last Reviewed:      29/07/2026 (Out-of-cycle review, triggered by CISA
                    Advisory AA23-XXX and Hospital C active containment)
Next Review:        31/07/2026 (Post-72-Hour Plan completion review)
                    01/10/2026 (Return to quarterly schedule thereafter)


================================================================================
PART 2: NEW ENTRY - FORTIGATE VULNERABILITY (CVE-2023-27997)
================================================================================

RISK ID:            RISK-NEW-001
Risk Title:         Unpatched Critical RCE on Perimeter Firewall
                    (CVE-2023-27997 - FortiOS SSL-VPN)
Date Identified:    29/07/2026
Date Updated:       29/07/2026
Risk Owner:         Sarah Park (Security Team Lead, network security)
Category:           External Threat / Vulnerability / Perimeter Defense

Description:        MedDefense's perimeter firewall (fw-meddefense-01,
                    FortiGate 100E) runs FortiOS 7.0.9, which is
                    vulnerable to CVE-2023-27997, a critical (CVSS 9.8)
                    heap-based buffer overflow in the SSL-VPN component.
                    An unauthenticated remote attacker can send a
                    specially crafted request to the SSL-VPN service
                    and achieve remote code execution (RCE) as root on
                    the firewall. This vulnerability is:
                    - Listed in CISA KEV (actively exploited)
                    - Weaponized in Metasploit and public GitHub PoCs
                    - Actively used by Crimson Tide against hospitals
                    - Present on MedDefense's ONLY perimeter firewall
                    - Exploitable with NO credentials and NO user
                      interaction

                    Successful exploitation provides the attacker with:
                    - Full control of the perimeter firewall
                    - Access to the internal flat network (10.10.10.0/24)
                    - Ability to decrypt/inspect/modify ALL VPN traffic
                    - Platform for lateral movement to ehr-db-01,
                      dc01, nas-01, and all other internal systems
                    - Ability to disable firewall logging (Phase 5 evasion)

                    This is the INITIAL ACCESS vector for the Crimson
                    Tide kill chain. The firewall is the SINGLE POINT
                    OF FAILURE for all 3 MedDefense sites.

Threat Source:      NAMED THREAT ACTOR: Crimson Tide (CT) ransomware group
                    ACTIVE CAMPAIGN: July 2026, targeting U.S. healthcare
                    VULNERABILITY: CVE-2023-27997 (CVSS 9.8, CISA KEV)
                    EXPLOIT MATURITY: Public + Metasploit + weaponized

Vulnerabilities:    PRIMARY:
                    - CVE-2023-27997: FortiOS 7.0.9 SSL-VPN heap buffer
                      overflow (CVSS 9.8, unauthenticated RCE)
                    - 1x00-GAP-003: Perimeter firewall firmware not on
                      current stable release
                    
                    AGGRAVATING:
                    - 1x00-GAP-001: Flat network (no internal segmentation
                      to limit blast radius if firewall compromised)
                    - 1x00-GAP-008: No SSL inspection (attacker's post-
                      exploitation C2 traffic blends with normal HTTPS)
                    - 1x03 CG-007: Vulnerability Management Program not
                      operational (patching not performed)
                    
                    OPERATIONAL:
                    - FortiGate support contract EXPIRED (cannot download
                      patched firmware without renewal)
                    - No redundant firewall (single point of failure)
                    - Firewall terminates ALL VPN tunnels for ALL 3 sites

Likelihood:         5 - Almost Certain
                    BASIS:
                    - CISA KEV confirms active exploitation in the wild
                    - 5 hospitals hit in 10 days by the SAME exploit
                    - 3 of 5 in MedDefense's geographic region
                    - Hospital C (45 miles) in active containment
                    - MedDefense's FortiOS version (7.0.9) is in the
                      affected range (7.0.0-7.0.11)
                    - Public exploit available (Metasploit + GitHub)
                    - Attack complexity: LOW. No authentication.
                    - MedDefense's SSL-VPN was internet-facing until
                      disabled on 29/07/2026 (T1-1 temporary workaround)
                    
                    Without the T1-1 workaround, this would be a
                    CERTAINTY (likelihood 5 of 5). With SSL-VPN disabled,
                    the likelihood is reduced TEMPORARILY for the SSL-VPN
                    vector, but the vulnerability REMAINS on the system
                    and could be accidentally re-enabled or exploited via
                    a different path.

Impact:             5 - Catastrophic
                    BASIS:
                    - Firewall compromise = full internal network access
                    - All 3 sites depend on this single firewall
                    - VPN tunnel decryption = all inter-site PHI exposed
                    - Firewall bricking during failed patch = 3 sites
                      disconnected (no internet, no VPN)
                    - Expired support contract = no vendor assistance
                      if recovery needed
                    - This is the INITIAL ACCESS for the RISK-001
                      ransomware scenario with $34.96M SLE

Risk Score:         25 (5 × 5) - CRITICAL (MAXIMUM)
                    This risk is at the theoretical maximum on the
                    5×5 matrix, alongside the updated RISK-001.

SLE:                $34,955,000 (Same as RISK-001, as this is the
                    initial access vector for that risk)
                    
                    NOTE: If the firewall is compromised but the
                    attacker is detected and evicted BEFORE reaching
                    ehr-db-01 (Phases 3-7), the SLE could be lower:
                    - Incident response + forensic investigation:
                      $150,000
                    - Firewall rebuild/replacement: $50,000
                    - Reputational (attempted breach, no data loss):
                      $200,000
                    - Best-case SLE: $400,000
                    
                    However, with MedDefense's current lack of detection
                    (no SIEM, no EDR, no MSSP), early detection is
                    UNLIKELY. The worst-case SLE ($34.96M) is the
                    appropriate planning assumption.

ARO:                0.80 (80% probability of exploitation attempt
                    reaching MedDefense during this campaign)
                    
                    BASIS:
                    - CISA KEV exploitation rate for internet-facing
                      CVSS 9.8: ~85% within 30 days
                    - Regional campaign targeting: Hospital C confirms
                      active regional targeting
                    - Matching victim profile (healthcare + FortiOS +
                      unencrypted DB)
                    
                    NOTE: This ARO reflects the probability of an
                    ATTEMPT. With SSL-VPN disabled (T1-1), the
                    probability of SUCCESSFUL exploitation is
                    significantly reduced. The ARO for successful
                    exploitation post-T1-1 is estimated at 0.15
                    (residual risk after workaround).

ALE:                $27,964,000 (using worst-case SLE and pre-workaround ARO)
                    NOTE: Post-T1-1 residual ALE:
                    $34,955,000 × 0.15 = $5,243,250
                    The T1-1 workaround reduced the ALE by $22.7M
                    annually, at the cost of disabled remote VPN access.

Existing Controls:  - FortiGate firewall (the vulnerable device itself)
                    - SSL-VPN DISABLED effective 29/07/2026 21:15 local
                      (T1-1 temporary workaround - prevents exploitation
                      of this specific vector but disables remote access)
                    - IPsec site-to-site VPNs (NOT vulnerable to this
                      CVE, still operational)
                    - No IDS/IPS signatures for this CVE (not deployed)
                    - No WAF in front of SSL-VPN (not deployed)
                    - No redundant firewall (single point of failure)

Treatment:          MITIGATE - IMMEDIATE

                    The treatment is a TWO-PHASE approach:
                    
                    PHASE A (COMPLETED): Temporary workaround
                    Action: Disable SSL-VPN on all interfaces (T1-1)
                    Cost: $0 (operational cost: disabled remote VPN)
                    Risk reduction: Reduces ARO from 0.80 to 0.15
                    Residual ALE: $5.24M
                    Status: DONE 29/07/2026 21:15
                    
                    PHASE B (SCHEDULED): Permanent fix
                    Action: Renew support contract + patch to 7.0.12
                    (T2-1, part of 72-Hour Emergency Plan)
                    Cost: $2,400 (support contract renewal)
                    Risk reduction: Eliminates the vulnerability
                    entirely. ARO drops to ~0.05 (residual risk from
                    future zero-days).
                    Residual ALE: $34.96M × 0.05 = $1.75M
                    Status: SCHEDULED for 30/07/2026 05:00-07:00

                    COST-BENEFIT OF PATCHING:
                    ALE before Phase B: $5,243,250 (with workaround)
                    ALE after Phase B: $1,747,750 (patched)
                    Annual risk reduction: $3,495,500
                    Cost of mitigation: $2,400
                    ROI: ($3,495,500 - $2,400) / $2,400 = 1,455:1
                    
                    The $2,400 support contract renewal is JUSTIFIED.
                    Every $1 spent returns $1,455 in annual risk
                    reduction against this specific vulnerability.
                    Over a 3-year period (typical firewall lifecycle),
                    the ROI exceeds 4,300:1.

                    TREATMENT DECISION: MITIGATE IMMEDIATELY.
                    The cost of mitigation ($2,400) represents 0.0086%
                    of the ALE. This is one of the most cost-effective
                    security investments MedDefense can make.

Residual Risk:      After permanent fix (FortiOS 7.0.12):
                    Likelihood: 1 (Rare, ARO ~0.05 for new zero-day)
                    Impact: 5 (Catastrophic, SLE unchanged)
                    Residual Score: 5 - LOW
                    
                    NOTE: The impact remains 5 (Catastrophic) because
                    the firewall remains a single point of failure.
                    If a NEW zero-day RCE affects FortiOS 7.0.12,
                    MedDefense is exposed again. The permanent
                    mitigation for this residual risk is:
                    - CG-007: Vulnerability Management Program (rapid
                      patching for future CVEs)
                    - CG-010: Consider redundant firewall in FY2027
                      budget (estimated $15,000 one-time + $3,000/yr
                      support)

KRI:                KRI-005: New FortiOS CVE with CVSS >= 9.0 published
                    Source: NVD, Fortinet PSIRT, CISA KEV
                    Threshold: Any new critical FortiOS CVE → review
                    within 24 hours. If internet-facing service affected
                    → immediate workaround within 4 hours.

                    KRI-006: FortiGate configuration change detected
                    (SSL-VPN re-enabled, admin account created, firewall
                    rule modified) without approved change ticket.
                    Source: FortiGate syslog → MSSP (T3-5)
                    Threshold: Any unauthorized config change →
                    IMMEDIATE INCIDENT RESPONSE.

                    KRI-007: FortiGate support contract within 30 days
                    of expiration.
                    Source: Fortinet support portal, procurement calendar
                    Threshold: 90 days before expiry → renew. 30 days →
                    escalate to CISO. Expired → EMERGENCY (current state).

Last Reviewed:      29/07/2026 (Created in response to CISA Advisory)
Next Review:        30/07/2026 (Post-patching verification)
                    01/10/2026 (Return to quarterly schedule)


================================================================================
PART 3: REGISTER GOVERNANCE TEST
================================================================================

----------------------------------------------------------------------
GOVERNANCE TRIGGER FROM 1x03 T9
----------------------------------------------------------------------

The Risk Register Governance Note from 1x03 T9 defined the following
out-of-cycle review triggers:

QUOTE FROM 1x03 T9 GOVERNANCE NOTE:

  "OUT-OF-CYCLE REVIEW TRIGGERS:
   The Risk Register shall be reviewed outside the quarterly schedule
   when ANY of the following conditions are met:
   
   1. A new vulnerability with CVSS >= 9.0 is identified on a
      MedDefense system that is internet-facing or processes ePHI.
      
   2. A confirmed security incident occurs at MedDefense or at a
      peer healthcare organization in the same geographic region.
      
   3. A CISA Alert, CISA Emergency Directive, or CISA Known Exploited
      Vulnerability (KEV) catalog update directly references a product
      or system in use at MedDefense.
      
   4. The Annual Loss Expectancy (ALE) for any single risk changes by
      more than 50% due to new threat intelligence or business changes.
      
   5. A regulatory change (HIPAA, HITECH, state law) imposes new
      encryption or data protection requirements."

----------------------------------------------------------------------
DOES THE CRIMSON TIDE ADVISORY QUALIFY?
----------------------------------------------------------------------

YES. The Crimson Tide advisory triggers an out-of-cycle review under
MULTIPLE criteria simultaneously. This is an overwhelming governance
signal that immediate action is required.

CRITERION 1: CVSS >= 9.0 on Internet-Facing System
  STATUS: TRIGGERED
  DETAIL: CVE-2023-27997 has CVSS 9.8 (CRITICAL).
  AFFECTED SYSTEM: fw-meddefense-01 (FortiGate 100E, FortiOS 7.0.9).
  INTERNET-FACING: Yes. The SSL-VPN service was exposed on the public
  internet on TCP/443 until disabled on 29/07/2026.
  PROCESSES ePHI: Yes. The firewall terminates VPN tunnels carrying
  patient data between all 3 MedDefense sites.
  This trigger ALONE mandates an immediate out-of-cycle review.

CRITERION 2: Confirmed Security Incident at Peer Healthcare Organization
  STATUS: TRIGGERED
  DETAIL: Hospital C, a peer healthcare organization 45 miles from
  MedDefense Central, is in ACTIVE CONTAINMENT due to a Crimson Tide
  ransomware attack. The attack vector (CVE-2023-27997) and target
  profile (hospital with unencrypted patient database) match MedDefense's
  vulnerability profile exactly.
  SAME GEOGRAPHIC REGION: Yes. 45 miles is within the same healthcare
  market and likely shares patient referral networks.
  This trigger ALONE mandates an immediate out-of-cycle review.

CRITERION 3: CISA KEV Catalog Update Referencing MedDefense Product
  STATUS: TRIGGERED
  DETAIL: CVE-2023-27997 is listed in the CISA Known Exploited
  Vulnerabilities (KEV) catalog. The CISA advisory AA23-XXX specifically
  names Crimson Tide and describes the attack chain targeting FortiOS
  SSL-VPN. MedDefense uses FortiOS 7.0.9, which is in the affected
  version range.
  DIRECT REFERENCE: Yes. FortiOS is explicitly named as the affected
  product in both the CVE and the CISA advisory.
  This trigger ALONE mandates an immediate out-of-cycle review.

CRITERION 4: ALE Change >50% for Any Single Risk
  STATUS: TRIGGERED
  DETAIL: RISK-001 (Ransomware) ALE increased from $7,262,500 to
  $27,964,000, a change of +285%. This far exceeds the 50% threshold.
  NEW RISK ADDED: RISK-NEW-001 (FortiGate CVE) with ALE of $27,964,000
  (pre-workaround) or $5,243,250 (post-workaround).
  This trigger ALONE mandates an immediate out-of-cycle review.

CRITERION 5: Regulatory Change
  STATUS: NOT TRIGGERED (no new HIPAA or state law changes associated
  with this advisory).

----------------------------------------------------------------------
GOVERNANCE TEST RESULT
----------------------------------------------------------------------

The Crimson Tide advisory triggers FOUR of FIVE out-of-cycle review
criteria. This is the strongest possible governance signal that the
Risk Register MUST be updated immediately. If MedDefense's governance
process is functioning correctly:

1. The CISO (James Chen) should have been automatically alerted by
   ANY ONE of these triggers. Four simultaneous triggers is an
   unambiguous "all hands" signal.

2. The Risk Register update (this document) must be completed within
   4 hours of the trigger event (per 1x03 T9: "out-of-cycle reviews
   shall be completed within 4 business hours for critical triggers").

3. The updated Risk Register must be presented to the Board within
   24 hours (emergency Board briefing, T2-5 in the 72-Hour Plan).

4. All treatment decisions for affected risks must be re-evaluated
   against the updated ALE and ARO (completed in this document and
   in 1x05 T5 ALE Update).

GOVERNANCE COMPLIANCE STATUS:
  [x] Trigger detected: 29/07/2026 (date of CISA advisory publication)
  [x] Out-of-cycle review initiated: 29/07/2026
  [x] Risk Register updated: 29/07/2026 (this document)
  [x] ALE recalculated: 29/07/2026 (1x05 T5)
  [x] Treatment decisions re-evaluated: 29/07/2026
  [x] Emergency Board briefing scheduled: 30/07/2026 (T2-5)
  [x] 72-Hour Emergency Plan activated: 29/07/2026 (1x05 T3)

The governance process worked as designed. The triggers were recognized,
the review was conducted, and the appropriate actions were initiated.
The risk is not that the governance process failed — the risk is that
the controls it mandates are not yet deployed. That is the gap the
72-Hour Plan closes.


================================================================================
UPDATED RISK REGISTER SUMMARY
================================================================================

+----------+------------------+----------+----------+----------+----------+----------+
| RISK ID  | TITLE            | LIKELIHOOD| IMPACT  | SCORE    | ALE      | TREATMENT|
+----------+------------------+----------+----------+----------+----------+----------+
| RISK-001 | Crimson Tide     | 5 (Almost| 5 (Catas-| 25       | $27.96M  | MITIGATE |
|(UPDATED) | Ransomware       | Certain) | trophic) | CRITICAL |          | URGENTLY |
+----------+------------------+----------+----------+----------+----------+----------+
| RISK-NEW | FortiGate CVE-   | 5 (Almost| 5 (Catas-| 25       | $27.96M  | MITIGATE |
| -001     | 2023-27997 RCE   | Certain) | trophic) | CRITICAL | (pre-T1) | IMMED.   |
+----------+------------------+----------+----------+----------+----------+----------+

Both risks at MAXIMUM score (25/25).
Both risks being actively mitigated per 72-Hour Emergency Plan.
Post-72-Hour residual scores: RISK-001 → 4 (LOW), RISK-NEW-001 → 5 (LOW).


================================================================================
REFERENCES
================================================================================

- 1x03 T10 Risk Register (Original entries)
- 1x03 T9 Governance Note (Review triggers)
- 1x03 T6 ALE Calculation (Original ALE)
- 1x03 T7 Cost-Benefit Analysis
- 1x05 T0 CISA Advisory Analysis
- 1x05 T1 CVE Deep Dive
- 1x05 T5 ALE Update
- 1x05 T3 72-Hour Emergency Plan
- CISA Advisory AA23-XXX: Crimson Tide Ransomware Campaign
- CISA KEV Catalog: CVE-2023-27997
- NIST SP 800-30 Rev 1: Guide for Conducting Risk Assessments


================================================================================
END OF RISK REGISTER UPDATE
================================================================================
