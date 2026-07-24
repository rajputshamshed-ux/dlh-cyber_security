================================================================================
                    SECURITY STRATEGY DOCUMENT
                    MEDDEFENSE HEALTH SYSTEMS
================================================================================

Document Title:  Security Strategy Document - MedDefense Health Systems
Prepared For:    Board of Directors, MedDefense Health Systems
Prepared By:     shamshed rajput, Junior Security Analyst
Approved By:     James Chen, Deputy CISO
Date:            24/07/2026
Classification:  CONFIDENTIAL - Internal Use Only

Companion Documents:
- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment Summary (1x02)


================================================================================
1. EXECUTIVE SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| EXECUTIVE SUMMARY                                                          |
|                                                                             |
| CURRENT RISK POSTURE:                                                      |
| MedDefense Health Systems faces a HIGH residual risk posture. While the   |
| organization has made significant progress identifying vulnerabilities   |
| and threats, critical gaps remain. The flat network architecture,        |
| permanent vulnerabilities in legacy medical devices (MRI Windows XP),   |
| and absence of detection capabilities create a HIGH likelihood of a      |
| ransomware attack or data breach within the next 12 months.              |
|                                                                             |
| STRATEGIC APPROACH:                                                       |
| MedDefense will adopt a NIST CSF 2.0 strategic framework with CIS        |
| Controls v8 as the implementation roadmap. The strategy is organized     |
| around a $120,000 annual security budget, with a phased approach        |
| prioritizing: (1) immediate quick wins, (2) foundational controls      |
| (MFA, segmentation, SIEM), and (3) long-term architecture changes.     |
|                                                                             |
| TOTAL INVESTMENT:                                                         |
| $104,400 in technology + $15,600 in people/process = $120,000 total    |
| Expected ALE Reduction: $7,133,210 (68:1 ROI)                          |
|                                                                             |
| TOP 3 PRIORITY ACTIONS:                                                   |
| 1. Implement Network Segmentation (6 VLANs) - $12,000 - 1 week          |
| 2. Deploy MFA on VPN and Administrative Accounts - $8,000 - 1 month    |
| 3. Deploy SIEM (Wazuh) + Daytime-Only SOC - $40,000 - 1 month          |
+----------------------------------------------------------------------------+


================================================================================
2. GOVERNANCE FRAMEWORK
================================================================================

2.1 FRAMEWORK SELECTION RATIONALE
---------------------------------
+----------------------------------------------------------------------------+
| MedDefense will adopt NIST CSF 2.0 as its STRATEGIC BACKBONE and CIS    |
| Controls v8 as its IMPLEMENTATION ROADMAP.                                |
|                                                                             |
| NIST CSF 2.0 answers "WHAT should we do ?"                              |
| - Provides a common language for Board and security team                 |
| - Organized around 6 Functions: GOVERN, IDENTIFY, PROTECT, DETECT,       |
|   RESPOND, RECOVER                                                        |
| - No certification required - reduces administrative burden              |
|                                                                             |
| CIS Controls v8 answers "HOW should we do it ?"                         |
| - 18 prioritized, actionable safeguards                                 |
| - Implementation Groups (IG1, IG2, IG3) allow phased adoption           |
| - IG1 (56 safeguards) is achievable for a small security team            |
|                                                                             |
| ISO 27001 is a 3-5 YEAR GOAL for certification.                         |
+----------------------------------------------------------------------------+

2.2 NIST CSF CURRENT VS TARGET PROFILE
--------------------------------------
+------------------+---------------------+---------------------+
| Function         | Current Level       | Target Level        |
|                  |                     | (12 months)         |
+------------------+---------------------+---------------------+
| GOVERN           | NOT IMPLEMENTED     | PARTIAL             |
| IDENTIFY         | PARTIAL             | MANAGED             |
| PROTECT          | PARTIAL             | MANAGED             |
| DETECT           | NOT IMPLEMENTED     | PARTIAL             |
| RESPOND          | NOT IMPLEMENTED     | PARTIAL             |
| RECOVER          | NOT IMPLEMENTED     | PARTIAL             |
+------------------+---------------------+---------------------+

2.3 CIS CONTROLS MATURITY SCORECARD
-----------------------------------
+------------------+---------------------+------------------------------------------+
| Score            | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| IMPLEMENTED      | 0                   | 0%                                       |
| PARTIAL          | 8                   | 44.4%                                    |
| NOT IMPLEMENTED  | 10                  | 55.6%                                    |
+------------------+---------------------+------------------------------------------+

TOP 5 PRIORITY CIS CONTROLS:
1. CIS Control 5 - Access Control Management (MFA)
2. CIS Control 6 - Continuous Vulnerability Management
3. CIS Control 11 - Network Infrastructure Management
4. CIS Control 7 - Audit Log Management
5. CIS Control 16 - Incident Response Management

2.4 GOVERNANCE STRUCTURE AND ROLES
----------------------------------
+---------------------------+--------------------------------------------------+
| Role                      | Person/Position                                  |
+---------------------------+--------------------------------------------------+
| Data Owner                | Department Heads                                 |
| Data Controller           | CEO (Dr. Patricia Morales)                       |
| Data Processor            | MedTech Solutions, Vendors                       |
| Data Custodian/Steward    | IT Department (Sarah Park)                       |
| Interim Security Lead     | James Chen (Deputy CISO)                         |
+---------------------------+--------------------------------------------------+

RACI MATRIX SUMMARY:
- CEO: Accountable for Budget, Policy, Risk (executive decisions)
- James Chen: Accountable for security operations, Policy drafting
- Sarah Park: Responsible for technical execution
- Dept Heads: Accountable for Data Ownership; Consulted on Risk
- Security Analyst: Responsible for Training, Vendor Risk, Audit


================================================================================
3. QUANTITATIVE RISK ANALYSIS
================================================================================

3.1 TOP 5 RISKS BY ALE
----------------------
+----------+------------------+------------------+------------------+
| Rank     | Risk             | ALE              | Treatment        |
+----------+------------------+------------------+------------------+
| #1       | Data Breach      | $4,310,625       | MITIGATE         |
|          | (PHI Exposure)   |                  |                  |
+----------+------------------+------------------+------------------+
| #2       | VPN Compromise   | $1,334,945       | MITIGATE         |
|          | (Full Network)   |                  |                  |
+----------+------------------+------------------+------------------+
| #3       | Insider Data     | $360,000         | MITIGATE         |
|          | Theft            |                  |                  |
+----------+------------------+------------------+------------------+
| #4       | Ransomware EHR   | $273,615         | MITIGATE         |
+----------+------------------+------------------+------------------+
| #5       | Medical IoT      | $88,000          | ACCEPT           |
|          | (Patient Safety) |                  | (with Compens.)  |
+----------+------------------+------------------+------------------+

3.2 RISK REGISTER SUMMARY
-------------------------
+----------+------------------+------------------+------------------+
| Risk ID  | Risk Description | Inherent Score   | Treatment        |
+----------+------------------+------------------+------------------+
| RISK-001 | Data Breach EHR  | 25 (CRITICAL)    | MITIGATE         |
| RISK-002 | VPN Compromise   | 20 (CRITICAL)    | MITIGATE         |
| RISK-003 | Ransomware EHR   | 20 (CRITICAL)    | MITIGATE         |
| RISK-004 | Insider Data     | 15 (HIGH)        | MITIGATE         |
|          | Theft            |                  |                  |
| RISK-005 | Medical IoT      | 15 (HIGH)        | ACCEPT           |
|          | (Patient Safety) |                  |                  |
| RISK-006 | Supply Chain     | 15 (HIGH)        | MITIGATE         |
| RISK-007 | No IR Capability | 20 (CRITICAL)    | MITIGATE         |
| RISK-008 | Westside Breach  | 12 (HIGH)        | ACCEPT           |
| RISK-009 | Shadow IT        | 16 (HIGH)        | ACCEPT (Partial) |
| RISK-010 | PACS Data Loss   | 15 (HIGH)        | MITIGATE         |
+----------+------------------+------------------+------------------+

3.3 RISK APPETITE STATEMENT
---------------------------
+----------------------------------------------------------------------------+
| MedDefense Health Systems is committed to protecting patient safety and    |
| preserving the confidentiality, integrity, and availability of patient     |
| data as its highest priorities. The organization accepts a MODERATE        |
| level of operational and financial risk, provided that all risks to        |
| patient safety are either mitigated or accompanied by documented           |
| compensating measures. Risks with an inherent score of 20 or above         |
| (CRITICAL) require explicit Board or CEO approval for acceptance.          |
| Acceptance decisions are documented, reviewed quarterly, and re-evaluated  |
| when the threat landscape changes.                                        |
+----------------------------------------------------------------------------+


================================================================================
4. CONTROL STRATEGY
================================================================================

4.1 COST-BENEFIT ANALYSIS RESULTS
---------------------------------
+----------+------------------+------------------+------------------+
| Rank     | Control          | Annual Cost      | Net Value        |
+----------+------------------+------------------+------------------+
| #1       | Network          | $12,000          | $1,839,696       |
|          | Segmentation     |                  |                  |
+----------+------------------+------------------+------------------+
| #2       | MFA Deployment   | $8,000           | $1,767,756       |
+----------+------------------+------------------+------------------+
| #3       | SIEM (Wazuh)     | $5,000           | $1,474,796       |
+----------+------------------+------------------+------------------+
| #4       | EDR Upgrade      | $30,000          | $711,636         |
+----------+------------------+------------------+------------------+
| #5       | Offsite Backup   | $14,400          | $629,024         |
+----------+------------------+------------------+------------------+
| #6       | Daytime-Only SOC | $35,000          | $675,302         |
+----------+------------------+------------------+------------------+
| #7       | Westside         | $5,000           | $58,723          |
|          | Firewall         |                  |                  |
+----------+------------------+------------------+------------------+
| #8       | IoT Isolation    | $18,000          | $77,585          |
+----------+------------------+------------------+------------------+

4.2 BUDGET ALLOCATION
---------------------
+----------------------------------------------------------------------------+
| TOTAL BUDGET: $120,000                                                     |
|                                                                             |
| CONTROLS FUNDED (6 controls):                                              |
| 1. Network Segmentation:                         $12,000                  |
| 2. MFA Deployment:                              $8,000                   |
| 3. SIEM (Wazuh):                                $5,000                   |
| 4. EDR Upgrade:                                 $30,000                  |
| 5. Offsite Backup:                              $14,400                  |
| 6. Daytime-Only SOC:                            $35,000                  |
|                                                                             |
| Total spend:                                   $104,400                  |
| Budget remaining:                             $15,600                   |
|                                                                             |
| PEOPLE AND PROCESS ($15,600):                                               |
| - Security awareness training:                 $8,000                    |
| - IR plan development + tabletop:              $5,000                    |
| - Policy documentation:                        $2,600                    |
+----------------------------------------------------------------------------+

4.3 QUICK WINS (0-2 WEEKS)
--------------------------
+----------+------------------+------------------------------------------+
| Quick    | Title            | Risk Reduction                           |
| Win #    |                  |                                          |
+----------+------------------+------------------------------------------+
| #1       | Disable Default  | Removes easiest path to IoT compromise  |
|          | Credentials      |                                          |
+----------+------------------+------------------------------------------+
| #2       | Disable SSH      | Eliminates credential theft via SSH     |
|          | Password Auth    |                                          |
+----------+------------------+------------------------------------------+
| #3       | Restrict         | Eliminates direct database access       |
|          | PostgreSQL       |                                          |
+----------+------------------+------------------------------------------+
| #4       | Enable Screen    | Prevents unauthorized PHI access        |
|          | Lock             |                                          |
+----------+------------------+------------------------------------------+
| #5       | Phishing         | Reduces phishing success rate           |
|          | Awareness        |                                          |
+----------+------------------+------------------------------------------+

TOTAL COST: $0
TOTAL TIMELINE: 7 days (parallel execution)


================================================================================
5. ARCHITECTURE RECOMMENDATIONS
================================================================================

5.1 NETWORK SEGMENTATION DESIGN (6 ZONES)
-----------------------------------------
+----------+------------------+------------------+---------------------------+
| Zone     | Name             | IP Range         | Systems Included          |
+----------+------------------+------------------+---------------------------+
| VLAN 10  | Server Zone      | 10.10.10.0/24    | EHR, AD, Billing, Backup, |
|          |                  |                  | PACS, File Server         |
+----------+------------------+------------------+---------------------------+
| VLAN 20  | Clinical Zone    | 10.10.20.0/24    | Nurse Stations,           |
|          |                  |                  | Physician Workstations    |
+----------+------------------+------------------+---------------------------+
| VLAN 30  | Medical Device   | 10.10.30.0/24    | Monitors, Pumps, MRI, CT  |
|          | Zone             |                  |                           |
+----------+------------------+------------------+---------------------------+
| VLAN 40  | Management Zone  | 10.10.40.0/24    | IT Admin Workstations,    |
|          |                  |                  | Security Tools            |
+----------+------------------+------------------+---------------------------+
| VLAN 50  | Guest/IoT Zone   | 10.10.50.0/24    | Guest WiFi, Printers,     |
|          |                  |                  | HVAC                      |
+----------+------------------+------------------+---------------------------+
| VLAN 60  | Westside Zone    | 10.10.60.0/24    | Westside Clinic           |
+----------+------------------+------------------+---------------------------+

5.2 KEY FIREWALL RULES
----------------------
+----------+------------------+------------------+-----------------+
| Rule #   | Source           | Destination      | Action           |
+----------+------------------+------------------+-----------------+
| 1        | Server (EHR)     | Clinical (443)   | ALLOW            |
| 2        | Clinical         | Server (EHR)     | ALLOW            |
| 3        | Clinical         | Medical Device   | ALLOW            |
| 4        | Server (PACS)    | Medical Device   | ALLOW            |
| 5        | Management       | ALL Zones (SSH)  | ALLOW (MFA)      |
| 6        | Guest Zone       | ANY Internal     | DENY             |
| 7        | Clinical         | PostgreSQL       | DENY             |
+----------+------------------+------------------+-----------------+

5.3 KILL CHAIN DISRUPTION
-------------------------
+----------+------------------+------------------------------------------+
| Kill     | Title            | Disrupted by Segmentation?               |
| Chain    |                  |                                          |
+----------+------------------+------------------------------------------+
| KC #1    | VPN Ransomware   | ✅ YES - 100% (all 5 steps)              |
| KC #2    | Phishing → EHR   | ✅ YES - 100% (all 5 steps)              |
| KC #3    | IoT Patient      | ✅ YES - 100% (all 5 steps)              |
|          | Safety           |                                          |
| KC #4    | MRI → EHR        | ✅ YES - 100% (all 5 steps)              |
| KC #5    | Supply Chain     | PARTIAL (vendor access remains)          |
+----------+------------------+------------------------------------------+

TOTAL KILL CHAINS DISRUPTED: 4 out of 5 (80%)


================================================================================
6. POLICY FOUNDATION
================================================================================

6.1 ACCEPTABLE USE POLICY (AUP) SUMMARY
---------------------------------------
+----------------------------------------------------------------------------+
| The Acceptable Use Policy (AUP) defines the responsibilities of every      |
| user who accesses MedDefense systems. Key provisions include:              |
|                                                                             |
| - PROHIBITED: Accessing PHI without authorization                        |
| - PROHIBITED: USB drives on clinical workstations (unless approved)     |
| - PROHIBITED: Shadow IT (unauthorized devices/cloud services)           |
| - PROHIBITED: Shared accounts                                             |
| - REQUIRED: MFA for all remote access                                    |
| - REQUIRED: Screen lock after 5 minutes                                 |
| - REQUIRED: Annual security awareness training                          |
| - REQUIRED: Password 12 characters, complexity, 90-day rotation         |
| - REQUIRED: Immediate reporting of security incidents                   |
|                                                                             |
| Enforcement: Verbal warning → Written warning → Suspension → Termination  |
+----------------------------------------------------------------------------+

6.2 POLICY ROADMAP
------------------
+----------+------------------+------------------------------------------+
| Timeline | Policy           | Priority                                 |
+----------+------------------+------------------------------------------+
| Month 1  | AUP (Drafted)    | IMMEDIATE                                |
| Month 2  | Password/        | HIGH                                     |
|          | Authentication   |                                          |
| Month 3  | Incident         | HIGH                                     |
|          | Response Plan    |                                          |
| Month 4  | Remote Access    | MEDIUM                                   |
| Month 5  | Data             | MEDIUM                                   |
|          | Classification   |                                          |
| Month 6  | Vendor Security  | MEDIUM                                   |
+----------+------------------+------------------------------------------+


================================================================================
7. RESIDUAL RISK ASSESSMENT
================================================================================

7.1 RED TEAM FINDINGS
---------------------
+----------------------------------------------------------------------------+
| RESIDUAL RISK: HIGH                                                         |
|                                                                             |
| The security blueprint survives the red team exercise, but with           |
| SIGNIFICANT RESIDUAL RISK.                                                 |
|                                                                             |
| Strengths:                                                                 |
| - Segmentation disrupts 80% of kill chains                              |
| - MFA stops credential theft                                              |
| - SIEM + Daytime SOC provides detection during business hours            |
| - Offsite backups enable recovery                                         |
|                                                                             |
| Weaknesses:                                                               |
| - MRI Windows XP is a permanent backdoor (GAP-007)                       |
| - Night-time attacks go undetected (Daytime-Only SOC)                    |
| - Insider threats remain (no DLP, no MDM)                                |
| - Vendor accounts (MedTech) still have direct access                    |
+----------------------------------------------------------------------------+

7.2 ACCEPTED RISKS WITH JUSTIFICATION
-------------------------------------
+----------+------------------+------------------------------------------+
| Risk ID  | Risk Description  | Justification                            |
+----------+------------------+------------------------------------------+
| RISK-005 | Medical IoT      | Compensating controls reduce risk to     |
|          | Compromise       | acceptable level; budget prioritized     |
+----------+------------------+------------------------------------------+
| RISK-008 | Westside         | Cost of mitigation > ALE; risk          |
|          | Perimeter        | contained; budget prioritized            |
+----------+------------------+------------------------------------------+
| RISK-009 | Shadow IT        | Known devices documented; quarterly      |
|          |                  | scanning detects new devices             |
+----------+------------------+------------------------------------------+

7.3 YEAR 2 PRIORITIES
---------------------
+----------+------------------+------------------------------------------+
| Priority | Initiative       | Estimated Cost                           |
+----------+------------------+------------------------------------------+
| #1       | MRI Windows XP   | $50,000                                  |
|          | Compensating     |                                          |
|          | Controls         |                                          |
+----------+------------------+------------------------------------------+
| #2       | 24/7 Managed SOC | $80,000                                  |
+----------+------------------+------------------------------------------+
| #3       | Medical IoT      | $18,000                                  |
|          | Isolation        |                                          |
+----------+------------------+------------------------------------------+
| #4       | DLP Deployment   | $15,000                                  |
+----------+------------------+------------------------------------------+


================================================================================
8. IMPLEMENTATION ROADMAP
================================================================================

PHASE 1: QUICK WINS + PROCUREMENT (MONTHS 1-2)
-----------------------------------------------
+----------+------------------+------------------------------------------+
| Timeline | Activity         | Owner                                    |
+----------+------------------+------------------------------------------+
| Week 1   | Disable Default  | Biomedical + IT Security                 |
|          | Credentials      |                                          |
+----------+------------------+------------------------------------------+
| Week 1   | Disable SSH      | IT Systems Team                          |
|          | Password Auth    |                                          |
+----------+------------------+------------------------------------------+
| Week 1   | Restrict         | DBA + IT Security                        |
|          | PostgreSQL       |                                          |
+----------+------------------+------------------------------------------+
| Week 2   | Enable Screen    | IT Systems Team + Nursing Leadership    |
|          | Lock             |                                          |
+----------+------------------+------------------------------------------+
| Week 2   | Phishing         | Security Analyst + HR                    |
|          | Awareness        |                                          |
+----------+------------------+------------------------------------------+
| Month 2  | Procure EDR,     | IT + Security                            |
|          | Offsite Backup   |                                          |
+----------+------------------+------------------------------------------+

SUCCESS METRICS:
- All quick wins completed within 2 weeks
- Phishing email open rate >80%
- Screen lock policy enforced on all clinical workstations
- EDR and offsite backup contracts signed

PHASE 2: CORE CONTROLS DEPLOYMENT (MONTHS 3-4)
-----------------------------------------------
+----------+------------------+------------------------------------------+
| Timeline | Activity         | Owner                                    |
+----------+------------------+------------------------------------------+
| Month 3  | Network          | IT Network Team                          |
|          | Segmentation     |                                          |
+----------+------------------+------------------------------------------+
| Month 3  | MFA Deployment   | IT + Security                            |
+----------+------------------+------------------------------------------+
| Month 3  | SIEM (Wazuh)     | IT + Security                            |
|          | Deployment       |                                          |
+----------+------------------+------------------------------------------+
| Month 4  | EDR Deployment   | IT + Security                            |
+----------+------------------+------------------------------------------+
| Month 4  | Offsite Backup   | IT (Backup Admin)                        |
|          | Implementation   |                                          |
+----------+------------------+------------------------------------------+
| Month 4  | Daytime-Only SOC | Security Analyst + James                 |
|          | Onboarding       |                                          |
+----------+------------------+------------------------------------------+

SUCCESS METRICS:
- Network segmentation completed (6 VLANs)
- MFA enabled on all VPN and administrative accounts
- SIEM collecting logs from critical systems
- EDR deployed on all servers
- Offsite backups configured and tested
- Daytime SOC operational

PHASE 3: VALIDATION + OPTIMIZATION (MONTHS 5-6)
------------------------------------------------
+----------+------------------+------------------------------------------+
| Timeline | Activity         | Owner                                    |
+----------+------------------+------------------------------------------+
| Month 5  | IR Plan          | James + Security Analyst                 |
|          | Development      |                                          |
+----------+------------------+------------------------------------------+
| Month 5  | Tabletop         | James + Sarah + Dept Heads               |
|          | Exercise         |                                          |
+----------+------------------+------------------------------------------+
| Month 5  | AUP Rollout      | HR + Security                            |
+----------+------------------+------------------------------------------+
| Month 6  | Vulnerability    | Security Analyst                         |
|          | Re-Scan          |                                          |
+----------+------------------+------------------------------------------+
| Month 6  | Risk Register    | James + Security Analyst                 |
|          | Update           |                                          |
+----------+------------------+------------------------------------------+
| Month 6  | Board            | James                                     |
|          | Presentation     |                                          |
+----------+------------------+------------------------------------------+

SUCCESS METRICS:
- IR plan documented and tabletop executed
- AUP signed by all employees
- Vulnerability scan shows 50% reduction in findings
- Risk register updated with control effectiveness
- Board presentation delivered


================================================================================
9. NEXT STEPS
================================================================================

+----------------------------------------------------------------------------+
| TRANSITION TO PROJECT 1x04: CRYPTOGRAPHIC FOUNDATION                       |
|                                                                             |
| This Security Strategy Document completes the 1x03 Defense Blueprint       |
| project. The next project (1x04: Cryptographic Foundation) will focus      |
| on:                                                                        |
|                                                                             |
| 1. DATA ENCRYPTION STRATEGY:                                               |
|    - Data at rest (EHR database, backups, endpoints)                      |
|    - Data in transit (internal network, DICOM, email)                    |
|    - Data in use (screen locking, memory encryption)                      |
|                                                                             |
| 2. KEY MANAGEMENT:                                                         |
|    - PKI infrastructure for MedDefense                                   |
|    - Certificate lifecycle management                                    |
|    - Key storage and rotation policies                                   |
|                                                                             |
| 3. CRYPTOGRAPHIC CONTROLS:                                                 |
|    - TLS/SSL configuration                                                |
|    - Email encryption                                                     |
|    - Database encryption                                                  |
|                                                                             |
| THE PATH FROM STRATEGY TO IMPLEMENTATION:                                  |
|                                                                             |
| Strategy (1x03) → Cryptographic Foundation (1x04) →                       |
| Compliance & Assurance → Continuous Improvement                           |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment Summary (1x02)
- NIST CSF 2.0
- CIS Controls v8


================================================================================
END OF SECURITY STRATEGY DOCUMENT
================================================================================
