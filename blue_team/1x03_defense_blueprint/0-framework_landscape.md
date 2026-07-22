================================================================================
                    FRAMEWORK LANDSCAPE - MEDDEFENSE HEALTH SYSTEMS
                    Task 0: The Framework Landscape
================================================================================

Exercise: Task 0 - The Framework Landscape
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Understand the purpose, scope and relationship of the three major
          security frameworks used in enterprise defense.

Sources: NIST CSF 2.0, CIS Controls v8, ISO/IEC 27001


================================================================================
PART 1: THREE-FRAMEWORK SUMMARY
================================================================================

NIST CSF 2.0
------------
+----------------------------------------------------------------------------+
| WHAT IT IS:                                                                |
| The NIST Cybersecurity Framework (CSF) 2.0 is a guidance document         |
| published by the National Institute of Standards and Technology (NIST)   |
| that provides a taxonomy of high-level cybersecurity outcomes for         |
| managing cybersecurity risks [citation:4]. It is designed to be used by   |
| any organization — regardless of size, sector, or maturity [citation:4].  |
|                                                                             |
| PRIMARY PURPOSE:                                                           |
| To provide a common language for organizations to understand, assess,    |
| prioritize, and communicate their cybersecurity efforts [citation:4].     |
| It helps organizations answer "What should we do ?" to manage cyber risk  |
| [citation:11].                                                             |
|                                                                             |
| STRUCTURE:                                                                 |
| CSF 2.0 is organized around six core Functions [citation:1]:              |
| - GOVERN: Establish and monitor cybersecurity risk management strategy   |
| - IDENTIFY: Understand assets, risks, and vulnerabilities                |
| - PROTECT: Implement safeguards                                           |
| - DETECT: Identify cybersecurity events                                  |
| - RESPOND: Take action against detected events                           |
| - RECOVER: Restore capabilities after an incident                        |
| These Functions contain 22 Categories and 106 Subcategories [citation:1]. |
|                                                                             |
| TYPICAL USERS:                                                             |
| Organizations of all sizes and sectors worldwide use NIST CSF. It is      |
| the most downloaded NIST technical publication with over 3 million        |
| views and downloads [citation:7]. It is especially popular in critical   |
| infrastructure sectors like healthcare [citation:1].                      |
+----------------------------------------------------------------------------+


CIS CONTROLS V8
---------------
+----------------------------------------------------------------------------+
| WHAT IT IS:                                                                |
| The CIS Controls are a prioritized set of cybersecurity safeguards       |
| published by the Center for Internet Security (CIS), a nonprofit          |
| organization [citation:11]. Version 8.1 was released in June 2024,        |
| introducing a new Governance security function [citation:2].              |
|                                                                             |
| PRIMARY PURPOSE:                                                           |
| To provide specific, actionable, and prioritized ways to protect against  |
| the most prevalent cyber attacks [citation:2][citation:11]. They answer   |
| "How should we do it ?" by giving concrete safeguards.                    |
|                                                                             |
| STRUCTURE:                                                                 |
| Version 8 is organized into 18 Controls (formerly 20 in v7) [citation:11]:|
| 1. Inventory and Control of Enterprise Assets                            |
| 2. Inventory and Control of Software Assets                              |
| 3. Data Protection                                                        |
| 4. Secure Configuration of Enterprise Assets                             |
| 5. Access Control Management                                              |
| 6. Continuous Vulnerability Management                                   |
| 7. Audit Log Management                                                   |
| 8. Email and Web Browser Protections                                     |
| 9. Malware Defenses                                                       |
| 10. Data Recovery                                                         |
| 11. Network Infrastructure Management                                     |
| 12. Network Monitoring and Defense                                        |
| 13. Security Awareness and Skills Training                               |
| 14. Service Provider Management                                           |
| 15. Application Software Security                                         |
| 16. Incident Response Management                                          |
| 17. Penetration Testing                                                   |
| Implementation Groups (IG1, IG2, IG3) allow organizations to start with   |
| IG1 (56 safeguards) and progress [citation:11].                          |
|                                                                             |
| TYPICAL USERS:                                                             |
| Any enterprise seeking practical, prioritized security guidance. They     |
| are mapped to multiple frameworks including NIST CSF, HIPAA, and PCI DSS  |
| [citation:2][citation:11]. They are referenced in state cybersecurity     |
| safe harbor statutes in Ohio, Utah, Connecticut, and Iowa [citation:2].   |
+----------------------------------------------------------------------------+


ISO/IEC 27001
-------------
+----------------------------------------------------------------------------+
| WHAT IT IS:                                                                |
| ISO/IEC 27001 is the world's best-known international standard for        |
| Information Security Management Systems (ISMS), jointly published by     |
| ISO and IEC [citation:12][citation:9][citation:3]. It specifies           |
| requirements for establishing, implementing, maintaining, and             |
| continually improving an ISMS [citation:3][citation:12].                  |
|                                                                             |
| PRIMARY PURPOSE:                                                           |
| To provide a risk-based framework for protecting information assets       |
| through a management system that preserves confidentiality, integrity,   |
| and availability [citation:3][citation:12]. It answers "Can we prove      |
| we are doing it ?" through certification [citation:6].                    |
|                                                                             |
| STRUCTURE:                                                                 |
| ISO 27001:2022 is organized with 14 security control sections [citation:9]:|
| 1. Information Security Policy                                            |
| 2. Organization of Information Security                                  |
| 3. Risk Assessment and Treatment                                          |
| 4. Asset Management                                                        |
| 5. Access Control                                                          |
| 6. Cryptography                                                            |
| 7. Physical Security                                                       |
| 8. Operations Security                                                     |
| 9. Communications Security                                                 |
| 10. System Acquisition, Development and Maintenance                      |
| 11. Supplier Relationships                                                 |
| 12. Compliance with Legal Requirements                                   |
| 13. Information Quality Management                                        |
| 14. Risk Monitoring and Review                                             |
| It uses a top-down, risk-based approach and requires a documented         |
| management system [citation:9].                                           |
|                                                                             |
| TYPICAL USERS:                                                             |
| Organizations of all sizes and sectors worldwide. Over 70,000             |
| certificates are reported in 150+ countries across all economic sectors   |
| [citation:12][citation:6]. It is frequently referenced in laws,           |
| regulations, and commercial contracts [citation:6].                       |
+----------------------------------------------------------------------------+


================================================================================
PART 2: RELATIONSHIP MAP
================================================================================

+----------------------------------------------------------------------------+
| RELATIONSHIP MAP                                                           |
|                                                                             |
| The three frameworks are NOT competitors. They serve different purposes   |
| and can be used together in a complementary manner:                       |
|                                                                             |
| NIST CSF answers "WHAT should we do ?"                                    |
| It provides a strategic, high-level framework of cybersecurity outcomes  |
| organized by six Functions (Govern, Identify, Protect, Detect, Respond,   |
| Recover). It tells you what capabilities you need to build [citation:4].  |
|                                                                             |
| CIS Controls answers "HOW should we do it ?"                              |
| It provides 18 specific, prioritized safeguards (Inventory and Control    |
| of Enterprise Assets, Data Protection, etc.) that tell you exactly what   |
| technical and operational steps to take. It is the implementation guide   |
| [citation:2][citation:11].                                                |
|                                                                             |
| ISO 27001 answers "CAN WE PROVE we are doing it ?"                        |
| It provides a management system framework (ISMS) with requirements for    |
| documentation, internal audits, and continual improvement [citation:3][citation:12]. |
| It enables third-party certification that demonstrates compliance to      |
| regulators, partners, and customers [citation:6][citation:9].             |
|                                                                             |
| HOW THEY WORK TOGETHER:                                                    |
| An organization can use NIST CSF to define its target security posture   |
| (the "what"), CIS Controls to implement the technical safeguards         |
| (the "how"), and ISO 27001 to formalize the management system and         |
| achieve certification (the "proof") [citation:2][citation:11].            |
|                                                                             |
| CIS Controls v8.1 was specifically aligned with NIST CSF 2.0 [citation:2]. |
| Both frameworks provide informative references to each other, enabling    |
| seamless mapping [citation:7].                                             |
+----------------------------------------------------------------------------+


================================================================================
PART 3: MEDDEFENSE FRAMEWORK SELECTION
================================================================================

+----------------------------------------------------------------------------+
| RECOMMENDED FRAMEWORK SELECTION                                            |
|                                                                             |
| MedDefense should adopt NIST CSF 2.0 as its STRATEGIC BACKBONE,           |
| supplemented by CIS Controls v8 for practical implementation guidance.    |
|                                                                             |
| JUSTIFICATION:                                                             |
|                                                                             |
| 1. NIST CSF 2.0 is the MOST SUITABLE strategic backbone because:          |
|    - It is designed for organizations of all sizes and sectors            |
|      [citation:4]                                                          |
|    - It provides a common language for communicating with the Board      |
|      and regulators [citation:4]                                          |
|    - It is widely used in healthcare and critical infrastructure         |
|      [citation:1]                                                         |
|    - It does not require certification, reducing administrative burden   |
|      for a small team                                                     |
|    - It can be implemented incrementally using Organizational Profiles   |
|      and Tiers [citation:7]                                               |
|                                                                             |
| 2. CIS Controls v8 is the RECOMMENDED IMPLEMENTATION TOOL because:        |
|    - It provides specific, actionable safeguards [citation:2][citation:11]|
|    - It offers Implementation Groups (IG1, IG2, IG3) allowing phased     |
|      adoption [citation:11]                                               |
|    - IG1 (56 safeguards) is achievable for a small security team         |
|    - It is mapped to NIST CSF 2.0 [citation:2]                           |
|                                                                             |
| 3. WHY NOT ISO 27001 NOW:                                                 |
|    - ISO 27001 requires significant documentation, formal audits, and     |
|      management commitment [citation:9]                                   |
|    - MedDefense has limited staff (1 security analyst, 1 deputy CISO)    |
|    - Certification is resource-intensive (typically 12-18 months)        |
|    - The Board's priority is risk reduction, not certification           |
|                                                                             |
| However, ISO 27001 should be considered as a 3-5 YEAR GOAL to            |
| demonstrate regulatory compliance and build stakeholder trust            |
| [citation:6][citation:12].                                               |
|                                                                             |
| RECOMMENDED APPROACH:                                                      |
| Step 1: Use NIST CSF 2.0 to define target outcomes and create             |
|         Organizational Profiles [citation:7]                             |
| Step 2: Use CIS Controls v8 (starting with IG1) as the implementation    |
|         roadmap [citation:11]                                             |
| Step 3: Map existing controls (from 1x00) to CIS Safeguards             |
| Step 4: Build a phased roadmap using CSF Tiers and CIS Implementation     |
|         Groups                                                            |
| Step 5: Consider ISO 27001 certification as a 3-5 year strategic goal    |
+----------------------------------------------------------------------------+


================================================================================
KEY FINDINGS
================================================================================

1. NIST CSF 2.0 provides the "WHAT" - a strategic framework of cybersecurity
   outcomes organized around 6 Functions (Govern, Identify, Protect, Detect,
   Respond, Recover) [citation:4].

2. CIS Controls v8 provides the "HOW" - 18 prioritized, actionable
   safeguards with Implementation Groups (IG1, IG2, IG3) for phased
   adoption [citation:2][citation:11].

3. ISO 27001 provides the "PROOF" - a certifiable ISMS standard that
   demonstrates compliance to regulators and stakeholders [citation:3]
   [citation:12].

4. The three frameworks are complementary and can be used together [citation:2]
   [citation:11]. CIS Controls v8.1 was specifically aligned with NIST
   CSF 2.0 [citation:2].

5. For MedDefense, the recommended approach is:
   - Strategic backbone: NIST CSF 2.0 (best fit for healthcare, no
     certification required)
   - Implementation guidance: CIS Controls v8 (practical, prioritized,
     IG1 achievable)
   - Long-term goal: ISO 27001 certification (3-5 year target)


================================================================================
REFERENCES
================================================================================

- NIST CSF 2.0: https://www.nist.gov/cyberframework
- CIS Controls v8: https://www.cisecurity.org/controls
- ISO/IEC 27001: https://www.iso.org/standard/27001

Cross-References:
- Security Posture Assessment (1x00)
- Threat Landscape Report (1x01)
- Vulnerability Assessment (1x02)


================================================================================
END OF FRAMEWORK LANDSCAPE REPORT
================================================================================
