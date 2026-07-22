================================================================================
                    GOVERNANCE ARCHITECTURE - MEDDEFENSE HEALTH SYSTEMS
                    Task 4: The Governance Architecture
================================================================================

Exercise: Task 4 - The Governance Architecture
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Design the security governance structure that MedDefense needs to
          execute and sustain a security program.

Sources: 1x00 Organization Structure, 1x03 NIST CSF Mapping (T1), 1x03 CIS Controls Audit (T2)


================================================================================
PART 1: RACI MATRIX
================================================================================

+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Activity                  | CEO              | Deputy CISO      | IT Director      | Department       | Security         |
|                           | (Dr. Morales)    | (James Chen)     | (Sarah Park)     | Heads            | Analyst (You)    |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security budget approval  | A                | R                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vulnerability remediation | I                | A                | R                | I                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response         | I                | A                | R                | C                | R                |
| execution                 |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | R                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness        | I                | A                | R                | C                | R                |
| training                  |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure - "the buck stops here")
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

KEY INSIGHTS:
- James Chen (Deputy CISO) is Accountable for MOST security activities
- Sarah Park (IT Director) is Responsible for remediation and incident execution
- The Security Analyst executes day-to-day activities (R for remediation, training, vendor risk)
- The CEO is Accountable for budget approval and risk acceptance (ultimate authority)


================================================================================
PART 2: ROLE DEFINITIONS
================================================================================

DATA OWNER: Department Heads (Clinical Directors, Finance Director, HR Director)

MEANING: The Data Owner has ultimate responsibility for a specific data set.
They determine who can access the data, what it can be used for, and how it
should be classified.

WHY: Department Heads know what data their department generates, why it is
needed, and how it is used in clinical or administrative operations.

DATA CONTROLLER: Dr. Patricia Morales (CEO) + James Chen (Deputy CISO)

MEANING: The Data Controller determines the purposes and means of processing
personal data. They decide WHY patient data is collected and HOW it is
processed. This is a legal and compliance role under regulatory frameworks.

WHY: The CEO holds ultimate legal accountability for data protection. James
Chen provides the security expertise to implement controls.

DATA PROCESSOR: MedTech Solutions (EHR vendor), ClearView Security, other
third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They do not decide what to do with the data - they execute the processing
according to the Controller's instructions (contracts, SLAs).

WHY: MedTech processes patient data through the EHR system. These vendors
must be contractually obligated to protect MedDefense data.

DATA CUSTODIAN / STEWARD: IT Department (Sarah Park, System Administrators,
Database Administrator)

MEANING: The Data Custodian is responsible for the technical implementation
of data protection controls. They maintain the systems that store and process
data, apply security patches, manage backups, and enforce access controls.

WHY: IT manages the servers, databases, and systems where data lives. They
are responsible for the technical security of the data.


================================================================================
PART 3: THE CISO QUESTION
================================================================================

CONSEQUENCES OF THE CURRENT GAP (No CISO):
------------------------------------------
1. STRATEGIC VACUUM: Without a CISO, there is no single executive accountable
   for the security program's success. James Chen is acting but has no formal
   authority (from 1x00: "James has authority over security policy but no
   authority over IT operations - this creates friction").

2. BOARD COMMUNICATION: No direct line from the security program to the Board.
   James Chen must go through the CEO, which delays decisions.

3. DECISION DEADLOCK: When IT (Sarah Park) and Security (James Chen) disagree,
   there is no higher security authority to resolve it.

4. ATTRACTION/RETENTION: Top security talent expects a clear career path.
   Acting roles are unattractive for experienced professionals.

5. REGULATORY CONCERNS: HIPAA requires a designated security official.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| RECOMMENDATION: HIRE A FULL-TIME CISO ($160,000-$200,000/year)             |
|                                                                             |
| MedDefense is transitioning from a security program that is "handled on    |
| the side by IT" to a formal, framework-aligned security function. This    |
| transition requires an executive-level security leader with:              |
| - Authority over security policies                                        |
| - Direct access to the Board                                              |
| - Ability to resolve IT vs. Security conflicts                            |
| - A career path for the security team                                    |
|                                                                             |
| A vCISO (virtual CISO) would cost $60,000-$80,000/year and would         |
| provide strategic guidance, but would NOT:                               |
| - Be present for day-to-day decisions                                    |
| - Have authority over IT operations                                      |
| - Build institutional knowledge over time                                |
|                                                                             |
| BUDGET CONSTRAINT: The $120,000 security budget CANNOT fund a            |
| full-time CISO ($160K-$200K) AND the $104,400 remediation priorities.    |
| However, the CISO position is a CAPITAL INVESTMENT in the security       |
| program's success - it should be funded separately from the operational  |
| security budget. MedDefense should request a separate $160,000-$200,000  |
| for CISO compensation in the next fiscal year.                           |
|                                                                             |
| RECOMMENDED PHASED APPROACH:                                              |
| Phase 1 (6 months): Appoint James Chen as interim CISO with Board        |
|         approval and formal authority                                    |
| Phase 2 (6-12 months): Begin recruiting a full-time CISO                |
| Phase 3 (12+ months): Hire full-time CISO, transition James Chen to      |
|         Deputy                                                           |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+----------------------------------------+
| Element  | Responsible      | Notes                                  |
+----------+------------------+----------------------------------------+
| RACI     | CEO (A), James   | Clear accountability for each activity |
|          | (R/A), Sarah (R) |                                        |
+----------+------------------+----------------------------------------+
| Data     | Dept Heads       | Own data classification and access     |
| Owner    |                  |                                        |
+----------+------------------+----------------------------------------+
| Data     | CEO + James      | Legal accountability for data          |
| Controller|                  | processing                             |
+----------+------------------+----------------------------------------+
| Data     | MedTech,         | Process data under contract            |
| Processor| Vendors          |                                        |
+----------+------------------+----------------------------------------+
| Data     | IT Department    | Technical implementation of controls   |
| Custodian|                  |                                        |
+----------+------------------+----------------------------------------+
| CISO     | Full-time        | Required for strategic leadership,     |
|          | (Recommended)    | separate budget request needed        |
+----------+------------------+----------------------------------------+


================================================================================
REFERENCES
================================================================================

- Organization Chart (1x00 Doc 6)
- NIST CSF Mapping (1x03 T1)
- CIS Controls Audit (1x03 T2)
- HIPAA Security Officer requirements
- GDPR Data Controller/Processor definitions


================================================================================
END OF GOVERNANCE ARCHITECTURE REPORT
================================================================================
