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
| Incident response execution| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | R                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure)
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)


================================================================================
PART 2: ROLE DEFINITIONS
================================================================================

DATA OWNER: Department Heads (Clinical Directors, Finance Director, HR Director)

MEANING: The Data Owner has ultimate responsibility for a specific data set.
They determine who can access the data, what it can be used for, and how it
should be classified. Department Heads hold this role because they know what
data their department generates and how it is used.

DATA CONTROLLER: Dr. Patricia Morales (CEO) + James Chen (Deputy CISO)

MEANING: The Data Controller determines the purposes and means of processing
personal data. They decide WHY patient data is collected and HOW it is
processed. The CEO holds ultimate legal accountability, while James Chen
provides the security expertise.

DATA PROCESSOR: MedTech Solutions (EHR vendor), ClearView Security, and
other third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They execute processing according to the Controller's instructions. MedTech
processes patient data through the EHR system under contract.

DATA CUSTODIAN / STEWARD: IT Department (Sarah Park, System Administrators,
Database Administrator)

MEANING: The Data Custodian is responsible for the technical implementation
of data protection controls. They maintain the systems that store and process
data, apply patches, manage backups, and enforce access controls. IT manages
the servers and databases where data lives.


================================================================================
PART 3: THE CISO QUESTION
================================================================================

CONSEQUENCES OF THE CURRENT GAP (No CISO):
------------------------------------------
1. STRATEGIC VACUUM: No single executive is accountable for the security
   program. James Chen is acting but has no formal authority.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path.

5. REGULATORY CONCERNS: HIPAA requires a designated security official.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year). The      |
| organization is transitioning from security handled "on the side by IT"   |
| to a formal framework-aligned program. This requires an executive leader  |
| with authority over policies, direct Board access, and the ability to     |
| resolve IT vs. Security conflicts. A vCISO ($60,000-$80,000) would not    |
| be present for day-to-day decisions or build institutional knowledge.     |
|                                                                             |
| BUDGET CONSTRAINT: The $120,000 security budget cannot fund a full-time   |
| CISO and the $104,400 remediation priorities. The CISO should be funded   |
| separately as a capital investment. MedDefense should request a separate  |
| $160,000-$200,000 for CISO compensation in the next fiscal year.          |
|                                                                             |
| PHASED APPROACH:                                                            |
| Phase 1 (6 months): Appoint James Chen as interim CISO with formal        |
|         authority                                                         |
| Phase 2 (6-12 months): Begin recruiting a full-time CISO                |
| Phase 3 (12+ months): Hire full-time CISO, transition James to Deputy    |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Organization Chart (1x00 Doc 6)
- NIST CSF Mapping (1x03 T1)
- CIS Controls Audit (1x03 T2)
- HIPAA Security Officer requirements


================================================================================
END OF GOVERNANCE ARCHITECTURE REPORT
================================================================================

