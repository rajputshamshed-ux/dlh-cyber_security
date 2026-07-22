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
| Activity                  | CEO              | Deputy CISO      | IT Director      | Dept Heads       | Security         |
|                           | (Dr. Morales)    | (James Chen)     | (Sarah Park)     |                  | Analyst (You)    |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security budget approval  | A                | C                | R                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vulnerability remediation | A                | R                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| A                | R                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | C                | R                | I                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| A                | R                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | A                | R                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | A                | R                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A                | I                |
| (within departments)      |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure - "the buck stops here")
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

GOVERNANCE PRINCIPLES:
+----------------------------------------------------------------------------+
| 1. CEO is Accountable for ALL security activities (ultimate authority)     |
| 2. Deputy CISO (James) is Responsible for security program execution       |
| 3. IT Director (Sarah) is Responsible for technical implementation        |
| 4. Dept Heads are Accountable for data ownership within their departments  |
| 5. Security Analyst supports execution (Responsible on some tasks)        |
+----------------------------------------------------------------------------+

KEY INSIGHTS:
- CEO retains Accountable on ALL activities, resolving the vacant CISO issue
- James and Sarah share Responsible (execution) with clear division
- Dept Heads are Accountable only for data ownership (where business impact is highest)
- Security Analyst is Responsible for training, vendor risk, and audit coordination


================================================================================
PART 2: ROLE DEFINITIONS
================================================================================

Data Owner: Department Heads (Clinical Directors, Finance Director, HR Director)

MEANING: The Data Owner has ultimate accountability for a specific data set
within their department. They determine who can access the data, what it can
be used for, and how it should be classified. Department Heads hold this role
because they are accountable for the data their department generates and uses,
and they understand the clinical or operational impact of data decisions.
This is the only area where Dept Heads are Accountable (A).

Data Controller: Dr. Patricia Morales (CEO)

MEANING: The Data Controller determines the purposes and means of processing
personal data. They decide WHY patient data is collected and HOW it is
processed. The CEO holds this role because it is a legal accountability that
cannot be delegated below the executive level. James Chen provides security
expertise as a Consultant to the Data Controller.

Data Processor: MedTech Solutions (EHR vendor), ClearView Security, and
other third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They execute processing according to the Controller's instructions. MedTech
processes patient data through the EHR system under contract. They are not
accountable for data decisions, only for secure execution.

Data Custodian/Steward: IT Department (Sarah Park, System Administrators,
Database Administrator)

MEANING: The Data Custodian/Steward is responsible for the technical
implementation of data protection controls. They maintain the systems that
store and process data, apply patches, manage backups, and enforce access
controls. IT manages the servers and databases where data lives.

GOVERNANCE DISTINCTION:
+---------------------------+--------------------------------------------------+
| Role                      | Responsibility                                    |
+---------------------------+--------------------------------------------------+
| Data Owner                | Decides WHO can access data (Department Heads)   |
| Data Controller           | Decides WHY data is collected (CEO)              |
| Data Processor            | Executes processing under contract (Vendors)    |
| Data Custodian/Steward    | Implements HOW data is protected (IT)           |
+---------------------------+--------------------------------------------------+


================================================================================
PART 3: THE CISO QUESTION
================================================================================

CURRENT SITUATION: The CISO position at MedDefense is VACANT.

CONSEQUENCES OF THE VACANT CISO POSITION:
------------------------------------------
1. STRATEGIC VACUUM: No single executive is accountable for the security
   program. James Chen is acting but has no formal authority because the
   CISO role remains vacant. This is why the RACI matrix shows CEO as
   Accountable for ALL activities - to bridge the gap.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path. A vacant
   CISO position makes recruitment difficult and risks losing James Chen.

5. REGULATORY CONCERNS: HIPAA requires a designated security official. The
   vacant position creates compliance exposure.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year) to fill  |
| the vacant position. The organization is transitioning from security      |
| handled "on the side by IT" to a formal framework-aligned program. This  |
| requires an executive leader with authority over policies, direct Board   |
| access, and the ability to resolve IT vs. Security conflicts. James Chen |
| is a strong Deputy but lacks the authority to make budget and policy     |
| decisions. Until a CISO is hired, the CEO retains ultimate Accountable   |
| on all security activities (as shown in the RACI matrix).               |
|                                                                             |
| A vCISO ($60,000-$80,000) would provide strategic guidance but would     |
| not have authority over IT operations, be present for day-to-day         |
| decisions, or build institutional knowledge.                             |
|                                                                             |
| BUDGET CONSTRAINT: The $120,000 security budget cannot fund a full-time   |
| CISO and the $104,400 remediation priorities. The CISO should be funded   |
| separately as a capital investment. MedDefense should request a separate  |
| $160,000-$200,000 for CISO compensation in the next fiscal year.          |
|                                                                             |
| PHASED APPROACH:                                                            |
| Phase 1 (6 months): Appoint James Chen as interim CISO with formal        |
|         authority while the CISO position remains vacant                 |
| Phase 2 (6-12 months): Begin recruiting a full-time CISO to fill the      |
|         vacant role                                                       |
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
