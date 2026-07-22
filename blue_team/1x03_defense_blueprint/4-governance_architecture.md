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
| Vulnerability remediation | I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A                | I                |
| (within departments)      |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure)
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

GOVERNANCE PRINCIPLES:
+----------------------------------------------------------------------------+
| 1. CEO is Accountable only for executive decisions: Budget, Policy, Risk   |
| 2. Deputy CISO (James) is Accountable for security operations:             |
|    Remediation, Incident Response, Policy drafting, Training, Vendor Risk  |
| 3. IT Director (Sarah) is Responsible for technical execution:             |
|    Remediation, Incident Response, Audit coordination, Budget execution    |
| 4. Dept Heads are Accountable only for Data Ownership (business impact)    |
| 5. Security Analyst executes day-to-day tasks (Training, Vendor Risk,      |
|    Audit coordination)                                                    |
+----------------------------------------------------------------------------+

KEY INSIGHTS:
- CEO: A only on executive decisions (Budget, Policy, Risk) - NOT on operations
- James: A on security operations, R on Policy approval (he drafts, CEO approves)
- Sarah: R on technical execution across multiple activities
- Dept Heads: A on Data Ownership only (their domain expertise matters)
- Analyst: R on Training, Vendor Risk, Audit coordination (execution role)


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
   CISO role remains vacant.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path. A vacant
   CISO position makes recruitment difficult.

5. REGULATORY CONCERNS: HIPAA requires a designated security official. The
   vacant position creates compliance exposure.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year) to fill  |
| the vacant position. The organization is transitioning from security      |
| handled "on the side by IT" to a formal framework-aligned program. This  |
| requires an executive leader with authority over policies, direct Board   |
| access, and the ability to resolve IT vs. Security conflicts.            |
|                                                                             |
| CURRENT RACI REFLECTS THE VACANCY:                                         |
| James Chen (Deputy CISO) is Accountable for security operations but       |
| cannot make budget or policy decisions (CEO retains A on those). This    |
| is the practical limitation of having a vacant CISO position.            |
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
|         authority to resolve the vacant gap                             |
| Phase 2 (6-12 months): Begin recruiting a full-time CISO                  |
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
| Security budget approval  | A                | R                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vulnerability remediation | I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | R                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A                | I                |
| (within departments)      |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure)
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

GOVERNANCE PRINCIPLES:
+----------------------------------------------------------------------------+
| 1. CEO is Accountable for executive decisions: Budget, Policy, Risk        |
| 2. Deputy CISO (James) is Accountable for security program:                |
|    Remediation, Incident Response, Policy (as drafter), Risk (as advisor), |
|    Training, Vendor Risk, Audit                                           |
| 3. IT Director (Sarah) is Responsible for technical execution:             |
|    Remediation, Incident Response, Audit coordination, Training execution  |
| 4. Dept Heads are Accountable only for Data Ownership; Consulted on       |
|    Remediation, Risk, and Incident (business impact)                     |
| 5. Security Analyst executes day-to-day tasks: Training, Vendor Risk,      |
|    Audit coordination                                                     |
+----------------------------------------------------------------------------+

KEY INSIGHTS:
- CEO: A only on Budget, Policy, Risk (executive decisions)
- James: A on ALL security operations, R on Policy and Risk (he leads security)
- Sarah: R on technical execution (Remediation, Incident, Audit, Training)
- Dept Heads: A on Data Ownership, C on Remediation/Risk/Incident (business input)
- Analyst: R on Training, Vendor Risk, Audit coordination (execution)


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

Data Controller: Dr. Patricia Morales (CEO) + James Chen (Deputy CISO)

MEANING: The Data Controller determines the purposes and means of processing
personal data. They decide WHY patient data is collected and HOW it is
processed. The CEO holds ultimate legal accountability, while James Chen
provides the security expertise to define how data is processed securely.

Data Processor: MedTech Solutions (EHR vendor), ClearView Security, and
other third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They execute processing according to the Controller's instructions. MedTech
processes patient data through the EHR system under contract.

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
| Data Controller           | Decides WHY data is collected (CEO + James)      |
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
   CISO role remains vacant.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path. A vacant
   CISO position makes recruitment difficult.

5. REGULATORY CONCERNS: HIPAA requires a designated security official. The
   vacant position creates compliance exposure.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year) to fill  |
| the vacant position. The RACI matrix shows James Chen (Deputy CISO) as    |
| Accountable for most security operations, but he lacks the formal         |
| authority to make budget and policy decisions without CEO approval.      |
|                                                                             |
| A full-time CISO would:                                                   |
| - Have formal authority to approve policies and budgets                  |
| - Report directly to the Board                                            |
| - Resolve IT vs. Security conflicts                                      |
| - Build institutional knowledge over time                                |
|                                                                             |
| A vCISO ($60,000-$80,000) would provide strategic guidance but would     |
| not have authority over IT operations or build institutional knowledge.  |
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
| Vulnerability remediation | I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A                | I                |
| (within departments)      |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure)
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

GOVERNANCE PRINCIPLES:
+----------------------------------------------------------------------------+
| 1. CEO retains Accountable on executive decisions: Budget, Policy, Risk    |
| 2. Deputy CISO (James) is Accountable for security operations:             |
|    Remediation, Incident Response, Policy drafting, Training, Audit,       |
|    Vendor Risk                                                             |
| 3. IT Director (Sarah) is Responsible for technical execution:             |
|    Budget execution, Remediation, Incident Response, Training, Audit       |
| 4. Dept Heads are Accountable for Data Ownership; Consulted on Risk,       |
|    Remediation, and Incident (business impact)                           |
| 5. Security Analyst executes day-to-day tasks: Training, Vendor Risk,      |
|    Audit coordination                                                     |
+----------------------------------------------------------------------------+

KEY INSIGHTS:
- CEO: A only on Budget, Policy, Risk (executive decisions)
- James: A on security operations, R on Policy (drafts), C on Budget/Risk (advises)
- Sarah: R on technical execution (Remediation, Incident, Budget execution)
- Dept Heads: A on Data Ownership, C on Risk/Remediation (business input)
- Analyst: R on Training, Vendor Risk, Audit coordination


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
cannot be delegated below the executive level.

Data Processor: MedTech Solutions (EHR vendor), ClearView Security, and
other third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They execute processing according to the Controller's instructions. MedTech
processes patient data through the EHR system under contract.

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
   CISO role remains vacant.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path. A vacant
   CISO position makes recruitment difficult.

5. REGULATORY CONCERNS: HIPAA requires a designated security official. The
   vacant position creates compliance exposure.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year) to fill  |
| the vacant position. The organization is transitioning from security      |
| handled "on the side by IT" to a formal framework-aligned program. This  |
| requires an executive leader with authority over policies, direct Board   |
| access, and the ability to resolve IT vs. Security conflicts.            |
|                                                                             |
| The RACI matrix reflects the current limitation: James Chen (Deputy       |
| CISO) is Accountable for security operations but cannot approve budgets   |
| or policies without CEO approval. A full-time CISO would resolve this    |
| governance gap.                                                           |
|                                                                             |
| A vCISO ($60,000-$80,000) would provide strategic guidance but would     |
| not have authority over IT operations or build institutional knowledge.  |
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
SUMMARY OF GOVERNANCE ROLES
================================================================================

+---------------------------+---------------------------+
| Role                      | Person/Position           |
+---------------------------+---------------------------+
| Data Owner                | Department Heads          |
+---------------------------+---------------------------+
| Data Controller           | CEO (Dr. Morales)         |
+---------------------------+---------------------------+
| Data Processor            | MedTech, Vendors          |
+---------------------------+---------------------------+
| Data Custodian/Steward    | IT Department             |
+---------------------------+---------------------------+
| Interim Security Lead     | James Chen (Deputy CISO)  |
+---------------------------+---------------------------+


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
| Security budget approval  | A                | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vulnerability remediation | I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy approval  | A                | R                | C                | I                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A                | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness training| I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | R                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A                | I                |
| (within departments)      |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (executes the task)
A = Accountable (answers for success/failure)
C = Consulted (provides input before decisions)
I = Informed (notified after decisions)

GOVERNANCE PRINCIPLES:
+----------------------------------------------------------------------------+
| 1. CEO is Accountable for executive decisions: Budget, Policy, Risk        |
| 2. Deputy CISO (James) is Accountable for security operations:             |
|    Remediation, Incident Response, Policy drafting, Training, Audit        |
| 3. IT Director (Sarah) is Responsible for technical execution:             |
|    Remediation, Incident Response, Audit, Training                        |
| 4. Dept Heads are Accountable for Data Ownership; Consulted on Risk,       |
|    Remediation, and Incident (business impact)                           |
| 5. Security Analyst executes day-to-day tasks: Training, Vendor Risk,      |
|    Audit coordination                                                     |
+----------------------------------------------------------------------------+

AUTHORITY LINES:
+----------------------------------------------------------------------------+
| EXECUTIVE GOVERNANCE (CEO): Budget, Policy, Risk Acceptance                |
| SECURITY GOVERNANCE (James): Incident Response, Remediation, Policy       |
| TECHNICAL EXECUTION (Sarah): Remediation, Incident Response, Audit        |
| BUSINESS OWNERSHIP (Dept Heads): Data Ownership, Risk Consultation        |
| SUPPORT EXECUTION (Analyst): Training, Vendor Risk, Audit Coordination    |
+----------------------------------------------------------------------------+


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
cannot be delegated below the executive level.

Data Processor: MedTech Solutions (EHR vendor), ClearView Security, and
other third-party vendors processing MedDefense data

MEANING: The Data Processor processes data on behalf of the Data Controller.
They execute processing according to the Controller's instructions. MedTech
processes patient data through the EHR system under contract.

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
   CISO role remains vacant.

2. BOARD COMMUNICATION: No direct line from security to the Board. Decisions
   are delayed through the CEO.

3. DECISION DEADLOCK: When IT and Security disagree, there is no higher
   security authority to resolve it.

4. ATTRACTION/RETENTION: Top talent expects a clear career path. A vacant
   CISO position makes recruitment difficult.

5. REGULATORY CONCERNS: HIPAA requires a designated security official. The
   vacant position creates compliance exposure.

RECOMMENDATION: HIRE A FULL-TIME CISO
-------------------------------------
+----------------------------------------------------------------------------+
| MedDefense should hire a full-time CISO ($160,000-$200,000/year) to fill  |
| the vacant position. The organization is transitioning from security      |
| handled "on the side by IT" to a formal framework-aligned program. This  |
| requires an executive leader with authority over policies, direct Board   |
| access, and the ability to resolve IT vs. Security conflicts.            |
|                                                                             |
| The RACI matrix reflects the current limitation: James Chen (Deputy       |
| CISO) is Accountable for security operations but cannot approve budgets   |
| or policies without CEO approval. A full-time CISO would resolve this    |
| governance gap.                                                           |
|                                                                             |
| A vCISO ($60,000-$80,000) would provide strategic guidance but would     |
| not have authority over IT operations or build institutional knowledge.  |
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
