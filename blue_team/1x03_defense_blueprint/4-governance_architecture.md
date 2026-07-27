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
| Security budget approval  | A/R              | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vulnerability remediation | I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Incident response execution| I                | A                | R                | C                | C                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security policy           | A                | R                | C                | C                | C                |
| development and approval  |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Risk acceptance decisions | A/R              | C                | C                | C                | I                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Security awareness        | I                | A                | C                | R                | R                |
| training                  |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Vendor risk assessment    | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Audit coordination        | I                | A                | C                | C                | R                |
+---------------------------+------------------+------------------+------------------+------------------+------------------+
| Data ownership decisions  | I                | C                | C                | A/R              | I                |
| within departments        |                  |                  |                  |                  |                  |
+---------------------------+------------------+------------------+------------------+------------------+------------------+

LEGEND:
R = Responsible (Performs or coordinates the work)
A = Accountable (Holds final authority and answers for the result)
C = Consulted (Provides information or specialist advice before the decision)
I = Informed (Receives the final decision or status)


================================================================================
PART 2: GOVERNANCE PRINCIPLES
================================================================================

+----------------------------------------------------------------------------+
| GOVERNANCE PRINCIPLES                                                      |
|                                                                             |
| 1. CEO HOLDS EXECUTIVE DECISION AUTHORITY:                                  |
|    Dr. Morales is Accountable for security budget approval, final policy   |
|    approval, and risk acceptance. These decisions involve organizational   |
|    priorities, financial commitment, and business risk.                   |
|                                                                             |
| 2. DEPUTY CISO LEADS SECURITY GOVERNANCE AND RECOMMENDATIONS:              |
|    James drafts policies, develops security proposals, evaluates risk,    |
|    and remains Accountable for security operations. He does not           |
|    independently approve budgets or accept organizational risk.          |
|                                                                             |
| 3. IT DIRECTOR OWNS TECHNICAL EXECUTION:                                   |
|    Sarah implements remediation actions and supports incident response.   |
|    She provides technical cost and feasibility information but does not   |
|    hold executive budget or risk-acceptance authority.                   |
|                                                                             |
| 4. DEPARTMENT HEADS PRESERVE BUSINESS OWNERSHIP:                           |
|    Department Heads are Consulted where security decisions affect         |
|    clinical or operational processes. They are Accountable for decisions  |
|    concerning data owned by their departments and are Responsible for    |
|    ensuring their staff complete required training.                      |
|                                                                             |
| 5. SECURITY ANALYST PROVIDES OPERATIONAL SUPPORT:                          |
|    The analyst performs assessments, coordinates audits, supports         |
|    remediation and incident response, conducts vendor reviews, and       |
|    delivers awareness activities. The analyst does not approve           |
|    policies, budgets, or risk acceptance.                                |
+----------------------------------------------------------------------------+


================================================================================
PART 3: CLEAR AUTHORITY LINES
================================================================================

+------------------+--------------------------------------------------+
| Governance Area  | Authority                                        |
+------------------+--------------------------------------------------+
| Budget approval  | CEO                                               |
+------------------+--------------------------------------------------+
| Final policy     | CEO                                               |
| approval         |                                                  |
+------------------+--------------------------------------------------+
| Policy drafting  | Deputy CISO                                       |
| and              |                                                  |
| recommendation   |                                                  |
+------------------+--------------------------------------------------+
| Risk acceptance  | CEO                                               |
+------------------+--------------------------------------------------+
| Security         | Deputy CISO                                       |
| operational      |                                                  |
| oversight        |                                                  |
+------------------+--------------------------------------------------+
| Technical        | IT Director                                       |
| remediation and  |                                                  |
| incident actions |                                                  |
+------------------+--------------------------------------------------+
| Departmental     | Department Heads                                  |
| data ownership   |                                                  |
+------------------+--------------------------------------------------+
| Assessment and   | Security Analyst                                  |
| coordination     |                                                  |
| support          |                                                  |
+------------------+--------------------------------------------------+


================================================================================
PART 4: ROLE DEFINITIONS
================================================================================

Data Owner: Department Heads (Clinical Directors, Finance Director, HR Director)

MEANING: The Data Owner has ultimate accountability for a specific data set
within their department. They determine who can access the data, what it can
be used for, and how it should be classified. Department Heads hold this role
because they are accountable for the data their department generates and uses,
and they understand the clinical or operational impact of data decisions.
They are Accountable and Responsible for data ownership decisions.

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
PART 5: THE CISO QUESTION
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
SUMMARY
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

This structure separates executive accountability, security governance,
technical execution, business ownership, and analyst support. It prevents
James or Sarah from appearing to possess financial or business risk
authority while keeping them actively involved as security and technical
advisers.


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
