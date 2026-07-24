================================================================================
                    6-MONTH SECURITY ROADMAP - MEDDEFENSE HEALTH SYSTEMS
                    Task 18: The Roadmap
================================================================================

Exercise: Task 18 - The Roadmap
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Transform the strategy into a visual, dependency-aware
          implementation timeline.

Sources: 1x03 Security Strategy Document (T17), 1x03 Budget Allocation (T8),
         1x03 Quick Wins (T13), 1x03 Segmentation Architecture (T14)


================================================================================
MONTH-BY-MONTH BREAKDOWN
================================================================================

MONTH 1: QUICK WINS + PROCUREMENT
---------------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Disable default credentials on BD Alaris      |
|                  |    pumps (3 days)                               |
|                  | 2. Disable SSH password authentication on all    |
|                  |    Linux servers (5 days)                       |
|                  | 3. Restrict PostgreSQL to ehr-srv-01 only       |
|                  |    (1 day)                                      |
|                  | 4. Enable screen lock on clinical workstations   |
|                  |    (7 days)                                     |
|                  | 5. Conduct phishing awareness campaign          |
|                  |    (3 days)                                     |
|                  | 6. Procure EDR upgrade, offsite backup, Daytime |
|                  |    SOC services (15 days)                       |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: Biomedical + IT Security              |
| Owner(s)         | Action 2: IT Systems Team                       |
|                  | Action 3: DBA + IT Security                     |
|                  | Action 4: IT Systems + Nursing Leadership      |
|                  | Action 5: Security Analyst + HR                |
|                  | Action 6: IT Director + Deputy CISO            |
+------------------+--------------------------------------------------+
| Dependencies     | None - all actions can proceed in parallel      |
+------------------+--------------------------------------------------+
| Completion       | - All quick wins completed and verified         |
| Criteria         | - Procurement contracts signed                  |
|                  | - Phishing email open rate >80%                 |
+------------------+--------------------------------------------------+


MONTH 2: PROCUREMENT COMPLETION + DEPLOYMENT PLANNING
------------------------------------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Complete procurement of EDR, offsite backup,  |
|                  |    Daytime SOC                                   |
|                  | 2. Develop detailed deployment plans for each    |
|                  |    Phase 2 control                              |
|                  | 3. Schedule maintenance windows for network      |
|                  |    segmentation, MFA deployment                 |
|                  | 4. Coordinate with MedTech Solutions for vendor |
|                  |    MFA integration                             |
|                  | 5. Finalize AUP and distribute for review       |
|                  | 6. Begin IR Plan draft                          |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: IT Director + Deputy CISO             |
| Owner(s)         | Action 2: Security Analyst                      |
|                  | Action 3: IT Network Team + Security           |
|                  | Action 4: Deputy CISO + MedTech                |
|                  | Action 5: HR + Legal + Security                |
|                  | Action 6: Deputy CISO + Security Analyst       |
+------------------+--------------------------------------------------+
| Dependencies     | - Month 1 procurement must be complete         |
|                  | - AUP review requires HR and Legal availability|
+------------------+--------------------------------------------------+
| Completion       | - All procurement completed                     |
| Criteria         | - Deployment plans documented                  |
|                  | - Maintenance windows scheduled                 |
|                  | - AUP ready for approval                        |
+------------------+--------------------------------------------------+


MONTH 3: CORE CONTROLS - NETWORK SEGMENTATION + MFA
----------------------------------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Deploy network segmentation (6 VLANs)          |
|                  |    - Reconfigure switches (VLANs 10, 20, 30,     |
|                  |      40, 50, 60)                                 |
|                  |    - Configure inter-VLAN routing                |
|                  |    - Implement 10 firewall rules                 |
|                  |    - Test connectivity between zones            |
|                  | 2. Deploy MFA on VPN and administrative accounts |
|                  |    - Configure Azure AD Premium P1              |
|                  |    - Register users for MFA                     |
|                  |    - Test MFA functionality                      |
|                  | 3. Begin SIEM (Wazuh) deployment                |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: IT Network Team                       |
| Owner(s)         | Action 2: IT + Security                         |
|                  | Action 3: IT + Security Analyst                 |
+------------------+--------------------------------------------------+
| Dependencies     | - Procurement must be complete (Month 1-2)     |
|                  | - MFA requires Azure AD Premium P1 licenses    |
|                  | - Segmentation requires switch reconfiguration  |
+------------------+--------------------------------------------------+
| Completion       | - 6 VLANs configured and tested                 |
| Criteria         | - All 10 firewall rules implemented            |
|                  | - MFA enabled on all VPN and admin accounts     |
|                  | - Wazuh SIEM installed                          |
+------------------+--------------------------------------------------+


MONTH 4: CORE CONTROLS - EDR + BACKUPS + SIEM
-----------------------------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Deploy EDR on all servers                      |
|                  |    - Install Sophos Intercept X on servers       |
|                  |    - Configure policies                          |
|                  |    - Test alerting                               |
|                  | 2. Implement offsite immutable backups           |
|                  |    - Configure AWS S3 Glacier                   |
|                  |    - Test backup and restore                    |
|                  | 3. Complete SIEM deployment and configure       |
|                  |    alerting                                      |
|                  | 4. Onboard Daytime-Only SOC (8am-6pm)           |
|                  | 5. Conduct first vulnerability re-scan          |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: IT + Security                         |
| Owner(s)         | Action 2: IT (Backup Admin)                     |
|                  | Action 3: IT + Security Analyst                 |
|                  | Action 4: Security Analyst + James             |
|                  | Action 5: Security Analyst                      |
+------------------+--------------------------------------------------+
| Dependencies     | - EDR requires network segmentation in place   |
|                  |   (Month 3)                                     |
|                  | - Offsite backup requires network connectivity  |
|                  |   and AWS account                               |
|                  | - SIEM requires segmentation for log collection |
+------------------+--------------------------------------------------+
| Completion       | - EDR active on all servers                     |
| Criteria         | - Offsite backups configured and tested         |
|                  | - SIEM collecting logs from critical systems   |
|                  | - Daytime SOC operational                       |
|                  | - Vulnerability re-scan completed               |
+------------------+--------------------------------------------------+


MONTH 5: RESPONSE + RECOVERY
-----------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Finalize and approve IR Plan                  |
|                  |    - Document roles, responsibilities, contacts  |
|                  |    - Define escalation paths                     |
|                  |    - Create communication templates             |
|                  | 2. Conduct tabletop exercise (ransomware        |
|                  |    scenario)                                     |
|                  | 3. Finalize BCP/DR plans                         |
|                  | 4. Roll out AUP to all employees                |
|                  |    - Distribute policy                          |
|                  |    - Collect signed acknowledgments             |
|                  | 5. Begin data classification policy draft       |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: Deputy CISO + Security Analyst        |
| Owner(s)         | Action 2: Deputy CISO + Sarah + Dept Heads     |
|                  | Action 3: Deputy CISO + IT Director            |
|                  | Action 4: HR + Security                         |
|                  | Action 5: Deputy CISO + Security Analyst       |
+------------------+--------------------------------------------------+
| Dependencies     | - IR plan requires incident response           |
|                  |   coordination from all departments            |
|                  | - AUP requires legal review (Month 2)          |
|                  | - Tabletop exercise requires IR plan draft     |
+------------------+--------------------------------------------------+
| Completion       | - IR plan approved                              |
| Criteria         | - Tabletop exercise completed with lessons     |
|                  |   documented                                    |
|                  | - AUP signed by 90%+ employees                  |
|                  | - BCP/DR plans documented                       |
+------------------+--------------------------------------------------+


MONTH 6: VALIDATION + REPORTING
--------------------------------
+------------------+--------------------------------------------------+
| Actions          | 1. Full vulnerability re-scan                    |
|                  | 2. Validate all controls are functioning as      |
|                  |    intended                                      |
|                  | 3. Update Risk Register with control             |
|                  |    effectiveness                                  |
|                  | 4. Calculate post-control ALE                    |
|                  | 5. Prepare Board presentation                   |
|                  | 6. Develop Year 2 roadmap                       |
|                  | 7. Identify 1x04 Cryptographic Foundation       |
|                  |    priorities                                    |
+------------------+--------------------------------------------------+
| Responsible      | Action 1: Security Analyst                      |
| Owner(s)         | Action 2: IT + Security                         |
|                  | Action 3: Deputy CISO + Security Analyst       |
|                  | Action 4: Security Analyst                      |
|                  | Action 5: Deputy CISO                           |
|                  | Action 6: Deputy CISO + IT Director            |
|                  | Action 7: Deputy CISO                           |
+------------------+--------------------------------------------------+
| Dependencies     | - All previous controls must be deployed       |
|                  | - Re-scan requires scan tool configured         |
|                  | - Board presentation requires validation        |
|                  |   data                                          |
+------------------+--------------------------------------------------+
| Completion       | - Vulnerability scan shows >50% reduction       |
| Criteria         | - Risk register updated                         |
|                  | - Board presentation delivered                  |
|                  | - Year 2 roadmap approved                       |
+------------------+--------------------------------------------------+


================================================================================
DEPENDENCY CHAIN
================================================================================

+----------------------------------------------------------------------------+
| DEPENDENCY CHAIN #1: EDR REQUIRES SEGMENTATION                             |
|                                                                             |
| Network Segmentation (Month 3) → EDR Deployment (Month 4)                  |
|                                                                             |
| EDR needs to be aware of the new network zones to properly segment         |
| endpoint monitoring and protection policies. Without segmentation,        |
| EDR deployment is less effective.                                         |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| DEPENDENCY CHAIN #2: SIEM REQUIRES SEGMENTATION                            |
|                                                                             |
| Network Segmentation (Month 3) → SIEM Deployment (Month 4)                 |
|                                                                             |
| SIEM requires proper network visibility to collect logs from each zone.   |
| Segmentation allows the SIEM to monitor traffic between zones.            |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| DEPENDENCY CHAIN #3: OFFSITE BACKUP REQUIRES SEGMENTATION                  |
|                                                                             |
| Network Segmentation (Month 3) → Offsite Backup (Month 4)                 |
|                                                                             |
| Backup traffic must be isolated to the backup VLAN to prevent             |
| ransomware from encrypting backups. Segmentation provides the             |
| foundation for backup isolation.                                           |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| DEPENDENCY CHAIN #4: TABLETOP EXERCISE REQUIRES IR PLAN                   |
|                                                                             |
| IR Plan Draft (Month 2) → IR Plan Finalize (Month 5) → Tabletop          |
| Exercise (Month 5)                                                         |
|                                                                             |
| The tabletop exercise cannot be conducted without a documented IR plan.   |
| The draft must be completed before the exercise.                          |
+----------------------------------------------------------------------------+

+----------------------------------------------------------------------------+
| DEPENDENCY CHAIN #5: AUP REQUIRES LEGAL REVIEW                            |
|                                                                             |
| AUP Draft (Month 2) → AUP Legal Review (Month 2) → AUP Rollout           |
| (Month 5)                                                                  |
|                                                                             |
| The AUP must be reviewed by Legal before it can be rolled out to          |
| employees. This is a critical dependency.                                 |
+----------------------------------------------------------------------------+


================================================================================
DEPENDENCY DIAGRAM (TEXT)
================================================================================

+----------------------------------------------------------------------------+
| DEPENDENCY DIAGRAM                                                          |
|                                                                             |
| Month 1          Month 2          Month 3          Month 4          Month 5          Month 6 |
|                                                                             |
| Quick Wins ─────┐                                                          |
| (Procurement) ──┼──────► Segmentation ────────┐                          |
|                  │                            │                          |
|                  ├──────► MFA ─────────────────┼──────► EDR ─────────────┼──────► Validation |
|                  │                            │                          │                          |
|                  ├──────► SIEM ────────────────┼──────► Backups ─────────┼──────► Reporting |
|                  │                            │                          │                          |
|                  └──────► IR Plan Draft ──────┼──────► IR Finalize ─────┼──────► Tabletop |
|                                               │                          │                          |
|                                               └──────► AUP Review ──────┼──────► AUP Rollout |
+----------------------------------------------------------------------------+


================================================================================
MILESTONES
================================================================================

MILESTONE 1: QUICK WINS COMPLETE
--------------------------------
+------------------+--------------------------------------------------+
| Date             | End of Month 1                                   |
+------------------+--------------------------------------------------+
| Accomplished     | - All 5 quick wins completed and verified        |
|                  | - Procurement contracts signed                   |
|                  | - AUP drafted                                    |
+------------------+--------------------------------------------------+
| Success Metric   | - 100% of quick wins verified                    |
|                  | - Phishing email open rate >80%                  |
|                  | - EDR, offsite backup, SOC contracts signed     |
+------------------+--------------------------------------------------+
| Owner            | Deputy CISO + IT Director                        |
+------------------+--------------------------------------------------+


MILESTONE 2: CORE CONTROLS DEPLOYED
-----------------------------------
+------------------+--------------------------------------------------+
| Date             | End of Month 4                                   |
+------------------+--------------------------------------------------+
| Accomplished     | - Network segmentation (6 VLANs) deployed        |
|                  | - MFA enabled on VPN + admin accounts           |
|                  | - SIEM (Wazuh) deployed                          |
|                  | - EDR on all servers                             |
|                  | - Offsite immutable backups configured          |
|                  | - Daytime SOC operational                        |
+------------------+--------------------------------------------------+
| Success Metric   | - 6 VLANs confirmed in network scan             |
|                  | - MFA compliance >95%                            |
|                  | - SIEM logs from all critical systems           |
|                  | - EDR active on 100% of servers                 |
|                  | - Offsite backup test successful                |
|                  | - SOC active 8am-6pm                            |
+------------------+--------------------------------------------------+
| Owner            | IT Director + Deputy CISO                        |
+------------------+--------------------------------------------------+


MILESTONE 3: RESPONSE CAPABILITY ESTABLISHED
--------------------------------------------
+------------------+--------------------------------------------------+
| Date             | End of Month 5                                   |
+------------------+--------------------------------------------------+
| Accomplished     | - IR Plan finalized and approved                 |
|                  | - Tabletop exercise completed                    |
|                  | - BCP/DR plans documented                        |
|                  | - AUP signed by >90% employees                  |
+------------------+--------------------------------------------------+
| Success Metric   | - IR Plan approved by CEO                        |
|                  | - Tabletop exercise executed with lessons       |
|                  |   documented                                     |
|                  | - AUP completion rate >90%                       |
+------------------+--------------------------------------------------+
| Owner            | Deputy CISO + HR                                 |
+------------------+--------------------------------------------------+


MILESTONE 4: PROGRAM VALIDATED
------------------------------
+------------------+--------------------------------------------------+
| Date             | End of Month 6                                   |
+------------------+--------------------------------------------------+
| Accomplished     | - Vulnerability re-scan completed                |
|                  | - Risk register updated                          |
|                  | - Post-control ALE calculated                    |
|                  | - Board presentation delivered                   |
|                  | - Year 2 roadmap approved                        |
+------------------+--------------------------------------------------+
| Success Metric   | - Vulnerability findings reduced >50%           |
|                  | - Risk register updated with control            |
|                  |   effectiveness                                   |
|                  | - Board approved Year 2 budget                  |
+------------------+--------------------------------------------------+
| Owner            | Deputy CISO + Security Analyst                   |
+------------------+--------------------------------------------------+


================================================================================
RISK TO TIMELINE
================================================================================

RISK 1: VENDOR DELAYS
---------------------
+------------------+--------------------------------------------------+
| Risk Description | Delays in EDR licensing, offsite backup         |
|                  | provisioning, or Daytime SOC onboarding from    |
|                  | vendors.                                         |
+------------------+--------------------------------------------------+
| Likelihood       | MEDIUM                                            |
+------------------+--------------------------------------------------+
| Impact           | HIGH - Delays core control deployment by 2-4    |
|                  | weeks                                            |
+------------------+--------------------------------------------------+
| Contingency Plan | 1. Place orders immediately upon Board approval |
|                  | 2. Have backup vendors identified              |
|                  | 3. Use open-source alternatives (Wazuh, Veeam   |
|                  |    Community) while waiting for enterprise      |
|                  |    versions                                      |
|                  | 4. Start configuration work that does not       |
|                  |    require vendor licenses                      |
+------------------+--------------------------------------------------+


RISK 2: STAFF AVAILABILITY
--------------------------
+------------------+--------------------------------------------------+
| Risk Description | Key IT staff unavailable due to clinical         |
|                  | emergencies, annual leave, or competing          |
|                  | operational priorities.                          |
+------------------+--------------------------------------------------+
| Likelihood       | HIGH                                              |
+------------------+--------------------------------------------------+
| Impact           | MEDIUM - Delays technical implementation by 1-3  |
|                  | weeks                                            |
+------------------+--------------------------------------------------+
| Contingency Plan | 1. Cross-train Security Analyst on basic IT     |
|                  |    tasks                                          |
|                  | 2. Schedule maintenance windows 4 weeks in      |
|                  |    advance                                       |
|                  | 3. Identify external contractors as backup      |
|                  | 4. Buffer 1 week between dependent tasks       |
|                  | 5. Document all procedures to reduce             |
|                  |    dependency on specific individuals           |
+------------------+--------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Security Strategy Document (1x03 T17)
- Budget Allocation (1x03 T8)
- Quick Wins (1x03 T13)
- Segmentation Architecture (1x03 T14)


================================================================================
END OF 6-MONTH SECURITY ROADMAP REPORT
================================================================================
