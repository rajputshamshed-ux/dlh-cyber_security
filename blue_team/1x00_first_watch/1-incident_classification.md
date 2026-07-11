================================================================================
                    INCIDENT CLASSIFICATION - MEDDEFENSE HEALTH SYSTEMS
                    Task 1: The First Incidents
================================================================================


Exercise: Task 1 - The First Incidents
Analyst:Shamshed Rajput
Date: 11/07/2026

Methodology References:
- NIST SP 800-12 Rev.1: CIA Triad (Chapters 2-3) - Foundational framework
- NIST SP 800-30: Threat, Vulnerability, Risk definitions (Chapter 2)
- NIST SP 800-53 Rev.5: Control Families (taxonomy context)
- CIS Controls v8: Critical controls (top-level understanding)
- NIST CSF 2.0: Identify Function (asset context)
- CISA Healthcare Guide: Healthcare threat context
- ISO 27001 Gap Analysis: Structured assessment methodology
- HHS HICP: Healthcare security practices

Source: Marcus Webb's Incident Log (Last 6 Months)


================================================================================
INCIDENT CLASSIFICATION TABLE
================================================================================

+----------------------------------------------------------------------------------------------------------------------+
| INCIDENT CLASSIFICATION - CIA TRIAD ANALYSIS                                                                         |
+----------------------------------------------------------------------------------------------------------------------+

INCIDENT A - January 15
+------------------+--------------------------------------------------+
| Primary Pillar   | Availability                                     |
+------------------+--------------------------------------------------+
| Justification    | Billing system inaccessible for 4 days; claims   |
| (Primary)        | processing halted.                               |
+------------------+--------------------------------------------------+
| Secondary Pillar | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | Ransomware encrypted server contents, modifying  |
| (Secondary)      | data without authorization.                      |
+------------------+--------------------------------------------------+
| Incident Summary | Ransomware encrypted billing-srv-01. Claims      |
|                  | unprocessed for 4 days. Backup 3 weeks old       |
|                  | (misconfigured cron).                            |
+------------------+--------------------------------------------------+

INCIDENT B - February 2
+------------------+--------------------------------------------------+
| Primary Pillar   | Confidentiality                                  |
+------------------+--------------------------------------------------+
| Justification    | Patients accessed other patients' lab results    |
| (Primary)        | without authorization (PHI exposure).            |
+------------------+--------------------------------------------------+
| Secondary Pillar | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | URL parameter manipulation indicates broken      |
| (Secondary)      | access control logic (system integrity failure). |
+------------------+--------------------------------------------------+
| Incident Summary | Patient portal allowed patients to view other    |
|                  | patients' lab results via URL parameter          |
|                  | modification.                                    |
+------------------+--------------------------------------------------+

INCIDENT C - March 18
+------------------+--------------------------------------------------+
| Primary Pillar   | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | Dosage values incorrectly modified in database;  |
| (Primary)        | patient safety at risk.                          |
+------------------+--------------------------------------------------+
| Secondary Pillar | Availability                                     |
+------------------+--------------------------------------------------+
| Justification    | System displayed incorrect data for 6 hours;     |
| (Secondary)      | effectively unusable.                            |
+------------------+--------------------------------------------------+
| Incident Summary | Pharmacy system displayed incorrect dosages for  |
|                  | 6 hours due to database script bug.              |
+------------------+--------------------------------------------------+

INCIDENT D - April 5
+------------------+--------------------------------------------------+
| Primary Pillar   | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | Homepage content modified without authorization. |
| (Primary)        |                                                  |
+------------------+--------------------------------------------------+
| Secondary Pillar | Availability                                     |
+------------------+--------------------------------------------------+
| Justification    | Website was offline for 2 hours during           |
| (Secondary)      | restoration.                                     |
+------------------+--------------------------------------------------+
| Incident Summary | Public website defaced with political message.   |
|                  | Restored within 2 hours. No patient data on site.|
+------------------+--------------------------------------------------+

INCIDENT E - May 22
+------------------+--------------------------------------------------+
| Primary Pillar   | Availability                                     |
+------------------+--------------------------------------------------+
| Justification    | EHR system inaccessible for 9 hours; physicians  |
| (Primary)        | forced to use paper records.                     |
+------------------+--------------------------------------------------+
| Secondary Pillar | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | Rollback procedure untested; data integrity      |
| (Secondary)      | during migration unguaranteed.                   |
+------------------+--------------------------------------------------+
| Incident Summary | EHR system 9-hour outage during untested         |
|                  | database migration. Physicians used paper        |
|                  | records.                                         |
+------------------+--------------------------------------------------+

INCIDENT F - June 10
+------------------+--------------------------------------------------+
| Primary Pillar   | Confidentiality                                  |
+------------------+--------------------------------------------------+
| Justification    | Unauthorized device on internal network with     |
| (Primary)        | access to HR file share; employee data           |
|                  | potentially exposed.                             |
+------------------+--------------------------------------------------+
| Secondary Pillar | Integrity                                        |
+------------------+--------------------------------------------------+
| Justification    | Torrent client could introduce malware,          |
| (Secondary)      | potentially modifying network resources.         |
+------------------+--------------------------------------------------+
| Incident Summary | IT intern's personal laptop on internal network  |
|                  | (not guest) for 3 weeks, running torrent client. |
+------------------+--------------------------------------------------+


================================================================================
CIA TRIAD IMPACT STATISTICS
================================================================================

+------------------+---------------------+------------------------------------------+
| CIA Pillar       | Incidents           | Percentage                               |
+------------------+---------------------+------------------------------------------+
| Availability     | 3 (A, E, D*)        | 50%                                      |
| Integrity        | 2 (C, D)            | 33%                                      |
| Confidentiality  | 2 (B, F)            | 33%                                      |
| Multiple Pillars | 5 of 6              | 83%                                      |
+------------------+---------------------+------------------------------------------+

*Incident D impacted both Integrity and Availability.


================================================================================
PRIORITY CLASSIFICATION (Based on Impact)
================================================================================

+----------+---------------------+-----------------+------------------------------------------+
| Priority | Incident            | Primary Pillar  | Rationale                                |
+----------+---------------------+-----------------+------------------------------------------+
| CRITICAL | C (Pharmacy)        | Integrity       | Patient safety directly impacted.        |
| CRITICAL | B (Patient Portal)  | Confidentiality | PHI exposure. HIPAA regulatory risk.     |
| HIGH     | A (Ransomware)      | Availability    | 4-day operational disruption.            |
| HIGH     | E (EHR Outage)      | Availability    | 9-hour clinical disruption.              |
| MEDIUM   | F (Laptop)          | Confidentiality | Potential data exposure. Network         |
|          |                     |                 | segmentation failure.                    |
| LOW      | D (Website)         | Integrity       | No PHI exposure. Quick recovery.         |
+----------+---------------------+-----------------+------------------------------------------+


================================================================================
KEY FINDINGS
================================================================================

1. 83% of incidents impacted multiple CIA pillars.
   (NIST SP 800-12: CIA pillars are interconnected)

2. Availability was the most frequently impacted pillar (50%).
   Reflects operational challenges in healthcare IT.

3. Patient safety directly impacted in 2 incidents (C, E).
   (CISA Healthcare Guide: patient safety is primary concern)

4. Preventable failures (backup misconfig, untested scripts, untested
   rollback) caused 3 incidents.
   (ISO 27001 Gap Analysis: process failures are common gaps)

5. Network segmentation failures enabled Incident F.
   (CIS Control 12: network segmentation is critical)


================================================================================
END OF INCIDENT CLASSIFICATION REPORT
================================================================================
