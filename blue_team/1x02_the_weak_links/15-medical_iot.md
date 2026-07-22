================================================================================
                    MEDICAL IOT - MEDDEFENSE HEALTH SYSTEMS
                    Task 15: The Medical IoT
================================================================================

Exercise: Task 15 - The Medical IoT
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Assess vulnerabilities in connected medical devices with specific
          attention to patient safety implications.

Source: meddefense-vulnerability-scan.txt
Cross-References: 1x00 Gap Analysis (GAP-003, GAP-007), 1x01 Kill Chains


================================================================================
1. BD ALARIS ASSESSMENT
================================================================================

VULNERABILITY RESEARCH
----------------------
+----------------------------------------------------------------------------+
| Vendor Security Advisory: BD Alaris™ System Software v12.1.2              |
| Source: BD Document (Customer Highlights)                                |
| URL: https://www.bd.com/content/dam/bd-assets/bd-com/en-us/document/support/alaris-customer-highlights-v12-1-2.pdf |
+----------------------------------------------------------------------------+

VULNERABILITIES IDENTIFIED BY BD:
+----------------------------------------------------------------------------+
| 1. Interpeak (IPnet) TCP/IP Stack Vulnerability                           |
|    - Affects connected devices leveraging the IPnet standalone TCP/IP    |
|      networking stack                                                     |
|    - Requires compensating controls to minimize risk and impact         |
|                                                                             |
| 2. Network Session Vulnerability                                          |
|    - Authentication issue between BD Alaris PCU and BD Alaris Systems   |
|      Manager                                                              |
|    - Specified versions of the BD Alaris PCU and Systems Manager        |
|    - Customers should upgrade to v12.1.2 firmware AND Systems Manager   |
|      v12.3.0                                                             |
+----------------------------------------------------------------------------+

VENDOR RECOMMENDATIONS:
+----------------------------------------------------------------------------+
| 1. IMMEDIATE: Upgrade PCU firmware to v12.1.2                           |
| 2. IMMEDIATE: Upgrade Systems Manager to v12.3.0                        |
| 3. COMPENSATING CONTROLS: Implement network isolation and monitoring     |
|    as directed in the security bulletin                                 |
+----------------------------------------------------------------------------+

MEDDEFENSE IMPLEMENTATION STATUS:
+----------------------------------------------------------------------------+
| STATUS: UNKNOWN - The scan report (Finding 010) indicates the pumps     |
| are running firmware version 12.1.2. This is the version that ADDRESSES |
| the vulnerabilities but also the version that has NOT been cleared by    |
| the FDA (Distribution Hold).                                            |
|                                                                             |
| IMPORTANT CONTEXT FROM BD:                                                |
| - v12.1.2 is released under a Certificate of Medical Necessity (CMN)    |
|   program                                                                 |
| - "This device has not been cleared by FDA, and any FDA determination   |
|   regarding the device may take several months to over a year and may   |
|   not result in a cleared product"                                      |
| - The vulnerabilities ARE ADDRESSED but the device is in a regulatory   |
|   limbo state                                                            |
+----------------------------------------------------------------------------+


================================================================================
2. PHILIPS INTELLIVUE ASSESSMENT
================================================================================

WHAT DATA FLOWS THROUGH THESE INTERFACES?
-----------------------------------------
+----------------------------------------------------------------------------+
| DATA TYPES TRANSMITTED (Philips IntelliVue MX850/MX750):                  |
|                                                                             |
| 1. PATIENT VITAL SIGNS:                                                    |
|    - ECG, heart rate, blood pressure, SpO2, temperature, respiration     |
|                                                                             |
| 2. ALARM DATA:                                                             |
|    - Alarm conditions (encrypted via LAN to Active Display/XDS)          |
|                                                                             |
| 3. PATIENT IDENTIFIERS:                                                    |
|    - Patient names, MRNs, bed assignments                                 |
|                                                                             |
| 4. CONFIGURATION DATA:                                                     |
|    - Alarm thresholds, monitoring profiles                                |
|                                                                             |
| 5. HL7 DATA (Port 2575):                                                   |
|    - Patient demographic data                                             |
|    - Observation results                                                  |
|    - ADT (Admission, Discharge, Transfer) messages                       |
|                                                                             |
| Philips monitors are designed with cybersecurity features including:      |
| - Node authentication via certificates                                   |
| - Network data encryption                                                 |
| - Print report encryption                                                 |
| - Remote display data encryption                                         |
| - RFID/NFC card reader for user authentication                         |
|                                                                             |
| HOWEVER: The scan report found these devices on the FLAT NETWORK with     |
| NO VLAN isolation and unauthenticated web interfaces.                   |
+----------------------------------------------------------------------------+

WHAT AN ATTACKER WITH NETWORK ACCESS CAN SEE OR DO:
+----------------------------------------------------------------------------+
| With access to the flat network, an attacker can:                         |
|                                                                             |
| 1. VIEW PATIENT DATA:                                                      |
|    - Intercept HL7 messages containing PHI                               |
|    - Access web interfaces showing patient vital signs                  |
|                                                                             |
| 2. MANIPULATE DEVICE CONFIGURATION:                                       |
|    - Change alarm thresholds (potentially causing missed alarms)         |
|    - Modify monitoring profiles                                           |
|                                                                             |
| 3. TRIGGER FALSE ALARMS:                                                   |
|    - Send spoofed alarm messages causing clinical distraction             |
|                                                                             |
| 4. DENIAL OF SERVICE:                                                      |
|    - Flood HL7 port causing monitoring disruption                         |
|    - Crash device via web interface                                       |
|                                                                             |
| 5. PIVOT TO OTHER SYSTEMS:                                                 |
|    - Use the monitor as a stepping stone to the EHR or other devices    |
+----------------------------------------------------------------------------+


================================================================================
3. PATIENT SAFETY DIMENSION
================================================================================

+----------------------------------------------------------------------------+
| WHY MEDICAL DEVICE VULNERABILITIES ARE IN A DIFFERENT RISK CATEGORY       |
|                                                                             |
| Medical device vulnerabilities are in a fundamentally different risk      |
| category than IT system vulnerabilities because they can directly         |
| cause PATIENT HARM rather than just data loss.                           |
|                                                                             |
| A compromised workstation can lead to data theft or ransomware, but a    |
| compromised infusion pump can ALTER MEDICATION DOSAGES being delivered   |
| to a patient, potentially causing overdose, underdose, or death.  |
|                                                                             |
| Research shows that attacks on medical devices can lead to over-infusion |
| or under-infusion of medication, with direct consequences for patient    |
| safety .                                                  |
|                                                                             |
| WORST-CASE SCENARIO:                                                       |
|                                                                             |
| COMPROMISED WORKSTATION:                                                   |
| - Data breach (PHI exposure)                                              |
| - Ransomware encryption                                                   |
| - Operational disruption                                                  |
| - Financial and reputational damage                                      |
|                                                                             |
| COMPROMISED INFUSION PUMP:                                                 |
| - Patient receives incorrect medication dosage                           |
| - Patient injury or DEATH                                                 |
| - FDA recall and investigation                                            |
| - Criminal negligence charges                                              |
| - Massive liability lawsuits                                              |
| - Loss of patient trust in the healthcare system                        |
|                                                                             |
| The difference is: a workstation breach affects DATA. A pump breach      |
| affects PATIENTS. One can be fixed with backups. The other can end      |
| a life.                                                                    |
+----------------------------------------------------------------------------+


================================================================================
4. REMEDIATION CHALLENGE
================================================================================

+----------------------------------------------------------------------------+
| WHY PATCHING MEDICAL DEVICES IS HARDER THAN PATCHING IT SYSTEMS           |
|                                                                             |
| 1. REGULATORY FACTORS                                                     |
|    - FDA clearance required for software changes on medical devices       |
|    - The BD Alaris v12.1.2 update is under FDA review and has NOT been   |
|      cleared                                                              |
|    - "This device has not been cleared by FDA, and any FDA               |
|      determination regarding the device may take several months to       |
|      over a year and may not result in a cleared product"               |
|                                                                             |
| 2. OPERATIONAL FACTORS                                                   |
|    - Medical devices must operate 24/7 and cannot tolerate downtime      |
|    - Patching requires taking devices offline, which may impact          |
|      patient care                                                         |
|    - "Legacy devices can't be patched easily" because they are           |
|      designed for reliability and patient safety - not constant code    |
|      revisions                                      |
|    - Hospitals rely on equipment that often stays in service for a       |
|      decade or more because replacing them isn't financially or          |
|      operationally feasible                             |
|    - Cannot be tested in a lab environment before deployment (no         |
|      duplicate device)                                                    |
|                                                                             |
| 3. VENDOR DEPENDENCY                                                     |
|    - Only the manufacturer can create and validate patches              |
|    - The patch may require hardware replacement or vendor-led           |
|      remediation                                                          |
|    - BD is remediating devices at no charge but requires scheduling     |
|      through a formal process                             |
|    - SBOMs (Software Bills of Materials) are needed for transparency     |
|      but are often not provided                                           |
|                                                                             |
| 4. ENVIRONMENTAL FACTORS                                                 |
|    - Medical devices are often on the same network as other systems     |
|      (GAP-003) making segmentation difficult                            |
|    - Default credentials (GAP-007) are common and hard to change       |
|    - Devices may not have the resources to run modern security tools    |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Device   | Finding(s)       | Key Vulnerability                      | Priority         |
+----------+------------------+----------------------------------------+------------------+
| BD Alaris| 010 (Default     | Network Session Auth (CVE-2018-14786)  | CRITICAL         |
| Pumps    | Creds)           | Interpeak IPnet stack vulnerability   |                  |
|          |                  | Default credentials (admin/admin)    |                  |
+----------+------------------+----------------------------------------+------------------+
| Philips  | 016 (Web         | Unauthenticated web interfaces        | HIGH             |
| Monitors| Interfaces)      | HL7 traffic in cleartext              |                  |
|          |                  | Flat network exposure (GAP-003)       |                  |
+----------+------------------+----------------------------------------+------------------+
| PACS     | 024 (DICOM)      | Unencrypted medical images in transit | HIGH             |
| (DICOM)  |                  | (HIPAA violation)                     |                  |
+----------+------------------+----------------------------------------+------------------+


================================================================================
REFERENCES
================================================================================

- BD Alaris v12.1.2 Customer Highlights: https://www.bd.com/content/dam/bd-assets/bd-com/en-us/document/support/alaris-customer-highlights-v12-1-2.pdf
- BD Distribution Hold Notice: https://www.bd.com/en-us/support/alerts-and-notices-landing-page/distribution-hold-of-the-bd-alaris-system-update
- CIRCL CVE-2018-14786: https://vulnerability.circl.lu/search?vendor=Becton,+Dickinson+and+Company&product=Alaris+GS,+Alaris+GH,+Alaris+CC,+and+Alaris+TIVA
- Philips IntelliVue MX850: https://www.philips.si/healthcare/product/HC866470/intellivue-mx850-bedside-patient-monitor
- RunSafe Security: Beyond Patching - https://runsafesecurity.com/blog/beyond-patching-secure-medical-devices/
- PubMed: Security-Driven Product Design for Open-Source Medical Syringe Infusion Pumps

Cross-References to Project 1x00:
- Asset Registry (Task 7): IOT-001 (Philips monitors), IOT-002 (BD Alaris pumps)
- Gap Analysis (Task 12): GAP-003, GAP-007
- Legacy Dilemma (1x00 Task 6): MRI compensating controls

Cross-References to Project 1x01:
- Kill Chains (Task 10): KC #3 (IoT Patient Safety)
- Threat Actor Matrix (Task 6): Ransomware Groups (#1), Opportunistic (#6)


================================================================================
END OF MEDICAL IOT REPORT
================================================================================
