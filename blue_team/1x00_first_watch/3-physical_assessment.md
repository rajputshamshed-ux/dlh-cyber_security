================================================================================
                    WALK-THROUGH RISK ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 3: The Walk-Through
================================================================================

Exercise: Task 3 - The Walk-Through
Analyst: shamshed rajput
Date: 11/07/2026

Objective: Apply structured risk reasoning (Vulnerability, Threat, Impact)
          to physical observations in a real environment.

Methodology References:
- NIST SP 800-12 Rev.1: CIA Triad (Chapters 2-3) - Foundational framework
- NIST SP 800-30: Threat, Vulnerability, Risk definitions (Chapter 2)
- NIST SP 800-53 Rev.5: Security Controls - Control Families (PE, AC, SC)
- CIS Controls v8: Critical controls (top-level understanding)
- NIST CSF 2.0: Identify Function (asset context)
- CISA Healthcare Guide: Healthcare threat context
- ISO 27001 Gap Analysis: Structured assessment methodology
- HHS HICP: Healthcare security practices

Source: Physical walk-through of MedDefense Central
Context: James Chen (Deputy CISO) conducting facility tour


================================================================================
OBSERVATION 1: SERVER ROOM ACCESS
================================================================================

DESCRIPTION
-----------
+----------------------------------------------------------------------------+
| The server room is on the ground floor, accessed from a corridor shared    |
| with the cafeteria. The door uses the same generic badge that every        |
| employee (clinical, administrative, custodial) receives on their first     |
| day. There is no camera covering the door. There is no visitor log.        |
+----------------------------------------------------------------------------+

VULNERABILITY
-------------
+----------------------------------------------------------------------------+
| Physical access control failure:                                            |
| 1. Badge access is not restricted - all employees have the same level      |
|    of access to the server room, regardless of role or need.              |
| 2. No monitoring of the server room door (no camera).                     |
| 3. No accountability for visitors (no visitor log).                       |
| 4. Server room located in high-traffic area (near cafeteria).             |
+----------------------------------------------------------------------------+

NIST SP 800-53 Mapping: PE-3 (Physical Access Control), PE-6 (Monitoring
Physical Access), AC-2 (Account Management - least privilege violation)

THREAT
------
+----------------------------------------------------------------------------+
| Plausible Scenarios:                                                       |
| 1. A disgruntled employee with valid badge enters the server room at      |
|    night (no camera, no logging) and physically damages or steals         |
|    servers.                                                               |
| 2. A custodian (with valid badge) inadvertently unplugs a server while    |
|    cleaning, causing an outage.                                           |
| 3. An attacker tailgates an employee through the door during busy         |
|    lunch hours (cafeteria traffic). No camera means no evidence.          |
| 4. A vendor or visitor enters the server room without supervision         |
|    (no visitor log).                                                      |
+----------------------------------------------------------------------------+

IMPACT
------
+----------------------------------------------------------------------------+
| CIA Pillar(s) Impacted:                                                    |
|                                                                             |
| Availability: Physical damage, theft, or accidental unplugging of         |
|               servers would cause critical system outages.                |
|                                                                             |
| Confidentiality: An attacker could directly access servers and exfiltrate |
|                  PHI, billing data, or other sensitive information.        |
|                                                                             |
| Integrity: Physical access allows installation of malicious hardware      |
|            (keyloggers, network sniffers) or unauthorized modifications.  |
+----------------------------------------------------------------------------+

SEVERITY: CRITICAL
------------------
+----------------------------------------------------------------------------+
| The server room contains the core infrastructure (EHR, billing, AD,       |
| PACS, backups) that supports patient care and billing operations.         |
| Unrestricted physical access creates a single point of failure that       |
| compromises ALL CIA pillars simultaneously.                               |
+----------------------------------------------------------------------------+

NIST SP 800-53 REFERENCE: PE-3 (Physical Access Control), PE-6 (Monitoring),
AC-2 (Account Management)


================================================================================
OBSERVATION 2: NETWORK CLOSET
================================================================================

DESCRIPTION
-----------
+----------------------------------------------------------------------------+
| A network closet on the second floor (containing switches and patch       |
| panels) has no lock. The door is ajar. Inside, taped to the wall next     |
| to the switch stack, is a laminated sheet labeled "Network Maintenance    |
| Credentials" with a username and password for the switch management       |
| interface.                                                                |
+----------------------------------------------------------------------------+

VULNERABILITY
-------------
+----------------------------------------------------------------------------+
| Physical and technical access control failure:                             |
| 1. Unlocked, open network closet - anyone can access network equipment.   |
| 2. Credentials stored in plaintext and visible to anyone entering the     |
|    closet.                                                                |
| 3. No physical security for network infrastructure.                       |
| 4. Shared credentials (indicated by laminated sheet) - no accountability. |
| 5. Switch management interface accessible from the physical port.         |
+----------------------------------------------------------------------------+

NIST SP 800-53 Mapping: PE-2 (Physical Access Authorizations), IA-5
(Authenticator Management), AC-6 (Least Privilege), SC-8 (Transmission
Confidentiality - but credentials exposed physically)

THREAT
------
+----------------------------------------------------------------------------+
| Plausible Scenarios:                                                       |
| 1. Anyone who enters the closet (employee, visitor, attacker) obtains     |
|    the switch credentials and gains administrative access to the          |
|    network infrastructure.                                                |
| 2. An attacker physically connects a rogue device to the switch and       |
|    uses the credentials to configure VLAN hopping or network sniffing.    |
| 3. A disgruntled employee uses the credentials to reconfigure the         |
|    network, causing outages or redirecting traffic.                       |
| 4. A custodian or visitor inadvertently unplugs a critical network        |
|    cable from the open patch panel.                                       |
+----------------------------------------------------------------------------+

IMPACT
------
+----------------------------------------------------------------------------+
| CIA Pillar(s) Impacted:                                                    |
|                                                                             |
| Confidentiality: Network credentials allow attackers to intercept,        |
|                  sniff, or redirect sensitive traffic (PHI, billing).     |
|                                                                             |
| Integrity: Attacker can reconfigure network devices, modify routing,      |
|            or redirect traffic to malicious destinations.                 |
|                                                                             |
| Availability: Attacker can shut down network segments, disconnect         |
|               critical systems, or cause network-wide outages.            |
+----------------------------------------------------------------------------+

SEVERITY: CRITICAL
------------------
+----------------------------------------------------------------------------+
| The switch credentials provide privileged access to the entire flat       |
| network (10.10.0.0/16). This vulnerability is EASY to exploit (just      |
| walk into the closet) and provides nearly unrestricted control over       |
| the entire infrastructure, including medical devices.                     |
+----------------------------------------------------------------------------+

NIST SP 800-53 REFERENCE: IA-5 (Authenticator Management), PE-2 (Physical
Access), AC-6 (Least Privilege)


================================================================================
OBSERVATION 3: NURSE STATION
================================================================================

DESCRIPTION
-----------
+----------------------------------------------------------------------------+
| At the third-floor nurse station, a workstation is logged into the EHR    |
| system with a patient's record visible on screen. No staff member is      |
| present. The session appears to have been idle for at least 15 minutes.   |
| A sign above the station reads: "For efficiency, please do not log out    |
| between shifts."                                                           |
+----------------------------------------------------------------------------+

VULNERABILITY
-------------
+----------------------------------------------------------------------------+
| Session management and access control failure:                             |
| 1. Unlocked workstation with active EHR session and patient data visible. |
| 2. No screen lock timeout configured for idle sessions.                   |
| 3. Organizational culture encourages not logging out (signage).           |
| 4. Patient PHI exposed to anyone passing by.                              |
| 5. No proximity-based or automatic session locking.                       |
+----------------------------------------------------------------------------+

NIST SP 800-53 Mapping: AC-11 (Session Lock), SC-28 (Protection of
Information at Rest - screen viewing is a form of disclosure), AC-12
(Session Termination)

THREAT
------
+----------------------------------------------------------------------------+
| Plausible Scenarios:                                                       |
| 1. A passerby (patient, visitor, unauthorized staff) reads the patient    |
|    record displayed on the screen (PHI exposure).                         |
| 2. An unauthorized person uses the logged-in session to view or modify    |
|    patient records, order tests, or prescribe medications.                |
| 3. A disgruntled employee uses the active session to modify or delete     |
|    patient records (integrity violation).                                 |
| 4. An attacker uses the active session as a pivot point into the EHR      |
|    system to install malware or exfiltrate data.                          |
+----------------------------------------------------------------------------+

IMPACT
------
+----------------------------------------------------------------------------+
| CIA Pillar(s) Impacted:                                                    |
|                                                                             |
| Confidentiality: PHI is visible and accessible to anyone who approaches   |
|                  the workstation. Patient privacy is violated.            |
|                                                                             |
| Integrity: Active session allows unauthorized modification of patient     |
|            records, potentially causing medical errors.                   |
|                                                                             |
| Availability: Malicious actions could lock or corrupt patient records.    |
+----------------------------------------------------------------------------+

SEVERITY: HIGH
--------------
+----------------------------------------------------------------------------+
| Direct exposure of PHI in a high-traffic clinical area creates immediate |
| HIPAA compliance risk and potential for patient data breaches. However,  |
| the scope is limited to one workstation and can be remediated with       |
| screen lock policy.                                                       |
+----------------------------------------------------------------------------+

NIST SP 800-53 REFERENCE: AC-11 (Session Lock), AC-12 (Session Termination),
SC-28 (Protection of Information at Rest)


================================================================================
OBSERVATION 4: MEDICAL IOT
================================================================================

DESCRIPTION
-----------
+----------------------------------------------------------------------------+
| In a patient room, a connected vital signs monitor displays diagnostic    |
| information including the device's IP address (10.10.3.47) and firmware   |
| version (v2.1.3, last updated 2019). The network cable runs to a wall     |
| port labeled "MED-3F-12." You notice this is the same IP range as the     |
| workstations you saw at the nurse station.                                |
+----------------------------------------------------------------------------+

VULNERABILITY
-------------
+----------------------------------------------------------------------------+
| Network segmentation and device management failure:                        |
| 1. Medical IoT devices are on the same network (10.10.3.0/24) as          |
|    workstations (from Observation 3, 10.10.1.0/24 are on same 10.10.0.0  |
|    /16 flat network).                                                     |
| 2. Firmware v2.1.3 from 2019 is significantly outdated (5+ years).       |
| 3. No network segmentation between life-safety devices and workstations.  |
| 4. Device IP address and model information is publicly visible on the     |
|    monitor (information disclosure).                                      |
| 5. Unknown if device credentials are default or changed.                  |
+----------------------------------------------------------------------------+

NIST SP 800-53 Mapping: SC-7 (Boundary Protection - segmentation),
CM-3 (Change Control - firmware updates), CM-6 (Configuration Settings),
SI-2 (Flaw Remediation - patching)

THREAT
------
+----------------------------------------------------------------------------+
| Plausible Scenarios:                                                       |
| 1. An attacker compromises a workstation on the same network, then        |
|    pivots to the IoT devices using known vulnerabilities in outdated      |
|    firmware (v2.1.3 from 2019).                                           |
| 2. An attacker alters patient monitor readings, causing incorrect         |
|    clinical decisions or alarms.                                         |
| 3. An attacker disables the monitor remotely, causing alarm failure       |
|    for patient deterioration.                                             |
| 4. Malware (ransomware) spreads from a workstation to medical devices     |
|    via the flat network, encrypting life-safety systems.                  |
+----------------------------------------------------------------------------+

IMPACT
------
+----------------------------------------------------------------------------+
| CIA Pillar(s) Impacted:                                                    |
|                                                                             |
| Integrity: Patient monitor readings could be altered, leading to wrong    |
|            clinical decisions.                                             |
|                                                                             |
| Availability: Device could be disabled, causing loss of monitoring for    |
|               patients.                                                    |
|                                                                             |
| Patient Safety: This is a life-safety critical system. Incorrect          |
|                  readings or loss of monitoring directly endangers         |
|                  patients.                                                 |
+----------------------------------------------------------------------------+

SEVERITY: CRITICAL
------------------
+----------------------------------------------------------------------------+
| Life-safety medical devices on the same flat network as workstations      |
| creates the highest risk scenario: an attacker can reach and potentially  |
| manipulate devices that keep patients alive. Firmware is 5+ years old     |
| with known vulnerabilities.                                                |
+----------------------------------------------------------------------------+

NIST SP 800-53 REFERENCE: SC-7 (Boundary Protection - segmentation),
SI-2 (Flaw Remediation - patching), CM-3 (Change Control)


================================================================================
OBSERVATION 5: EMERGENCY EXIT
================================================================================

DESCRIPTION
-----------
+----------------------------------------------------------------------------+
| A fire exit door between the public waiting area and the restricted       |
| administrative wing is propped open with a wooden wedge. A handwritten    |
| sign taped to the door reads: "Please do not close, staff passage."       |
| Through the open door, you can see the hallway leading to the IT          |
| department and James Chen's office.                                       |
+----------------------------------------------------------------------------+

VULNERABILITY
-------------
+----------------------------------------------------------------------------+
| Physical security boundary failure:                                        |
| 1. Fire exit is propped open (wooden wedge) - no access control.          |
| 2. Public waiting area has direct access to restricted administrative     |
|    wing through open door.                                                |
| 3. No security awareness - handwritten sign encourages the behavior.      |
| 4. IT department and CISO office are in the restricted area.              |
| 5. No secondary barrier (turnstile, guard, camera).                      |
+----------------------------------------------------------------------------+

NIST SP 800-53 Mapping: PE-3 (Physical Access Control), PE-5 (Access Control
for Output Devices), PE-6 (Monitoring Physical Access), PE-8 (Visitor Access
Records)

THREAT
------
+----------------------------------------------------------------------------+
| Plausible Scenarios:                                                       |
| 1. An unauthorized person (patient, visitor, attacker) walks from the     |
|    public waiting area into the administrative wing.                      |
| 2. An attacker gains physical access to IT department and James Chen's   |
|    office, potentially accessing sensitive documents, laptops, or        |
|    network infrastructure.                                               |
| 3. A tailgater follows staff through the open door without challenge.    |
| 4. The open door violates fire safety codes (fire exit must remain       |
|    closed when not in emergency use).                                     |
+----------------------------------------------------------------------------+

IMPACT
------
+----------------------------------------------------------------------------+
| CIA Pillar(s) Impacted:                                                    |
|                                                                             |
| Confidentiality: Unauthorized individuals access administrative wing      |
|                  and IT department, potentially viewing sensitive         |
|                  documents, financial records, or security plans.         |
|                                                                             |
| Integrity: Physical access allows installation of devices, theft of       |
|            equipment, or sabotage.                                        |
|                                                                             |
| Availability: An attacker could physically damage IT infrastructure      |
|               or steal equipment causing outages.                         |
+----------------------------------------------------------------------------+

SEVERITY: HIGH
--------------
+----------------------------------------------------------------------------+
| While this is a physical security failure, it can be easily fixed with    |
| training and enforcing closure of the fire door. However, it              |
| demonstrates a systemic lack of security culture and awareness.           |
| Additionally, it creates a pathway to IT leadership and core             |
| infrastructure.                                                            |
+----------------------------------------------------------------------------+

NIST SP 800-53 REFERENCE: PE-3 (Physical Access Control), PE-6 (Monitoring
Physical Access), PE-8 (Visitor Access Records)


================================================================================
6. SUMMARY TABLE - ALL OBSERVATIONS
================================================================================

+----------+------------------------------------------+-----------------+------------------+
| Obs.     | Vulnerability                           | Threat          | Severity         |
+----------+------------------------------------------+-----------------+------------------+
| 1        | Unrestricted badge access to server      | Employee/       | CRITICAL         |
|          | room. No camera. No visitor log.        | attacker gains  |                  |
|          |                                          | physical access |                  |
|          |                                          | to servers      |                  |
+----------+------------------------------------------+-----------------+------------------+
| 2        | Unlocked network closet. Credentials     | Attacker gains  | CRITICAL         |
|          | taped to wall in plaintext.              | network admin   |                  |
|          |                                          | credentials     |                  |
+----------+------------------------------------------+-----------------+------------------+
| 3        | Unlocked EHR session. Screen visible.    | Passerby reads  | HIGH             |
|          | No screen lock. Sign encourages staying  | patient PHI     |                  |
|          | logged in.                               |                  |                  |
+----------+------------------------------------------+-----------------+------------------+
| 4        | Medical devices on flat network. Old     | Attacker pivots | CRITICAL         |
|          | firmware (2019). No segmentation.        | to life-safety  |                  |
|          |                                          | devices         |                  |
+----------+------------------------------------------+-----------------+------------------+
| 5        | Fire exit propped open. Public access    | Unauthorized    | HIGH             |
|          | to administrative wing.                  | entry to IT     |                  |
|          |                                          | department      |                  |
+----------+------------------------------------------+-----------------+------------------+


================================================================================
7. KEY TAKEAWAYS
================================================================================

1. Physical security is the foundation of information security.
   (NIST SP 800-53 PE family: Physical security controls)

2. Unrestricted physical access = full access to ALL CIA pillars.
   (NIST SP 800-12: Physical security enables all other security controls)

3. Credentials in plaintext (taped to wall) violate all authentication
   best practices. (NIST SP 800-53 IA-5: Authenticator Management)

4. Medical IoT devices on a flat network with workstations is a
   life-safety risk. (CISA Healthcare Guide: Segment medical devices)

5. Unlocked sessions expose PHI and violate HIPAA requirements.
   (HHS HICP: Access control)

6. Security culture failure: signs encouraging insecure behavior
   (Nurse station "don't log out") and propped doors.

7. All 5 observations represent gaps that can be addressed with
   relatively low-cost controls:
   - Restrict badge access
   - Install cameras
   - Implement screen locks
   - Segment network
   - Enforce door closure
   - Remove plaintext credentials


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Threat/Vulnerability/Risk
- NIST SP 800-53 Rev.5: Security Controls - PE, AC, SC, IA, SI, CM
- CIS Controls v8: Critical Security Controls
- NIST CSF 2.0: Identify Function
- CISA Healthcare and Public Health Sector Guide
- ISO 27001 Gap Analysis: Methodology
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF WALK-THROUGH RISK ANALYSIS REPORT
================================================================================
