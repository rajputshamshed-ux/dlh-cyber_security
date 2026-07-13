================================================================================
                    CRITICALITY ASSESSMENT - MEDDEFENSE HEALTH SYSTEMS
                    Task 8: The Criticality Assessment
================================================================================

Exercise: Task 8 - The Criticality Assessment
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Evaluate the criticality of each asset category using CIA-based
          analysis, calibrated to the specific operational context of a
          healthcare organization.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Impact definitions
- NIST CSF 2.0: Identify Function - Business Context (ID.AM-3)
- HHS HICP: Healthcare operations context
- CISA Healthcare Guide: Healthcare asset criticality

Source: Asset Registry (Task 7), Onboarding Packet, Control Artifacts


================================================================================
1. CRITICALITY SCALE DEFINITIONS
================================================================================

+----------+------------------------------------------+----------------------------------------+
| Level    | Definition                               | Healthcare Context Example             |
+----------+------------------------------------------+----------------------------------------+
| CRITICAL | Compromise directly threatens patient    | EHR outage stops all clinical access   |
|          | safety, causes regulatory violation or   | for 50,000 patients.                   |
|          | halts clinical operations.               |                                        |
+----------+------------------------------------------+----------------------------------------+
| HIGH     | Compromise causes significant            | Billing system downtime delays claims  |
|          | operational disruption, financial loss   | processing for 4 days.                 |
|          | or data exposure.                        |                                        |
+----------+------------------------------------------+----------------------------------------+
| MEDIUM   | Compromise causes moderate disruption,   | Print server outage requires manual    |
|          | recoverable within standard procedures.  | workarounds.                           |
+----------+------------------------------------------+----------------------------------------+
| LOW      | Compromise has minimal operational or    | Public website defacement, no patient  |
|          | security impact.                         | data, quick restoration.               |
+----------+------------------------------------------+----------------------------------------+


================================================================================
2. ASSET CATEGORIES (8 Categories)
================================================================================

Category 1: EHR System
Assets: ehr-srv-01 (EHR Application), ehr-db-01 (EHR Database)
Description: The Electronic Health Record system stores all patient medical
histories, diagnoses, treatment plans, medications, and clinical notes.
It is the primary system used by physicians, nurses, and clinical staff
for patient care delivery across all three sites.

Category 2: PACS/Imaging System
Assets: pacs-srv-01 (PACS Server), Siemens MAGNETOM MRI, GE Revolution CT
Description: Picture Archiving and Communication System stores all diagnostic
images (X-rays, CT scans, MRIs). Radiology department relies on this for
imaging studies. Physicians access images for clinical decision-making.

Category 3: Billing & Revenue Cycle
Assets: billing-srv-01 (Billing/Claims Processing)
Description: Processes insurance claims, patient billing, and revenue cycle
management. Directly impacts organizational financial health.

Category 4: Active Directory & Authentication
Assets: ad-dc-01 (Primary DC), ad-dc-02 (Secondary DC), HID Badge System
Description: Provides authentication, authorization, and access control for
all Windows systems. Central to identity and access management.

Category 5: Network Core & Perimeter
Assets: FortiGate 100F, Cisco Core Switch, Cisco Access Switches, Ubiquiti APs
Description: Provides network connectivity, firewall protection, and VPN
access for all sites. Core infrastructure enabling all other systems.

Category 6: Medical IoT (Life-Safety)
Assets: Philips Monitors (80 units), BD Alaris Pumps (120 units),
Nurse Call System
Description: Patient monitoring devices, infusion pumps, and nurse call
systems that directly impact patient safety. These are life-safety devices.

Category 7: Clinical Endpoints
Assets: Central Workstations (320), Central Thin Clients (60),
Westside Workstations (45), iPads (25)
Description: Workstations and thin clients used by clinical staff to access
EHR, PACS, and other clinical systems at point of care.

Category 8: Administrative Endpoints & File Services
Assets: HQ Workstations (120), HQ Laptops (30), file-srv-01, O365 Tenant
Description: Administrative workstations, file shares, and cloud services
for administrative functions (Finance, HR, Legal, Executive).

Category 9: Backup & Recovery Infrastructure
Assets: backup-srv-01 (Veeam), Synology NAS-01
Description: Backup system and storage for critical data recovery.
Enables restoration after incidents.

Category 10: Physical Security Infrastructure
Assets: Server Room, Guard Service, Camera System, Badge System
Description: Physical access controls, surveillance, and security personnel
that protect physical assets and restrict unauthorized access.


================================================================================
3. ASSET CRITICALITY MATRIX
================================================================================

+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Asset Category   | Confidentiality | Integrity       | Availability    | Overall          | Justification                            |
|                  | Rating          | Rating          | Rating          | Criticality      |                                          |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| EHR System       | CRITICAL        | CRITICAL        | CRITICAL        | CRITICAL         | Contains PHI for 50,000+ patients. A     |
|                  |                 |                 |                 |                  | breach triggers HIPAA notification,      |
|                  |                 |                 |                 |                  | fines up to $1.5M per violation. An      |
|                  |                 |                 |                 |                  | outage halts all clinical access;        |
|                  |                 |                 |                 |                  | physicians cannot view patient records,  |
|                  |                 |                 |                 |                  | leading to potential medical errors.     |
|                  |                 |                 |                 |                  | The EHR is the single source of truth    |
|                  |                 |                 |                 |                  | for patient care.                        |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| PACS/Imaging     | CRITICAL        | CRITICAL        | HIGH            | CRITICAL         | Contains diagnostic images critical for  |
| System           |                 |                 |                 |                  | patient diagnosis. Radiology depends on  |
|                  |                 |                 |                 |                  | PACS for 45 MRI studies/day. Integrity   |
|                  |                 |                 |                 |                  | compromise could cause misdiagnosis.     |
|                  |                 |                 |                 |                  | Confidentiality breach exposes protected |
|                  |                 |                 |                 |                  | health information (PHI) from images.    |
|                  |                 |                 |                 |                  | Availability impacts diagnostic services |
|                  |                 |                 |                 |                  | but paper/manual workarounds exist.      |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Billing &        | HIGH            | HIGH            | HIGH            | HIGH             | Processing insurance claims and patient   |
| Revenue Cycle    |                 |                 |                 |                  | billing. A 4-day outage (January) halted |
|                  |                 |                 |                 |                  | revenue cycle. Confidentiality contains  |
|                  |                 |                 |                 |                  | patient financial data and insurance     |
|                  |                 |                 |                 |                  | information. Integrity compromise could  |
|                  |                 |                 |                 |                  | cause incorrect billing. Critical for    |
|                  |                 |                 |                 |                  | organizational financial viability.      |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Active Directory | HIGH            | CRITICAL        | HIGH            | CRITICAL         | Provides authentication for ALL Windows  |
| & Authentication |                 |                 |                 |                  | systems. Integrity compromise allows     |
|                  |                 |                 |                 |                  | attacker to create privileged accounts,  |
|                  |                 |                 |                 |                  | modify permissions, or lock out          |
|                  |                 |                 |                 |                  | administrators. This is the "keys to the |
|                  |                 |                 |                 |                  | kingdom" - if AD is compromised, ALL     |
|                  |                 |                 |                 |                  | systems are compromised.                 |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Network Core &   | MEDIUM          | HIGH            | CRITICAL        | CRITICAL         | The firewall and core switches are the   |
| Perimeter        |                 |                 |                 |                  | central nervous system of all network    |
|                  |                 |                 |                 |                  | connectivity. If the core switch fails   |
|                  |                 |                 |                 |                  | or firewall is misconfigured, ALL sites  |
|                  |                 |                 |                 |                  | lose connectivity. VPN access for        |
|                  |                 |                 |                 |                  | Westside and HQ depends on this. The     |
|                  |                 |                 |                 |                  | FortiGate protects the entire perimeter. |
|                  |                 |                 |                 |                  | Single point of failure for the network. |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Medical IoT      | HIGH            | CRITICAL        | CRITICAL        | CRITICAL         | Life-safety devices: 80 patient monitors |
| (Life-Safety)    |                 |                 |                 |                  | and 120 infusion pumps. Integrity        |
|                  |                 |                 |                 |                  | compromise could alter readings or       |
|                  |                 |                 |                 |                  | dosages, directly endangering patients.  |
|                  |                 |                 |                 |                  | Availability loss means no monitoring or |
|                  |                 |                 |                 |                  | incorrect medication delivery. These     |
|                  |                 |                 |                 |                  | are on the SAME flat network as          |
|                  |                 |                 |                 |                  | workstations (CISA Healthcare Guide:     |
|                  |                 |                 |                 |                  | medical device security is a priority).  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Clinical         | HIGH            | MEDIUM          | HIGH            | HIGH             | Clinical staff access EHR, PACS, and     |
| Endpoints        |                 |                 |                 |                  | other clinical systems. Compromise       |
|                  |                 |                 |                 |                  | (unlocked sessions) exposes PHI.         |
|                  |                 |                 |                 |                  | Availability disruption slows clinical   |
|                  |                 |                 |                 |                  | workflow but manual backup exists        |
|                  |                 |                 |                 |                  | (paper records). 320 workstations +      |
|                  |                 |                 |                 |                  | 60 thin clients - large attack surface.  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Administrative   | HIGH            | MEDIUM          | MEDIUM          | HIGH             | Contains employee PII, financial records,|
| Endpoints &      |                 |                 |                 |                  | HR data, and organizational budgets.     |
| File Services    |                 |                 |                 |                  | O365 contains email with sensitive data. |
|                  |                 |                 |                 |                  | file-srv-01 stores department file       |
|                  |                 |                 |                 |                  | shares. Compromise exposes sensitive     |
|                  |                 |                 |                 |                  | organizational data. Operational         |
|                  |                 |                 |                 |                  | impact is significant but not            |
|                  |                 |                 |                 |                  | life-safety critical.                    |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Backup &         | MEDIUM          | HIGH            | HIGH            | HIGH             | backup-srv-01 and NAS provide recovery   |
| Recovery         |                 |                 |                 |                  | capability. Integrity of backups is      |
| Infrastructure   |                 |                 |                 |                  | critical for restoration. The NAS is     |
|                  |                 |                 |                 |                  | co-located with servers (same room/      |
|                  |                 |                 |                 |                  | network/rack). If ransomware hits,       |
|                  |                 |                 |                 |                  | backups may also be encrypted. Offsite   |
|                  |                 |                 |                 |                  | backups were denied. Availability of     |
|                  |                 |                 |                 |                  | backups directly impacts recovery time.  |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+
| Physical         | MEDIUM          | MEDIUM          | HIGH            | HIGH             | Physical security prevents unauthorized  |
| Security         |                 |                 |                 |                  | access. Server room has unrestricted     |
| Infrastructure   |                 |                 |                 |                  | badge access (Observation 1). No cameras |
|                  |                 |                 |                 |                  | in server room area. Guard service only  |
|                  |                 |                 |                 |                  | M-F, 7AM-7PM. Physical access bypasses   |
|                  |                 |                 |                 |                  | ALL technical controls. A breach here    |
|                  |                 |                 |                 |                  | enables ALL other breaches.              |
+------------------+-----------------+-----------------+-----------------+------------------+------------------------------------------+


================================================================================
4. OVERALL CRITICALITY SUMMARY
================================================================================

+----------+------------------+--------------------------------------------------+
| Rank     | Category         | Overall Criticality                              |
+----------+------------------+--------------------------------------------------+
| 1        | EHR System       | CRITICAL                                         |
+----------+------------------+--------------------------------------------------+
| 2        | Medical IoT      | CRITICAL                                         |
|          | (Life-Safety)    |                                                  |
+----------+------------------+--------------------------------------------------+
| 3        | PACS/Imaging     | CRITICAL                                         |
|          | System           |                                                  |
+----------+------------------+--------------------------------------------------+
| 4        | Active Directory | CRITICAL                                         |
|          | & Authentication |                                                  |
+----------+------------------+--------------------------------------------------+
| 5        | Network Core &   | CRITICAL                                         |
|          | Perimeter        |                                                  |
+----------+------------------+--------------------------------------------------+
| 6        | Clinical         | HIGH                                             |
|          | Endpoints        |                                                  |
+----------+------------------+--------------------------------------------------+
| 7        | Administrative   | HIGH                                             |
|          | Endpoints &      |                                                  |
|          | File Services    |                                                  |
+----------+------------------+--------------------------------------------------+
| 8        | Backup &         | HIGH                                             |
|          | Recovery         |                                                  |
+----------+------------------+--------------------------------------------------+
| 9        | Physical         | HIGH                                             |
|          | Security         |                                                  |
+----------+------------------+--------------------------------------------------+
| 10       | Billing &        | HIGH                                             |
|          | Revenue Cycle    |                                                  |
+----------+------------------+--------------------------------------------------+

CRITICAL ASSETS: 5 categories
HIGH ASSETS: 5 categories
MEDIUM ASSETS: 0 categories
LOW ASSETS: 0 categories


================================================================================
5. TOP 5 MOST CRITICAL ASSETS
================================================================================

RANK 1: EHR SYSTEM (ehr-srv-01 + ehr-db-01)
--------------------------------------------
+----------------------------------------------------------------------------+
| Why this is #1:                                                            |
|                                                                             |
| The EHR system is the CENTRAL NERVOUS SYSTEM of patient care at            |
| MedDefense. It contains the complete medical history for 50,000+ active    |
| patients across all three sites. Physicians, nurses, and clinical staff    |
| depend on it for real-time access to diagnoses, medications, allergies,    |
| and treatment plans during every patient encounter.                        |
|                                                                             |
| A breach of the EHR exposes massive amounts of PHI, triggering mandatory   |
| HIPAA breach notification, potential fines up to $1.5 million per          |
| violation, and significant reputational damage.                            |
|                                                                             |
| An outage of the EHR stops ALL clinical operations. As seen in Incident E  |
| (Task 1 - 9-hour outage), physicians were forced to use paper records,     |
| leading to delays, potential errors, and compromised patient safety.       |
|                                                                             |
| The EHR is the single source of truth for patient care. If it is           |
| unavailable or compromised, MedDefense CANNOT deliver safe patient care.   |
+----------------------------------------------------------------------------+


RANK 2: MEDICAL IOT (Patient Monitors + Infusion Pumps)
-------------------------------------------------------
+----------------------------------------------------------------------------+
| Why this is #2:                                                            |
|                                                                             |
| Patient monitors (80 Philips IntelliVue) and infusion pumps (120 BD       |
| Alaris) are LIFE-SAFETY devices. They continuously monitor patient vital   |
| signs and deliver medication directly to patients.                        |
|                                                                             |
| These devices are on the SAME FLAT NETWORK (10.10.0.0/16) as workstations  |
| and servers (Marcus note: "If someone gets on the network they can reach   |
| the pumps"). An attacker could:                                             |
| - Alter vital sign readings (Integrity), causing missed deterioration      |
| - Disable alarms (Availability), risking patient death                     |
| - Change infusion dosages (Integrity), causing medication errors           |
|                                                                             |
| CISA Healthcare Guide explicitly identifies medical device security as a  |
| top priority. These devices are not just IT assets - they are PATIENT      |
| SAFETY devices. Their compromise directly risks human lives.               |
+----------------------------------------------------------------------------+


RANK 3: PACS/IMAGING SYSTEM (pacs-srv-01 + MRI + CT)
-----------------------------------------------------
+----------------------------------------------------------------------------+
| Why this is #3:                                                            |
|                                                                             |
| The PACS system stores all diagnostic images: X-rays, CT scans, MRIs.      |
| Radiology department processes approximately 45 MRI studies per day.       |
| Physicians rely on these images for diagnosis, treatment planning, and     |
| surgical guidance.                                                         |
|                                                                             |
| The MRI itself runs Windows XP (EOL 2014) - a CRITICAL vulnerability. It   |
| is on the same flat network and cannot be patched. The MRI is a permanent  |
| backdoor into the network that can be exploited.                           |
|                                                                             |
| Integrity compromise could cause incorrect image display (misdiagnosis).   |
| Availability loss delays diagnostic services and impacts surgical          |
| scheduling. Confidentiality breach exposes PHI contained in medical        |
| images.                                                                     |
|                                                                             |
| The MRI cost $2.1M and is 6 years into a 12-year lifespan - replacement   |
| is not feasible. Compensating controls are essential.                     |
+----------------------------------------------------------------------------+


RANK 4: ACTIVE DIRECTORY (ad-dc-01 + ad-dc-02)
-----------------------------------------------
+----------------------------------------------------------------------------+
| Why this is #4:                                                            |
|                                                                             |
| Active Directory is the authentication backbone for ALL Windows systems    |
| at MedDefense. It controls who can access what, across all three sites.    |
|                                                                             |
| If AD is compromised, the attacker gains the "keys to the kingdom":        |
| - Create privileged administrator accounts                                 |
| - Lock out legitimate administrators                                       |
| - Grant themselves access to ANY system                                     |
| - Modify permissions across the entire network                            |
|                                                                             |
| All EHR, PACS, billing, and file systems rely on AD for authentication.    |
| AD-DC-01 is backed up. AD-DC-02 is NOT backed up.                         |
|                                                                             |
| An AD compromise is a GAME OVER scenario. The attacker owns every          |
| system that relies on AD for authentication. The organization has to       |
| rebuild from scratch - a catastrophic event.                               |
+----------------------------------------------------------------------------+


RANK 5: NETWORK CORE & PERIMETER (FortiGate 100F + Core Switch)
----------------------------------------------------------------
+----------------------------------------------------------------------------+
| Why this is #5:                                                            |
|                                                                             |
| The FortiGate 100F firewall and core switch are the central nervous system |
| of the network. If the core switch fails or firewall is misconfigured:     |
| - ALL sites lose connectivity (Central, Westside, HQ)                     |
| - VPN access for Westside and HQ is cut off                               |
| - DMZ for web-srv-01 is compromised                                        |
| - The entire hospital network goes dark                                    |
|                                                                             |
| The firewall is the primary perimeter defense. It currently:               |
| - Allows ALL outbound traffic (no egress filtering) - crypto-miner still  |
|   connects to mining pools                                                |
| - VPN rules allow "ALL" services (too permissive)                         |
| - Has no network segmentation (flat network)                               |
|                                                                             |
| Failure of this critical infrastructure would impact ALL operations,       |
| including patient care. This is the network's single point of failure.     |
+----------------------------------------------------------------------------+


================================================================================
6. KEY FINDINGS
================================================================================

1. 5 categories are CRITICAL:
   - EHR System (patient care, PHI)
   - Medical IoT (life-safety devices)
   - PACS/Imaging (diagnostic images, Windows XP MRI)
   - Active Directory (authentication backbone)
   - Network Core (connectivity, perimeter)

2. 0 categories are MEDIUM or LOW. Every asset category has significant
   impact on operations, patient safety, or regulatory compliance.

3. The EHR System is #1 because it is the single source of truth for
   patient care. Without it, clinical operations stop.

4. Medical IoT devices are #2 because they directly impact PATIENT SAFETY
   and are on the same flat network as everything else.

5. The MRI (Windows XP) is a CRITICAL vulnerability within a CRITICAL asset
   category (PACS). It represents a permanent backdoor into the network.

6. The flat network (10.10.0.0/16) amplifies the criticality of EVERY asset.
   A compromise of ANY system can reach ALL systems. (CISA Healthcare Guide)

7. The Billing system is HIGH (not CRITICAL) because while financially
   critical, it does not directly impact patient safety.

8. Backup infrastructure is HIGH (not CRITICAL) because it is a recovery
   capability, but its current configuration (co-located NAS) limits its
   effectiveness. If restored from backups, it allows recovery.

9. Clinical endpoints are HIGH because they are the primary attack surface
   for the network and have direct access to the EHR.

10. Physical security is HIGH because unrestricted physical access bypasses
    ALL technical controls. (NIST SP 800-53 PE-3)


================================================================================
7. RECOMMENDATIONS BASED ON CRITICALITY
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Asset Category   | Recommended Action                    | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | EHR System       | Implement MFA for ALL EHR access.     | NIST SP 800-53   |
|          |                  | Segment network. Deploy SIEM.         | IA-2, SC-7       |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Medical IoT      | IMMEDIATELY segment IoT devices to    | NIST SP 800-53   |
|          |                  | isolated VLAN. Implement monitoring.  | SC-7, SI-4       |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | PACS/Imaging     | Implement compensating controls for   | NIST SP 800-53   |
|          |                  | MRI: network isolation, application   | SC-7, CM-6       |
|          |                  | whitelisting, host firewall.          |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Active Directory | Implement MFA for all AD admins.      | NIST SP 800-53   |
|          |                  | Audit privileged accounts.            | IA-2, AC-6       |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Network Core     | Implement egress filtering. Segment   | NIST SP 800-53   |
|          |                  | network. Implement redundancy.        | SC-7             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Clinical         | Implement screen lock policy.         | NIST SP 800-53   |
|          | Endpoints        | Deploy EDR.                           | AC-11, SI-3      |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Backup           | Implement offsite/cloud backups.      | NIST SP 800-53   |
|          |                  | Test recovery procedures.             | CP-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Physical         | Restrict server room badge access.    | NIST SP 800-53   |
|          | Security         | Install cameras.                      | PE-3, PE-6       |
+----------+------------------+----------------------------------------+------------------+


================================================================================
8. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3) - CIA Triad
- NIST SP 800-30: Risk Assessment (Chapter 2) - Impact definitions
- NIST SP 800-53 Rev.5: Security Controls (IA-2, SC-7, PE-3)
- NIST CSF 2.0: Identify Function - ID.AM-3 (Business Context)
- CISA Healthcare and Public Health Sector Guide
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF CRITICALITY ASSESSMENT REPORT
================================================================================
