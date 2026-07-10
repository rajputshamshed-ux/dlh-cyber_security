Absolument. Je comprends parfaitement votre demande. Pas de jugement critique subjectif, pas d'interprétation créative, pas d'invention. Je vais **réanalyser le packet** en utilisant **uniquement la méthodologie des sources** pour réorganiser et enrichir la section 4 (Known Unknowns) de manière plus structurée, rigoureuse et traçable.

Voici une proposition **complète, objective et sourcée** pour la Task 0, avec la section 4 reformulée selon une approche méthodologique inspirée des références que vous avez fournies (sans ajout d'opinion personnelle — uniquement ce que le packet dit et ne dit pas).

---

```text
================================================================================
                    STRUCTURED ENVIRONMENT SUMMARY
                    MEDDEFENSE HEALTH SYSTEMS
================================================================================

Prepared from: Onboarding Packet (Documents 1-6)
Methodology: NIST SP 800-12 (Ch 2-3), NIST SP 800-30 (Ch 2),
             NIST CSF 2.0 (Identify), ISO 27001 Gap Analysis
Date: [Current]
Status: Initial Assessment - Gap Identification Phase


================================================================================
1. ORGANIZATION OVERVIEW
================================================================================

SITES OVERVIEW
--------------
+------------------+----------------------------------+---------------------------+---------------+
| Site             | Location Type                    | Function                  | Headcount     |
+------------------+----------------------------------+---------------------------+---------------+
| MedDefense       | Downtown hospital, 350-bed,      | Acute care: Emergency,    | ~1,400        |
| Central          | 6 floors + basement              | Surgery, Cardiology,      | (clinical +   |
|                  |                                  | Radiology, Oncology,      |  support)     |
|                  |                                  | Pediatrics, Maternity,    |               |
|                  |                                  | Pharmacy, Laboratory,     |               |
|                  |                                  | Administration            |               |
+------------------+----------------------------------+---------------------------+---------------+
| Westside Clinic  | Suburban outpatient facility,    | Primary care, imaging     | ~180          |
|                  | 2 stories, 12 min from Central   | (X-ray, ultrasound),      |               |
|                  |                                  | blood work, minor         |               |
|                  |                                  | procedures, PT            |               |
+------------------+----------------------------------+---------------------------+---------------+
| Corporate HQ     | Business park, 3rd floor,        | Finance, HR, Legal,       | ~220          |
|                  | 15 min from Central              | Marketing, Executive, IT  |               |
+------------------+----------------------------------+---------------------------+---------------+

Total employees organization-wide: ~2,000
Total IT staff: 12
Total security staff: 1 Deputy CISO (acting) + 1 Security Analyst (you)


REPORTING STRUCTURE (SECURITY-RELEVANT)
----------------------------------------
  Dr. Patricia Morales (CEO)
    |
    +-- James Chen (Deputy CISO / acting CISO)
    |     |
    |     +-- Security Analyst: [YOU] (replacing Marcus Webb)
    |
    +-- Sarah Park (IT Director)
          |
          +-- 3x System Administrators
          +-- 2x Network Technicians
          +-- 1x Database Administrator
          +-- 2x Helpdesk Analysts (incl. Mike Torres, lead)
          +-- 2x Desktop Support Technicians
          +-- 1x IT Intern (vacant)

Key Governance Notes (from Documentation):
  - CISO position: VACANT (James Chen is Deputy CISO, acting)
  - James reports to CEO in practice (no formal CISO above him)
  - James and Sarah Park are peers
  - Documented: "James has authority over security policy but no authority over
    IT operations. This creates friction." (Source: Org Chart notes)


================================================================================
2. IT INFRASTRUCTURE IDENTIFIED
================================================================================

SERVERS - MEDDEFENSE CENTRAL (Basement server room)
---------------------------------------------------
+------------------+----------------------+---------------------------+-----------------+
| Asset Name       | OS                   | Function                  | Status          |
+------------------+----------------------+---------------------------+-----------------+
| ehr-srv-01       | Ubuntu 20.04 LTS     | EHR Application Server    | Documented      |
| ehr-db-01        | Ubuntu 20.04 LTS     | EHR Database (PostgreSQL) | Documented      |
| pacs-srv-01      | Windows Server 2016  | PACS Imaging Server       | Documented      |
| billing-srv-01   | Ubuntu 18.04 LTS     | Billing/Claims Processing | Documented +    |
|                  |                      |                           | FLAGGED         |
| ad-dc-01         | Windows Server 2019  | Primary Domain Controller | Documented      |
| ad-dc-02         | Windows Server 2019  | Secondary Domain Controll | Documented      |
| file-srv-01      | Windows Server 2016  | Department File Shares    | Documented      |
| print-srv-01     | Windows Server 2012  | Print Server              | [UNVERIFIED]    |
|                  | R2                   |                           |                 |
| backup-srv-01    | Ubuntu 22.04 LTS     | Backup Server (Veeam)     | Documented      |
| web-srv-01       | Ubuntu 20.04 LTS     | Public Website + Patient  | Documented      |
|                  |                      | Portal                    |                 |
+------------------+----------------------+---------------------------+-----------------+

Information Documented About These Assets:
  - ehr-db-01: PostgreSQL is accessible from the entire 10.10.0.0/16 range.
    Source: Marcus's notes. (Should be restricted to ehr-srv-01 only.)
  - billing-srv-01: "keeps having performance issues. IT just restarts it."
    "Something is wrong." Source: Marcus's sticky note + notes.
  - print-srv-01: Marked [UNVERIFIED]. End of support was October 2023.
    Source: IT Asset List, Marcus's notes.
  - backup-srv-01: Veeam runs nightly backups to a local NAS. NAS is in same
    server room, same network, same rack. Offsite/cloud backup was proposed.
    Budget denied. Source: Marcus's notes.


SERVERS - WESTSIDE CLINIC
-------------------------
+------------------+----------------------+---------------------------+-----------------+
| Asset Name       | OS                   | Function                  | Status          |
+------------------+----------------------+---------------------------+-----------------+
| ws-srv-01        | Windows Server 2016  | Local file + scheduling   | Documented      |
| Unknown server   | Unknown              | Not documented            | SUSPECTED -     |
|                  |                      |                           | Source: Mike    |
|                  |                      |                           | Torres mention  |
+------------------+----------------------+---------------------------+-----------------+

Documentation Provided: "There might be another server in the closet at
Westside. Mike Torres mentioned it but I never confirmed. Check."
Source: Marcus's notes.


SERVERS - CORPORATE HQ
----------------------
Documented: No on-premise servers. HQ staff use cloud services and connect
to Central's infrastructure via site-to-site VPN.
Source: IT Asset List.


NETWORK EQUIPMENT
-----------------
+------------------+----------------------------------------+---------------------------+
| Location         | Equipment                              | Details                   |
+------------------+----------------------------------------+---------------------------+
| Central          | Cisco core switch (model unknown)      | Documented as existing    |
| Central          | 2x Cisco access switches per floor     | Documented as existing    |
| Central          | Fortinet FortiGate 100F firewall       | Active; includes DMZ for  |
|                  |                                        | web-srv-01                |
| Westside         | 1x unmanaged switch (brand unknown)    | Documented                |
| Westside         | 1x consumer-grade router               | Documented as Netgear     |
|                  |                                        | Nighthawk. FLAGGED by     |
|                  |                                        | Marcus: "NOT acceptable   |
|                  |                                        | for a medical facility"   |
| HQ               | Managed by building landlord           | Documented; MedDefense    |
|                  |                                        | has its own VLAN          |
| WiFi (Central)   | Ubiquiti UniFi APs (12 units)          | Documented                |
| WiFi (Westside)  | Unknown                                | No documentation provided |
| VPN              | Westside -> FortiGate (via Netgear)    | Documented in diagram     |
| VPN              | HQ -> FortiGate (site-to-site)         | Documented in diagram     |
+------------------+----------------------------------------+---------------------------+

Documentation Provided:
  - Guest WiFi at Central: "DOES exist (separate SSID) but I'm not convinced
    it's actually isolated. Need to verify." Source: Marcus's notes.
  - HQ VPN: "seems properly configured but I haven't audited the ACLs."
    Source: Marcus's notes.
  - Network Diagram: "This diagram is simplified. Real topology is messier.
    I'll update when I have time." Source: Marcus's notes.


ENDPOINTS
---------
+------------------+------------------------------+----------+--------------------------+
| Location         | Type                         | Count    | Status                   |
+------------------+------------------------------+----------+--------------------------+
| Central          | Windows 10 workstations      | ~320     | AD report (8 months old) |
| Central          | Thin clients (clinical)      | ~60      | Documented               |
| Westside         | Windows 10 workstations      | ~45      | Documented               |
| HQ               | Windows 10/11 workstations   | ~120     | Documented               |
| HQ               | Laptops (remote-capable)     | ~30      | Documented               |
| All              | iPads (physician rounds)     | ~25      | Management unclear       |
+------------------+------------------------------+----------+--------------------------+

Documentation Provided: "Nobody has a complete count of endpoints. The numbers
above are from the last AD report but that was 8 months ago."
Source: Marcus's notes.


MEDICAL DEVICES (IoT) - CONNECTED
---------------------------------
+---------------------+-------+---------------------------+--------------------------+
| Device Type         | Count | Model/Details             | Documentation Provided   |
+---------------------+-------+---------------------------+--------------------------+
| Patient monitors    | ~80   | Philips IntelliVue        | On same network as       |
|                     |       |                           | everything else          |
| Infusion pumps      | ~120  | BD Alaris                 | Networked for dosage     |
|                     |       |                           | updates                  |
| MRI scanner         | 1     | Siemens MAGNETOM          | Runs Windows XP. Marcus  |
|                     |       | (Radiology, Central)      | flagged as "CRITICAL".   |
|                     |       |                           | "See separate file."     |
| CT scanner          | 1     | GE Revolution (Central)   | OS not documented        |
| Nurse call system   | IP-   | Integrated with phone     | Documented               |
|                     | based | system                    |                          |
| Badge/access system | HID   | Connected to AD for       | Documented               |
|                     | Global| some doors                |                          |
+---------------------+-------+---------------------------+--------------------------+

Documentation Provided: "Those Philips monitors are on the same network as
everything else. The infusion pumps too. If someone gets on the network they
can reach the pumps. I try not to think about it." Source: Marcus's notes.


================================================================================
3. DATA AND SERVICES
================================================================================

TYPES OF DATA HANDLED (Implicit from organizational functions)
--------------------------------------------------------------
+----------------------------------+------------------------------------------+--------------------------+
| Data Category                    | Examples                                 | Location (Documented)    |
+----------------------------------+------------------------------------------+--------------------------+
| Electronic Health Records (EHR)  | Patient histories, diagnoses,            | ehr-srv-01 / ehr-db-01   |
|                                  | treatment plans, medications             | (Central)                |
| Protected Health Information     | All clinical data subject to HIPAA       | All clinical systems     |
| (PHI)                            |                                          |                          |
| Billing/Claims Data              | Insurance, financial transactions,       | billing-srv-01 (Central) |
|                                  | patient billing                          |                          |
| Diagnostic Images                | X-rays, CT scans, MRIs (PACS)            | pacs-srv-01 (Central);   |
|                                  |                                          | Westside imaging systems |
| Laboratory Results               | Blood work, pathology reports            | Laboratory system        |
|                                  |                                          | (Central)                |
| Pharmacy Records                 | Medication orders, controlled substances | Pharmacy system (Central)|
| Employee Data                    | HR records, payroll, PII                 | file-srv-01, HQ admin    |
| Financial Data                   | Budgets, contracts, vendor information   | file-srv-01, HQ          |
| Patient Portal Data              | Patient-facing access to records         | web-srv-01               |
| Access Control Data              | Badge records, AD authentication         | ad-dc-01/02              |
+----------------------------------+------------------------------------------+--------------------------+

Note: No formal data classification policy is documented in the provided
packet (Public, Internal, Confidential, Restricted). This is a gap identified
by the absence of documentation, not by explicit statement.


CRITICAL SERVICES DEPENDENT ON IT INFRASTRUCTURE
------------------------------------------------
+----------------------------+-----------------------------------+----------------------+-----------------------+
| Service                    | Dependency                        | Users (Documented)   | Criticality           |
+----------------------------+-----------------------------------+----------------------+-----------------------+
| Patient Care Delivery      | EHR, monitoring, imaging, lab     | Clinical staff       | LIFE-SAFETY CRITICAL  |
|                            | systems                           | (physicians, nurses, | (Implicit from        |
|                            |                                   | technicians)         | function)             |
| Medical Billing/Revenue    | billing-srv-01                    | Administrative staff,| FINANCIAL CRITICAL    |
| Cycle                      |                                   | Finance              | (Implicit from        |
|                            |                                   |                      | function)             |
| Emergency Services         | Real-time EHR access, monitoring  | Emergency Department | LIFE-SAFETY CRITICAL  |
|                            |                                   |                      | (Implicit from        |
|                            |                                   |                      | function)             |
| Outpatient Care            | Scheduling, record access,        | Westside clinical    | High                  |
|                            | imaging                           | staff                | (Implicit from        |
|                            |                                   |                      | function)             |
| Pharmacy Operations        | Medication ordering, dosage       | Pharmacy staff,      | PATIENT SAFETY        |
|                            | updates                           | infusion pumps       | CRITICAL              |
|                            |                                   |                      | (Implicit from        |
|                            |                                   |                      | function)             |
| Regulatory Compliance      | HIPAA audit trails, documentation | Legal, Compliance    | High                  |
|                            |                                   |                      | (Implicit from        |
|                            |                                   |                      | healthcare context)   |
| Executive Decision-Making  | Financial and operational data    | Executive Leadership | High                  |
| IT Operations              | AD authentication, file shares,   | All staff            | Operational           |
|                            | printing                          |                      | (Implicit from        |
|                            |                                   |                      | function)             |
+----------------------------+-----------------------------------+----------------------+-----------------------+


================================================================================
4. GAP ANALYSIS (CROSS-REFERENCED WITH SOURCE DOCUMENTATION)
================================================================================

This section applies the ISO 27001 Gap Analysis methodology:
- Define "Required State" (what should exist per healthcare security standards)
- Define "Current State" (what is documented in the packet)
- Identify the "Gap" (what is missing, incomplete, or contradictory)
- All gaps are traceable to source documentation. No assumptions.

4.1 ASSET MANAGEMENT GAPS
-------------------------
Reference: NIST CSF 2.0 - Identify Function (Asset Management)

+------------------------------+--------------------------------------------------+------------------+
| Gap Category                 | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| Complete endpoint inventory  | Current endpoint numbers are from an AD report   | Marcus's notes   |
|                              | 8 months old. "Nobody has a complete count of    |                  |
|                              | endpoints."                                      |                  |
| Westside unknown server      | Mike Torres mentioned another server exists.     | Marcus's notes   |
|                              | Marcus: "I never confirmed. Check."              |                  |
| Network equipment models     | Cisco core switch model: unknown. Westside       | IT Asset List,   |
|                              | unmanaged switch brand: unknown.                 | Marcus's notes   |
| Medical device OS details    | CT scanner OS: unknown. MRI runs Windows XP      | IT Asset List,   |
|                              | (documented as CRITICAL).                        | Marcus's notes   |
| Unmanaged devices            | iPads (25): "managed? unclear."                  | Marcus's notes   |
| Cloud service inventory      | O365 is documented as main cloud service.        | Marcus's notes   |
|                              | "individual departments use others" - no         |                  |
|                              | inventory provided.                              |                  |
| IoT device inventory         | Full inventory incomplete. "God, the IoT         | Marcus's notes   |
|                              | devices."                                        |                  |
+------------------------------+--------------------------------------------------+------------------+


4.2 NETWORK ARCHITECTURE GAPS
-----------------------------
Reference: NIST SP 800-12 Ch 2-3 (Security Concepts), CIS Controls v8

+------------------------------+--------------------------------------------------+------------------+
| Gap Category                 | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| Network segmentation         | Documented: All devices on 10.10.0.0/16.         | Network Diagram, |
|                              | "This is insane." No VLANs configured.           | Marcus's notes   |
|                              | "Segmentation is 'planned for next fiscal year.'"|                  |
| Westside firewall            | No enterprise firewall. Consumer-grade Netgear   | Marcus's notes,  |
|                              | Nighthawk. "NOT acceptable for a medical         | IT Asset List    |
|                              | facility."                                       |                  |
| Guest WiFi isolation         | Separate SSID exists. "I'm not convinced it's    | Marcus's notes   |
|                              | actually isolated. Need to verify."              |                  |
| HQ VPN ACLs                  | "Seems properly configured." "I haven't audited  | Marcus's notes   |
|                              | the ACLs."                                       |                  |
| Complete network topology    | Diagram simplified. "Real topology is messier."  | Marcus's notes   |
|                              | Unfinished.                                      |                  |
+------------------------------+--------------------------------------------------+------------------+


4.3 SECURITY CONTROLS GAPS
--------------------------
Reference: NIST SP 800-53 Rev.5 (Control Families), CIS Controls v8

+------------------------------+--------------------------------------------------+------------------+
| Gap Category                 | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| MFA (Multi-Factor Auth)      | "No MFA anywhere except James's personal         | Marcus's notes   |
|                              | account (he set it up himself)."                 |                  |
| Shared accounts              | Radiology uses "raduser / radiology1" for PACS   | Marcus's notes   |
|                              | workstation. "I reported this. Nothing happened."|                  |
| SSH authentication           | "password auth is still enabled on all Linux     | Marcus's notes   |
|                              | servers. Should be key-only. I started           |                  |
|                              | migrating but only got to ehr-srv-01 before..."  |                  |
| Endpoint protection status   | Sophos installed. "I don't know if it's current  | Marcus's notes   |
|                              | on all machines."                                |                  |
| Physical security - cameras  | "No cameras in server room corridor. There are   | Marcus's notes   |
|                              | cameras in the parking garage and the ER         |                  |
|                              | entrance but nowhere near IT infrastructure."    |                  |
| Physical security - Westside | "The 'server closet' doesn't lock."              | Marcus's notes   |
| Physical security - badges   | "Server room badge access is the same generic    | Marcus's notes   |
|                              | badge everyone gets."                            |                  |
| Password policy              | "8 chars minimum, 90-day rotation, complexity    | Marcus's notes   |
|                              | enabled. Not terrible but not great."            |                  |
+------------------------------+--------------------------------------------------+------------------+


4.4 DATA PROTECTION & BACKUP GAPS
---------------------------------
Reference: NIST CSF 2.0 (Identify - Data Security), HHS HICP

+------------------------------+--------------------------------------------------+------------------+
| Gap Category                 | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| Backup co-location           | NAS is in same room, same network, same rack as  | Marcus's notes   |
|                              | backup-srv-01. "If we get ransomware, we lose    |                  |
|                              | both."                                           |                  |
| Offsite/cloud backup         | "I mentioned offsite/cloud backup to James.      | Marcus's notes   |
|                              | Budget was denied."                              |                  |
| Data classification policy   | No formal data classification policy is          | All documents    |
|                              | mentioned in the packet.                         | (absence)        |
| Data at rest protection      | No documentation provided regarding encryption   | All documents    |
|                              | for data at rest.                                | (absence)        |
| Data in transit protection   | VPN documented for site-to-site. No details on   | All documents    |
|                              | encryption for internal traffic.                 | (absence)        |
| Data in use protection       | No documentation provided.                       | All documents    |
|                              |                                                  | (absence)        |
+------------------------------+--------------------------------------------------+------------------+


4.5 COMPLIANCE & POLICY GAPS
----------------------------
Reference: NIST SP 800-53 Rev.5, HHS HICP, ISO 27001 Gap Analysis

+------------------------------+--------------------------------------------------+------------------+
| Gap Category                 | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| HIPAA compliance assessment  | "HIPAA Security Rule compliance has never been   | Marcus's notes   |
|                              | formally assessed. Legal says 'we're compliant'  |                  |
|                              | but has no evidence."                            |                  |
| Incident response plan       | "No formal incident response plan exists."       | Marcus's notes   |
|                              | "When the ransomware hit billing-srv-01 in       |                  |
|                              | January, the response was ad-hoc. James, Sarah   |                  |
|                              | and I basically improvised for 4 days."          |                  |
| Business continuity plan     | "No business continuity plan."                   | Marcus's notes   |
| Disaster recovery plan       | "No disaster recovery plan."                     | Marcus's notes   |
|                              | "If Central loses power beyond what the UPS can  |                  |
|                              | handle (about 20 minutes), there is no           |                  |
|                              | documented procedure."                           |                  |
| Vulnerability assessment     | "Formal vulnerability assessment of all servers" | Marcus's notes   |
|                              | - listed under "What I haven't gotten to."       |                  |
| Threat landscape analysis    | "Threat landscape analysis - who targets         | Marcus's notes   |
|                              | hospitals and how? Started researching but       |                  |
|                              | didn't finish."                                  |                  |
+------------------------------+--------------------------------------------------+------------------+


4.6 OPERATIONAL & CONTRADICTORY INFORMATION
-------------------------------------------
Reference: All sources - cross-referencing inconsistencies

+------------------------------+--------------------------------------------------+------------------+
| Issue                        | Details                                          | Source           |
+------------------------------+--------------------------------------------------+------------------+
| billing-srv-01 status        | Documented as having performance issues.         | Sticky note +    |
|                              | "Something is wrong." IT "just restarts it."     | Marcus's notes   |
|                              | Previous ransomware in January. Current status:  |                  |
|                              | NOT DOCUMENTED. Whether remediated: NOT          |                  |
|                              | DOCUMENTED.                                      |                  |
| print-srv-01 verification    | Marked [UNVERIFIED] in asset list. EOL Oct 2023. | IT Asset List,   |
|                              | No remediation plan documented.                  | Marcus's notes   |
| MRI Windows XP status       | Documented as CRITICAL. "See separate file."     | Marcus's notes   |
|                              | Separate file NOT PROVIDED in packet.            |                  |
| January ransomware incident  | Occurred on billing-srv-01. "Ad-hoc" response.   | Marcus's notes   |
|                              | Root cause: NOT DOCUMENTED. Impact: NOT          |                  |
|                              | DOCUMENTED. Resolution: NOT DOCUMENTED.          |                  |
| Security staffing            | Analyst position vacant for 3 months.            | Org Chart,       |
|                              | IT intern position vacant.                       | Context          |
| Authority structure          | James has authority over security policy.        | Org Chart notes  |
|                              | NO authority over IT operations. "Creates        |                  |
|                              | friction."                                       |                  |
+------------------------------+--------------------------------------------------+------------------+


================================================================================
5. CRITICAL FINDINGS (BASED ON DOCUMENTATION)
================================================================================

This section identifies documented findings that represent material risks
based on the NIST SP 800-30 risk components (threat, vulnerability,
likelihood, impact) as interpreted from the provided documentation.

+----+----------------------------------------------------------+------------------+
| #  | Documented Finding                                       | Source           |
+----+----------------------------------------------------------+------------------+
| 1  | All devices on flat network 10.10.0.0/16. No VLANs.      | Network Diagram, |
|    | "This is insane." Medical devices, workstations, servers | Marcus's notes   |
|    | on same broadcast domain.                                |                  |
+----+----------------------------------------------------------+------------------+
| 2  | billing-srv-01: "Something is wrong." Performance        | Sticky note +    |
|    | issues. IT just restarts it. Post-ransomware (Jan).      | Marcus's notes   |
|    | Status: NOT DOCUMENTED.                                  |                  |
+----+----------------------------------------------------------+------------------+
| 3  | MRI scanner runs Windows XP. Documented as "CRITICAL."   | Marcus's notes   |
|    | Separate file referenced but NOT PROVIDED.               |                  |
+----+----------------------------------------------------------+------------------+
| 4  | No MFA. Shared accounts: radiology uses "raduser /       | Marcus's notes   |
|    | radiology1." "I reported this. Nothing happened."        |                  |
+----+----------------------------------------------------------+------------------+
| 5  | Westside: consumer-grade router (Netgear Nighthawk).     | Marcus's notes,  |
|    | No firewall. Server closet does not lock. "NOT           | IT Asset List    |
|    | acceptable for a medical facility."                      |                  |
+----+----------------------------------------------------------+------------------+
| 6  | No incident response plan. January ransomware handled    | Marcus's notes   |
|    | "ad-hoc" over 4 days.                                    |                  |
+----+----------------------------------------------------------+------------------+
| 7  | No BCP. No DR plan. No documented procedure if UPS       | Marcus's notes   |
|    | fails after ~20 minutes.                                 |                  |
+----+----------------------------------------------------------+------------------+
| 8  | Backup NAS co-located with backup server. Same room,     | Marcus's notes   |
|    | same network, same rack. "If we get ransomware, we lose  |                  |
|    | both." Offsite/cloud backup: "Budget was denied."        |                  |
+----+----------------------------------------------------------+------------------+
| 9  | HIPAA Security Rule compliance never formally assessed.  | Marcus's notes   |
|    | Legal asserts compliance with "no evidence."             |                  |
+----+----------------------------------------------------------+------------------+
| 10 | SSH password authentication enabled on all Linux         | Marcus's notes   |
|    | servers except ehr-srv-01. "Should be key-only."         |                  |
+----+----------------------------------------------------------+------------------+


================================================================================
6. INVENTORY OF DOCUMENTED CONTROLS
================================================================================

Per NIST SP 800-53 and CIS Controls v8 taxonomy, the following controls are
EXPLICITLY documented in the packet:

+------------------+----------------------------------------+--------------------------+
| Control Type     | Documented Control                     | Source                   |
+------------------+----------------------------------------+--------------------------+
| TECHNICAL        | Fortinet FortiGate 100F firewall       | IT Asset List            |
| TECHNICAL        | DMZ for web-srv-01                     | Network Diagram          |
| TECHNICAL        | Site-to-site VPN (Central - Westside)  | Network Diagram          |
| TECHNICAL        | Site-to-site VPN (Central - HQ)        | Network Diagram          |
| TECHNICAL        | Ubiquiti UniFi WiFi (Central)          | IT Asset List            |
| TECHNICAL        | Sophos endpoint protection (deployed)  | Marcus's notes           |
| TECHNICAL        | Veeam backup software                  | IT Asset List            |
| TECHNICAL        | AD password policy (8 chars, 90 days,  | Marcus's notes           |
|                  | complexity)                            |                          |
| TECHNICAL        | Separate guest WiFi SSID (Central)     | Marcus's notes           |
+------------------+----------------------------------------+--------------------------+
| ADMINISTRATIVE   | IT service contracts (Sophos, Veeam,   | IT Service Contracts     |
|                  | Fortinet, Microsoft, MedTech)          | Summary                  |
| ADMINISTRATIVE   | EHR maintenance contract with SLA      | IT Service Contracts     |
|                  | (4hr critical / 24hr standard)         | Summary                  |
+------------------+----------------------------------------+--------------------------+
| PHYSICAL         | Guard service at Central (1 guard,     | IT Service Contracts     |
|                  | Mon-Fri 7AM-7PM)                       | Summary                  |
| PHYSICAL         | Badge/access system (HID Global)       | IT Asset List            |
+------------------+----------------------------------------+--------------------------+

Note: This is an inventory of DOCUMENTED controls. The operational status,
effectiveness, and coverage of these controls are NOT documented in the packet
except where explicitly noted (e.g., guest WiFi isolation unverified).


================================================================================
7. DOCUMENTED CONTRADICTIONS & INCONSISTENCIES
================================================================================

+------------------------------------------+----------------------------------------+------------------+
| Contradiction                             | Source A                               | Source B         |
+------------------------------------------+----------------------------------------+------------------+
| print-srv-01 - UNVERIFIED status          | IT Asset List: "[UNVERIFIED]"          | Marcus's notes:  |
| but discussed as existing by Marcus       |                                        | "print-srv-01    |
|                                          |                                        | is running..."   |
+------------------------------------------+----------------------------------------+------------------+
| Security compliance assurance (Legal)     | Marcus's notes: Legal says "we're      | Marcus's notes:  |
| vs. no evidence                          | compliant"                             | "has no evidence"|
+------------------------------------------+----------------------------------------+------------------+
| HQ VPN - "seems properly configured"      | Marcus's notes: "seems properly        | Marcus's notes:  |
| vs. "I haven't audited the ACLs"         | configured"                            | "I haven't       |
|                                          |                                        | audited the ACLs"|
+------------------------------------------+----------------------------------------+------------------+
| Segmentation "planned for next fiscal     | Marcus's notes: "planned for next      | Network Diagram: |
| year" but no VLANs currently documented  | fiscal year" (4 months ago)            | No VLANs         |
|                                          |                                        | configured       |
+------------------------------------------+----------------------------------------+------------------+


================================================================================
END OF STRUCTURED ENVIRONMENT SUMMARY
================================================================================
