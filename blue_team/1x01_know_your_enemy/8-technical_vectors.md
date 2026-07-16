================================================================================
                    TECHNICAL VECTOR ASSESSMENT - MEDDEFENSE HEALTH SYSTEMS
                    Task 8: The Technical Vectors
================================================================================

Exercise: Task 8 - The Technical Vectors
Analyst: shamshed rajput 
Date: 16/07/2026
Objective: Identify and analyze the technical (non-human) attack vectors
          specific to MedDefense using concrete evidence from the network
          scan and posture assessment.

Methodology References:
- Security+ 2.2: Technical vectors
- NIST SP 800-30: Vulnerability assessment
- CISA Advisory AA24-131A (File 1)
- CIS Controls v8: Control 1, 7, 12

Cross-References to Project 1x00:
- Network Scan Summary (Task 7): Ports and services
- Asset Registry (Task 7): All assets
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor types
- Control Matrix (Task 10): Existing controls
- Task 2 (Symptom Trap): Crypto-miner evidence


================================================================================
VECTOR 1: VULNERABLE SOFTWARE
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | VULNERABLE SOFTWARE                               |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. Apache 2.4.29 running on billing-srv-01        |
|                  |    (Ubuntu 18.04 LTS). Known Remote Code          |
|                  |    Execution (RCE) vulnerability. This was        |
|                  |    exploited to deploy the crypto-miner.         |
|                  |    (Source: Task 2, Network Scan)                 |
|                  |                                                   |
|                  | 2. Ubuntu 18.04 LTS on billing-srv-01 - EOL       |
|                  |    April 2023. No security updates since then.   |
|                  |                                                   |
|                  | 3. Other Ubuntu 20.04 LTS servers (ehr-srv-01,    |
|                  |    ehr-db-01, web-srv-01) - patch status unknown |
|                  |                                                   |
|                  | 4. Apache 2.4.29 on web-srv-01 - same            |
|                  |    vulnerability as billing-srv-01 if not        |
|                  |    patched                                        |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | billing-srv-01 (CRITICAL - Billing)              |
| Asset(s)         | web-srv-01 (HIGH - Public Website/Portal)        |
|                  | ehr-srv-01 (CRITICAL - EHR App)                  |
|                  | ehr-db-01 (CRITICAL - EHR Database)              |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | Unskilled / Opportunistic (#3) - crypto-miner    |
|                  | proves this. Also Ransomware Groups (#1) would   |
|                  | exploit Apache vulnerabilities.                   |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | An attacker scans for Apache 2.4.29 RCE. They    |
|                  | find billing-srv-01, exploit the vulnerability,   |
|                  | and deploy malware (crypto-miner or ransomware).  |
|                  | From the compromised server, they pivot to the    |
|                  | EHR database and Active Directory via the flat    |
|                  | network.                                          |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | C-008: Sophos Endpoint Protection (workstations,  |
|                  | NOT servers)                                      |
|                  | C-005: SSH Hardening on ehr-srv-01 only           |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-014: No Patch Management                      |
|                  | GAP-001: No SIEM - Exploitation undetected        |
|                  | GAP-003: Flat Network - Pivoting possible         |
+------------------+--------------------------------------------------+


================================================================================
VECTOR 2: UNSUPPORTED SYSTEMS
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | UNSUPPORTED SYSTEMS                               |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. MRI Scanner Control Workstation - Windows XP   |
|                  |    Embedded (EOL April 2014 - 12+ years          |
|                  |    unsupported). Known vulnerabilities            |
|                  |    (EternalBlue, MS17-010).                       |
|                  |    (Source: Asset Registry SRV-013, Task 6)      |
|                  |                                                   |
|                  | 2. print-srv-01 - Windows Server 2012 R2          |
|                  |    (EOL October 2023 - 8+ months unsupported).   |
|                  |    [UNVERIFIED] status.                          |
|                  |    (Source: Asset Registry SRV-008)              |
|                  |                                                   |
|                  | 3. billing-srv-01 - Ubuntu 18.04 LTS (EOL         |
|                  |    April 2023 - 12+ months unsupported).         |
|                  |    (Source: Asset Registry SRV-004)              |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | MRI Scanner (CRITICAL - Patient safety)          |
| Asset(s)         | print-srv-01 (UNKNOWN - Printing services)       |
|                  | billing-srv-01 (CRITICAL - Billing)              |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | Ransomware Groups (#1) - They actively target    |
|                  | EOL systems. Unskilled/Opportunistic (#3) -      |
|                  | Automated scanners will find these.              |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | An attacker scans for Windows XP on the flat     |
|                  | network. They find the MRI workstation and       |
|                  | exploit EternalBlue (MS17-010). They gain        |
|                  | SYSTEM-level access, then pivot to the EHR,      |
|                  | billing, and AD. The MRI cannot be patched,      |
|                  | so this vulnerability is PERMANENT.              |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | NONE                                              |
|                  | No compensating controls in place.               |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-007: No Compensating Controls for MRI        |
|                  | GAP-003: Flat Network - Legacy systems on        |
|                  | network                                           |
|                  | GAP-014: No Patch Management - EOL systems       |
|                  | cannot be patched                                 |
+------------------+--------------------------------------------------+


================================================================================
VECTOR 3: OPEN SERVICE PORTS
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | OPEN SERVICE PORTS                                |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. PostgreSQL (port 5432) on ehr-db-01 -          |
|                  |    accessible from entire 10.10.0.0/16 network.  |
|                  |    (Source: Marcus's notes, Network Scan)         |
|                  |                                                   |
|                  | 2. MySQL (port 3306) on billing-srv-01 -         |
|                  |    accessible from entire 10.10.0.0/16 network.  |
|                  |    (Source: Network Scan)                         |
|                  |                                                   |
|                  | 3. RDP (port 3389) on select workstations -       |
|                  |    potentially accessible network-wide.          |
|                  |    (Source: Network Scan)                         |
|                  |                                                   |
|                  | 4. Medical IoT web interfaces - accessible on     |
|                  |    the flat network                               |
|                  |    (Source: Asset Registry IOT-001, IOT-002)     |
|                  |                                                   |
|                  | 5. SSH (port 22) on all Linux servers -          |
|                  |    password auth enabled on most (except          |
|                  |    ehr-srv-01).                                   |
|                  |    (Source: Artifact 2, Marcus's notes)          |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | ehr-db-01 (CRITICAL - PHI for 50,000 patients)   |
| Asset(s)         | billing-srv-01 (CRITICAL - Billing data)         |
|                  | All Linux servers (SSH)                          |
|                  | Medical IoT devices (Patient safety)             |
|                  | Select workstations (RDP)                        |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | Ransomware Groups (#1) - Lateral movement        |
|                  | Unskilled/Opportunistic (#3) - Scanning for open |
|                  | ports                                             |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | An attacker compromises a workstation. They      |
|                  | scan the flat network and discover port 5432     |
|                  | (PostgreSQL) on ehr-db-01. They connect to the   |
|                  | database using stolen credentials and exfiltrate |
|                  | PHI for 50,000 patients. No network firewall     |
|                  | blocks the connection because all ports are      |
|                  | open internally.                                  |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | C-005: SSH Hardening on ehr-srv-01 only          |
|                  | C-006: Password Policy (AD) - weak protection    |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-003: Flat Network - No segmentation          |
|                  | GAP-001: No SIEM - Connections not monitored     |
|                  | GAP-004: No MFA - Credential theft provides      |
|                  | access                                            |
+------------------+--------------------------------------------------+


================================================================================
VECTOR 4: DEFAULT CREDENTIALS
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | DEFAULT CREDENTIALS                               |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. PACS Workstation - Shared account              |
|                  |    "raduser/radiology1" used by entire           |
|                  |    radiology department.                          |
|                  |    (Source: Marcus's notes, Walk-through Obs)    |
|                  |                                                   |
|                  | 2. BD Alaris Infusion Pumps - Unknown if         |
|                  |    default credentials (admin/admin) have been   |
|                  |    changed. Breach 3 (Task 13) specifically      |
|                  |    involved default credentials on infusion      |
|                  |    pump management consoles.                     |
|                  |    (Source: Asset Registry IOT-002, Task 13)     |
|                  |                                                   |
|                  | 3. Raspberry Pi - Default credentials            |
|                  |    (pi/raspberry) - SSH access logs showed       |
|                  |    connections from unknown IPs.                  |
|                  |    (Source: Task 11 - Shadow IT)                 |
|                  |                                                   |
|                  | 4. Switch Management Credentials - Taped to wall |
|                  |    in plaintext. (Source: Walk-through Obs 2)   |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | PACS System (CRITICAL - Imaging data)           |
| Asset(s)         | BD Alaris Infusion Pumps (CRITICAL - Patient    |
|                  | safety)                                          |
|                  | Raspberry Pi (SHADOW IT - Unmanaged)            |
|                  | Network Switches (CRITICAL - Network            |
|                  | infrastructure)                                   |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | Unskilled/Opportunistic (#3) - Automated         |
|                  | scanners look for default credentials            |
|                  | Ransomware Groups (#1) - Will use stolen        |
|                  | credentials                                       |
|                  | Insider (Malicious) (#4) - Knows about shared   |
|                  | accounts                                          |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | An attacker scans the flat network and discovers |
|                  | the PACS workstation. They try default           |
|                  | credentials and gain access. From the PACS       |
|                  | workstation, they pivot to the EHR database.     |
|                  | Alternatively, the infusion pump management      |
|                  | console is accessed with default credentials,   |
|                  | and patient medication data is manipulated.     |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | C-007: Shared Account Policy (exists but NOT    |
|                  | enforced)                                         |
|                  | C-006: Password Policy (AD - does not cover     |
|                  | non-AD devices)                                   |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-007: Shared Account Policy Not Enforced     |
|                  | GAP-003: Flat Network - Default credentials     |
|                  | accessible network-wide                           |
|                  | GAP-010: No Audits - Credentials not reviewed    |
|                  | GAP-004: No MFA - Default credentials suffice    |
+------------------+--------------------------------------------------+


================================================================================
VECTOR 5: UNSECURE NETWORKS
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | UNSECURE NETWORKS                                 |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. FLAT NETWORK - All devices on 10.10.0.0/16    |
|                  |    with NO VLANs or segmentation.                |
|                  |    (Source: Network Diagram, Marcus's notes)     |
|                  |                                                   |
|                  | 2. Westside Clinic - Consumer-grade Netgear       |
|                  |    Nighthawk router. NO enterprise firewall.    |
|                  |    (Source: Asset Registry NET-004, Marcus's    |
|                  |    notes)                                         |
|                  |                                                   |
|                  | 3. Guest WiFi at Central - Separate SSID exists  |
|                  |    but isolation is UNVERIFIED.                  |
|                  |    (Source: Marcus's notes, Walk-through Obs)    |
|                  |                                                   |
|                  | 4. No egress filtering - Outbound traffic        |
|                  |    unrestricted (C-002 allows ALL outbound).    |
|                  |    (Source: Artifact 1, Firewall Config)         |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | ALL assets (EHR, PACS, billing, AD, IoT,         |
| Asset(s)         | endpoints, medical devices, backups)             |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | ALL actors. The flat network amplifies EVERY     |
|                  | attack.                                           |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | An attacker compromises ANY system on the        |
|                  | network (workstation, IoT device, guest WiFi).   |
|                  | They can now reach EVERY other system. The       |
|                  | EHR database, Active Directory, billing system,  |
|                  | and medical IoT devices are all accessible. No   |
|                  | internal firewall rules slow them down. This     |
|                  | turns a single compromised system into a        |
|                  | catastrophic breach.                             |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | C-001: Perimeter Firewall (FortiGate 100F) -     |
|                  | only at Central, NOT Westside                    |
|                  | C-003: VPN Access (Westside/HQ) - but VPN is     |
|                  | on consumer router at Westside                   |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-003: Flat Network - No segmentation          |
|                  | GAP-008: Egress Filtering - Outbound             |
|                  | unrestricted                                      |
|                  | GAP-001: No SIEM - Network activity undetected   |
+------------------+--------------------------------------------------+


================================================================================
VECTOR 6: REMOVABLE DEVICES / UNMANAGED ENDPOINTS
================================================================================

VECTOR CATEGORY
---------------
+------------------+--------------------------------------------------+
| Vector Category  | REMOVABLE DEVICES / UNMANAGED ENDPOINTS          |
+------------------+--------------------------------------------------+

MEDDEFENSE EVIDENCE
-------------------
+------------------+--------------------------------------------------+
| Evidence         | 1. No USB restriction GPO - Employees can plug   |
|                  |    unauthorized removable media into             |
|                  |    workstations.                                  |
|                  |    (Source: Control Matrix, no documented USB    |
|                  |    policy)                                        |
|                  |                                                   |
|                  | 2. Unmanaged iPads - ~25 iPads used by           |
|                  |    physicians. No MDM/EMM solution deployed.     |
|                  |    (Source: Asset Registry END-006, Artifact 4)  |
|                  |                                                   |
|                  | 3. Shadow IT Devices - Dr. Patel's NAS,          |
|                  |    Raspberry Pi. Unmanaged, unknown security     |
|                  |    status.                                        |
|                  |    (Source: Task 11 - Shadow IT)                 |
|                  |                                                   |
|                  | 4. 15 endpoints not reporting to Sophos - some   |
|                  |    may be lost, stolen, or decommissioned.       |
|                  |    (Source: Artifact 4 - Sophos Status Report)   |
+------------------+--------------------------------------------------+

AFFECTED ASSETS
---------------
+------------------+--------------------------------------------------+
| Affected         | All workstations (USB vector)                    |
| Asset(s)         | iPads (unmanaged endpoints)                      |
|                  | Shadow IT devices (Dr. Patel's NAS, Raspberry    |
|                  | Pi)                                              |
|                  | Lost/stolen devices (15 not reporting)          |
+------------------+--------------------------------------------------+

ACTOR MOST LIKELY TO EXPLOIT
----------------------------
+------------------+--------------------------------------------------+
| Actor            | Insider (Malicious) (#4) - USB data theft       |
|                  | Unskilled/Opportunistic (#3) - Shadow IT        |
|                  | scanning                                          |
|                  | Insider (Negligent) (#2) - Lost devices          |
+------------------+--------------------------------------------------+

EXPLOITATION SCENARIO
---------------------
+------------------+--------------------------------------------------+
| Scenario         | A disgruntled employee copies patient records    |
|                  | to a USB drive using a workstation with no USB  |
|                  | restrictions. Alternatively, a physician's       |
|                  | unmanaged iPad is lost, containing PHI. The     |
|                  | Raspberry Pi (shadow IT) with default           |
|                  | credentials is discovered by an attacker and    |
|                  | used as a pivot point into the network.         |
+------------------+--------------------------------------------------+

CURRENT PROTECTION
------------------
+------------------+--------------------------------------------------+
| Protection       | C-008: Sophos Endpoint Protection (workstations) |
|                  | C-010: Sophos Detections (workstations)          |
|                  | C-013: Security Awareness Training (limited)    |
+------------------+--------------------------------------------------+

GAP REFERENCE
-------------
+------------------+--------------------------------------------------+
| Gap              | GAP-009: Shadow IT - Unmanaged devices           |
|                  | GAP-010: No Audits - No review of endpoints      |
|                  | GAP-003: Flat Network - Shadow IT on network    |
|                  | GAP-014: No Patch Management - USB drivers      |
|                  | unpatched                                         |
+------------------+--------------------------------------------------+


================================================================================
TECHNICAL VECTOR SUMMARY
================================================================================

+----------+---------------------+------------------------------------------+------------------+
| Vector   | Category            | Most Critical Evidence                   | Primary Gap      |
+----------+---------------------+------------------------------------------+------------------+
| #1       | Vulnerable Software | Apache 2.4.29 RCE on billing-srv-01      | GAP-014          |
| #2       | Unsupported Systems | Windows XP MRI (EOL 2014)                | GAP-007          |
| #3       | Open Service Ports  | PostgreSQL 5432 network-wide             | GAP-003          |
| #4       | Default Credentials | PACS "raduser/radiology1"                | GAP-007          |
| #5       | Unsecure Networks   | Flat network 10.10.0.0/16                | GAP-003          |
| #6       | Removable/Unmanaged | Shadow IT devices                        | GAP-009          |
+----------+---------------------+------------------------------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. The FLAT NETWORK (GAP-003) is the PRIMARY ENABLER for ALL technical
   vectors. Every technical vulnerability identified becomes network-wide
   because there is no segmentation.

2. The MRI Windows XP (GAP-007) is the SINGLE MOST DANGEROUS technical
   vector. It is a permanent, unpatchable backdoor on the flat network.

3. The Apache 2.4.29 vulnerability on billing-srv-01 is ACTIVELY BEING
   EXPLOITED (crypto-miner). This proves technical vectors are being used
   against MedDefense TODAY.

4. Default credentials exist across multiple systems (PACS, infusion pumps,
   Raspberry Pi, switch management). This is a systemic credential
   management failure.

5. USB restrictions and MDM for iPads are completely absent. Data can be
   exfiltrated via physical media without restriction.

6. All 6 technical vectors are enabled by the same 3 gaps:
   - GAP-003: Flat Network (amplifies everything)
   - GAP-014: No Patch Management (allows exploitation)
   - GAP-001: No SIEM (allows undetected operation)

7. The pattern is consistent: MedDefense has NO visibility, NO segmentation,
   and NO patching. This is the technical equivalent of building on sand.


================================================================================
REFERENCES
================================================================================

- Security+ 2.2: Technical vectors
- NIST SP 800-30: Vulnerability assessment
- CISA Advisory AA24-131A (File 1)
- CIS Controls v8: Control 1, 7, 12

Cross-References to Project 1x00:
- Network Scan Summary (Task 7): Ports and services
- Asset Registry (Task 7): All assets
- Gap Analysis (Task 12): All Gap IDs
- Threat Actor Matrix (Task 6): Actor types
- Control Matrix (Task 10): Existing controls
- Task 2 (Symptom Trap): Crypto-miner evidence
- Task 11 (Shadow IT): Unmanaged devices


================================================================================
END OF TECHNICAL VECTOR ASSESSMENT
================================================================================
