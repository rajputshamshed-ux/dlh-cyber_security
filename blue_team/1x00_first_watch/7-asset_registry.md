================================================================================
                    ASSET REGISTRY - MEDDEFENSE HEALTH SYSTEMS
                    Task 7: The Asset Registry
================================================================================

Exercise: Task 7 - The Asset Registry
Analyst: shamshed rajput
Date: 13/07/2026

Objective: Build a comprehensive, structured asset inventory by consolidating
          information from multiple sources accumulated throughout the project.

Methodology References:
- NIST SP 800-12 Rev.1: Security Concepts (Chapters 2-3) - CIA Triad
- NIST CSF 2.0: Identify Function - Asset Management (ID.AM)
- NIST SP 800-53 Rev.5: CM-8 (Information System Component Inventory)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- ISO 27001: A.8.1 (Asset Inventory)
- HHS HICP: Healthcare asset management practices

Sources:
- Task 0: Onboarding Packet (Docs 1-6)
- Task 1: Incident Log
- Task 2: Symptom Trap (billing-srv-01 diagnostics)
- Task 3: Walk-through Observations
- Task 4: Control Artifacts
- Task 6: Legacy Dilemma (MRI)
- Network Scan Summary (Nmap-style)


================================================================================
1. ASSET REGISTRY
================================================================================

ASSET ID KEY:
- SRV = Server
- END = Endpoint (workstation/laptop/thin client)
- NET = Network Device
- IOT = IoT Medical Device
- DTA = Data Store
- APP = Application
- PHY = Physical Infrastructure

+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| Asset   | Name                | Type      | Location          | Owner     | OS/Platform         | Critical Services   | Network Segment   | Status   | Notes                                    |
| ID      |                     |           |                   |           |                     |                     |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-001 | ehr-srv-01          | Server    | Central (Basement)| IT        | Ubuntu 20.04 LTS    | EHR Application     | 10.10.0.0/16      | Active   | SSH hardened (key-only). Doc 2.         |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-002 | ehr-db-01           | Server    | Central (Basement)| IT        | Ubuntu 20.04 LTS    | EHR Database        | 10.10.0.0/16      | Active   | PostgreSQL accessible from /16. Doc 2.  |
|         |                     |           |                   |           |                     | (PostgreSQL)        |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-003 | pacs-srv-01         | Server    | Central (Basement)| Radiology | Windows Server 2016 | PACS Imaging        | 10.10.0.0/16      | Active   | NOT backed up (too large). Doc 2, Art 5.|
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-004 | billing-srv-01      | Server    | Central (Basement)| Finance   | Ubuntu 18.04 LTS    | Billing/Claims      | 10.10.0.0/16      | Active   | Crypto-miner found. Post-ransomware.    |
|         |                     |           |                   |           |                     | Processing          |                   |          | Doc 2, Task 1-2.                         |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-005 | ad-dc-01            | Server    | Central (Basement)| IT        | Windows Server 2019 | Primary Domain      | 10.10.0.0/16      | Active   | AD authentication. Doc 2.                |
|         |                     |           |                   |           |                     | Controller          |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-006 | ad-dc-02            | Server    | Central (Basement)| IT        | Windows Server 2019 | Secondary Domain    | 10.10.0.0/16      | Active   | NOT backed up (redundant). Doc 2, Art 5.|
|         |                     |           |                   |           |                     | Controller          |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-007 | file-srv-01         | Server    | Central (Basement)| IT        | Windows Server 2016 | Department File     | 10.10.0.0/16      | Active   | HR/Finance data. Doc 2, Art 5.           |
|         |                     |           |                   |           |                     | Shares              |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-008 | print-srv-01        | Server    | Central (Basement)| IT        | Windows Server 2012 | Print Services      | 10.10.0.0/16      | Unknown  | [UNVERIFIED]. EOL Oct 2023. Doc 2.      |
|         |                     |           |                   |           | R2                  |                     |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-009 | backup-srv-01       | Server    | Central (Basement)| IT        | Ubuntu 22.04 LTS    | Veeam Backups       | 10.10.0.0/16      | Active   | NAS co-located. Offsite denied. Art 5.  |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-010 | web-srv-01          | Server    | Central (DMZ)     | IT/Marketing | Ubuntu 20.04 LTS    | Public Website +    | 10.10.0.0/16      | Active   | In DMZ. Patient portal. Doc 2.          |
|         |                     |           |                   |           |                     | Patient Portal      |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-011 | ws-srv-01           | Server    | Westside          | IT        | Windows Server 2016 | Local File +        | 10.10.0.0/16      | Active   | Scheduling. Doc 2.                       |
|         |                     |           |                   |           |                     | Scheduling          |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-012 | ws-srv-02 (unknown) | Server    | Westside          | Unknown   | Unknown             | Unknown             | Unknown           | Unknown  | Suspected by Mike Torres. NOT confirmed.|
|         |                     |           |                   |           |                     |                     |                   |          | Doc 2 (Marcus note).                     |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| SRV-013 | MRI-control         | Server    | Central (Radiology)| Radiology | Windows XP Embedded | MRI Control         | 10.10.3.0/24      | Active   | CRITICAL - EOL 2014. Task 6.            |
|         |                     |           |                   |           |                     | Software            |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-001 | Central Workstations | Endpoint  | Central (All      | Clinical  | Windows 10          | Clinical Access     | 10.10.0.0/16      | Active   | ~320. AD report 8 mo old. Doc 2.        |
|         |                     |           | floors)           |           |                     |                     |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-002 | Central Thin Clients | Endpoint  | Central (Clinical)| Clinical  | Thin OS             | Clinical Access     | 10.10.0.0/16      | Active   | ~60 units. Doc 2.                        |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-003 | Westside Workstations| Endpoint  | Westside          | Clinical  | Windows 10          | Clinical Access     | 10.10.0.0/16      | Active   | ~45 units. Doc 2.                        |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-004 | HQ Workstations      | Endpoint  | Corporate HQ      | Admin     | Windows 10/11       | O365, File Access   | 10.10.0.0/16      | Active   | ~120 units. Doc 2.                       |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-005 | HQ Laptops           | Endpoint  | Corporate HQ      | Admin     | Windows 10/11       | Remote Access       | 10.10.0.0/16      | Active   | ~30 units. Remote-capable. Doc 2.       |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| END-006 | iPads (Clinical)     | Endpoint  | Central/Westside  | Clinical  | iOS                 | EHR Viewing         | 10.10.0.0/16      | Unknown  | ~25. Management unclear. Doc 2.         |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-001 | Philips Monitors     | IoT Medical| Central (Patient  | Clinical  | Unknown             | Patient Monitoring  | 10.10.0.0/16      | Active   | ~80 units. Flat network. Doc 2.         |
|         |                     |           | rooms)            |           |                     |                     |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-002 | BD Alaris Pumps      | IoT Medical| Central (Patient  | Clinical  | Unknown             | Infusion Dosage     | 10.10.0.0/16      | Active   | ~120 units. Networked for updates. Doc 2.|
|         |                     |           | rooms)            |           |                     | Updates             |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-003 | Siemens MAGNETOM MRI | IoT Medical| Central (Radiology)| Radiology | Windows XP Embedded | Diagnostic Imaging  | 10.10.3.0/24      | Active   | CRITICAL - EOL 2014. Task 6. Cost $2.1M.|
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-004 | GE Revolution CT     | IoT Medical| Central (Radiology)| Radiology | Unknown             | Diagnostic Imaging  | 10.10.0.0/16      | Active   | OS unknown. Doc 2.                       |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-005 | Nurse Call System    | IoT Medical| Central           | Clinical  | IP-based            | Patient Alerts      | 10.10.0.0/16      | Active   | Integrated with phone system. Doc 2.    |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| IOT-006 | HID Badge System     | IoT Medical| All Sites         | Security  | Connected to AD     | Physical Access     | 10.10.0.0/16      | Active   | Some doors only. Doc 2.                  |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-001 | FortiGate 100F       | Network   | Central           | IT        | FortiOS             | Perimeter Firewall  | 10.10.0.0/16      | Active   | Rules allow ALL outbound. Art 1.        |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-002 | Cisco Core Switch    | Network   | Central           | IT        | Unknown             | Core Networking     | 10.10.0.0/16      | Active   | Model unknown. Doc 2.                   |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-003 | Cisco Access Switches| Network   | Central (per      | IT        | Unknown             | Access Networking   | 10.10.0.0/16      | Active   | 2 per floor. Model unknown. Doc 2.      |
|         |                     |           | floor)            |           |                     |                     |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-004 | Westside Router      | Network   | Westside          | IT        | Netgear Nighthawk   | Site-to-Site VPN    | 10.10.0.0/16      | Active   | Consumer-grade. NOT acceptable. Doc 2.  |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-005 | Westside Switch      | Network   | Westside          | IT        | Unknown             | Access Networking   | 10.10.0.0/16      | Active   | Unmanaged. Brand unknown. Doc 2.        |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-006 | UniFi APs (Central)  | Network   | Central           | IT        | Ubiquiti            | WiFi Access         | 10.10.0.0/16      | Active   | 12 units. Doc 2.                        |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| NET-007 | HQ Building Network  | Network   | Corporate HQ      | Landlord  | Unknown             | Network Access      | 10.10.0.0/16      | Active   | Building-managed. MedDefense VLAN. Doc 2.|
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| DTA-001 | Synology NAS-01     | Data Store| Central (Basement)| IT        | Synology DSM        | Backup Storage      | 10.10.0.0/16      | Active   | 24TB RAID5. Co-located with servers.    |
|         |                     |           |                   |           |                     |                     |                   |          | Art 5.                                  |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| DTA-002 | O365 Tenant         | Data Store| Cloud (Microsoft) | IT        | Microsoft 365       | Email, SharePoint,  | N/A               | Active   | Org-wide. $432k/year. Art 4.            |
|         |                     |           |                   |           |                     | OneDrive            |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| PHY-001 | Server Room         | Physical  | Central (Basement)| IT        | N/A                 | Housing ALL servers | N/A               | Active   | Unrestricted badge access. No camera.   |
|         |                     |           |                   |           |                     |                     |                   |          | Obs 1, Task 3.                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| PHY-002 | Network Closet (Flr2)| Physical  | Central (Floor 2) | IT        | N/A                 | Switches/Patch      | N/A               | Active   | No lock. Door ajar. Credentials taped.  |
|         |                     |           |                   |           |                     | Panels              |                   |          | Obs 2, Task 3.                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| PHY-003 | Nurse Station        | Physical  | Central (Floor 3) | Nursing   | N/A                 | Clinical Access     | N/A               | Active   | Unlocked EHR sessions. Sign encourages  |
|         |                     |           |                   |           |                     |                     |                   |          | staying logged in. Obs 3, Task 3.      |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+
| PHY-004 | Fire Exit Door       | Physical  | Central (Public/  | Facilities| N/A                 | Access Control      | N/A               | Active   | Propped open with wedge. Obs 5, Task 3. |
|         |                     |           | Admin boundary)   |           |                     | Boundary            |                   |          |                                          |
+---------+---------------------+-----------+-------------------+-----------+---------------------+---------------------+------------------+----------+------------------------------------------+

TOTAL ASSETS IDENTIFIED: 37


================================================================================
2. RECONCILIATION NOTES
================================================================================

2.1 ASSETS FOUND IN NETWORK SCAN - NOT IN DOCUMENTATION (Shadow IT)
--------------------------------------------------------------------
+------------------+-----------+------------------------------------------+------------------+
| IP Address       | Hostname  | OS Detected                             | Discovery Source |
+------------------+-----------+------------------------------------------+------------------+
| 10.10.2.45       | UNKNOWN   | Windows 10                              | Network Scan     |
| 10.10.2.178      | UNKNOWN   | Linux 2.6.32                            | Network Scan     |
| 10.10.3.88       | UNKNOWN   | Windows 7                               | Network Scan     |
| 10.10.3.112      | UNKNOWN   | Unknown                                 | Network Scan     |
| 10.10.1.67       | UNKNOWN   | Windows 10                              | Network Scan     |
+------------------+-----------+------------------------------------------+------------------+

FINDING: 5 devices detected in network scan that do NOT appear in ANY
documentation from Tasks 0-6. These represent SHADOW IT systems that are
not inventoried, not managed, and not secured. They could be:
- Personal devices connected to the network
- Unauthorized departmental systems
- Legacy systems forgotten by IT
- Rogue devices (potential attacker presence)

RISK: These devices have no controls documented, no monitoring, no patch
management, and no accountability. They represent an unknown attack surface.

RECOMMENDATION: Immediate investigation. These devices must be identified,
registered, and either secured or removed from the network.

2.2 ASSETS IN DOCUMENTATION - NOT IN NETWORK SCAN
--------------------------------------------------
+------------------+------------------------------------------+------------------+
| Asset            | Reason for Absence                       | Action Required  |
+------------------+------------------------------------------+------------------+
| print-srv-01     | [UNVERIFIED] - May be decommissioned     | Verify status.   |
|                  | or offline. EOL Oct 2023.                | Update inventory.|
+------------------+------------------------------------------+------------------+
| ws-srv-02        | Suspected server - never confirmed.      | Investigate with |
| (Westside)       | Mike Torres mentioned it.                | Mike Torres.     |
+------------------+------------------------------------------+------------------+
| iPads (25 units) | MDM not deployed. Management unclear.    | Locate, assess,  |
|                  | May not be on active scan.               | deploy MDM.      |
+------------------+------------------------------------------+------------------+
| O365 Tenant      | Cloud-based. Not in network scan.        | Document         |
|                  |                                          | separately.      |
+------------------+------------------------------------------+------------------+
| Physical Assets  | Server Room, Network Closet, Nurse       | Documented in    |
| (PHY-001 to -004)| Station, Fire Exit Door                  | registry.        |
+------------------+------------------------------------------+------------------+

FINDING: 5 documented assets are missing from the network scan. Some are
expected (cloud, physical). Some represent data quality issues.

2.3 DISCREPANCIES AND CONTRADICTIONS
------------------------------------
+------------------+------------------------------------------+------------------+
| Source           | Issue                                    | Resolution       |
+------------------+------------------------------------------+------------------+
| Doc 2 vs. Art 5  | pacs-srv-01: Documented but NOT backed   | Confirm backup   |
|                  | up. "Too large" according to Art 5.      | status. Update   |
|                  |                                          | registry.        |
+------------------+------------------------------------------+------------------+
| Doc 2 vs. Art 4  | Server AV status: Doc 2 says Sophos      | Verify Sophos    |
|                  | exists. Art 4 shows server protection    | licensing.       |
|                  | license NOT purchased.                   |                  |
+------------------+------------------------------------------+------------------+
| Doc 2 vs. Marcus | print-srv-01: [UNVERIFIED] but Marcus    | Investigate      |
| Notes            | notes discuss it as existing.            | physical status. |
+------------------+------------------------------------------+------------------+
| Obs 2 vs. Art 6  | Network closet: Observed unlocked.       | No camera in     |
|                  | Art 6 shows no cameras in network        | closet area.     |
|                  | closets. Consistent.                      |                  |
+------------------+------------------------------------------+------------------+
| Art 5 vs. Marcus | backups: Art 5 shows Veeam for all       | Confirm which    |
| Notes            | VMs. Marcus notes NAS co-located.        | VMs are actually |
|                  | Consistent.                              | backed up.       |
+------------------+------------------------------------------+------------------+


================================================================================
3. ASSET STATISTICS
================================================================================

+------------------+---------------------+------------------------------------------+
| Asset Type       | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| Server           | 13 (SRV-001 to 013) | 35.1%                                    |
| Endpoint         | 6 (END-001 to 006)  | 16.2%                                    |
| IoT Medical      | 6 (IOT-001 to 006)  | 16.2%                                    |
| Network Device   | 7 (NET-001 to 007)  | 18.9%                                    |
| Data Store       | 2 (DTA-001 to 002)  | 5.4%                                     |
| Physical         | 4 (PHY-001 to 004)  | 10.8%                                    |
| Application      | 0                   | 0%                                       |
+------------------+---------------------+------------------------------------------+
| TOTAL            | 38                  | 100%                                     |

+------------------+---------------------+------------------------------------------+
| Status           | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| Active           | 35                  | 92.1%                                    |
| Deprecated       | 0                   | 0%                                       |
| Shadow IT        | 5 (scan)            | 13.2% (of total network assets)          |
| Unknown          | 3 (SRV-008, SRV-012,| 7.9%                                     |
|                  | END-006)            |                                          |
+------------------+---------------------+------------------------------------------+

+------------------+---------------------+------------------------------------------+
| Location         | Count               | Percentage                               |
+------------------+---------------------+------------------------------------------+
| Central          | 29                  | 76.3%                                    |
| Westside         | 4                   | 10.5%                                    |
| Corporate HQ     | 2                   | 5.3%                                     |
| Cloud            | 1                   | 2.6%                                     |
| Unknown          | 2                   | 5.3%                                     |
+------------------+---------------------+------------------------------------------+


================================================================================
4. KEY FINDINGS
================================================================================

1. 38 assets identified across all sources. Documentation was incomplete
   but consolidation reveals the full picture.

2. 5 Shadow IT assets detected in network scan with no documentation.
   These represent an unmanaged attack surface and must be investigated.

3. 3 assets have "Unknown" status:
   - print-srv-01: [UNVERIFIED], EOL
   - ws-srv-02 (Westside): Suspected but never confirmed
   - iPads: Management unclear

4. Critical vulnerabilities identified in registry:
   - MRI-control (SRV-013): Windows XP EOL 2014
   - print-srv-01 (SRV-008): Windows 2012 R2 EOL Oct 2023
   - Westside Router (NET-004): Consumer-grade, no firewall

5. Backup gaps identified:
   - pacs-srv-01: NOT backed up
   - ad-dc-02: NOT backed up
   - Westside servers: NOT backed up
   - O365: NOT backed up by MedDefense

6. The flat network (10.10.0.0/16) means ALL assets are on the same
   segment, regardless of criticality or function.

7. IoT medical devices (12 units across 6 types) are on the same network
   as servers and workstations. (CISA Healthcare Guide - major concern)

8. Physical assets (server room, network closet, nurse station, fire exit)
   represent security gaps identified in Task 3 but are now documented
   in the registry.


================================================================================
5. RECOMMENDATIONS
================================================================================

+----------+------------------+----------------------------------------+------------------+
| Priority | Action           | Justification                          | Framework        |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Investigate 5    | Unknown systems on network represent   | CIS Control 1    |
|          | Shadow IT assets | unmanaged risk. Identify and secure.   |                  |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Verify ws-srv-02 | Suspected server at Westside.          | NIST SP 800-53   |
|          | existence        | Confirm and document.                  | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| CRITICAL | Update endpoint  | Current counts are 8 months old.       | NIST CSF 2.0     |
|          | inventory        | Perform active scan.                   | ID.AM-1          |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Implement MDM    | iPads are unmanaged. Deploy MDM.       | NIST SP 800-53   |
|          | for iPads        |                                        | CM-8             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Verify           | Confirm backup status of pacs-srv-01,  | NIST SP 800-53   |
|          | backup status    | ad-dc-02, Westside.                    | CP-9             |
+----------+------------------+----------------------------------------+------------------+
| HIGH     | Document O365    | Cloud assets must be included in       | NIST CSF 2.0     |
|          | asset            | inventory.                             | ID.AM-2          |
+----------+------------------+----------------------------------------+------------------+
| MEDIUM   | Update registry  | Make registry the single source of     | NIST SP 800-53   |
|          | regularly        | truth. Review quarterly.               | CM-8             |
+----------+------------------+----------------------------------------+------------------+


================================================================================
6. KEY TAKEAWAYS
================================================================================

1. Asset management is the FOUNDATION of security.
   (NIST CSF 2.0 - IDENTIFY function: If you don't know what you have,
   you cannot protect it.)

2. Multiple sources reveal different pictures. Consolidation is essential.
   (ISO 27001 A.8.1: Asset inventory requires ongoing maintenance)

3. Shadow IT is a significant risk.
   5 undocumented devices in network scan = unknown attack surface.

4. Backup coverage is inconsistent.
   Critical systems (PACS, AD secondary, Westside) are NOT backed up.

5. IoT medical devices are on the same flat network as everything else.
   (CISA Healthcare Guide: Medical device segmentation is critical)

6. Physical assets must be inventoried alongside IT assets.
   Physical security gaps enable all other breaches.

7. Asset statuses (Active, Unknown, Shadow IT) must be documented
   and reconciled regularly.

8. The registry is a LIVING document, not a one-time exercise.


================================================================================
7. REFERENCES
================================================================================

- NIST SP 800-12 Rev.1: Information Security (Chapters 2-3)
- NIST SP 800-30: Risk Assessment (Chapter 2)
- NIST SP 800-53 Rev.5: CM-8 (Information System Component Inventory)
- NIST SP 800-53 Rev.5: RA-5 (Vulnerability Scanning)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- NIST CSF 2.0: Identify Function - ID.AM (Asset Management)
- CISA Healthcare and Public Health Sector Guide
- ISO 27001: A.8.1 (Asset Inventory)
- HHS HICP: Healthcare Cybersecurity Practices


================================================================================
END OF ASSET REGISTRY REPORT
================================================================================
