================================================================================
                    SUPPLY CHAIN RISK ASSESSMENT - MEDDEFENSE HEALTH SYSTEMS
                    Task 5: The Supply Chain Question
================================================================================

Exercise: Task 5 - The Supply Chain Question
Analyst: shamshed rajput 
Date: 15/07/2026
Objective: Map and evaluate third-party risk exposure across MedDefense's
          vendor ecosystem.

Methodology References:
- NIST SP 800-53: CM-8 (Asset Inventory), AC-6 (Least Privilege)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- ISO 27001: A.8.1 (Asset Inventory), A.8.2 (Acceptable Use)
- CISA Healthcare Guide: Healthcare threat context

Cross-References to Project 1x00:
- Onboarding Packet (Task 0): Vendor Contracts
- Asset Registry (Task 7): Critical assets
- Control Matrix (Task 10): C-001, C-006, C-013, C-014
- Gap Analysis (Task 12): GAP-004 (No MFA), GAP-001 (No SIEM),
  GAP-012 (No Vendor Account Management)


================================================================================
VENDOR 1: MEDTECH SOLUTIONS
================================================================================

VENDOR OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Vendor           | MedTech Solutions                                |
+------------------+--------------------------------------------------+
| Service          | EHR maintenance provider                         |
+------------------+--------------------------------------------------+
| Annual Cost      | $145,000                                         |
+------------------+--------------------------------------------------+
| SLA              | 4hr response for critical issues, 24hr standard  |
+------------------+--------------------------------------------------+
| Scope            | EHR software updates, bug fixes, performance     |
|                  | optimization, issue diagnosis                    |
+------------------+--------------------------------------------------+

ACCESS TYPE
-----------
+------------------+--------------------------------------------------+
| Access Type      | APPLICATION + DATA                                |
+------------------+--------------------------------------------------+
| Access Scope     | Direct server access to ehr-srv-01 (EHR           |
|                  | Application Server) and ehr-db-01 (EHR Database). |
|                  | MedTech engineers can:                            |
|                  | - Access the EHR application                      |
|                  | - Read and modify the EHR database               |
|                  | - Push software updates                           |
|                  | - Diagnose performance issues                     |
|                  | - Review audit logs                               |
|                  | - Potentially access PHI for 50,000+ patients    |
+------------------+--------------------------------------------------+

COMPROMISE SCENARIO
-------------------
+------------------+--------------------------------------------------+
| COMPROMISE SCENARIO:                                                       |
|                                                                             |
| If MedTech Solutions is breached:                                          |
|                                                                             |
| 1. Attackers gain access to MedTech's internal network.                    |
| 2. They discover MedTech's remote access credentials for MedDefense.       |
| 3. They use these credentials to connect directly to ehr-srv-01 and        |
|    ehr-db-01 through the maintenance portal.                              |
| 4. They exfiltrate the entire EHR database (PHI for 50,000+ patients).    |
| 5. Alternatively, they install ransomware on the EHR system, encrypting   |
|    patient records and disrupting clinical operations.                    |
|                                                                             |
| MedTech's credentials have NO MFA and likely NO limitation on what they   |
| can access. The flat network means once they are on the EHR server, they  |
| can access any system on the network.                                      |
+------------------+--------------------------------------------------+

EXISTING CONTROLS
-----------------
+------------------+--------------------------------------------------+
| Existing         | C-005: SSH Hardening on ehr-srv-01 (only)        |
| Controls         | C-006: Password Policy (AD)                      |
|                  | C-009: Veeam Backups (limited)                   |
|                  |                                                  |
|                  | CONTROLS THAT ARE MISSING:                       |
|                  | - NO MFA for vendor accounts                     |
|                  | - NO monitoring of vendor activity (no SIEM)   |
|                  | - NO least privilege (vendor has full access)   |
|                  | - NO regular vendor access reviews               |
|                  | - NO vendor-specific incident response           |
+------------------+--------------------------------------------------+

RISK ASSESSMENT
---------------
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | MedTech has DIRECT ACCESS to the #1 critical     |
|                  | asset: the EHR system. A compromise of MedTech   |
|                  | provides immediate, undetected access to the     |
|                  | EHR database containing PHI for 50,000 patients. |
|                  | The flat network means lateral movement to       |
|                  | billing, AD, and PACS is trivial. This is the    |
|                  | highest supply chain risk.                       |
+------------------+--------------------------------------------------+


================================================================================
VENDOR 2: MICROSOFT (O365 E3)
================================================================================

VENDOR OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Vendor           | Microsoft                                        |
+------------------+--------------------------------------------------+
| Service          | O365 E3 (org-wide email, SharePoint, OneDrive)   |
+------------------+--------------------------------------------------+
| Annual Cost      | $432,000                                         |
+------------------+--------------------------------------------------+
| Scope            | Email hosting, file storage, collaboration,      |
|                  | identity management (if Entra ID is used)        |
+------------------+--------------------------------------------------+

ACCESS TYPE
-----------
+------------------+--------------------------------------------------+
| Access Type      | DATA (Cloud)                                     |
+------------------+--------------------------------------------------+
| Access Scope     | MedDefense's entire O365 tenant includes:        |
|                  | - All employee emails (2,000 users)              |
|                  | - All SharePoint sites and documents             |
|                  | - All OneDrive files (employee data)             |
|                  | - Potentially PHI in emails and attachments      |
|                  | - Financial documents, HR records, contracts     |
|                  | - Executive communications                       |
|                  | - If Entra ID is used: identity directory for    |
|                  |   all systems                                    |
+------------------+--------------------------------------------------+

COMPROMISE SCENARIO
-------------------
+------------------+--------------------------------------------------+
| COMPROMISE SCENARIO:                                                       |
|                                                                             |
| If Microsoft is breached (or more likely, a MedDefense O365 admin          |
| account is compromised):                                                   |
|                                                                             |
| 1. Attacker gains access to MedDefense's O365 tenant.                     |
| 2. They create mailbox forwarding rules to exfiltrate emails containing   |
|    PHI, financial data, or strategic plans.                               |
| 3. They download all SharePoint and OneDrive content.                     |
| 4. They send phishing emails to all 2,000 employees from legitimate       |
|    MedDefense email addresses.                                            |
| 5. If Entra ID is used for authentication, they can access any system    |
|    that uses MedDefense identity.                                         |
| 6. The attack goes undetected because there is no monitoring of O365      |
|    activity.                                                              |
+------------------+--------------------------------------------------+

EXISTING CONTROLS
-----------------
+------------------+--------------------------------------------------+
| Existing         | C-006: Password Policy (AD)                      |
| Controls         | C-013: Security Awareness Training (limited)     |
|                  |                                                  |
|                  | CONTROLS THAT ARE MISSING:                       |
|                  | - NO MFA for O365 accounts (GAP-004)             |
|                  | - NO Conditional Access policies                 |
|                  | - NO mail rule monitoring (GAP-013)              |
|                  | - NO DLP for email/SharePoint                    |
|                  | - NO monitoring of admin activity in O365       |
|                  | - NO third-party backup of O365 data             |
+------------------+--------------------------------------------------+

RISK ASSESSMENT
---------------
+------------------+--------------------------------------------------+
| Risk Level       | HIGH                                             |
+------------------+--------------------------------------------------+
| Justification    | Microsoft itself is not the primary risk -      |
|                  | MedDefense's O365 tenant is. The tenant contains |
|                  | massive amounts of sensitive data (PHI,         |
|                  | financial, HR). A compromised O365 account       |
|                  | enables silent data exfiltration. However,       |
|                  | Microsoft as a vendor is highly secure; the      |
|                  | risk is the configuration and management of      |
|                  | the MedDefense tenant.                          |
+------------------+--------------------------------------------------+


================================================================================
VENDOR 3: SOPHOS
================================================================================

VENDOR OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Vendor           | Sophos                                          |
+------------------+--------------------------------------------------+
| Service          | Endpoint Protection (antivirus/EDR)              |
+------------------+--------------------------------------------------+
| Annual Cost      | $18,000                                         |
+------------------+--------------------------------------------------+
| Scope            | Antivirus and endpoint protection on all         |
|                  | managed Windows workstations (387 devices)      |
+------------------+--------------------------------------------------+

ACCESS TYPE
-----------
+------------------+--------------------------------------------------+
| Access Type      | APPLICATION + NETWORK                             |
+------------------+--------------------------------------------------+
| Access Scope     | Sophos agent installed on all managed            |
|                  | workstations. Sophos Central console can:        |
|                  | - Push configuration changes                     |
|                  | - Deploy software updates                        |
|                  | - Execute scans                                  |
|                  | - Potentially execute commands on endpoints      |
|                  | - View endpoint status and detections            |
|                  | - Collect endpoint data                          |
+------------------+--------------------------------------------------+

COMPROMISE SCENARIO
-------------------
+------------------+--------------------------------------------------+
| COMPROMISE SCENARIO:                                                       |
|                                                                             |
| If Sophos is breached (or Sophos credentials are compromised):             |
|                                                                             |
| 1. Attacker gains access to MedDefense's Sophos Central console.           |
| 2. They push malicious updates to all 387 managed endpoints.              |
| 3. This gives them full control over all clinical and administrative      |
|    workstations.                                                           |
| 4. They deploy ransomware to all endpoints simultaneously.                |
| 5. They use the endpoints as pivot points to access the EHR, billing,    |
|    and AD.                                                                |
|                                                                             |
| Alternatively, a compromised Sophos agent could be used to exfiltrate     |
| data from endpoints.                                                       |
+------------------+--------------------------------------------------+

EXISTING CONTROLS
-----------------
+------------------+--------------------------------------------------+
| Existing         | C-008: Sophos Endpoint Protection (Preventive/   |
| Controls         | Detective)                                       |
|                  | C-010: Sophos Detections (Detective)             |
|                  |                                                  |
|                  | CONTROLS THAT ARE MISSING:                       |
|                  | - NO MFA for Sophos admin console                |
|                  | - NO monitoring of Sophos console activity       |
|                  | - NO review of Sophos configuration changes      |
|                  | - NO segmentation between workstations           |
+------------------+--------------------------------------------------+

RISK ASSESSMENT
---------------
+------------------+--------------------------------------------------+
| Risk Level       | HIGH                                             |
+------------------+--------------------------------------------------+
| Justification    | Sophos has broad reach across all managed        |
|                  | endpoints. A compromised Sophos console provides  |
|                  | control over 387 workstations. However, the      |
|                  | impact is limited to endpoints - not directly    |
|                  | to servers. The risk is high but not critical    |
|                  | because the console does not have direct access  |
|                  | to the EHR database.                             |
+------------------+--------------------------------------------------+


================================================================================
VENDOR 4: SIEMENS (MRI MANUFACTURER)
================================================================================

VENDOR OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Vendor           | Siemens                                          |
+------------------+--------------------------------------------------+
| Service          | MRI scanner manufacturer and maintenance         |
+------------------+--------------------------------------------------+
| Cost             | $2.1 million (capital cost)                      |
+------------------+--------------------------------------------------+
| Scope            | Periodic maintenance of the MRI scanner and      |
|                  | Windows XP control workstation, firmware updates |
+------------------+--------------------------------------------------+

ACCESS TYPE
-----------
+------------------+--------------------------------------------------+
| Access Type      | PHYSICAL + APPLICATION (limited)                  |
+------------------+--------------------------------------------------+
| Access Scope     | Siemens technicians have physical access to the  |
|                  | MRI suite during maintenance visits. They may    |
|                  | also have remote access to the MRI control       |
|                  | workstation for diagnostics. The MRI control     |
|                  | workstation is on the same flat network as the   |
|                  | rest of the hospital (10.10.0.0/16).             |
+------------------+--------------------------------------------------+

COMPROMISE SCENARIO
-------------------
+------------------+--------------------------------------------------+
| COMPROMISE SCENARIO:                                                       |
|                                                                             |
| If Siemens is breached:                                                   |
|                                                                             |
| 1. Attacker gains access to Siemens' remote support credentials for        |
|    MedDefense's MRI.                                                      |
| 2. They use these credentials to access the MRI control workstation.      |
| 3. The MRI runs Windows XP with known vulnerabilities (EOL 2014).        |
| 4. They exploit the Windows XP vulnerabilities to install malware on the  |
|    MRI workstation.                                                       |
| 5. From the MRI workstation, they pivot across the flat network to the    |
|    EHR, billing, AD, and other systems.                                  |
|                                                                             |
| Alternatively, a compromised Siemens technician could physically install  |
|    malicious hardware during a maintenance visit.                         |
+------------------+--------------------------------------------------+

EXISTING CONTROLS
-----------------
+------------------+--------------------------------------------------+
| Existing         | NO effective controls on the MRI workstation.    |
| Controls         |                                                  |
|                  | CONTROLS THAT ARE MISSING:                       |
|                  | - NO segmentation (MRI on flat network)          |
|                  | - NO compensating controls (GAP-007)             |
|                  | - NO monitoring of MRI traffic (GAP-001)         |
|                  | - NO MFA on MRI access (GAP-004)                 |
|                  | - NO vendor access review                        |
|                  | - NO physical access controls for MRI suite     |
|                  |    (Observation 1)                              |
+------------------+--------------------------------------------------+

RISK ASSESSMENT
---------------
+------------------+--------------------------------------------------+
| Risk Level       | CRITICAL                                         |
+------------------+--------------------------------------------------+
| Justification    | The MRI Windows XP workstation is a PERMANENT    |
|                  | backdoor into the MedDefense network. Siemens   |
|                  | has access to this workstation. A compromise of  |
|                  | Siemens' credentials provides direct access to   |
|                  | the flat network through an EOL system.          |
|                  | This is the same vulnerability identified in     |
|                  | GAP-007. The combination of vendor access and    |
|                  | an unpatched system makes this CRITICAL.        |
+------------------+--------------------------------------------------+


================================================================================
VENDOR 5: GREENFIELD BUILDING MANAGEMENT
================================================================================

VENDOR OVERVIEW
---------------
+------------------+--------------------------------------------------+
| Vendor           | Greenfield Building Management                   |
+------------------+--------------------------------------------------+
| Service          | HQ office building management and network        |
|                  | infrastructure                                    |
+------------------+--------------------------------------------------+
| Cost             | Included in lease                                |
+------------------+--------------------------------------------------+
| Scope            | Building operations, network connectivity,       |
|                  | physical security (building-level), internet     |
|                  | service                                           |

ACCESS TYPE
-----------
+------------------+--------------------------------------------------+
| Access Type      | PHYSICAL + NETWORK                               |
+------------------+--------------------------------------------------+
| Access Scope     | Greenfield manages:                              |
|                  | - Building network infrastructure (switches,     |
|                  |   routers)                                       |
|                  | - Internet connectivity to the HQ                |
|                  | - Physical access to the building               |
|                  | - HVAC, electrical, fire systems (not security   |
|                  |   relevant but could impact availability)        |
|                  |                                                  |
|                  | MedDefense has its own VLAN on Greenfield's      |
|                  | network. Greenfield has access to the building- |
|                  | level network but should NOT have access to      |
|                  | the MedDefense VLAN (in theory).                |
+------------------+--------------------------------------------------+

COMPROMISE SCENARIO
-------------------
+------------------+--------------------------------------------------+
| COMPROMISE SCENARIO:                                                       |
|                                                                             |
| If Greenfield is breached:                                               |
|                                                                             |
| 1. Attacker gains access to Greenfield's building management network.     |
| 2. They discover the MedDefense VLAN.                                    |
| 3. They attempt to pivot from the building network to the MedDefense      |
|    VLAN.                                                                  |
| 4. If the VLAN is properly isolated, they cannot cross.                  |
| 5. If the VLAN is misconfigured (not uncommon), they gain access to       |
|    MedDefense's HQ network.                                              |
| 6. From HQ, they can access MedDefense Central via the site-to-site       |
|    VPN (which requires credentials).                                     |
|                                                                             |
| Alternatively, a compromised Greenfield employee could physically access |
|    MedDefense offices during off-hours.                                  |
+------------------+--------------------------------------------------+

EXISTING CONTROLS
-----------------
+------------------+--------------------------------------------------+
| Existing         | C-001: Firewall - Perimeter Protection (HQ VPN)  |
| Controls         |                                                  |
|                  | CONTROLS THAT ARE MISSING:                       |
|                  | - NO visibility into Greenfield's security       |
|                  | - NO contractual security requirements          |
|                  | - NO monitoring of building network traffic     |
|                  | - NO audit of VLAN configuration                 |
|                  | - NO physical access control for MedDefense     |
|                  |    offices (building-level)                     |
+------------------+--------------------------------------------------+

RISK ASSESSMENT
---------------
+------------------+--------------------------------------------------+
| Risk Level       | MEDIUM                                           |
+------------------+--------------------------------------------------+
| Justification    | Greenfield has access to the building-level      |
|                  | network but should not have access to the        |
|                  | MedDefense VLAN. The risk depends on the VLAN   |
|                  | configuration being correct. If misconfigured,   |
|                  | an attacker could pivot to MedDefense's HQ      |
|                  | network. However, Greenfield does not have       |
|                  | direct access to the VPN credentials required    |
|                  | to reach Central. The risk is MEDIUM but should  |
|                  | be verified.                                     |
+------------------+--------------------------------------------------+


================================================================================
SUPPLY CHAIN RISK SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| SUPPLY CHAIN RISK SUMMARY                                                  |
|                                                                             |
| The single vendor compromise that would cause the most damage to          |
| MedDefense is MEDTECH SOLUTIONS. MedTech has DIRECT ACCESS to the EHR     |
| system (ehr-srv-01 and ehr-db-01), which contains PHI for 50,000+        |
| patients. A breach of MedTech provides immediate, undetected access to   |
| the most critical asset. The flat network means the attacker can pivot    |
| to billing, AD, and all other systems. Unlike other vendors, MedTech     |
| does not require a second step - they are already on the inside.          |
|                                                                             |
| The single most important control MedDefense should implement first to    |
| reduce supply chain risk across ALL vendors is MULTI-FACTOR               |
| AUTHENTICATION (MFA) FOR ALL VENDOR ACCOUNTS (GAP-004). Every vendor      |
| with remote access (MedTech, Siemens, Sophos) currently has NO MFA.       |
| Implementing MFA would immediately reduce the risk of credential theft    |
| for all vendor accounts. Combined with least-privilege access and         |
| vendor activity monitoring (SIEM), MFA provides the highest risk          |
| reduction per dollar for supply chain risk.                               |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| Vendor   | Service          | Access Type     | Access Scope    | Risk Level       | Key Gap                                  |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| MedTech  | EHR Maintenance  | Application +   | Full access to  | CRITICAL         | No MFA, No least privilege, No           |
| Solutions|                  | Data            | ehr-srv-01 and  |                  | monitoring, No vendor access review      |
|          |                  |                 | ehr-db-01       |                  |                                          |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| Microsoft| O365 E3          | Data (Cloud)    | Emails,         | HIGH             | No MFA, No DLP, No monitoring, No       |
|          |                  |                 | SharePoint,     |                  | Conditional Access                       |
|          |                  |                 | OneDrive        |                  |                                          |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| Sophos   | Endpoint         | Application +   | 387 managed     | HIGH             | No MFA, No monitoring, No change         |
|          | Protection       | Network         | endpoints       |                  | review                                   |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| Siemens  | MRI Maintenance  | Physical +      | MRI control     | CRITICAL         | GAP-007 (No compensating controls),     |
|          |                  | Application     | workstation     |                  | No segmentation, No MFA, No monitoring   |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+
| Greenfield| Building        | Physical +      | Building        | MEDIUM           | No visibility into Greenfield's          |
|          | Management       | Network         | network,        |                  | security, No VLAN audit                  |
|          |                  |                 | VLAN            |                  |                                          |
+----------+------------------+-----------------+-----------------+------------------+------------------------------------------+


================================================================================
REFERENCES
================================================================================

- NIST SP 800-53: CM-8 (Asset Inventory), AC-6 (Least Privilege)
- CIS Controls v8: Control 1 (Inventory and Control of Enterprise Assets)
- ISO 27001: A.8.1 (Asset Inventory), A.8.2 (Acceptable Use)
- CISA Healthcare Guide: Healthcare threat context
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)

Cross-References to Project 1x00:
- Onboarding Packet (Task 0): Vendor Contracts (Artifact 4)
- Asset Registry (Task 7): ehr-srv-01, ehr-db-01, MRI
- Control Matrix (Task 10): C-001, C-005, C-006, C-008, C-009, C-010, C-013
- Gap Analysis (Task 12): GAP-001, GAP-004, GAP-007, GAP-013
- Shadow IT (Task 11): Vendor accounts


================================================================================
END OF SUPPLY CHAIN RISK ASSESSMENT
================================================================================
