================================================================================
                    SEGMENTATION ARCHITECTURE - MEDDEFENSE HEALTH SYSTEMS
                    Task 14: The Segmentation Architecture
================================================================================

Exercise: Task 14 - The Segmentation Architecture
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Design a network segmentation plan that transforms MedDefense's
          flat network into a defensible architecture.

Sources: 1x00 Network Diagram, 1x01 Kill Chains, 1x02 Vulnerability Scan,
         1x03 Risk Register (T10)

Current State: 10.10.0.0/16 flat network with NO VLANs or segmentation


================================================================================
PART 1: ZONE DEFINITION
================================================================================

ZONE 1: SERVER ZONE (VLAN 10)
------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Server Zone (VLAN 10)                            |
+------------------+--------------------------------------------------+
| Purpose          | Host all critical backend servers                |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.10.0/24 (replacing 10.10.2.0/24)           |
+------------------+--------------------------------------------------+
| Systems          | - ehr-srv-01 (EHR Application)                   |
| Included         | - ehr-db-01 (EHR Database - PostgreSQL)          |
|                  | - billing-srv-01 (Billing/Claims)                |
|                  | - ad-dc-01 (Primary Domain Controller)           |
|                  | - ad-dc-02 (Secondary Domain Controller)         |
|                  | - file-srv-01 (File Shares)                      |
|                  | - backup-srv-01 (Veeam Backup)                   |
|                  | - pacs-srv-01 (PACS Imaging)                     |
+------------------+--------------------------------------------------+
| Allowed Outbound | - EHR server to Clinical Workstations (EHR       |
| Connections     |   traffic only)                                  |
|                  | - AD to Clinical Workstations (authentication)   |
|                  | - File server to Clinical/Admin Workstations    |
|                  | - Database to EHR application server (within     |
|                  |   same zone)                                     |
|                  | - Backup server to NAS (within same zone)       |
|                  | - PACS to Radiology Workstations (imaging data) |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - Clinical workstations to EHR (port 443/8080)  |
| Connections     | - Clinical workstations to AD (port 389/636)    |
|                  | - Clinical workstations to File server          |
|                  | - Radiology workstations to PACS (port 11112)   |
|                  | - IT Admin workstations to Server Management    |
|                  |   (SSH/RDP - restricted)                        |
+------------------+--------------------------------------------------+

ZONE 2: CLINICAL WORKSTATION ZONE (VLAN 20)
---------------------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Clinical Workstation Zone (VLAN 20)              |
+------------------+--------------------------------------------------+
| Purpose          | Host all clinical workstations used by medical   |
|                  | staff                                            |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.20.0/24 (replacing 10.10.1.0/24)           |
+------------------+--------------------------------------------------+
| Systems          | - Nurse station workstations (~320)              |
| Included         | - Physician workstations                         |
|                  | - Thin clients in clinical areas (~60)           |
|                  | - Radiology workstations                         |
|                  | - Westside Clinic workstations (~45)             |
|                  | - Clinical iPads (25, MDM-managed)              |
+------------------+--------------------------------------------------+
| Allowed Outbound | - EHR access (port 443/8080) to Server Zone     |
| Connections     | - AD authentication to Server Zone               |
|                  | - PACS access (port 11112) to Server Zone       |
|                  | - Internet access (HTTP/HTTPS) - via proxy      |
|                  | - Email (O365) - via internet                   |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - IT Admin workstations for management          |
| Connections     | - Security tools for endpoint monitoring        |
|                  | - No direct inbound from Guest or Internet      |
+------------------+--------------------------------------------------+

ZONE 3: MEDICAL DEVICE ZONE (VLAN 30)
--------------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Medical Device Zone (VLAN 30)                    |
+------------------+--------------------------------------------------+
| Purpose          | Isolate all IoT medical devices to protect       |
|                  | patient safety and prevent lateral movement     |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.30.0/24 (replacing 10.10.3.0/24)           |
+------------------+--------------------------------------------------+
| Systems          | - BD Alaris Infusion Pumps (~120)                |
| Included         | - Philips IntelliVue Monitors (~80)              |
|                  | - MRI Workstation (Windows XP)                   |
|                  | - CT Scanner                                     |
|                  | - Nurse Call System                              |
|                  | - HID Badge/Access System                        |
+------------------+--------------------------------------------------+
| Allowed Outbound | - Patient data to PACS (port 11112)              |
| Connections     | - Monitor data to Clinical Workstations (viewing)|
|                  | - Pump status to Clinical Workstations          |
|                  | - MRI images to PACS                             |
|                  | - Firmware updates from vendor (restricted)     |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - Clinical workstations to view monitoring data |
| Connections     | - Clinical workstations to MRI/PACS             |
|                  | - Biomed engineering workstation (management)   |
|                  | - NO inbound from internet                      |
|                  | - NO inbound from Server Zone except PACS      |
+------------------+--------------------------------------------------+

ZONE 4: MANAGEMENT ZONE (VLAN 40)
----------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Management Zone (VLAN 40)                        |
+------------------+--------------------------------------------------+
| Purpose          | Secure administrative access to all systems      |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.40.0/24                                    |
+------------------+--------------------------------------------------+
| Systems          | - IT Admin workstations (3-5)                    |
| Included         | - Security Analyst workstation                   |
|                  | - Network management tools                       |
|                  | - SIEM console (future)                         |
|                  | - Backup management console                      |
+------------------+--------------------------------------------------+
| Allowed Outbound | - SSH/RDP to ALL zones (restricted)             |
| Connections     | - Management console to all zones               |
|                  | - Security tools to all zones                   |
|                  | - Internet access (restricted - admin only)    |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - FROM Server Zone (logs, alerts)               |
| Connections     | - MFA REQUIRED for ALL access                   |
|                  | - Jump host required for admin access          |
+------------------+--------------------------------------------------+

ZONE 5: GUEST/IOT ZONE (VLAN 50)
---------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Guest/IoT Zone (VLAN 50)                         |
+------------------+--------------------------------------------------+
| Purpose          | Isolate non-clinical devices and guest WiFi      |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.50.0/24                                    |
+------------------+--------------------------------------------------+
| Systems          | - Guest WiFi access points                       |
| Included         | - Visitor network access                         |
|                  | - Printers/copiers (non-critical)               |
|                  | - HVAC/Environmental systems                     |
|                  | - IP cameras (non-clinical)                     |
+------------------+--------------------------------------------------+
| Allowed Outbound | - Internet access ONLY                           |
| Connections     | - Printers to print servers (if needed)         |
|                  | - NO access to clinical or server networks      |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - FROM Internet (guest WiFi)                    |
| Connections     | - NO inbound from internal zones                |
+------------------+--------------------------------------------------+

ZONE 6: WESTSIDE CLINIC ZONE (VLAN 60)
---------------------------------------
+------------------+--------------------------------------------------+
| Zone Name        | Westside Clinic Zone (VLAN 60)                   |
+------------------+--------------------------------------------------+
| Purpose          | Secure the Westside outpatient facility          |
+------------------+--------------------------------------------------+
| IP Range         | 10.10.60.0/24 (replacing 10.10.10.0/24)          |
+------------------+--------------------------------------------------+
| Systems          | - ws-srv-01 (Local file/scheduling)              |
| Included         | - Westside workstations (~45)                    |
|                  | - Westside medical devices                       |
|                  | - FortiGate 40F (new enterprise firewall)       |
+------------------+--------------------------------------------------+
| Allowed Outbound | - VPN tunnel to Central (encrypted)              |
| Connections     | - EHR access through VPN                         |
|                  | - AD authentication through VPN                  |
+------------------+--------------------------------------------------+
| Allowed Inbound  | - FROM Central Server Zone (EHR, AD)             |
| Connections     | - VPN tunnel from Central                        |
+------------------+--------------------------------------------------+


================================================================================
PART 2: FIREWALL RULES
================================================================================

CRITICAL FIREWALL RULES (PSEUDOCODE)
------------------------------------

+----------+------------------+------------------+-----------------+------------------+
| Rule #   | Source           | Destination      | Port/Protocol   | Action           |
+----------+------------------+------------------+-----------------+------------------+
| 1        | Server Zone      | Clinical Zone    | 443/tcp         | ALLOW            |
|          | (EHR)            |                  | (EHR Traffic)   |                  |
+----------+------------------+------------------+-----------------+------------------+
| 2        | Server Zone      | Clinical Zone    | 389/tcp, 636/tcp| ALLOW            |
|          | (AD)             |                  | (AD Auth)       |                  |
+----------+------------------+------------------+-----------------+------------------+
| 3        | Clinical Zone    | Server Zone      | 443/tcp         | ALLOW            |
|          | (Workstations)   | (EHR)            | (EHR Access)    |                  |
+----------+------------------+------------------+-----------------+------------------+
| 4        | Clinical Zone    | Medical Device   | 2575/tcp        | ALLOW            |
|          | (Workstations)   | Zone             | (Patient Data)  |                  |
+----------+------------------+------------------+-----------------+------------------+
| 5        | Server Zone      | Medical Device   | 11112/tcp       | ALLOW            |
|          | (PACS)           | Zone (MRI)       | (DICOM Images)  |                  |
+----------+------------------+------------------+-----------------+------------------+
| 6        | Management Zone  | ALL Zones        | 22/tcp, 3389/tcp| ALLOW            |
|          | (Admin)          |                  | (SSH/RDP)       | (with MFA)       |
+----------+------------------+------------------+-----------------+------------------+
| 7        | Guest Zone       | Internet         | 80/tcp, 443/tcp | ALLOW            |
|          |                  |                  | (Web)           |                  |
+----------+------------------+------------------+-----------------+------------------+
| 8        | Westside Zone    | Server Zone      | ALL             | ALLOW            |
|          | (VPN)            |                  | (VPN Tunnel)    |                  |
+----------+------------------+------------------+-----------------+------------------+
| 9        | Guest Zone       | ANY Internal     | ANY             | DENY             |
|          |                  |                  |                 |                  |
+----------+------------------+------------------+-----------------+------------------+
| 10       | Clinical Zone    | Server Zone      | 5432/tcp        | DENY             |
|          |                  | (PostgreSQL)     |                 |                  |
+----------+------------------+------------------+-----------------+------------------+

EXPLANATION OF DENY RULES
-------------------------
+----------------------------------------------------------------------------+
| RULE 9: Guest Zone → ANY Internal: DENY                                    |
| Prevents guest WiFi users from accessing ANY internal network resources.  |
| This addresses the risk of guest WiFi being used to pivot to clinical     |
| systems (identified in 1x00). This disrupts Kill Chain #3.               |
+----------------------------------------------------------------------------+
| RULE 10: Clinical Zone → Server Zone (PostgreSQL 5432): DENY              |
| Prevents clinical workstations from directly connecting to the            |
| PostgreSQL database. This enforces the application-layer control and     |
| prevents lateral movement to the EHR database. This disrupts Kill       |
| Chain #2 (Phishing → EHR) at Step 5.                                    |
+----------------------------------------------------------------------------+


================================================================================
PART 3: KILL CHAIN IMPACT
================================================================================

KILL CHAIN #1 (VPN RANSOMWARE) - STEP-BY-STEP IMPACT
----------------------------------------------------
+----------------------------------------------------------------------------+
| KILL CHAIN #1: RANSOMWARE THROUGH UNPATCHED VPN                            |
|                                                                             |
| Step 1 - Initial Access (VPN Exploit)                                     |
|   WITHOUT SEGMENTATION: Attacker gains VPN access to entire network      |
|   WITH SEGMENTATION: Attacker only gains access to VPN termination zone   |
|   (Westside Zone or DMZ). Cannot reach Server Zone directly.              |
|   SEGMENTATION BREAKS CHAIN: YES                                          |
|                                                                             |
| Step 2 - Establish Foothold                                               |
|   WITHOUT SEGMENTATION: Attacker installs backdoor on any system         |
|   WITH SEGMENTATION: Attacker confined to VPN zone. Cannot reach          |
|   clinical or server systems.                                              |
|   SEGMENTATION BREAKS CHAIN: YES                                          |
|                                                                             |
| Step 3 - Lateral Movement to Domain Controller                           |
|   WITHOUT SEGMENTATION: Attacker moves freely across flat network        |
|   WITH SEGMENTATION: Domain Controller is in Server Zone. Attacker       |
|   cannot reach it from VPN/Clinical zone without crossing firewall.      |
|   SEGMENTATION BREAKS CHAIN: YES                                          |
|                                                                             |
| Step 4 - Deploy Ransomware via Group Policy                               |
|   WITHOUT SEGMENTATION: GPO reaches ALL systems                          |
|   WITH SEGMENTATION: GPO only reaches systems in the same zone. Other   |
|   zones are isolated.                                                     |
|   SEGMENTATION BREAKS CHAIN: YES                                          |
|                                                                             |
| Step 5 - Impact                                                           |
|   WITHOUT SEGMENTATION: ALL systems encrypted                            |
|   WITH SEGMENTATION: Only systems in the compromised zone are affected   |
|   SEGMENTATION BREAKS CHAIN: YES                                          |
+----------------------------------------------------------------------------+

KILL CHAIN IMPACT SUMMARY
-------------------------
+----------+------------------+------------------------------------------+
| Kill     | Title            | Disrupted by Segmentation?               |
| Chain    |                  |                                          |
+----------+------------------+------------------------------------------+
| KC #1    | VPN Ransomware   | ✅ YES - 100% (all 5 steps)              |
+----------+------------------+------------------------------------------+
| KC #2    | Phishing → EHR   | ✅ YES - 100% (all 5 steps)              |
+----------+------------------+------------------------------------------+
| KC #3    | IoT Patient      | ✅ YES - 100% (all 5 steps)              |
|          | Safety           |                                          |
+----------+------------------+------------------------------------------+
| KC #4    | MRI → EHR        | ✅ YES - 100% (all 5 steps)              |
+----------+------------------+------------------------------------------+
| KC #5    | Supply Chain     | PARTIAL - Vendor access remains          |
|          |                  | but lateral movement is blocked          |
+----------+------------------+------------------------------------------+

TOTAL KILL CHAINS DISRUPTED: 4 out of 5 (80%)

+----------------------------------------------------------------------------+
| SEGMENTATION IMPACT SUMMARY                                                 |
|                                                                             |
| This segmentation design disrupts 80% of the top 5 kill chains entirely.  |
| The flat network was the PRIMARY ENABLER of lateral movement in every     |
| kill chain. Segmentation contains lateral movement, making each attack   |
| a localized incident rather than a network-wide catastrophe.             |
|                                                                             |
| The one remaining kill chain (Supply Chain) is partially disrupted       |
| because vendor access (MedTech) may still allow initial entry. However,  |
| lateral movement to other zones is blocked, limiting the damage.         |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Network Diagram (1x00 Doc 5)
- Kill Chains (1x01 T10)
- Vulnerability Scan (1x02)
- Risk Register (1x03 T10)


================================================================================
END OF SEGMENTATION ARCHITECTURE REPORT
================================================================================
