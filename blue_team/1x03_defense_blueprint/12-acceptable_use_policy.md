================================================================================
                    ACCEPTABLE USE POLICY - MEDDEFENSE HEALTH SYSTEMS
                    Task 12: The Policy Draft
================================================================================

Exercise: Task 12 - The Policy Draft
Analyst: shamshed rajput
Date: 24/07/2026
Objective: Draft an Acceptable Use Policy (AUP) for MedDefense that is
          grounded in identified risks, enforceable and realistic for a
          hospital environment.

Sources: 1x00 Asset Registry, 1x00 Data Map, 1x00 Gap Analysis,
         1x02 Vulnerability Scan, 1x03 Control Selection (T11)


================================================================================
MEDDEFENSE HEALTH SYSTEMS
ACCEPTABLE USE POLICY
================================================================================

Document Number: MD-POL-001
Effective Date: [Current Date]
Version: 1.0
Approved By: Dr. Patricia Morales, CEO
Classification: Internal

================================================================================
1. PURPOSE
================================================================================

MedDefense Health Systems relies on its information systems and data assets
to provide safe, effective patient care. This Acceptable Use Policy (AUP)
defines the responsibilities of every user who accesses MedDefense systems,
data, or networks. Its purpose is to protect patient data, ensure compliance
with regulatory requirements (HIPAA), and maintain the availability and
integrity of clinical and administrative systems.

================================================================================
2. SCOPE
================================================================================

This policy applies to ALL individuals who access MedDefense information
systems, including:

- All employees (full-time, part-time, and temporary)
- Contractors and consultants
- Third-party vendors with access to MedDefense systems
- Students, interns, and volunteers
- Any other user granted access to MedDefense systems

This policy covers ALL MedDefense systems and data, including:

- Electronic Health Records (EHR) system
- PACS medical imaging system
- Billing and claims processing systems
- Active Directory and authentication systems
- MedDefense network (wired and wireless)
- All workstations, laptops, thin clients, and mobile devices
- Cloud services (O365, SharePoint, OneDrive)
- Medical IoT devices (as applicable to users)
- Personal devices used to access MedDefense systems

================================================================================
3. GENERAL PRINCIPLES
================================================================================

Users of MedDefense systems are expected to:

- Use MedDefense systems solely for authorized business and clinical purposes
- Protect patient data as required by law and MedDefense policy
- Report suspected security incidents or violations immediately
- Use strong, unique passwords and comply with authentication requirements
- Exercise good judgment and common sense
- Complete annual security awareness training

================================================================================
4. ACCEPTABLE USE
================================================================================

4.1 Clinical Use:
- Access patient records only when required for patient care or authorized
  administrative purposes
- Use the EHR system in accordance with clinical workflows
- Log out of systems when leaving workstations unattended

4.2 Administrative Use:
- Use MedDefense systems for authorized administrative work
- Access financial and HR systems only as required for job duties
- Send and receive email for authorized business purposes

4.3 Internet Use:
- Use the internet for business-related purposes
- Limited personal use during breaks is permitted if it does not interfere
  with work, consume excessive bandwidth, or violate any policy

4.4 Communication:
- Use MedDefense email and messaging systems for professional communication
- Identify yourself appropriately in all communications
- Exercise caution with external email, especially links and attachments

================================================================================
5. PROHIBITED ACTIVITIES
================================================================================

The following activities are strictly prohibited:

5.1 Access Violations:
- Accessing patient records without a legitimate clinical or administrative
  need (this includes accessing records of celebrities, colleagues, family,
  or your own records without authorization)
- Sharing or disclosing PHI to unauthorized individuals
- Using another person's credentials or allowing others to use yours
- Using shared or generic accounts (except where explicitly approved for
  specific use cases, with documented justification)

5.2 System Integrity:
- Installing unauthorized software on MedDefense systems
- Modifying system configurations or security settings
- Removing or disabling security controls (antivirus, endpoint protection)
- Attempting to bypass security controls or access restrictions

5.3 Data Protection:
- Copying or storing PHI on personally owned devices or removable media
- Transmitting PHI over unencrypted channels
- Deleting or modifying audit logs
- Storing PHI in unauthorized cloud services (shadow IT)

5.4 Network and Systems:
- Connecting unauthorized devices to the MedDefense network
- Setting up wireless access points or sharing network connections
- Conducting any form of network scanning, penetration testing, or
  vulnerability assessment without explicit authorization from the
  Deputy CISO
- Using peer-to-peer file sharing or torrent clients

5.5 Prohibited Content:
- Accessing, downloading, or distributing illegal content
- Accessing inappropriate or offensive material
- Sending harassing, threatening, or discriminatory communications
- Engaging in any activity that could compromise patient safety or
  clinical operations

5.6 Financial Transactions:
- Using MedDefense systems to conduct personal financial transactions
- Processing financial transactions outside of approved MedDefense
  financial systems and procedures

================================================================================
6. PERSONAL DEVICES AND REMOVABLE MEDIA
================================================================================

6.1 Personal Laptops and Smartphones:

Personal devices may be used to access MedDefense systems ONLY if:
- They are explicitly approved by IT for clinical or business use
- They meet MedDefense security requirements (encryption, patching)
- They are enrolled in Mobile Device Management (MDM)
- They are not used to store PHI locally

6.2 USB Drives and Removable Media:

- USB drives are PROHIBITED on MedDefense workstations except:
  - For approved backup or data transfer operations (requires IT approval)
  - For system administration purposes (requires IT approval)
- The use of personal USB drives to copy or transfer PHI is STRICTLY
  PROHIBITED
- Any USB device used for approved purposes must be encrypted

6.3 Shadow IT:

- No employee may purchase, install, or deploy any IT hardware, software,
  or cloud service without prior IT approval
- This includes (but is not limited to): personal NAS devices, unauthorized
  cloud storage (Dropbox, Google Drive, personal O365), Raspberry Pi
  devices, or any other unmanaged computing device
- Unauthorized devices discovered on the network will be immediately
  disconnected and investigated

================================================================================
7. PASSWORD AND AUTHENTICATION REQUIREMENTS
================================================================================

7.1 Password Policy:

- Passwords must be at least 12 characters in length
- Passwords must include a combination of uppercase letters, lowercase
  letters, numbers, and special characters
- Passwords must be changed every 90 days
- The previous 5 passwords must not be reused
- Accounts lock after 5 failed login attempts for 30 minutes
- Default credentials on any system must be changed immediately upon
  first login

7.2 Multi-Factor Authentication (MFA):

- MFA is REQUIRED for:
  - All remote access (VPN)
  - All administrative accounts
  - All vendor accounts
  - All access to the EHR system from outside the MedDefense network
- MFA must be configured and used at all times

7.3 Authentication Best Practices:

- Do not share passwords with anyone
- Do not write passwords down or store them in unencrypted files
- Use password managers where approved by IT
- Report suspected credential compromise immediately

================================================================================
8. DATA HANDLING REQUIREMENTS
================================================================================

8.1 Data Classification (from MedDefense Data Map):

Data at MedDefense is classified into four levels:

+------------------+--------------------------------------------------+
| Classification   | Description                                      |
+------------------+--------------------------------------------------+
| RESTRICTED       | Patient medical records, PHI, SSNs, credit card  |
|                  | numbers, billing/insurance information          |
+------------------+--------------------------------------------------+
| CONFIDENTIAL     | Employee salaries, strategic plans, vendor       |
|                  | contracts, financial budgets, audit findings    |
+------------------+--------------------------------------------------+
| INTERNAL         | Internal memos, org charts, meeting notes,       |
|                  | department schedules                             |
+------------------+--------------------------------------------------+
| PUBLIC           | Website content, public phone numbers,           |
|                  | marketing materials                              |
+------------------+--------------------------------------------------+

8.2 Data Protection Requirements:

- RESTRICTED and CONFIDENTIAL data MUST be encrypted at rest
- RESTRICTED data MUST be encrypted in transit
- RESTRICTED data must not be stored on personal devices
- Access to RESTRICTED data must be logged and auditable
- RESTRICTED data must not be transmitted via email unless encrypted
- Employees must not share RESTRICTED data with unauthorized individuals
- Clinical staff must only access patient data relevant to their
  current patient assignments

8.3 Data Disposal:

- Confidential and Restricted data must be disposed of using secure deletion
  methods
- Printed documents containing PHI must be shredded before disposal
- Electronic media containing PHI must be destroyed or securely wiped
  before disposal

================================================================================
9. MONITORING AND ENFORCEMENT
================================================================================

9.1 Monitoring:

MedDefense reserves the right to monitor all activity on its systems and
networks, including:

- Access to patient records (audit logs)
- Email and internet usage
- Network traffic patterns
- System activity and performance
- Login attempts and authentication events
- VPN and remote access activity
- Vendor access to systems

Monitoring will be conducted in accordance with applicable laws and
regulations. Employees have no expectation of privacy when using
MedDefense systems.

9.2 Enforcement:

Violations of this policy will result in disciplinary action, up to and
including:

- Verbal warning for minor violations
- Written warning for first-time violations
- Suspension of system access
- Termination of employment
- Legal action (for criminal acts, including PHI breaches)
- Reporting to regulatory authorities as required by law

The Deputy CISO, in consultation with HR and Legal, will determine the
appropriate disciplinary response.

9.3 Reporting Violations:

Employees who suspect a violation of this policy must report it immediately
to the Deputy CISO, their manager, or through the anonymous reporting
channel.

================================================================================
10. EXCEPTIONS
================================================================================

Exceptions to this policy must be approved in writing by the Deputy CISO
and, where appropriate, the CEO. Exceptions will be documented with:

- The specific policy requirement being waived
- The business justification for the exception
- The duration of the exception
- Any compensating controls implemented to mitigate risk

Exceptions will be reviewed quarterly to ensure they remain justified.

================================================================================
11. ROLES AND RESPONSIBILITIES
================================================================================

+---------------------------+--------------------------------------------------+
| Role                      | Responsibility                                   |
+---------------------------+--------------------------------------------------+
| CEO / Board               | Approves policy; ultimate accountability        |
| Deputy CISO               | Policy owner; reviews and updates policy;       |
|                           | enforces compliance                              |
| IT Director               | Implements technical controls; assists with     |
|                           | enforcement                                      |
| Department Heads          | Ensure staff are aware of and comply with       |
|                           | policy; enforce within departments             |
| All Employees             | Comply with policy; report violations           |
+---------------------------+--------------------------------------------------+

================================================================================
12. ACKNOWLEDGMENT
================================================================================

I acknowledge that I have read and understand the MedDefense Health Systems
Acceptable Use Policy. I agree to comply with all requirements of this policy.
I understand that violation of this policy may result in disciplinary action,
up to and including termination of employment and legal action.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Employee Name (Print): _______________________________________________________

Employee Signature: _________________________________________________________

Date: _______________________

Department: _______________________________________________________________

Manager Signature: _________________________________________________________

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

This acknowledgment must be signed prior to receiving system access and
re-acknowledged annually.

================================================================================
13. REVIEW CYCLE
================================================================================

This policy will be reviewed annually by the Deputy CISO, or more frequently
if:

- A significant security incident occurs
- New regulations or compliance requirements emerge
- Major changes to MedDefense's technology environment occur
- A change in the threat landscape warrants policy updates

================================================================================
14. REFERENCES
================================================================================

- HIPAA Security Rule
- NIST CSF 2.0
- CIS Controls v8
- MedDefense Security Posture Assessment (1x00)
- MedDefense Threat Landscape Report (1x01)
- MedDefense Vulnerability Assessment (1x02)


================================================================================
END OF ACCEPTABLE USE POLICY
================================================================================
