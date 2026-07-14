================================================================================
                    SOCIAL ENGINEERING ANALYSIS - MEDDEFENSE HEALTH SYSTEMS
                    Task 4: The Human Vector
================================================================================

Exercise: Task 4 - The Human Vector
Analyst: shamshed rajput 
Date: 14/07/2026
Objective: Identify, classify and analyze social engineering attack vectors
          in a healthcare context, including red flags and countermeasures.

Methodology References:
- Security+ 2.2: Social engineering vectors (phishing, vishing, smishing,
  pretexting, BEC, impersonation, watering hole, brand impersonation,
  typosquatting)
- KnowBe4: Social Engineering Red Flags
- NIST SP 800-61: Attack vectors and indicators

Cross-References to Project 1x00:
- Gap Analysis (Task 12): GAP-001 (No SIEM), GAP-004 (No MFA),
  GAP-010 (No Audits), GAP-011 (No Enforcement), GAP-013 (Email Security),
  GAP-016 (Web App Security)
- Control Matrix (Task 10): C-001, C-006, C-013, C-014


================================================================================
SCENARIO 1: FORTIGATE SUPPORT PHISHING EMAIL
================================================================================

SCENARIO DESCRIPTION
--------------------
An email arrives in the inbox of Sarah Park (IT Director), appearing to come
from FortiGate support: "Critical firmware vulnerability detected on your
FortiGate 100F. Click here to download the emergency patch. Failure to patch
within 24 hours may result in service termination." The sender domain is
fortinet-support.net.

+------------------+--------------------------------------------------+
| Vector Type      | PHISHING (email-based)                           |
+------------------+--------------------------------------------------+
| Target           | Sarah Park, IT Director. She is the decision-    |
|                  | maker for network infrastructure and is          |
|                  | responsible for firewall management. An attacker |
|                  | who compromises her credentials gains control    |
|                  | over the organization's primary perimeter device |
|                  | and the entire IT budget.                        |
+------------------+--------------------------------------------------+
| Psychological    | URGENCY + AUTHORITY - "Failure to patch within   |
| Lever            | 24 hours may result in service termination"      |
|                  | creates urgency. The email appears to come from  |
|                  | a trusted vendor (FortiGate) and references a    |
|                  | "critical vulnerability" to establish authority. |
+------------------+--------------------------------------------------+
| Red Flags        | 1. The sender domain is fortinet-support.net     |
|                  |    instead of fortinet.com.                     |
|                  | 2. "Service termination" is not how legitimate   |
|                  |    vendors communicate patch urgency.           |
|                  | 3. The email asks to click a link to download a  |
|                  |    patch - legitimate vendors provide patches    |
|                  |    through official support portals.            |
|                  | 4. Generic greeting, no reference to MedDefense  |
|                  |    or specific FortiGate device.                |
+------------------+--------------------------------------------------+
| Technical        | 1. Email filtering to detect typosquatting      |
| Control          |    domains and spoofed sender addresses.         |
|                  | 2. MFA on all administrative accounts (GAP-004) |
|                  |    - even if credentials are captured, the      |
|                  |    attacker cannot access the firewall.         |
|                  | 3. SPF/DKIM/DMARC email authentication.         |
+------------------+--------------------------------------------------+
| Administrative   | 1. Vendor communication policy: all critical     |
| Control          |    security alerts must be verified through      |
|                  |    official support channels, not email links.   |
|                  | 2. Security awareness training on identifying    |
|                  |    phishing emails targeting IT staff.          |
|                  | 3. Incident reporting procedure: suspicious     |
|                  |    emails must be reported to security team.     |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 2: CEO IMPERSONATION - WIRE TRANSFER (BEC)
================================================================================

SCENARIO DESCRIPTION
--------------------
The CFO (Robert Kim) receives an email from what appears to be Dr. Patricia
Morales (CEO): "Robert, I need you to process a wire transfer of $85,000 to
the account below immediately. This is for a confidential equipment
acquisition. Do not discuss with anyone until the deal closes. I am in
meetings all day, email only." The sender address has a subtle difference
from the real CEO email.

+------------------+--------------------------------------------------+
| Vector Type      | BUSINESS EMAIL COMPROMISE (BEC) / IMPERSONATION  |
+------------------+--------------------------------------------------+
| Target           | Robert Kim, CFO. He has authority to approve      |
|                  | wire transfers and financial transactions.       |
|                  | $85,000 is a significant amount but not large    |
|                  | enough to trigger unusual scrutiny. The          |
|                  | "confidential equipment acquisition" pretext is  |
|                  | plausible given the organization's size.         |
+------------------+--------------------------------------------------+
| Psychological    | AUTHORITY + URGENCY + FAMILIARITY - The email    |
| Lever            | appears to come from the CEO (authority).        |
|                  | "Immediately" and "Do not discuss with anyone"   |
|                  | create urgency and isolation (no verification).  |
|                  | The request references a plausible hospital      |
|                  | activity (equipment acquisition).                |
+------------------+--------------------------------------------------+
| Red Flags        | 1. The sender address has a subtle difference    |
|                  |    from the real CEO email (e.g., dr.morales@    |
|                  |    meddefense-h.com vs dr.morales@meddefense.com)|
|                  | 2. The request asks to bypass normal financial   |
|                  |    approval processes and not discuss with       |
|                  |    anyone.                                       |
|                  | 3. The email is marked "email only" to prevent   |
|                  |    voice verification.                          |
|                  | 4. Urgency is used to prevent careful review.   |
+------------------+--------------------------------------------------+
| Technical        | 1. Email authentication (SPF/DKIM/DMARC) to     |
| Control          |    detect spoofed domains.                      |
|                  | 2. Email filtering to flag external emails      |
|                  |    impersonating internal executives.            |
|                  | 3. AI-based BEC detection tools.                |
+------------------+--------------------------------------------------+
| Administrative   | 1. Two-person approval for wire transfers        |
| Control          |    requiring verbal confirmation from the       |
|                  |    requesting executive.                        |
|                  | 2. Financial policy requiring verification of   |
|                  |    any unusual financial request through a      |
|                  |    known, confirmed channel.                    |
|                  | 3. Security awareness training specifically on  |
|                  |    BEC targeting finance staff.                 |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 3: IT IMPERSONATION - CREDENTIAL HARVESTING (VISHING)
================================================================================

SCENARIO DESCRIPTION
--------------------
A nurse at MedDefense Central answers the phone. The caller identifies
themselves as "Mike from IT" and says: "We're doing an emergency security
audit after the billing server incident. I need to verify your login works
correctly. Can you read me your username and the password you use for the
EHR system ?"

+------------------+--------------------------------------------------+
| Vector Type      | VISHING (voice phishing)                         |
+------------------+--------------------------------------------------+
| Target           | A nurse at MedDefense Central. Nurses are         |
|                  | trained to be helpful and responsive to urgent   |
|                  | requests. They are under time pressure and may   |
|                  | not question a caller who appears authoritative. |
|                  | Their EHR credentials provide access to PHI.    |
+------------------+--------------------------------------------------+
| Psychological    | URGENCY + AUTHORITY + HELPFULNESS - The          |
| Lever            | "emergency security audit" reference to the      |
|                  | recent billing server incident adds credibility. |
|                  | "Mike from IT" impersonates a known role.        |
|                  | Nurses are trained to help - asking them to      |
|                  | "verify credentials" preys on this tendency.    |
+------------------+--------------------------------------------------+
| Red Flags        | 1. IT will never ask for a user's password over  |
|                  |    the phone.                                   |
|                  | 2. No prior notification of a security audit.    |
|                  | 3. The caller requests sensitive credentials     |
|                  |    directly.                                    |
|                  | 4. The caller cannot be verified (no callback    |
|                  |    number, no badge).                           |
+------------------+--------------------------------------------------+
| Technical        | 1. MFA on EHR access (GAP-004) - even if         |
| Control          |    credentials are captured, MFA blocks access.  |
|                  | 2. SIEM alerting on credential usage from        |
|                  |    unusual locations (GAP-001).                 |
|                  | 3. Self-service password reset tools eliminate   |
|                  |    the need for IT staff to handle credentials.  |
+------------------+--------------------------------------------------+
| Administrative   | 1. Policy: IT staff will never ask for passwords |
| Control          |    over the phone. All credential issues must be |
|                  |    handled through the helpdesk ticketing        |
|                  |    system.                                      |
|                  | 2. Security awareness training for clinical      |
|                  |    staff on vishing and social engineering.     |
|                  | 3. Incident reporting procedure: any suspicious  |
|                  |    call must be reported immediately.            |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 4: PARKING PERMIT SMISHING
================================================================================

SCENARIO DESCRIPTION
--------------------
All MedDefense employees receive a text message: "MedDefense Parking: Your
staff parking permit expires tomorrow. Renew immediately to avoid towing:
[link]." The link leads to a page that looks like MedDefense's internal HR
portal and asks for AD credentials.

+------------------+--------------------------------------------------+
| Vector Type      | SMISHING (SMS phishing)                          |
+------------------+--------------------------------------------------+
| Target           | All MedDefense employees (~2,000). Wide          |
|                  | targeting increases the chance someone falls    |
|                  | for it. Employees are accustomed to receiving   |
|                  | messages about parking. The threat of towing    |
|                  | creates immediate concern.                      |
+------------------+--------------------------------------------------+
| Psychological    | URGENCY + FEAR - "Renew immediately to avoid    |
| Lever            | towing" creates urgency and fear of              |
|                  | consequences. The message appears official and  |
|                  | references a real concern (parking permits).    |
+------------------+--------------------------------------------------+
| Red Flags        | 1. The message asks for AD credentials through  |
|                  |    a link - legitimate parking renewal would    |
|                  |    not require AD credentials.                  |
|                  | 2. The link URL is unfamiliar or suspicious     |
|                  |    (not meddefense.com).                       |
|                  | 3. No prior notification about parking permit   |
|                  |    expiration.                                  |
|                  | 4. Urgency and threat ("to avoid towing") are  |
|                  |    used to bypass careful thought.             |
+------------------+--------------------------------------------------+
| Technical        | 1. Email/Mobile Device Management (MDM) to      |
| Control          |    block malicious links.                       |
|                  | 2. MFA on AD credentials (GAP-004) - captured   |
|                  |    credentials are useless without MFA.         |
|                  | 3. DNS filtering to block known malicious       |
|                  |    domains.                                     |
+------------------+--------------------------------------------------+
| Administrative   | 1. Security awareness training to identify      |
| Control          |    smishing messages.                           |
|                  | 2. Policy requiring all HR/administrative       |
|                  |    communications to come through official      |
|                  |    channels (email/portal, not SMS).           |
|                  | 3. Incident reporting procedure for suspicious  |
|                  |    text messages.                               |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 5: COMPROMISED INDUSTRY WEBSITE (WATERING HOLE)
================================================================================

SCENARIO DESCRIPTION
--------------------
The website of the Regional Healthcare Association (an industry group that
MedDefense physicians visit monthly for CME credits) is compromised.
Visitors who browse specific pages are silently redirected to a site that
attempts to exploit a browser vulnerability to install malware.

+------------------+--------------------------------------------------+
| Vector Type      | WATERING HOLE ATTACK                            |
+------------------+--------------------------------------------------+
| Target           | MedDefense physicians and clinical staff who     |
|                  | regularly visit the industry group website for   |
|                  | Continuing Medical Education (CME) credits.     |
|                  | Attackers compromise a trusted third-party site |
|                  | that the target visits routinely.               |
+------------------+--------------------------------------------------+
| Psychological    | TRUST + FAMILIARITY - The site is known and     |
| Lever            | trusted by MedDefense staff. They have no       |
|                  | reason to suspect it is compromised. The        |
|                  | attack requires no user action beyond visiting  |
|                  | the site.                                       |
+------------------+--------------------------------------------------+
| Red Flags        | 1. Unusual pop-ups or browser warnings when     |
|                  |    visiting a normally safe site.               |
|                  | 2. The site URL redirects to an unexpected      |
|                  |    destination.                                 |
|                  | 3. Browser security warnings (SSL certificate   |
|                  |    errors, mixed content warnings).            |
|                  | 4. Unusual system performance after visiting    |
|                  |    the site.                                    |
+------------------+--------------------------------------------------+
| Technical        | 1. Endpoint Detection and Response (EDR) to     |
| Control          |    detect and block malware execution.          |
|                  | 2. Web filtering and DNS protection to block    |
|                  |    known malicious domains.                    |
|                  | 3. Browser security extensions/ad-blockers.    |
|                  | 4. Regular patching of browsers and plugins    |
|                  |    (GAP-014).                                  |
+------------------+--------------------------------------------------+
| Administrative   | 1. Policy requiring all staff to use corporate   |
| Control          |    devices with EDR for internet browsing.     |
|                  | 2. Security awareness: report any unusual       |
|                  |    browser behavior.                            |
|                  | 3. Regular vulnerability scanning of            |
|                  |    third-party sites used by staff (not         |
|                  |    directly controllable but can be monitored). |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 6: TYPOSQUATTING FAKE PATIENT PORTAL
================================================================================

SCENARIO DESCRIPTION
--------------------
Someone registers the domain meddefence-portal.com (note: "defence" instead
of "defense"). They create a pixel-perfect copy of MedDefense's patient
portal. Google Ads are purchased so this fake portal appears above the real
one in search results for "MedDefense patient portal."

+------------------+--------------------------------------------------+
| Vector Type      | TYPOSQUATTING + BRAND IMPERSONATION              |
+------------------+--------------------------------------------------+
| Target           | Patients, visitors, and potential patients      |
|                  | searching for the MedDefense patient portal.    |
|                  | The fake site appears in search results above   |
|                  | the legitimate one due to Google Ads.          |
|                  | Credentials entered on the fake site are        |
|                  | captured by attackers.                          |
+------------------+--------------------------------------------------+
| Psychological    | FAMILIARITY + TRUST - The site looks exactly    |
| Lever            | like the real MedDefense portal. Users trust    |
|                  | it because it appears at the top of search      |
|                  | results. The domain is one letter different     |
|                  | from the real one.                             |
+------------------+--------------------------------------------------+
| Red Flags        | 1. The URL has a subtle spelling difference     |
|                  |    ("defence" vs "defense").                    |
|                  | 2. The SSL certificate may not be valid or      |
|                  |    may not match the organization.             |
|                  | 3. The site may not have the same privacy       |
|                  |    policy or contact information as the real    |
|                  |    portal.                                      |
|                  | 4. Any prompt for credentials on a page that    |
|                  |    is accessed via a search result should be    |
|                  |    carefully verified.                         |
+------------------+--------------------------------------------------+
| Technical        | 1. Domain monitoring to detect typosquatting    |
| Control          |    domains (with automated takedown).           |
|                  | 2. MFA on patient portal access (GAP-004) -     |
|                  |    captured credentials are useless.           |
|                  | 3. Web Application Firewall (WAF) to detect     |
|                  |    and block credential stuffing attempts.     |
|                  | 4. Brand monitoring and Google Ads reporting   |
|                  |    to identify impersonation.                  |
+------------------+--------------------------------------------------+
| Administrative   | 1. Legal trademark protection and domain        |
| Control          |    registration monitoring.                    |
|                  | 2. Policy to regularly monitor for              |
|                  |    typosquatting and brand impersonation.       |
|                  | 3. Customer/patient communication: notify       |
|                  |    patients about the legitimate portal URL    |
|                  |    and warn about scams.                       |
+------------------+--------------------------------------------------+


================================================================================
SCENARIO 7: TAILGATING INTO IT DEPARTMENT
================================================================================

SCENARIO DESCRIPTION
--------------------
A person in scrubs carrying a stethoscope and a hospital-branded coffee cup
approaches the restricted corridor leading to the IT department. They follow
a staff member through the badge-controlled door, saying warmly: "Thanks!
My badge is in my locker, I'm just running back to grab something from my
desk." Their visitor badge, partially hidden by the stethoscope, expired
two days ago.

+------------------+--------------------------------------------------+
| Vector Type      | IMPERSONATION + TAILGATING (PHYSICAL)            |
+------------------+--------------------------------------------------+
| Target           | IT department and server room area. The attacker |
|                  | gains physical access to restricted areas        |
|                  | without using a badge. This bypasses ALL        |
|                  | technical controls.                              |
+------------------+--------------------------------------------------+
| Psychological    | HELPFULNESS + FAMILIARITY + AUTHORITY - The     |
| Lever            | person appears to be a hospital employee (scrubs,|
|                  | stethoscope, branded coffee cup). They know the  |
|                  | entrance procedure and speak confidently. They  |
|                  | exploit the target's instinct to be helpful.    |
+------------------+--------------------------------------------------+
| Red Flags        | 1. The person's badge is hidden or expired.     |
|                  | 2. They do not have a visible, current visitor  |
|                  |    badge.                                       |
|                  | 3. They are entering a restricted area without   |
|                  |    swiping their own badge.                     |
|                  | 4. Their explanation is vague ("running back to  |
|                  |    grab something from my desk").               |
|                  | 5. They seem too friendly or familiar.          |
+------------------+--------------------------------------------------+
| Technical        | 1. Physical access control with active badge    |
| Control          |    verification (C-018) - doors that require     |
|                  |    badge AND PIN or biometrics.                 |
|                  | 2. Security cameras in restricted corridors     |
|                  |    (C-012 upgrade needed - currently NO cameras |
|                  |    in server room area).                        |
|                  | 3. Mantraps (two-door systems) that prevent     |
|                  |    tailgating.                                  |
+------------------+--------------------------------------------------+
| Administrative   | 1. Policy requiring all staff to challenge       |
| Control          |    strangers in restricted areas.               |
|                  | 2. Visitor management policy: all visitors must  |
|                  |    be escorted and wear visible badges.        |
|                  | 3. Security awareness training: "If you see     |
|                  |    something, say something."                  |
|                  | 4. Regular physical security audits (GAP-010).  |
+------------------+--------------------------------------------------+


================================================================================
SOCIAL ENGINEERING PATTERN ANALYSIS
================================================================================

+----------------------------------------------------------------------------+
| SOCIAL ENGINEERING PATTERN ANALYSIS                                        |
|                                                                             |
| Across all 7 scenarios, several patterns emerge:                            |
|                                                                             |
| 1. URGENCY is the most common psychological lever (Scenarios 1, 2, 4).    |
|    Attackers create artificial time pressure to prevent careful thought.   |
|                                                                             |
| 2. AUTHORITY is used in 4 of 7 scenarios (1, 2, 3, 7). Attackers           |
|    impersonate IT support, executives, or appear as insiders with          |
|    legitimate authority.                                                   |
|                                                                             |
| 3. The organization's security culture is weak. Scenario 1 targets         |
|    an IT Director who should know better. Scenario 3 preys on nurses      |
|    who are trained to be helpful. Scenario 7 exploits the lack of         |
|    physical security awareness.                                            |
|                                                                             |
| 4. Technical controls (MFA, email filtering, EDR) can mitigate many       |
|    of these attacks, but administrative controls (training, policies,     |
|    enforcement) are equally important.                                    |
|                                                                             |
| 5. MedDefense's gaps from 1x00 directly enable these attacks:             |
|    - GAP-004 (No MFA) enables credential theft from Scenarios 1, 3, 4, 6  |
|    - GAP-001 (No SIEM) means successful attacks go undetected             |
|    - GAP-011 (No Enforcement) means staff don't take security seriously   |
|    - GAP-013 (Email Security) enables Scenarios 1 and 2                  |
|    - GAP-016 (Web App Security) enables Scenario 6                       |
|                                                                             |
| 6. The human vector is the most dangerous attack surface because it       |
|    cannot be fully patched. Even with perfect technical controls, one     |
|    helpful employee can undermine them all.                              |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- Security+ 2.2: Social engineering vectors
- KnowBe4: Social Engineering Red Flags
- NIST SP 800-61: Attack vectors and indicators
- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare" (File 2)

Cross-References to Project 1x00:
- Gap Analysis (Task 12): GAP-001, GAP-004, GAP-010, GAP-011, GAP-013,
  GAP-016
- Control Matrix (Task 10): C-001, C-006, C-013, C-014
- Walk-through Observations (Task 3): Physical access gaps


================================================================================
END OF SOCIAL ENGINEERING ANALYSIS
================================================================================
