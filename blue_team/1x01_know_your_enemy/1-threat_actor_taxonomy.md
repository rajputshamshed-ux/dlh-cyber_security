================================================================================
                    THREAT ACTOR TAXONOMY - MEDDEFENSE HEALTH SYSTEMS
                    Task 1: The Threat Actor Taxonomy
================================================================================

Exercise: Task 1 - The Threat Actor Taxonomy
Analyst: shamshed rajput
Date: 13/07/2026
Objective: Classify threat actors by type, attributes and motivation from
          observed behavior alone.

Methodology References:
- HC3 Threat Actor Categories (from marcus-intelligence-dossier.txt)
- Security+ Threat Actor Framework: Nation-state, Organized Crime, Hacktivist,
  Insider Threat, Unskilled Attacker, Shadow IT
- NIST SP 800-30: Threat source characteristics

Sources: threat-actor-reports.txt (8 anonymized intelligence reports)


================================================================================
REPORT A: RANSOMWARE DEPLOYMENT
================================================================================

REPORT DESCRIPTION:
--------------------
A 350-bed regional hospital experienced a ransomware attack that encrypted
its EHR, billing, and scheduling systems. The attackers gained initial
access through a VPN appliance vulnerability (CVE published 6 months prior).
They moved laterally across the network, reached the Domain Controller,
exfiltrated 35GB of patient data, and deployed ransomware via Group Policy.
A ransom demand of $2.5 million was delivered with a 48-hour deadline.
The attackers communicated professionally and had a negotiation portal.

+------------------+--------------------------------------------------+
| Actor Type       | ORGANIZED CRIME / RANSOMWARE GROUP                |
+------------------+--------------------------------------------------+
| Internal/        | EXTERNAL - Initial access came from outside via   |
| External         | VPN appliance vulnerability. The attackers had no |
|                  | prior internal access.                           |
+------------------+--------------------------------------------------+
| Resources        | HIGH - Ransomware-as-a-Service infrastructure,    |
|                  | negotiation portal, professional communication,   |
|                  | and ability to purchase initial access from      |
|                  | brokers.                                          |
+------------------+--------------------------------------------------+
| Sophistication   | MEDIUM to HIGH - Used VPN exploit, lateral        |
|                  | movement, Group Policy deployment, and double     |
|                  | extortion tactics. This is a professional         |
|                  | operation with established business processes.    |
+------------------+--------------------------------------------------+
| Primary          | FINANCIAL GAIN - The ransom demand and double     |
| Motivation       | extortion (encryption + data theft) indicate      |
|                  | financial motivation. Healthcare is targeted for  |
|                  | its ability to pay.                               |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - The behavior matches documented RaaS       |
| Level            | group TTPs: VPN exploitation, lateral movement,   |
|                  | Group Policy deployment, ransom demand,           |
|                  | negotiation portal. This is a classic ransomware  |
|                  | operation.                                        |
+------------------+--------------------------------------------------+


================================================================================
REPORT B: PHARMACEUTICAL RESEARCH THEFT
================================================================================

REPORT DESCRIPTION:
--------------------
A pharmaceutical company conducting clinical trials for a novel cancer drug
experienced a sophisticated breach. The attackers remained undetected for
11 months. They specifically targeted research data related to drug formula
trials, intellectual property documents, and email communications with
regulatory agencies. No ransomware was deployed. No data was encrypted.
The attackers used custom-built malware that was not detected by antivirus.
They accessed the network through a zero-day vulnerability in the company's
secure file transfer system.

+------------------+--------------------------------------------------+
| Actor Type       | NATION-STATE APT GROUP                           |
+------------------+--------------------------------------------------+
| Internal/        | EXTERNAL - Initial access via zero-day in        |
| External         | file transfer system. No insider assistance      |
|                  | indicated.                                        |
+------------------+--------------------------------------------------+
| Resources        | HIGH - Zero-day exploitation capability, custom  |
|                  | malware, ability to maintain access for 11       |
|                  | months without detection. This requires          |
|                  | significant funding and development capability.  |
+------------------+--------------------------------------------------+
| Sophistication   | VERY HIGH - Custom malware, zero-day exploit,    |
|                  | prolonged stealth, selective data targeting.     |
|                  | This is the highest level of sophistication.     |
+------------------+--------------------------------------------------+
| Primary          | ESPIONAGE / INTELLECTUAL PROPERTY THEFT - The    |
| Motivation       | targeting of clinical trial data and drug        |
|                  | formulas indicates strategic/economic espionage, |
|                  | not financial gain.                              |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - Long-term stealth, zero-day exploitation, |
| Level            | selective targeting of research data, custom     |
|                  | malware, no encryption/ransom demand. These      |
|                  | characteristics are hallmarks of nation-state    |
|                  | APT activity.                                     |
+------------------+--------------------------------------------------+


================================================================================
REPORT C: DISGRUNTLED EMPLOYEE DATA THEFT
================================================================================

REPORT DESCRIPTION:
--------------------
A hospital discovered that a former billing department employee had accessed
the EHR system 23 times over 6 weeks after their termination date. The
employee used their active credentials to download patient records for
1,847 individuals. The access occurred exclusively between 10 PM and 2 AM
from an IP address associated with the employee's home internet. The
employee was terminated for performance issues 6 weeks prior to discovery.

+------------------+--------------------------------------------------+
| Actor Type       | INSIDER THREAT (MALICIOUS)                       |
+------------------+--------------------------------------------------+
| Internal/        | BOTH - The actor was an internal employee who    |
| External         | used internal credentials. However, they        |
|                  | accessed from an external location (home IP).   |
|                  | The breach was enabled by internal access        |
|                  | privileges that should have been revoked.       |
+------------------+--------------------------------------------------+
| Resources        | LOW - The attacker used their own credentials    |
|                  | and a personal computer. No specialized tools    |
|                  | or funding were required.                        |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - Basic access using existing credentials.   |
|                  | No exploitation of vulnerabilities. No evasion  |
|                  | techniques beyond off-hours access.             |
+------------------+--------------------------------------------------+
| Primary          | REVENGE / FINANCIAL GAIN - The employee was      |
| Motivation       | terminated for performance issues. Motivation    |
|                  | could be revenge (sabotage) or financial gain    |
|                  | (selling patient records on dark web).           |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - The timing (post-termination), off-hours  |
| Level            | access, and use of legitimate credentials        |
|                  | strongly indicate a malicious insider threat.   |
+------------------+--------------------------------------------------+


================================================================================
REPORT D: WEBSITE DEFACEMENT - POLITICAL MESSAGE
================================================================================

REPORT DESCRIPTION:
--------------------
A hospital's public-facing website was defaced. The homepage was replaced
with a political message protesting the hospital's partnership with a
government agency involved in immigration enforcement. The attackers
exploited a known vulnerability in the hospital's content management system
(version outdated). No patient data was accessed or stolen. The site was
restored within 6 hours. A group claimed responsibility on social media.

+------------------+--------------------------------------------------+
| Actor Type       | HACKTIVIST                                       |
+------------------+--------------------------------------------------+
| Internal/        | EXTERNAL - Attack came from outside via          |
| External         | vulnerability in the content management system.   |
+------------------+--------------------------------------------------+
| Resources        | LOW - Used a known, publicly available exploit   |
|                  | against an outdated CMS. No custom tools.       |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - Exploited a known vulnerability. No       |
|                  | lateral movement, no data theft, no persistence. |
|                  | Basic web defacement.                            |
+------------------+--------------------------------------------------+
| Primary          | PHILOSOPHICAL / POLITICAL - The political        |
| Motivation       | message and social media claim indicate          |
|                  | ideological motivation. No financial gain was    |
|                  | sought.                                           |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - Public claim of responsibility, political |
| Level            | messaging, no data theft, no encryption. These   |
|                  | are hallmarks of hacktivist activity.            |
+------------------+--------------------------------------------------+


================================================================================
REPORT E: CRYPTO-MINING ON BILLING SERVER
================================================================================

REPORT DESCRIPTION:
--------------------
A hospital noticed performance degradation on a billing server. Investigation
revealed a crypto-miner running on the server, consuming 94% of CPU
resources. The miner was installed via an exploit in an outdated version of
Apache (2.4.29) running on the server. The server was on the hospital's
main network. The attacker had installed the miner and configured it to
connect to a mining pool. No other systems were accessed. No data was stolen
or encrypted.

+------------------+--------------------------------------------------+
| Actor Type       | UNSKILLED / OPPORTUNISTIC ATTACKER               |
+------------------+--------------------------------------------------+
| Internal/        | EXTERNAL - Initial access via internet-facing    |
| External         | Apache vulnerability. The attacker scanned for   |
|                  | vulnerable services and exploited one.          |
+------------------+--------------------------------------------------+
| Resources        | LOW - Used a publicly available exploit for      |
|                  | Apache 2.4.29 RCE. No custom tools.              |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - Automated scanning and exploitation. No   |
|                  | lateral movement, no persistence beyond the      |
|                  | miner, no data theft. The attacker did not       |
|                  | explore the network.                             |
+------------------+--------------------------------------------------+
| Primary          | FINANCIAL GAIN (OPPORTUNISTIC) - The goal was    |
| Motivation       | to mine cryptocurrency using the hospital's      |
|                  | resources. This is low-effort financial gain.    |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - The crypto-miner on billing-srv-01 is     |
| Level            | exactly this scenario from Project 1x00 (Task 2).|
|                  | The attacker scanned for vulnerable services,   |
|                  | exploited a known vulnerability, and dropped a   |
|                  | miner. No targeting, no sophistication.          |
+------------------+--------------------------------------------------+


================================================================================
REPORT F: SHADOW IT DEVICE ON NETWORK
================================================================================

REPORT DESCRIPTION:
--------------------
During a network inventory scan, a security analyst discovered an unknown
device on the hospital network. The device was a Raspberry Pi located in a
maintenance closet. It had been running for 8 months with default credentials
(pi/raspberry). The device was connected to the main network and had network
scanning tools installed. No one in IT knew who set it up or what it was
doing. The device had SSH access logs showing connections from multiple
unknown IP addresses over the past 3 months.

+------------------+--------------------------------------------------+
| Actor Type       | SHADOW IT                                        |
+------------------+--------------------------------------------------+
| Internal/        | INTERNAL - The device was physically installed   |
| External         | inside the hospital by someone with internal      |
|                  | access. Unknown IP connections from outside are   |
|                  | suspicious but the device itself is internal.     |
+------------------+--------------------------------------------------+
| Resources        | LOW - A Raspberry Pi is inexpensive. The default  |
|                  | credentials indicate minimal effort.             |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - The device was configured poorly (default  |
|                  | credentials). No advanced evasion or             |
|                  | protection.                                       |
+------------------+--------------------------------------------------+
| Primary          | UNKNOWN / INCIDENTAL - The original purpose may   |
| Motivation       | have been legitimate (network monitoring) but     |
|                  | was forgotten. The unknown IP connections suggest |
|                  | it may have been co-opted by attackers.          |
+------------------+--------------------------------------------------+
| Confidence       | MEDIUM - The device is clearly shadow IT, but     |
| Level            | the original purpose and who is connecting from   |
|                  | unknown IPs is unclear. The default credentials   |
|                  | suggest it was either poorly managed or           |
|                  | intentionally set up as a backdoor.              |
+------------------+--------------------------------------------------+


================================================================================
REPORT G: AMBIGUOUS - PHISHING CAMPAIGN
================================================================================

REPORT DESCRIPTION:
--------------------
A hospital network experienced a phishing campaign targeting its finance
department. Employees received emails that appeared to be from the CFO,
requesting urgent wire transfers. The emails were well-written with proper
grammar and used the CFO's name and title. No malicious attachments were
found. The emails originated from a domain that was one character different
from the hospital's legitimate domain. No employee actually fell for the
phishing attempt. The campaign was reported to IT, who blocked the domain.

+------------------+--------------------------------------------------+
| Actor Type       | AMBIGUOUS - Multiple actor types could fit       |
+------------------+--------------------------------------------------+
| POSSIBILITY 1:   | ORGANIZED CRIME - Financial motivation.          |
| ORGANIZED CRIME  | Business Email Compromise (BEC) is a common       |
|                  | tactic used by organized crime groups to steal    |
|                  | money through wire fraud. They often use          |
|                  | typosquatting domains and impersonate executives. |
+------------------+--------------------------------------------------+
| POSSIBILITY 2:   | UNSKILLED / OPPORTUNISTIC - The attackers used    |
| UNSKILLED /      | a common BEC template. No sophisticated          |
| OPPORTUNISTIC    | malware or advanced techniques. The failure of   |
|                  | the campaign (no one fell for it) suggests low   |
|                  | sophistication.                                   |
+------------------+--------------------------------------------------+
| POSSIBILITY 3:   | INSIDER THREAT - Someone with knowledge of the   |
| INSIDER          | CFO's name, title, and email habits could be     |
|                  | conducting reconnaissance for a future attack.   |
+------------------+--------------------------------------------------+
| Internal/        | EXTERNAL - The emails originated from an         |
| External         | external domain (typosquatting). The attackers   |
|                  | had no internal access.                           |
+------------------+--------------------------------------------------+
| Resources        | LOW - A domain registration is inexpensive. The   |
|                  | emails were text-based with no attachments.      |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - Basic BEC phishing. No malware, no         |
|                  | exploitation, no attachments.                    |
+------------------+--------------------------------------------------+
| Primary          | FINANCIAL GAIN - The goal was to trick employees  |
| Motivation       | into transferring money to a fraudulent account.  |
+------------------+--------------------------------------------------+
| Confidence       | LOW - The evidence is insufficient to determine   |
| Level            | the actor type. Multiple types could have        |
|                  | conducted this phishing campaign.                 |
+------------------+--------------------------------------------------+

+----------------------------------------------------------------------------+
| EVIDENCE TO DISTINGUISH BETWEEN POSSIBILITIES:                             |
|                                                                             |
| To distinguish between the possibilities, the following evidence would    |
| help:                                                                       |
|                                                                             |
| 1. Was this part of a broader campaign targeting similar hospitals ?       |
|    - If yes, suggests organized crime (scale).                             |
|                                                                             |
| 2. Did the attackers follow up with more sophisticated techniques ?        |
|    - If yes, suggests higher sophistication (organized crime).            |
|                                                                             |
| 3. Were there signs of reconnaissance on specific employees beforehand ?  |
|    - If yes, suggests targeted reconnaissance (organized crime or          |
|      insider).                                                              |
|                                                                             |
| 4. Did the attackers attempt other entry methods simultaneously ?          |
|    - If yes, suggests a coordinated attack (organized crime).             |
|                                                                             |
| 5. Were the emails sent from a compromised internal account ?              |
|    - If yes, suggests insider or prior compromise.                         |
|                                                                             |
| 6. Is this part of a pattern of similar BEC attacks in the sector ?        |
|    - If yes, suggests organized crime sector targeting.                    |
+----------------------------------------------------------------------------+


================================================================================
REPORT H: DORMANT ACCOUNT WITH ADMIN PRIVILEGES
================================================================================

REPORT DESCRIPTION:
--------------------
A hospital's IT team discovered that an old service account with Domain Admin
privileges had been active for 14 months after the project it was created for
had ended. The account password had not been changed in 24 months. Audit logs
showed login attempts from 3 different IP addresses outside the hospital's
network over the past 2 months. Each attempt was unsuccessful (incorrect
password). The account was immediately disabled.

+------------------+--------------------------------------------------+
| Actor Type       | INSIDER THREAT (NEGLIGENT) / POTENTIAL ATTACKER  |
+------------------+--------------------------------------------------+
| Internal/        | INTERNAL - The account existed inside the        |
| External         | organization. External IP addresses attempted    |
|                  | to access it from outside.                       |
+------------------+--------------------------------------------------+
| Resources        | LOW - No special tools were used. The attackers  |
|                  | attempted brute-force or password guessing.     |
+------------------+--------------------------------------------------+
| Sophistication   | LOW - Account discovery and password guessing    |
|                  | or brute force. No exploitation of                |
|                  | vulnerabilities.                                  |
+------------------+--------------------------------------------------+
| Primary          | OPPORTUNISTIC / POTENTIAL FINANCIAL GAIN -       |
| Motivation       | Attackers scanning for weak passwords and        |
|                  | privileged accounts. They had not yet gained      |
|                  | access, so motivation is inferred from the       |
|                  | target (Domain Admin).                            |
+------------------+--------------------------------------------------+
| Confidence       | HIGH - The dormant account with admin privileges  |
| Level            | is a classic case of insider negligence. The      |
|                  | external login attempts indicate attackers       |
|                  | discovered the account and were trying to gain   |
|                  | access. The organization's lack of credential     |
|                  | management is the primary vulnerability.         |
+------------------+--------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| Report   | Actor Type          | Internal/      | Resources   | Sophistication  | Primary          | Confidence       |
|          |                     | External       |             |                 | Motivation       | Level            |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| A        | Organized Crime     | External        | HIGH        | MEDIUM-HIGH     | Financial Gain   | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| B        | Nation-State APT    | External        | HIGH        | VERY HIGH       | Espionage        | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| C        | Insider (Malicious) | BOTH            | LOW         | LOW             | Revenge/Gain    | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| D        | Hacktivist          | External        | LOW         | LOW             | Political       | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| E        | Unskilled/Opportun. | External        | LOW         | LOW             | Financial Gain   | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| F        | Shadow IT           | Internal        | LOW         | LOW             | Unknown          | MEDIUM           |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| G        | AMBIGUOUS           | External        | LOW         | LOW             | Financial Gain   | LOW              |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+
| H        | Insider (Negligent) | Internal        | LOW         | LOW             | Opportunistic    | HIGH             |
+----------+---------------------+-----------------+-------------+-----------------+------------------+------------------+


================================================================================
KEY FINDINGS
================================================================================

1. Most reports (6 of 8) can be classified with HIGH confidence based on
   observed behavior alone. This demonstrates that behavior patterns are
   often sufficient to infer actor type.

2. Report G (Phishing BEC) is the only genuinely ambiguous case. Multiple
   actor types could have conducted this attack. Additional evidence is
   needed for confident classification.

3. Report F (Shadow IT) is also ambiguous, but the internal nature and
   physical presence make it clearly shadow IT even if the purpose is
   unknown.

4. The following attributes are the strongest indicators of actor type:
   - Motivation (financial vs ideological vs strategic)
   - Sophistication (custom tools vs public exploits)
   - Targeting (selective vs opportunistic)
   - Dwell time (short vs prolonged)
   - Follow-on actions (data theft vs encryption vs defacement)


================================================================================
REFERENCES
================================================================================

- HC3 Analyst Note: "Threat Actor Categories Targeting Healthcare"
  (marcus-intelligence-dossier.txt - File 2)
- Security+ Threat Actor Framework
- NIST SP 800-30: Threat source characteristics
- Project 1x00 - Task 2: The Symptom Trap (billing-srv-01 crypto-miner)


================================================================================
END OF THREAT ACTOR TAXONOMY REPORT
================================================================================
