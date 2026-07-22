================================================================================
                    PRIORITY MATRIX - MEDDEFENSE HEALTH SYSTEMS
                    Task 20: The Priority Matrix
================================================================================

Exercise: Task 20 - The Priority Matrix
Analyst: shamshed rajput
Date: 22/07/2026
Objective: Produce the definitive vulnerability remediation timeline organized
          by urgency.

Source: meddefense-vulnerability-scan.txt
Cross-References: T16 (Noise Filter), T17 (CVSS Contextualizer), T19 (Remediation Map)


================================================================================
HORIZON 1: IMMEDIATE (24-48 HOURS)
================================================================================
Criteria: Weaponized exploit + critical asset + active threat

+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| Finding  | Description      | Remediation Action                     | Owner                | Cost             |
| ID       |                  |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 004      | Windows XP EOL   | Isolate MRI on dedicated VLAN. Apply   | IT + Security        | $10,000          |
|          | on MRI with      | host firewall + app whitelisting.      |                      |                  |
|          | weaponized       | (Compensating controls)                |                      |                  |
|          | exploits         |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 031      | Ghostcat on      | Patch Tomcat to 9.0.43+ OR disable     | IT + Vendor         | $2,000           |
|          | ehr-srv-01       | AJP connector. (Patch)                 | (MedTech)           |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 003      | PostgreSQL       | Restrict pg_hba.conf to ehr-srv-01     | IT (DBA)             | $500             |
|          | unrestricted on  | only. (Configuration Change)           |                      |                  |
|          | ehr-db-01        |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 010      | BD Alaris pumps  | Change default credentials on ALL      | Biomedical          | $1,000           |
|          | with admin/admin | 7 pumps. (Configuration Change)        | Engineering + IT    |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
|          |                  | HORIZON 1 TOTAL                         |                      | $13,500          |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+


================================================================================
HORIZON 2: SHORT-TERM (7 DAYS)
================================================================================
Criteria: Critical/High CVE with PoC + important asset

+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| Finding  | Description      | Remediation Action                     | Owner                | Cost             |
| ID       |                  |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 001      | Apache RCE       | Patch Apache to 2.4.52+. (Patch)       | IT + Vendor          | $3,000           |
|          | (CVE-2021-44790) |                                        |                      |                  |
|          | on billing-      |                                        |                      |                  |
|          | srv-01           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 002      | Apache PrivEsc   | Patch Apache to 2.4.39+                | IT + Vendor          | $0               |
|          | (CVE-2019-0211)  | (Combined with Finding 001)            |                      | (combined)       |
|          | on billing-      |                                        |                      |                  |
|          | srv-01           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 006      | MySQL            | Bind MySQL to localhost only.          | IT (DBA)             | $500             |
|          | unrestricted on  | (Configuration Change)                 |                      |                  |
|          | billing-srv-01   |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 007      | LDAP signing not | Enable LDAP signing enforcement on     | IT (AD Admin)        | $1,000           |
|          | required on      | ad-dc-01. (Configuration Change)       |                      |                  |
|          | ad-dc-01         |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 009      | SSH password     | Disable SSH password auth and enforce  | IT (Sysadmin)        | $500             |
|          | auth on billing- | key-only. (Configuration Change)       |                      |                  |
|          | srv-01           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 011      | Ubuntu 18.04 EOL | Activate Ubuntu ESM. (Patch)           | IT (Sysadmin)        | $2,500           |
|          | on billing-      |                                        |                      | (annual)         |
|          | srv-01           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 026      | Kernel outdated  | Apply kernel updates + ESM.            | IT (Sysadmin)        | $0               |
|          | on billing-      | (Patch - combined with 011)            |                      | (combined)       |
|          | srv-01           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 015      | NAS management   | Restrict NAS management to admin IPs.  | IT (Backup Admin)    | $1,000           |
|          | accessible       | (Configuration Change)                 |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
|          |                  | HORIZON 2 TOTAL                         |                      | $8,500           |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+


================================================================================
HORIZON 3: MEDIUM-TERM (30 DAYS)
================================================================================
Criteria: High/Medium CVE or significant misconfiguration

+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| Finding  | Description      | Remediation Action                     | Owner                | Cost             |
| ID       |                  |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 005      | TLS 1.0 support  | Disable TLS 1.0/1.1 on web-srv-01.     | IT (Web Admin)       | $500             |
|          | on patient       | (Configuration Change)                 |                      |                  |
|          | portal           |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 012      | Missing HTTP     | Configure security headers (HSTS, CSP, | IT (Web Admin)       | $500             |
|          | headers on       | X-Frame-Options). (Configuration)      |                      |                  |
|          | patient portal   |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 013      | SSL certificate  | Renew Let's Encrypt certificate.       | IT (Web Admin)       | $0               |
|          | expiring soon    | (Configuration Change)                 |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 016      | Medical device   | Isolate Philips monitors on IoT VLAN.  | IT + Biomedical     | $5,000           |
|          | web interfaces   | (Compensating Control)                 | Engineering         |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 018      | Weak Kerberos    | Disable DES/RC4 encryption types.      | IT (AD Admin)        | $1,000           |
|          | encryption on    | (Configuration Change)                 |                      |                  |
|          | ad-dc-01/02      |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 019      | RDP enabled on   | Restrict RDP to authorized admins      | IT (Sysadmin)        | $500             |
|          | workstations     | only. (Configuration Change)           |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 021      | HTTP TRACE       | Disable HTTP TRACE method.             | IT (Web Admin)       | $100             |
|          | enabled          | (Configuration Change)                 |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 023      | USB unrestricted | Enforce USB restriction GPO on all     | IT (AD Admin)        | $500             |
|          | on workstations  | workstations. (Configuration Change)   |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 024      | DICOM without    | Enable TLS encryption for DICOM.       | IT + Vendor         | $2,000           |
|          | encryption on    | (Configuration Change)                 | (PACS)              |                  |
|          | pacs-srv-01      |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 025      | DNS zone         | Restrict zone transfers to authorized  | IT (AD Admin)        | $100             |
|          | transfer on      | DNS servers only. (Configuration)      |                      |                  |
|          | ad-dc-01         |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 028      | Shadow IT        | Investigate and document unknown       | IT + Security        | $1,000           |
|          | (Unknown Linux)  | Linux device. (Investigate)            |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 029      | Shadow IT        | Investigate and document unknown       | IT + Security        | $1,000           |
|          | (Grafana device) | Linux device + patch Grafana.          |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
|          |                  | HORIZON 3 TOTAL                         |                      | $12,200          |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+


================================================================================
HORIZON 4: LONG-TERM (90 DAYS)
================================================================================
Criteria: Architecture changes, EOL migrations, systemic fixes

+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| Finding  | Description      | Remediation Action                     | Owner                | Cost             |
| ID       |                  |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 008      | Windows Server   | Migrate print server to Windows Server | IT (Sysadmin)        | $3,000           |
|          | 2012 R2 EOL on   | 2022 OR apply ESU. (Migration)         |                      |                  |
|          | print-srv-01     |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 014      | Consumer-grade   | Replace Netgear router with enterprise | IT (Network)         | $5,000           |
|          | router at        | firewall at Westside. (Architecture)   |                      |                  |
|          | Westside         |                                        |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| 004      | MRI Windows XP   | Evaluate virtualization or replacement | IT + Radiology       | $50,000+         |
|          | (continued)      | of MRI control workstation.            | + Vendor            | (if replacement) |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
| GAP-003  | Flat Network     | Implement network segmentation across  | IT (Network)         | $15,000          |
|          | (Overall)        | entire infrastructure. (Architecture)  |                      |                  |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+
|          |                  | HORIZON 4 TOTAL                         |                      | $73,000+         |
+----------+------------------+----------------------------------------+------------------------------------------+------------------+


================================================================================
BUDGET SUMMARY
================================================================================

+----------------------------------------------------------------------------+
| BUDGET SUMMARY                                                             |
|                                                                             |
| TOTAL ESTIMATED COST OF REMEDIATIONS:                                      |
|                                                                             |
| Horizon 1 (Immediate - 48h):                    $13,500                    |
| Horizon 2 (Short-term - 7 days):               $8,500                     |
| Horizon 3 (Medium-term - 30 days):             $12,200                    |
| Horizon 4 (Long-term - 90 days):               $73,000+                   |
|                                                                             |
| TOTAL:                                         $107,200+                   |
|                                                                             |
| ANNUAL SECURITY BUDGET (1x00):                  $120,000                   |
|                                                                             |
| BUDGET REMAINING:                                $12,800                    |
|                                                                             |
| BUDGET ANALYSIS:                                                           |
|                                                                             |
| The total estimated cost of all remediations ($107,200+) is within the     |
| $120,000 annual security budget. However, the Horizon 4 MRI replacement    |
| cost ($50,000) is a CAPITAL EXPENDITURE, not operational expense.         |
|                                                                             |
| RECOMMENDED BUDGET ALLOCATION:                                             |
|                                                                             |
| 1. Horizon 1 + 2 + 3 (OPEX):                    $34,200                    |
| 2. Horizon 4 - Network Segmentation:            $15,000                    |
| 3. Horizon 4 - Westside Firewall:               $5,000                     |
| 4. Horizon 4 - Print Server Migration:          $3,000                     |
|                                                                             |
| Subtotal (Deferred OpEx):                       $57,200                    |
|                                                                             |
| MRI Replacement (CapEx):                        $50,000 (requires         |
|                                                  capital budget approval) |
|                                                                             |
| DEFERRED ITEMS:                                                             |
|                                                                             |
| - MRI Replacement ($50,000) must be deferred to a separate capital        |
|   budget request. This is not an operational expense.                     |
|                                                                             |
| - Network Segmentation ($15,000) can be phased over two quarters to       |
|   spread the cost.                                                         |
|                                                                             |
| - If the MRI is virtualized instead of replaced, the cost drops to        |
|   $5,000-$10,000, making the total budget more manageable.               |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+------------------+------------------+------------------+
| Horizon  | Timeline         | Findings Count   | Total Cost       | Cumulative       |
+----------+------------------+------------------+------------------+------------------+
| Immediate| 24-48 hours      | 4                | $13,500          | $13,500          |
+----------+------------------+------------------+------------------+------------------+
| Short-   | 7 days           | 8                | $8,500           | $22,000          |
| term     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| Medium-  | 30 days          | 12               | $12,200          | $34,200          |
| term     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+
| Long-    | 90 days          | 4                | $73,000+         | $107,200+        |
| term     |                  |                  |                  |                  |
+----------+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-vulnerability-scan.txt
- Noise Filter (T16)
- CVSS Contextualizer (T17)
- Remediation Map (T19)
- Security Budget (1x00)


================================================================================
END OF PRIORITY MATRIX REPORT
================================================================================

