================================================================================
                    KEY MANAGEMENT PLAN - MEDDEFENSE HEALTH SYSTEMS
                    Task 14: Hardware Security and Key Management
================================================================================

Exercise: Task 14 - Hardware Security and Key Management
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Evaluate TPM, HSM, Secure Enclave, and KMS technologies, design a
          key management strategy for MedDefense, and justify the HSM decision
          using ALE from the Risk Register.

Sources: NIST SP 800-175B, Sec+ 1.4, 1x03 Risk Register & ALE,
         T13 Encryption Level Recommendations, T12 LUKS Implementation,
         T10 TLS Configuration


================================================================================
PART 1: HARDWARE SECURITY TECHNOLOGY COMPARISON
================================================================================

+------------------+------------------+------------------+------------------+------------------------------------------+
| Technology       | What It Is       | What It Protects | Typical Cost     | Typical Deployment                       |
+------------------+------------------+------------------+------------------+------------------------------------------+
| TPM (Trusted     | A dedicated,     | Platform         | Effectively      | Embedded on server/endpoint              |
| Platform Module) | tamper-resistant | integrity        | zero. Integrated | motherboards. One TPM per                |
|                  | microcontroller  | (Secure Boot),   | into all modern  | physical machine. Used to                |
|                  | integrated on    | system-level     | enterprise-grade | bind/seal disk encryption                |
|                  | the motherboard. | encryption keys  | hardware by      | keys to the hardware state.              |
|                  | A passive, low-  | (BitLocker,      | default.         |                                          |
|                  | cost chip for    | LUKS binding),   |                  |                                          |
|                  | platform trust   | platform identity|                  |                                          |
|                  | and key sealing. |                  |                  |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+
| HSM (Hardware    | A dedicated,     | Cryptographic    | High for on-prem | Network-attached appliance               |
| Security Module) | high-assurance   | private keys at  | ($20,000+ per    | in a data center, or a                   |
|                  | hardware         | the highest      | appliance).      | virtual/cloud service                    |
|                  | appliance or     | level of         | Cloud HSM-as-a-  | (e.g., AWS CloudHSM,                     |
|                  | plug-in card     | assurance.       | Service is       | Azure Dedicated HSM).                    |
|                  | for key          | Protects against | accessible:      | One HSM can serve                        |
|                  | lifecycle        | logical and      | $1-3/key/month.  | thousands of workloads.                  |
|                  | management.      | physical         |                  |                                          |
|                  | Private keys     | extraction.      |                  |                                          |
|                  | never leave the  |                  |                  |                                          |
|                  | HSM in plaintext.|                  |                  |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+
| Secure Enclave   | An isolated,     | Confidentiality  | Zero hardware    | A feature of the main CPU                |
| (TEE - Trusted   | hardware-        | and integrity of | cost (feature    | die (Intel SGX, AMD SEV,                 |
| Execution        | enforced area    | code and data    | of modern CPUs). | ARM TrustZone). Deployed                 |
| Environment)     | within a CPU.    | IN USE. Shields  | High software    | via SDKs. The application                |
|                  | A "black box"    | a running        | engineering cost | is refactored to run the                 |
|                  | for processing   | application from | to refactor.     | sensitive portion inside                 |
|                  | sensitive data.  | the host OS,     |                  | the enclave.                             |
|                  |                  | hypervisor, and  |                  |                                          |
|                  |                  | physical memory  |                  |                                          |
|                  |                  | probes.          |                  |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+
| KMS (Software    | A centralized,   | Convenience,     | Low to mid-range.| A software service or                    |
| Key Management   | multi-tenant     | policy           | Cloud providers  | virtual appliance, either                |
| Service)         | software service | enforcement,     | charge per key   | on-premises or as a                      |
|                  | that manages     | access control,  | (~$1/key/month)  | managed cloud service                    |
|                  | the lifecycle    | and audit        | + API call fees. | (e.g., AWS KMS, Azure                    |
|                  | of keys via a    | logging for keys | Open-source      | Key Vault). It's the                     |
|                  | unified API.     | across an org.   | versions are     | central control plane for                |
|                  | Relies on        | Protects against | free but require | encryption operations.                   |
|                  | envelope         | mismanagement,   | self-hosting.    |                                          |
|                  | encryption.      | not physical     |                  |                                          |
|                  |                  | extraction.      |                  |                                          |
+------------------+------------------+------------------+------------------+------------------------------------------+


================================================================================
PART 2: MEDDEFENSE KEY MANAGEMENT PLAN
================================================================================

This plan maps every encryption key from tasks 10, 12, and 13 to a specific
storage location, access control policy, rotation procedure, and recovery
strategy, aligned with the 1x03 governance structure.

KEY 1: DATABASE ENCRYPTION MASTER KEY (T13 Recommendation: AES-256-GCM)
-------------------------------------------------------------------------
+------------------+--------------------------------------------------+
| Storage          | AWS KMS with HSM backing, or a dedicated on-prem  |
| Location         | HSM. NEVER stored on the database server (ehr-   |
|                  | db-01) or in a config file.                      |
+------------------+--------------------------------------------------+
| Access Control   | Role: KMS Administrator (Security Team). The     |
|                  | PostgreSQL service account on ehr-db-01 has      |
|                  | `decrypt` permission via the KMS API but can     |
|                  | NEVER extract the raw master key material.       |
+------------------+--------------------------------------------------+
| Rotation         | Frequency: Annually, or immediately upon         |
|                  | security incident.                               |
|                  | Process: Automated via KMS. A new master key     |
|                  | version is created. All Data Encryption Keys     |
|                  | (DEKs) are re-wrapped with the new master key    |
|                  | version without re-encrypting the underlying data.|
+------------------+--------------------------------------------------+
| Compromise       | Immediately revoke the master key in KMS, which  |
| Procedure        | cryptographically invalidates all DEKs encrypted |
|                  | under it. Initiate incident response (Link to    |
|                  | Risk R-004: Unauthorized Database Access).       |
|                  | Rotate all DEKs and re-encrypt sensitive fields. |
+------------------+--------------------------------------------------+
| Loss Procedure   | Not applicable. The KMS is a highly durable,     |
|                  | managed service. The key is stored redundantly   |
|                  | within the HSM service boundary.                 |
+------------------+--------------------------------------------------+


KEY 2: BACKUP STORAGE ENCRYPTION KEY (T12: LUKS Volume Key on NAS-01)
-----------------------------------------------------------------------
+------------------+--------------------------------------------------+
| Storage          | Wrapped by a TPM on the NAS-01 device, or        |
| Location         | unlocked at boot via a network-based Tang server |
|                  | using Clevis. The raw key is not stored in a     |
|                  | configuration file.                              |
+------------------+--------------------------------------------------+
| Access Control   | Role: Server Administrator (initiates reboot).   |
|                  | No human operator knows the raw key material.    |
|                  | Access to the Tang server is restricted to the   |
|                  | NAS's IP via firewall rules.                     |
+------------------+--------------------------------------------------+
| Rotation         | Frequency: Annually, requiring volume            |
|                  | re-encryption during a maintenance window.       |
|                  | Process: Add a new LUKS key slot with the new    |
|                  | key, then remove the old key slot after          |
|                  | successful re-encryption (`cryptsetup-reencrypt`).|
+------------------+--------------------------------------------------+
| Compromise       | Physically destroy or cryptographically wipe     |
| Procedure        | the NAS-01 drives. All existing backups are      |
|                  | considered tainted. Initiate Disaster Recovery   |
|                  | from the last known good, offsite, offline       |
|                  | backup (stored with a different key).            |
+------------------+--------------------------------------------------+
| Loss Procedure   | Recoverable via a key escrow file (a Tang server |
|                  | or a secure offline USB key). The escrow media   |
|                  | is protected with a strong passphrase and stored |
|                  | in a physical safe.                              |
|                  | Access to Safe: Security Director and CISO       |
|                  | (dual control).                                  |
+------------------+--------------------------------------------------+


KEY 3: PATIENT PORTAL TLS PRIVATE KEY (T10: TLS 1.3 Certificate)
------------------------------------------------------------------
+------------------+--------------------------------------------------+
| Storage          | On the patient-portal-srv-01 web server, stored  |
| Location         | with OS-level file permissions (e.g., chmod 400  |
|                  | on Linux). Ideally, the private key is stored in |
|                  | a TPM or software keystore if available.         |
+------------------+--------------------------------------------------+
| Access Control   | Role: Application Administrator. The web service |
|                  | account (e.g., nginx) has read-only access.      |
+------------------+--------------------------------------------------+
| Rotation         | Frequency: Every 90 days, aligned with the       |
|                  | Let's Encrypt certificate lifecycle.             |
|                  | Process: Fully automated via certbot renewal     |
|                  | hooks. A new private key is generated and the    |
|                  | old one is archived upon each renewal.           |
+------------------+--------------------------------------------------+
| Compromise       | Immediately revoke the certificate via the       |
| Procedure        | Let's Encrypt ACME account or the CA portal.     |
|                  | This invalidates the certificate and triggers    |
|                  | OCSP failure. Replace with a new key pair.       |
|                  | Initiate incident response (Link to Risk R-007:  |
|                  | Patient Portal Data Breach).                     |
+------------------+--------------------------------------------------+
| Loss Procedure   | Trivial. Generate a new 256-bit ECDSA private    |
|                  | key and request a new certificate from the CA.   |
|                  | The old certificate becomes invalid.             |
+------------------+--------------------------------------------------+


KEY 4: VPN TUNNEL KEYS (IPsec Pre-Shared Keys or Private Keys)
----------------------------------------------------------------
+------------------+--------------------------------------------------+
| Storage          | On the VPN concentrator/firewall at each of the  |
| Location         | three MedDefense sites.                          |
+------------------+--------------------------------------------------+
| Access Control   | Role: Network Security Engineer. Access to the   |
|                  | firewall management interface is via a secure,   |
|                  | logged jump host with MFA.                       |
+------------------+--------------------------------------------------+
| Rotation         | Frequency: Every 6-12 months.                    |
|                  | Process: Manual, coordinated change between all  |
|                  | three sites. Requires a defined maintenance      |
|                  | window and out-of-band verification.             |
+------------------+--------------------------------------------------+
| Compromise       | Immediately rotate the key. If a PSK, the new    |
| Procedure        | PSK must be deployed to all three sites          |
|                  | simultaneously. Treat as a critical network      |
|                  | security incident (Link to Risk R-009: Inter-    |
|                  | site Network Sniffing).                          |
+------------------+--------------------------------------------------+
| Loss Procedure   | Generate a new key on the primary VPN appliance  |
|                  | and securely transmit it to the other two sites  |
|                  | via an out-of-band method (e.g., phone call with |
|                  | verbal verification, or encrypted email).        |
+------------------+--------------------------------------------------+


================================================================================
PART 3: THE HSM DECISION - COST-BENEFIT ANALYSIS
================================================================================

DECISION QUESTION:
Should MedDefense invest in an HSM to protect the database encryption master
key, or accept the risk of a software-based key compromise?

1. THE RISK TO MITIGATE (from 1x03 Risk Register)
--------------------------------------------------
+------------------+--------------------------------------------------+
| Risk ID          | R-004: Unauthorized Patient Database Access       |
+------------------+--------------------------------------------------+
| Threat           | Attacker gains root-level access to the database  |
|                  | server (ehr-db-01) and extracts the encryption    |
|                  | master key from a configuration file, environment |
|                  | variable, or software KMS on the same host.       |
+------------------+--------------------------------------------------+
| Vulnerability    | The master encryption key is stored in software   |
|                  | on the same server as the encrypted data.         |
|                  | Encryption without secure key storage is merely   |
|                  | obfuscation.                                      |
+------------------+--------------------------------------------------+
| Impact           | Catastrophic. Full breach of 50,000 patient       |
|                  | records. Triggers mandatory HIPAA breach          |
|                  | notification, OCR investigation, and class-action |
|                  | lawsuits.                                         |
+------------------+--------------------------------------------------+
| ALE Calculation  | Average cost per breached healthcare record       |
| (from 1x03)      | (IBM Cost of a Data Breach Report): $499.         |
|                  | Total breach cost: 50,000 records * $499/record   |
|                  | = $24,950,000.                                    |
|                  | Likelihood: Once every 10 years (based on         |
|                  | 1x03 assessment of MedDefense's threat landscape).|
|                  | Annualized Loss Expectancy (ALE):                 |
|                  | $24,950,000 / 10 years = $2,495,000 per year.     |
+------------------+--------------------------------------------------+


2. THE MITIGATION COST (Cloud HSM-as-a-Service)
--------------------------------------------------
+------------------+--------------------------------------------------+
| Solution         | Cloud-based HSM-as-a-Service (e.g., AWS           |
|                  | CloudHSM or Azure Dedicated HSM).                 |
+------------------+--------------------------------------------------+
| Cost Model       | ~$1.50 per key per month. MedDefense requires     |
|                  | one master key for the patient database.          |
+------------------+--------------------------------------------------+
| Total Annual Cost| $1.50/key/month * 1 key * 12 months = $18/year.   |
+------------------+--------------------------------------------------+
| Risk Reduction   | An attacker with root access cannot extract the   |
|                  | master key. They can only call the HSM's API to   |
|                  | decrypt data, which is auditable, rate-limited,   |
|                  | and revocable. This changes the breach scenario   |
|                  | from "mass data exfiltration" to "potentially a   |
|                  | few queries before detection and key revocation." |
|                  | The residual ALE is a fraction of the original.   |
+------------------+--------------------------------------------------+


3. RETURN ON SECURITY INVESTMENT (ROSI)
-----------------------------------------
+------------------+--------------------------------------------------+
| Annual Risk (ALE)| $2,495,000                                       |
| Before Mitigation|                                                  |
+------------------+--------------------------------------------------+
| Annual Cost of   | $18                                              |
| Mitigation       |                                                  |
+------------------+--------------------------------------------------+
| ROSI             | ALE Before - ALE After - Mitigation Cost         |
|                  | = $2,495,000 - (Negligible Residual Risk) - $18  |
|                  | = ~$2,494,982 in annual risk reduction.          |
+------------------+--------------------------------------------------+


4. JUSTIFICATION & DECISION
-----------------------------
The investment is unequivocally justified and recommended. This is not a
borderline cost-benefit analysis; it is a clear imperative for a healthcare
organization handling patient data.

- COLOSSAL ROI: The cost of the HSM ($18/year) is vanishingly small compared
  to the ALE ($2.5M/year). The return on security investment is over 138,000x.

- ELIMINATES THE SINGLE POINT OF FAILURE: The HSM directly addresses the fatal
  weakness identified in the 2023 Thales report, where "keys were mismanaged."
  It moves MedDefense from a "checkbox" encryption posture to a high-assurance,
  state-of-the-art key protection posture. An attacker compromising the database
  server cannot walk away with the database and the key.

- HIPAA COMPLIANCE & DUE DILIGENCE: Storing an encryption key on the same
  server as the encrypted data is widely considered negligent for PHI. Using
  an HSM provides a demonstrable, auditable control that meets HIPAA's
  "addressable" encryption implementation specifications to a high standard.

- DECISION: Deploy a cloud-based HSM to generate, store, and manage the
  patient database encryption master key. The key material must never exist
  in plaintext outside the HSM boundary. This is the foundational security
  element upon which the entire database encryption strategy rests.


================================================================================
REFERENCES
================================================================================

- NIST SP 800-175B: Guideline for Using Cryptographic Standards
- Sec+ 1.4: Hardware Security (TPM, HSM, Secure Enclave)
- 1x03 Risk Register: Risk R-004 (Unauthorized DB Access) and ALE Calculations
- T13 Encryption Levels Report: Database Encryption Decision
- T12 LUKS Implementation: NAS Backup Encryption
- T10 TLS Configuration: Patient Portal Certificate
- IBM Cost of a Data Breach Report (Healthcare Benchmark)


================================================================================
END OF KEY MANAGEMENT PLAN REPORT
================================================================================
