Introduction

    "Attackers don't hack in. They log in." — CISA Director Jen Easterly, 2023

Linux is hardened. billing-srv-01, web-srv-01 and log-srv-01 are locked down, monitored by auditd and compliant with the CIS Benchmark to 84 points. That was the easy part. Because Linux runs 3 servers at MedDefense. Windows runs everything else.

280 workstations across 3 sites. 2 domain controllers managing authentication for 2,000 staff. Active Directory controlling every login, every password policy, every security setting across the entire organization. Group Policy Objects that have never been reviewed, some dating back to when Marcus Webb was still here. Sysmon nowhere to be found. PowerShell Script Block Logging disabled. AppLocker non-existent. The Windows Firewall turned off on 2 of 3 profiles. And the Crimson Tide advisory (1x05) explicitly documented that in all 5 hospital breaches, the attacker used Group Policy to deploy ransomware across every Windows endpoint simultaneously.

Windows is where the attacker lives after initial access. Active Directory is the crown jewel. If the attacker owns AD, they own everything: every workstation, every server, every user, every password. The 5 hospitals hit by Crimson Tide all had one thing in common: weak AD configurations that the attacker exploited for lateral movement, privilege escalation and ransomware deployment.

This project teaches you to think in Windows. Not as a Windows administrator, but as a security engineer who uses Active Directory, Group Policy, Sysmon and PowerShell as defensive weapons. Every script you write will be in PowerShell. Every configuration will be deployed through GPO. Every detection capability will generate Windows Events that become the telemetry you export and analyze as an analyst in Module 3.
Why this matters

Linux hardening protects 3 servers. Windows hardening protects 280 workstations and the domain controllers that authenticate every human in the organization. The blast radius of a Windows misconfiguration is not one server. It is the entire enterprise. When the Crimson Tide attacker created a malicious GPO on the domain controller, that GPO executed on every Windows machine in the domain within 90 minutes. One misconfiguration. 280 compromised endpoints.
Context

Week seven at MedDefense. Wednesday morning.

James Chen walks in with a printed screenshot of the Crimson Tide advisory, Phase 6 highlighted in yellow:

"Deployment method: Group Policy Object pushed from compromised Domain Controller. Payload: Modified BlackSuit variant. Encryption: AES-256-CBC with RSA-2048 wrapped key. Targets: All Windows systems."

He sets it on your desk.

"The attacker used GPO to deploy ransomware because GPO is how Windows pushes changes to every machine. If we do not lock down our GPOs, harden our AD, deploy Sysmon and monitor our domain controllers, the same GPO mechanism that we use to enforce security will be used against us to deploy the next payload."

Sarah Park adds: "We have a Windows Server 2022 domain controller and the MedDefense domain is live. You have full Domain Admin access. The domain has 14 user accounts across 3 departments, 5 service accounts, and zero security hardening. The password policy minimum is 7 characters. There is no lockout. RC4 Kerberos is enabled. SMBv1 is enabled. I could go on, but I think you get the picture."

James concludes: "I need this domain locked down. GPO hardening, Sysmon deployed, audit policies configured, AppLocker in place, Windows Firewall enforced, service accounts audited. And I need a PowerShell script that validates all of it, because I am going to run that script every week."
Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

Active Directory Security

    How Active Directory structures authentication and authorization (DCs, OUs, GPOs, groups)

    How Group Policy Objects are applied (LSDOU order), how to diagnose GPO conflicts, and how to deploy security settings via GPO

    The critical Windows Event IDs for security monitoring (4624, 4625, 4648, 4688, 4720, 4726, 4732, 1102) and what each reveals about an attacker's behavior

Windows Hardening

    How to harden password policy, account lockout and authentication protocols via GPO

    How to configure Advanced Audit Policies for security-relevant event generation

    How to deploy Sysmon with a detection-optimized configuration and tune it for specific threats

    How to configure AppLocker for application allow-listing

    How to harden SMB, RDP, Windows Firewall and service accounts

Endpoint Detection

    How Sysmon works, what each critical Event ID captures and how to write custom detection rules

    How PowerShell Script Block Logging and Constrained Language Mode reduce the attacker's toolkit

    How Windows Firewall rules enforce network segmentation at the endpoint level

Resources

Read or Watch:

Active Directory Security

    Microsoft: Active Directory Security Best Practices -- Official hardening guide.

    CISA: Detecting and Mitigating Active Directory Compromises -- Real-world AD attack patterns.

Sysmon

    Microsoft Sysinternals: Sysmon -- Official documentation and download.

    SwiftOnSecurity Sysmon Config -- The reference detection configuration.

Windows Hardening

    CIS Benchmark for Windows Server 2022 -- Download the PDF.

    Microsoft Security Baselines -- Microsoft's own hardening recommendations.

Man or Help:

    Get-Help Set-ADDefaultDomainPasswordPolicy

    Get-Help New-GPO

    Get-Help Set-GPRegistryValue

    Get-Help Get-WinEvent

    Get-Help New-NetFirewallRule

Requirements
General

    A README.md file, at the root of the folder of the project, is mandatory.

    All your files should end with a new line.

PowerShell Scripting

    All your scripts must have the .ps1 extension.

    All scripts must include a comment header with: script name, purpose, author and date.

    All scripts must use Set-StrictMode -Version Latest and $ErrorActionPreference = "Stop" for robust error handling.

Lab Environment
Parameter 	Value
Lab Name 	DC01
Operating System 	Windows Server 2022
Domain 	meddefense.local
Username 	analyst
Password 	Analyst2026!
Privileges 	Domain Admin
Access Method 	Direct VM login
Tools Used 	PowerShell and Windows GUI tools
Login Details

Use the following credentials to log in to the Windows Server 2022 VM:

Domain: meddefense.local
Username: analyst
Password: Analyst2026!

All lab work is performed directly on the DC01 VM using PowerShell and GUI-based administrative tools.


## SYSTEM HARDENING

### 1. CIS Benchmark
**FR :** Un CIS Benchmark est un document de référence qui liste les configurations de sécurité recommandées pour un système spécifique (Ubuntu, Windows Server, etc.), organisé par sections numérotées. L'appliquer avec jugement professionnel signifie choisir les règles qui bloquent les menaces réelles (Crimson Tide) et documenter celles qu'on ignore, plutôt que d'appliquer aveuglément les 800 pages.

**EN :** A CIS Benchmark is a reference document listing recommended security configurations for a specific system (Ubuntu, Windows Server, etc.), organized by numbered sections. Applying it with professional judgment means selecting rules that block real threats (Crimson Tide) and documenting skipped ones, rather than blindly applying all 800 pages.

---

### 2. SSH Hardening
**FR :** Durcir SSH consiste à désactiver l'authentification par mot de passe (clé SSH obligatoire), interdire la connexion directe en root, limiter les utilisateurs autorisés, couper les sessions inactives après 10 minutes, et forcer le protocole SSH version 2. Cela bloque le mouvement latéral Crimson Tide Phase 3 qui utilise des identifiants volés.

**EN :** Hardening SSH means disabling password authentication (key-only), prohibiting direct root login, restricting allowed users, cutting idle sessions after 10 minutes, and enforcing SSH protocol version 2. This blocks Crimson Tide Phase 3 lateral movement using stolen credentials.

---

### 3. Kernel Hardening (sysctl)
**FR :** Durcir le noyau via sysctl active les SYN cookies contre les attaques DoS, désactive les redirections ICMP pour empêcher le détournement de trafic, coupe le routage IP pour bloquer l'utilisation du serveur comme pivot, active l'ASLR pour rendre les exploits mémoire imprévisibles, et restreint les core dumps pour éviter les fuites d'informations.

**EN :** Kernel hardening via sysctl enables SYN cookies against DoS attacks, disables ICMP redirects to prevent traffic hijacking, turns off IP forwarding to block server pivoting, enables ASLR to make memory exploits unpredictable, and restricts core dumps to prevent information leaks.

---

### 4. Filesystem Permissions
**FR :** Auditer les permissions du système de fichiers consiste à repérer les binaires SUID/SGID inutiles (qui s'exécutent en root), corriger les fichiers modifiables par tous, et appliquer les options de montage `noexec` (interdit l'exécution), `nosuid` (ignore les bits SUID), `nodev` (bloque les fichiers périphériques) sur `/tmp`, `/var/tmp` et `/dev/shm`.

**EN :** Auditing filesystem permissions means finding unnecessary SUID/SGID binaries (which run as root), fixing world-writable files, and applying mount options `noexec` (blocks execution), `nosuid` (ignores SUID bits), `nodev` (blocks device files) on `/tmp`, `/var/tmp`, and `/dev/shm`.

---

### 5. AppArmor Profiles
**FR :** Configurer AppArmor en mode enforce confine chaque service exposé (Apache, MySQL) à ses répertoires autorisés uniquement. Même si un attaquant compromet le serveur web, il ne peut pas lire `/etc/shadow` ni exécuter un shell inversé. C'est le confinement obligatoire au niveau du noyau, intégré par défaut dans Ubuntu.

**EN :** Configuring AppArmor in enforce mode confines each exposed service (Apache, MySQL) to its allowed directories only. Even if an attacker compromises the web server, they cannot read `/etc/shadow` or execute a reverse shell. This is mandatory kernel-level confinement, integrated by default in Ubuntu.

---

### 6. PAM Configuration
**FR :** Configurer PAM (Pluggable Authentication Modules) impose des mots de passe de 14 caractères minimum avec complexité (chiffres, majuscules, minuscules, caractères spéciaux), verrouille le compte après 5 échecs pendant 15 minutes, et garde un historique des 12 derniers mots de passe pour empêcher leur réutilisation.

**EN :** Configuring PAM (Pluggable Authentication Modules) enforces 14-character minimum passwords with complexity (digits, uppercase, lowercase, special characters), locks accounts after 5 failures for 15 minutes, and keeps a history of the last 12 passwords to prevent reuse.

---

### 7. auditd Deployment
**FR :** Déployer auditd enregistre au niveau du noyau tous les événements de sécurité : qui lit `/etc/shadow`, qui exécute `sudo`, qui modifie les fichiers de configuration SSH, qui télécharge avec `wget` ou `curl`. Ces logs envoyés à `log-srv-01` survivent à un effacement local par un attaquant (Crimson Tide Phase 5).

**EN :** Deploying auditd records all security events at kernel level: who reads `/etc/shadow`, who runs `sudo`, who modifies SSH configuration files, who downloads with `wget` or `curl`. These logs forwarded to `log-srv-01` survive local clearing by an attacker (Crimson Tide Phase 5).

---

### 8. rsyslog and Log Rotation
**FR :** Configurer rsyslog structure les logs d'authentification, système, cron et noyau dans des fichiers séparés. La rotation conserve 90 jours pour `auth.log` et 60 jours pour `syslog`, avec compression après 7 jours. Les permissions `640 root:adm` empêchent les utilisateurs non autorisés de lire les logs.

**EN :** Configuring rsyslog structures authentication, system, cron, and kernel logs into separate files. Rotation keeps 90 days for `auth.log` and 60 days for `syslog`, with compression after 7 days. Permissions `640 root:adm` prevent unauthorized users from reading logs.

---

### 9. Host Firewall (UFW)
**FR :** Implémenter un pare-feu avec politique "deny par défaut" en entrée bloque tout le trafic entrant sauf les services approuvés : SSH depuis le réseau management uniquement, HTTP/HTTPS pour le portail patient, MySQL depuis le réseau applicatif uniquement. Même si un service est activé par erreur, le firewall le bloque.

**EN :** Implementing a firewall with default-deny inbound policy blocks all incoming traffic except approved services: SSH from management network only, HTTP/HTTPS for patient portal, MySQL from application network only. Even if a service is accidentally enabled, the firewall blocks it.

---

## OPERATIONAL SKILLS

### 10. Lynis Audit and Delta Measurement
**FR :** Exécuter un audit Lynis donne un score de hardening sur 100. Le parser avec `2-lynis_parse.sh` extrait les warnings, suggestions et checks manuels en JSON. Mesurer le delta avant/après (ex: 52 → 84) prouve l'amélioration. C'est la preuve pour les auditeurs HIPAA.

**EN :** Running a Lynis audit gives a hardening score out of 100. Parsing it with `2-lynis_parse.sh` extracts warnings, suggestions, and manual checks into JSON. Measuring the before/after delta (e.g., 52 → 84) proves improvement. This is evidence for HIPAA auditors.

---

### 11. Gap Analysis Against CIS Controls
**FR :** Croiser les résultats Lynis avec les contrôles CIS signifie mapper chaque warning à la section CIS correspondante (ex: SSH-7408 → CIS 5.2.7). Cela produit une liste priorisée de ce qui doit être corrigé, triée par sévérité, avec la tâche de remédiation associée.

**EN :** Cross-referencing Lynis findings with CIS controls means mapping each warning to the corresponding CIS section (e.g., SSH-7408 → CIS 5.2.7). This produces a prioritized list of what needs fixing, sorted by severity, with the associated remediation task.

---

### 12. Idempotent Bash Scripts with JSON Output
**FR :** Écrire des scripts bash idempotents signifie qu'on peut les exécuter 2 fois sans effet de bord : ils vérifient l'état avant de modifier (`grep -q` avant `sed`). La sortie JSON structurée permet aux outils d'analyse de lire les résultats automatiquement plutôt que de parser du texte libre.

**EN :** Writing idempotent bash scripts means they can run twice without side effects: they check state before modifying (`grep -q` before `sed`). Structured JSON output allows analysis tools to read results automatically instead of parsing free text.

---

### 13. Master Hardening Pipeline
**FR :** Construire un orchestrateur (`14-hardening_orchestrator.sh`) exécute les 13 scripts de durcissement dans l'ordre de dépendance, s'arrête si un script échoue, et produit un rapport JSON avec le delta Lynis avant/après. Un serveur passe de zéro à production-ready en 20 minutes.

**EN :** Building a master orchestrator (`14-hardening_orchestrator.sh`) runs all 13 hardening scripts in dependency order, stops if any script fails, and produces a JSON report with before/after Lynis delta. A server goes from zero to production-ready in 20 minutes.

---

## PROFESSIONAL JUDGMENT

### 14. When to Skip a CIS Recommendation
**FR :** Ignorer une recommandation CIS est acceptable quand elle casse une application clinique critique (ex: laisser TLS 1.0 pour un appareil médical legacy). On documente la déviation avec un contrôle compensatoire (isolation VLAN) et une date de revue. La conformité aveugle peut tuer des patients ; le jugement professionnel les protège.

**EN :** Skipping a CIS recommendation is acceptable when it breaks a critical clinical application (e.g., keeping TLS 1.0 for legacy medical device). Document the deviation with a compensating control (VLAN isolation) and a review date. Blind compliance can kill patients; professional judgment protects them.

---

### 15. Balancing Security and Clinical Operations
**FR :** Équilibrer la sécurité et les opérations cliniques signifie qu'on ne peut pas couper l'EHR pour appliquer un patch pendant les heures de soins. On planifie les changements pendant les fenêtres de maintenance (dimanche 02:00-04:00), on prépare un rollback, et on s'assure que les procédures papier sont prêtes en cas de panne.

**EN :** Balancing security and clinical operations means you cannot take down the EHR to apply a patch during patient care hours. Schedule changes during maintenance windows (Sunday 02:00-04:00), prepare a rollback, and ensure paper procedures are ready in case of downtime.
## ACTIVE DIRECTORY SECURITY

### 1. Active Directory Structure
**FR :** Active Directory organise l'authentification et l'autorisation via des Domain Controllers (DCs), des Unités d'Organisation (OUs), des Group Policy Objects (GPOs) et des groupes de sécurité. Comprendre l'ordre d'application des GPOs (Local → Site → Domaine → OU) permet de diagnostiquer les conflits et de déployer les paramètres de sécurité au bon niveau. C'est le cerveau de l'infrastructure Windows.

**EN :** Active Directory organizes authentication and authorization through Domain Controllers (DCs), Organizational Units (OUs), Group Policy Objects (GPOs), and security groups. Understanding GPO application order (Local → Site → Domain → OU) allows diagnosing conflicts and deploying security settings at the right level. It's the brain of Windows infrastructure.

---

### 2. Critical Windows Event IDs
**FR :** Les Event IDs critiques (4624 connexion réussie, 4625 échec, 4648 utilisation d'identifiants explicites, 4688 création de processus, 4720 création de compte, 4726 suppression de compte, 4732 ajout à un groupe, 1102 effacement des logs) révèlent le comportement d'un attaquant. 4625 en rafale = brute-force. 4732 sur Domain Admins = escalade de privilèges. 1102 = Crimson Tide Phase 5.

**EN :** Critical Event IDs (4624 successful logon, 4625 failed logon, 4648 explicit credentials, 4688 process creation, 4720 account created, 4726 account deleted, 4732 member added to group, 1102 audit log cleared) reveal attacker behavior. Burst of 4625 = brute-force. 4732 on Domain Admins = privilege escalation. 1102 = Crimson Tide Phase 5.

---

## WINDOWS HARDENING

### 3. Password and Lockout Policy via GPO
**FR :** Durcir la politique de mots de passe via GPO impose 14 caractères minimum avec complexité activée, un historique de 24 mots de passe, et un verrouillage après 5 échecs pendant 15 minutes. C'est la correction directe de FIND-PW-001 et FIND-LOCK-001. Sans cela, le Kerberoasting (Crimson Tide Phase 2) reste trivial.

**EN :** Hardening password policy via GPO enforces 14-character minimum with complexity enabled, 24-password history, and lockout after 5 failures for 15 minutes. This is the direct fix for FIND-PW-001 and FIND-LOCK-001. Without it, Kerberoasting (Crimson Tide Phase 2) remains trivial.

---

### 4. Advanced Audit Policies
**FR :** Configurer les Advanced Audit Policies via GPO active la journalisation granulaire : Process Creation (4688), Logon (4624/4625), Special Logon (4672), Account Management (4720/4726/4732), Sensitive Privilege Use. La journalisation en ligne de commande inclut les commandes complètes dans 4688. Cela transforme les logs Windows de "bruit" en "preuve".

**EN :** Configuring Advanced Audit Policies via GPO enables granular logging: Process Creation (4688), Logon (4624/4625), Special Logon (4672), Account Management (4720/4726/4732), Sensitive Privilege Use. Command-line logging includes full commands in 4688. This transforms Windows logs from "noise" to "evidence."

---

### 5. Sysmon Deployment and Detection
**FR :** Déployer Sysmon avec une configuration optimisée capture ce que les logs Windows ne voient pas : connexions réseau (Event ID 3), création de fichiers (11), modifications registre (13), requêtes DNS (22), chargement de DLL (7). Sans Sysmon, détecter le mouvement latéral (PsExec, WMI) et l'exfiltration (Rclone) de Crimson Tide est quasiment impossible.

**EN :** Deploying Sysmon with an optimized configuration captures what Windows logs miss: network connections (Event ID 3), file creation (11), registry modifications (13), DNS queries (22), DLL loads (7). Without Sysmon, detecting Crimson Tide lateral movement (PsExec, WMI) and exfiltration (Rclone) is nearly impossible.

---

### 6. AppLocker Application Allow-Listing
**FR :** Configurer AppLocker en mode allow-listing bloque tout exécutable non approuvé. Règles : autoriser `C:\Windows\*`, `C:\Program Files\*`, et les applications cliniques comme DicomViewer.exe. Tout le reste est bloqué. Crimson Tide Phase 6 (déploiement ransomware via GPO) échoue car l'exécutable malveillant n'est pas dans la liste autorisée.

**EN :** Configuring AppLocker in allow-listing mode blocks all unapproved executables. Rules: allow `C:\Windows\*`, `C:\Program Files\*`, and clinical apps like DicomViewer.exe. Everything else is blocked. Crimson Tide Phase 6 (ransomware deployment via GPO) fails because the malicious executable is not on the allowed list.

---

### 7. SMB and Protocol Hardening
**FR :** Désactiver SMBv1 élimine la surface d'attaque EternalBlue (WannaCry, NotPetya). Forcer la signature SMB empêche les attaques par relais. Désactiver LLMNR bloque le vol d'identifiants par empoisonnement de résolution de noms. Désactiver NetBIOS supprime un protocole legacy inutile. Ces protocoles sont des vecteurs de mouvement latéral (Phase 4).

**EN :** Disabling SMBv1 eliminates the EternalBlue attack surface (WannaCry, NotPetya). Enforcing SMB signing prevents relay attacks. Disabling LLMNR blocks credential theft via name resolution poisoning. Disabling NetBIOS removes an unnecessary legacy protocol. These protocols are lateral movement vectors (Phase 4).

---

## ENDPOINT DETECTION

### 8. Sysmon Event IDs and Detection Rules
**FR :** Sysmon capture les Event IDs critiques : 1 (création processus avec hash), 3 (connexion réseau), 7 (chargement DLL), 11 (création fichier), 13 (modification registre), 22 (requête DNS). Les règles custom détectent rclone.exe (exfiltration Phase 4), vssadmin delete shadows (ransomware Phase 7), schtasks /create (persistence Phase 2), et PowerShell encodé -enc (exécution furtive Phase 3).

**EN :** Sysmon captures critical Event IDs: 1 (process creation with hash), 3 (network connection), 7 (DLL load), 11 (file creation), 13 (registry modification), 22 (DNS query). Custom rules detect rclone.exe (exfiltration Phase 4), vssadmin delete shadows (ransomware Phase 7), schtasks /create (persistence Phase 2), and encoded PowerShell -enc (stealth execution Phase 3).

---

### 9. PowerShell Logging and Restrictions
**FR :** Activer le Script Block Logging (Event ID 4104) capture le contenu décodé des commandes PowerShell, y compris les commandes encodées en Base64 (-enc). Le Module Logging (4103) enregistre les modules chargés. La Transcription sauvegarde l'intégralité des sessions. Sans cela, un attaquant peut exécuter `powershell.exe -enc [base64]` sans laisser de trace.

**EN :** Enabling Script Block Logging (Event ID 4104) captures decoded content of PowerShell commands, including Base64-encoded commands (-enc). Module Logging (4103) records loaded modules. Transcription saves full session output. Without this, an attacker can run `powershell.exe -enc [base64]` leaving no trace.

---

### 10. Windows Firewall Rules
**FR :** Les règles de pare-feu Windows appliquent la segmentation réseau au niveau endpoint : SSH uniquement depuis le réseau management (10.10.1.0/24), MySQL uniquement depuis les serveurs applicatifs (10.10.2.0/24). Même sur un réseau plat, le firewall bloque le mouvement latéral non autorisé. C'est la dernière ligne de défense si la segmentation réseau n'est pas encore déployée.

**EN :** Windows Firewall rules enforce network segmentation at endpoint level: SSH only from management network (10.10.1.0/24), MySQL only from application servers (10.10.2.0/24). Even on a flat network, the firewall blocks unauthorized lateral movement. This is the last line of defense if network segmentation is not yet deployed.
