Introduction

    "Security is not a product. Security is a process." — Bruce Schneier

You spent weeks telling MedDefense what was wrong with its infrastructure. You wrote five reports. You quantified the risk. You calculated the ALE. You designed the strategy, secured the budget and presented to the Board.

Now stop writing and start configuring.

This project is the first line of code in MedDefense's defense. The Linux servers that run the patient portal, the billing system and the log collection host are exposed, misconfigured and running default settings that you yourself flagged in Finding 009 (SSH password auth), Finding 011 (Ubuntu 18.04 without ESM) and Finding 026 (outdated kernel with 47 known CVEs). The Crimson Tide advisory showed that every hospital breach started with a misconfigured service on a reachable server. Your servers are reachable. Your services are misconfigured. The difference between MedDefense and Hospital C (currently in FBI containment 45 miles away) is what you do in the next 22 hours.

This project produces no report. It produces hardened systems and the scripts that harden them. Every deliverable is a shell script that produces structured JSON output or a measurable system state change. When you finish, billing-srv-01's Lynis hardening index will have risen from the low 50s to above 80. SSH will reject password authentication. Unnecessary SUID binaries will be stripped. auditd will log every privilege escalation attempt. AppArmor will confine every exposed service. And every change will be automated in a script that can harden the next server in minutes instead of hours.
Why this matters

Every SOC analyst who has worked a hospital breach will tell you the same thing: the attacker did not need a zero-day. They needed a default SSH config, an unnecessary service and a missing audit trail. Linux hardening is not glamorous work, but it is the work that eliminates the easy wins attackers depend on. The CIS Benchmark methodology you learn here is the same methodology you will apply to Windows, to firewalls, to network devices. This is your training ground. The method transfers everywhere.
Context

Week seven at MedDefense Health Systems. Monday morning.

The Board approved the security strategy on Friday. The 72-hour emergency plan from the Crimson Tide response is in Phase 2. James Chen has divided the roadmap into workstreams. Yours is infrastructure hardening.

He hands you a printed checklist:

"Three Linux servers. Three weeks of risk sitting in production. Here is what happens this week:"

    billing-srv-01 (Ubuntu 22.04, fresh OS upgrade from 18.04, Apache 2.4.x, MySQL, SSH) -- the server that had the crypto-miner. The upgrade resolved Finding 011 but the system needs full hardening.

    web-srv-01 (Ubuntu 22.04, Apache/Nginx, patient portal) -- internet-facing, TLS already improved (from 1x04 work), but OS-level hardening is zero.

    log-srv-01 (Ubuntu 22.04, fresh build) -- the centralized log collection host. Must be the most hardened server in the environment because if the log server is compromised, the attacker can erase the evidence.

"I want scripts, not notes. If billing-srv-01 burns tomorrow and we have to rebuild, I want to run one script and have a hardened server in 20 minutes. Document the exceptions, automate the rest."

Sarah Park adds: "And the CIS Benchmark for Ubuntu is 800 pages. Do not try to implement all of it. Pick the controls that matter for our threat model, apply them, justify what you skip, and prove the system is harder to break than it was yesterday."
Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

System Hardening

    What a CIS Benchmark is, how it is structured and how to apply it with professional judgment (not blind compliance)

    How to harden SSH for enterprise use: key-only authentication, root login prohibition, idle timeouts, allowed users, protocol enforcement

    How to harden the Linux kernel via sysctl: network stack protections (SYN cookies, ICMP redirects, IP forwarding), ASLR, core dump restrictions

    How to audit and remediate filesystem permissions: SUID/SGID binaries, world-writable files, mount options (noexec, nosuid, nodev)

    How to configure AppArmor profiles in enforce mode for exposed services

    How to configure PAM for password quality enforcement and login attempt limiting

    How to deploy and configure auditd for security-relevant event logging

    How to configure rsyslog and log rotation for structured, exportable logging

    How to implement a host firewall with default-deny posture

Operational Skills

    How to run a Lynis audit, parse the results programmatically, and measure the hardening delta (before vs after)

    How to cross-reference audit findings against CIS controls to produce a gap analysis

    How to write idempotent bash scripts that automate hardening operations and produce structured JSON outputs

    How to build a master hardening pipeline that can harden a server from zero to production-ready in one execution

Professional Judgment

    When to apply a CIS recommendation and when to skip it with a documented compensating control

    How to balance security hardening against clinical operational requirements

Resources

Read or Watch:

CIS Benchmarks

    CIS Benchmark for Ubuntu Linux 22.04 LTS -- Download the PDF. Read Sections 1 (Initial Setup) and 5 (Access/Authentication). You do not need to read all 800 pages.

    CIS Benchmarks Overview -- How benchmarks are structured and maintained.

Linux Hardening

    NIST SP 800-123: Guide to General Server Security -- Section 4 covers OS hardening principles.

    Linux Audit System Documentation -- auditd reference.

    AppArmor Wiki -- Profile syntax and enforcement modes.

Man or Help:

    man sshd_config

    man sysctl

    man sysctl.conf

    man pam_pwquality

    man pam_faillock

    man auditctl

    man auditd

    man aa-status

    man aa-enforce

    man lynis

    man rsyslog.conf

    man ufw

Requirements
General

    A README.md file, at the root of the folder of the project, is mandatory.

    All your files should end with a new line.

Bash Scripting

    All your scripts must be executable.

    The first line of all your scripts should be exactly #!/bin/bash.

    All your files should end with a new line.

Specific Project Rules

    Scripts are the primary deliverable. Every hardening action must be captured in a script that can be re-executed on a fresh system. The script IS the documentation.

    Idempotent scripts only. Running the script twice must produce the same result as running it once. Use conditional checks before making changes.

    JSON outputs for all structured data. Every analysis, assessment and validation task produces a structured JSON file. These outputs are machine-readable and auto-checkable.

    Show the delta. Before any hardening, capture the system state (Lynis score, open ports, SUID list). After hardening, capture the same metrics. The delta is the proof of work.

    Justify every deviation. If a CIS recommendation is not applied, create a comment in the script explaining why and what compensating control exists.

    Connect to MedDefense. Comments in scripts should reference the threat or vulnerability that each setting addresses.
        Example: # Disable SSH password auth - addresses 1x02 Finding 009 and Crimson Tide Phase 3 (SSH lateral movement)

Lab Access

Connection Details:
Parameter 	Value
Lab Name 	billing-srv-01
Target Host 	Local VM
Username 	analyst
Auth Method 	Analyst2026!

Connection Example:

From your local computer:

ssh -p 2222 analyst@127.0.0.1

From the Windows VM (Next Lesson):

ssh analyst@10.10.1.10




https://www.cisecurity.org/benchmark/ubuntu_linux



https://csrc.nist.gov/pubs/sp/800/123/final





man7.org > Linux > man-pages
	

Linux/UNIX system programming training
auditd(8) — Linux manual page

NAME | SYNOPSIS | DESCRIPTION | OPTIONS | SIGNALS | EXIT CODES | FILES | NOTES | SEE ALSO | AUTHOR | COLOPHON

AUDITD(8)            System Administration Utilities            AUDITD(8)

NAME         top

       auditd - The Linux Audit daemon

SYNOPSIS         top

       auditd
       [-f] [-l] [-n] [-s disable|enable|nochange] [-c <config_dir>]

DESCRIPTION         top

       auditd is the userspace component to the Linux Auditing System.
       It's responsible for writing audit records to the disk. Viewing
       the logs is done with the ausearch or aureport utilities.
       Configuring the audit system or loading rules is done with the
       auditctl utility. During startup, the rules in
       /etc/audit/audit.rules are read by auditctl and loaded into the
       kernel. Alternately, there is also an augenrules program that
       reads rules located in /etc/audit/rules.d/ and compiles them into
       an audit.rules file. The audit daemon itself has some
       configuration options that the admin may wish to customize. They
       are found in the auditd.conf file.

OPTIONS         top

       -f     leave the audit daemon in the foreground for debugging.
              Messages also go to stderr rather than the audit log.

       -l     allow the audit daemon to follow symlinks for config files.

       -n     no fork. This is useful for running off of inittab or
              systemd.

       -s=ENABLE_STATE
              specify when starting if auditd should change the current
              value for the kernel enabled flag. Valid values for
              ENABLE_STATE are "disable", "enable" or "nochange". The
              default is to enable (and disable when auditd terminates).
              The value of the enabled flag may be changed during the
              lifetime of auditd using 'auditctl -e'.

       -c     Specify alternate config file directory. Note that this
              same directory will be passed to the dispatcher. (default:
              /etc/audit/)

SIGNALS         top

       SIGHUP causes auditd to reconfigure. This means that auditd re-
              reads the configuration file. If there are no syntax
              errors, it will proceed to implement the requested changes.
              If the reconfigure is successful, a DAEMON_CONFIG event is
              recorded in the logs. If not successful, error handling is
              controlled by space_left_action, admin_space_left_action,
              disk_full_action, and disk_error_action parameters in
              auditd.conf.

       SIGTERM
              caused auditd to discontinue processing audit events, write
              a shutdown audit event, and exit.

       SIGUSR1
              causes auditd to immediately rotate the logs. It will
              consult the max_log_file_action to see if it should keep
              the logs or not.

       SIGUSR2
              causes auditd to attempt to resume logging and passing
              events to plugins. This is usually needed after logging has
              been suspended or the internal queue is overflowed. Either
              of these conditions depends on the applicable configuration
              settings.

       SIGCONT
              causes auditd to dump a report of internal state to
              /run/audit/auditd.state.

EXIT CODES         top

       1      Cannot adjust priority, daemonize, open audit netlink,
              write the pid file, start up plugins, resolve the machine
              name, set audit pid, or other initialization tasks.

       2      Invalid or excessive command line arguments

       4      The audit daemon doesn't have sufficient privilege

       6      There is an error in the configuration file

FILES         top

       /etc/audit/auditd.conf - configuration file for audit daemon

       /etc/audit/audit.rules - audit rules to be loaded at startup

       /etc/audit/rules.d/ - directory holding individual sets of rules
       to be compiled into one file by augenrules.

       /etc/audit/plugins.d/ - directory holding individual plugin
       configuration files.

       /etc/audit/audit-stop.rules - These rules are loaded when the
       audit daemon stops.

       /run/audit/auditd.state - report about internal state.

NOTES         top

       A boot param of audit=1 should be added to ensure that all
       processes that run before the audit daemon starts is marked as
       auditable by the kernel. Not doing that will make a few processes
       impossible to properly audit.

       The audit daemon can receive audit events from other audit daemons
       via the audisp-remote plugin. The audit daemon may be linked with
       tcp_wrappers to control which machines can connect. If this is the
       case, you can add an entry to hosts.allow and deny.

SEE ALSO         top

       auditd.conf(5), auditd-plugins(5), ausearch(8), aureport(8),
       auditctl(8), augenrules(8), audit.rules(7).

AUTHOR         top

       Steve Grubb

COLOPHON         top

       This page is part of the audit (Linux Audit) project.  Information
       about the project can be found at 
       ⟨http://people.redhat.com/sgrubb/audit/⟩.  If you have a bug report
       for this manual page, send it to linux-audit@redhat.com.  This
       page was obtained from the project's upstream Git repository
       ⟨https://github.com/linux-audit/audit-userspace.git⟩ on
       2026-05-24.  (At that time, the date of the most recent commit
       that was found in the repository was 2026-05-17.)  If you discover
       any rendering problems in this HTML version of the page, or you
       believe there is a better or more up-to-date source for the page,
       or you have corrections or improvements to the information in this
       COLOPHON (which is not part of the original manual page), send a
       mail to man-pages@man7.org

Red Hat                         Sept 2021                       AUDITD(8)

Pages that refer to this page: audit_request_features(3),  audit_request_status(3),  audit_set_backlog_limit(3),  audit_set_backlog_wait_time(3),  audit_set_enabled(3),  audit_set_failure(3),  audit_set_pid(3),  audit_set_rate_limit(3),  get_auditfail_action(3),  auditd.conf(5),  auditd.cron(5),  auditd-plugins(5),  zos-remote.conf(5),  audit.rules(7),  audispd-zos-remote(8),  auditctl(8),  augenrules(8),  aureport(8),  ausearch(8),  pam_loginuid(8),  systemd-update-utmp.service(8)

HTML rendering created 2026-05-30 by Michael Kerrisk, author of The Linux Programming Interface.

For details of in-depth Linux/UNIX system programming training courses that I teach, look here.

Hosting by jambit GmbH.
		Cover of TLPI




https://gitlab.com/apparmor/apparmor/-/wikis/home


Homepage

    avatarAppArmor
    avatarapparmor
    Wiki
    Home

Home
Last edited by John Johansen 1 month ago
AppArmor

Welcome to the AppArmor security project wiki, the wiki for users and developers of the AppArmor security project.
Description

AppArmor is an effective and easy-to-use Linux application security system. AppArmor proactively protects the operating system and applications from external or internal threats, even zero-day attacks, by enforcing good behavior and preventing even unknown application flaws from being exploited. AppArmor security policies completely define what system resources individual applications can access, and with what privileges. A number of default policies are included with AppArmor, and using a combination of advanced static analysis and learning-based tools, AppArmor policies for even very complex applications can be deployed successfully in a matter of hours.

More details about AppArmor can be found in the documentation
Getting AppArmor
Distributions and Ports

Distributions that include AppArmor:

    Annvix
    Arch Linux, documentation and Arch specific notes
    CentOs, documentation and CentOS specific notes
    Debian, documentation and Debian specific notes
    Gentoo
    openSUSE (integrated in default install), documentation and Suse specific notes
    Pardus Linux
    PLD
    Ubuntu (integrated in default install), documentation and Ubuntu specific notes

Any derivatives of these distributions should also have AppArmor available. Updated RPMS can be found at the openSUSE Build Service. These are not limited to SUSE distributions.
Source code

The AppArmor project source is split between the kernel module, available in the Linux kernel and git development tree and the user space tools available in launchpad.
Kernel

AppArmor is in the upstream kernel as of 2.6.36. Earlier releases are available in the kernel module git tree:

    How to get the AppArmor kernel source

    Note: the master branch is not stable and will be rebased from time to time. Release branches will be stable and will not be rebased.

The AppArmor v2.4 compatibility patches are available in the stable kernel branches. eg v3.4-aa2.8 or in the release tarballs in the kernel-patches directory.
Userspace

    Current development release 5.0.1
    Current stable release 4.1.7
    supported release: 3.1.7

    User space tools

    How to get the AppArmor user space tools

Profiles

See the Profiles page for information about AppArmor profiles.
Documentation

AppArmor documentation for the project, including manuals, tutorials, technical documentation and more:

    Documentation about the AppArmor security project

Reporting Bugs

    Bug tracking is hosted in GitLab at https://gitlab.com/apparmor/apparmor/-/issues
    Historical Bug Tracking is hosted in Launchpad at https://bugs.launchpad.net/apparmor. We still accept bugreports there, but GitLab is preferred.
    email bugs@apparmor.net it will forward to the appropriate people and/or the mailing list
    security issues security@apparmor.net it will forward to the security team and NOT to a public list

Reporting Security Vulnerabilities

There are 3 ways that security bugs can be reported: as a bug on GitLab (preferred), on Launchpad or by mail.
On GitLab (preferred)

Open a new issue on GitLab at https://gitlab.com/apparmor/apparmor/-/issues.

When creating the issue, enable the checkbox

````This issue is confidential and should only be visible to team members with at least Reporter access.```

On Launchpad

On launchpad, create a new bug at https://bugs.launchpad.net/apparmor.

When creating the bug change the

This bug contains information that is:
Public

to Private Security

this will allow only you and the apparmor security team to see the bug, until it status is changed to Public Security by either you or the apparmor security team.
email (no account needed)

If the security issue contains information that is public or can be public. Send an email to

apparmor@lists.ubuntu.com

Emails to the list from addresses without an account will go into moderation, so there will be a delay before they hit the list but any email that isn't spam will be moderated through. There is no need to signup to be on the mailing list.

If the issue should may need an embargo you can send an email to

security@apparmor.net
Joining AppArmor

    Mailing list for discussing AppArmor development and use.
    The IRC channel is #apparmor on irc.oftc.net
    Bug Tracking - project apparmor on launchpad.net
    Translations - project apparmor on launchpad.net
    Code - project apparmor on GitLab

Meetings are held regularly on the IRC channel and are open to the everyone. Please see MeetingAgenda for times.
How to Contribute

Contributions to AppArmor are welcome. Anyone can pull the code from the git repository or from launchpad, and begin hacking on the code. Patches can be contributed by posting them to the mailing list for review or submitting a merge request on GitLab. Please see the CommitPolicy, Versioning, and Coding Style before sending patches.

Commit privileges to the git tree and GitLab master repository are restricted, but can be earned by any developer who is involved in the project.
What happened to the profile repository?

AppArmor profile repository
Comments

Please register or sign in to add a comment.

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
