================================================================================
                    IMPLEMENTATION PLAYBOOK - MEDDEFENSE HEALTH SYSTEMS
                    Task 20: The Implementation Playbook
================================================================================

Exercise: Task 20 - The Implementation Playbook
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Produce a step-by-step operational playbook for the first 5
          cryptographic changes to be deployed in production. This is
          the document the IT team executes on Monday morning.

Sources: T10 TLS Configuration, T12 LUKS Implementation, T13 Encryption Levels,
         T14 Key Management Plan, T15 Crypto Posture Audit (CRYPTO-001 through
         CRYPTO-010), T16 Attack Surface, T17 Certificate Lifecycle, T19 HIPAA


================================================================================
BEFORE YOU START: PRE-FLIGHT CHECKLIST
================================================================================

This checklist must be completed before ANY of the 5 actions below.

[ ] Maintenance window approved by IT Manager and CISO.
[ ] Rollback plan reviewed and understood by all team members.
[ ] Communication template prepared for each stakeholder group.
[ ] Monitoring dashboards open and visible (Uptime Kuma, server metrics).
[ ] SSH access to target servers verified (credentials, MFA working).
[ ] Console/out-of-band access verified (iDRAC/iLO) in case SSH breaks.
[ ] Backup of current configuration saved on separate system.
[ ] Incident response contact list confirmed and accessible.


================================================================================
ACTION #1: DEPLOY TLS 1.3 ON PATIENT PORTAL WITH AUTOMATED CERTIFICATE RENEWAL
================================================================================

Priority:            IMMEDIATE (18-day deadline from CRYPTO-002, T15)
System Affected:     patient-portal-srv-01 (10.10.10.25)
Service:             nginx 1.24.0 reverse proxy for patient.meddefense.com
Impact:              Patient-facing web portal. 800+ patients/day.
                     Downtime directly impacts patient care.

Prerequisites:
  [ ] Server root/sudo access verified.
  [ ] Current nginx configuration backed up: cp /etc/nginx/nginx.conf
      /backup/nginx.conf.$(date +%Y%m%d)
  [ ] Current certificate details documented: openssl x509 -in
      /etc/nginx/ssl/portal.crt -text -noout > /backup/old_cert_info.txt
  [ ] Let's Encrypt account created (one-time): certbot register --email
      security@meddefense.com --agree-tos
  [ ] DNS A record for patient.meddefense.com verified as pointing to
      patient-portal-srv-01's public IP.
  [ ] Firewall rule verified: inbound TCP/80 and TCP/443 open to
      patient-portal-srv-01.
  [ ] Maintenance window: Sunday 02:00-04:00 local time (lowest traffic).

Steps:

  1. STOP. Verify pre-flight checklist is complete. Open monitoring
     dashboard for patient-portal-srv-01. Open a second SSH session
     as a backup (do not close your primary session).

  2. Test certbot dry-run to validate ACME challenge will succeed:
     certbot certonly --webroot -w /var/www/html \
       -d patient.meddefense.com --dry-run
     Expected output: "The dry run was successful."

  3. If dry-run fails, STOP. Do not proceed. Debug DNS, firewall, or
     webroot path. Do not proceed until dry-run succeeds.

  4. Request the actual certificate (ECDSA P-256, preferred by Let's Encrypt):
     certbot certonly --webroot -w /var/www/html \
       -d patient.meddefense.com \
       --key-type ecdsa --elliptic-curve secp256r1
     Certificate and key will be stored at:
     /etc/letsencrypt/live/patient.meddefense.com/fullchain.pem
     /etc/letsencrypt/live/patient.meddefense.com/privkey.pem

  5. Update nginx configuration to use the new certificate and enforce
     TLS 1.3 with strong cipher suites. Add to the server block:

     ssl_certificate     /etc/letsencrypt/live/patient.meddefense.com/fullchain.pem;
     ssl_certificate_key /etc/letsencrypt/live/patient.meddefense.com/privkey.pem;
     ssl_protocols       TLSv1.3;
     ssl_ciphers         TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
     ssl_prefer_server_ciphers off;
     ssl_session_tickets off;
     ssl_stapling        on;
     ssl_stapling_verify on;
     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

  6. Remove any ssl_protocols lines that include TLSv1, TLSv1.1, TLSv1.2.
     Remove any ssl_ciphers lines referencing RC4, 3DES, CBC-mode, or MD5.

  7. Test the nginx configuration for syntax errors:
     nginx -t
     Expected output: "syntax is ok" and "test is successful."
     If NOT ok, STOP. Do not reload. Fix the syntax error.

  8. Reload nginx to apply the new configuration:
     systemctl reload nginx

  9. Wait 10 seconds. Verify nginx is running:
     systemctl status nginx

Validation:

  - [ ] Local test: curl -I https://patient.meddefense.com
        Expected: HTTP 200. No certificate errors.
  - [ ] OpenSSL test: openssl s_client -connect patient.meddefense.com:443
        -tls1_3 | grep -E "Protocol|Cipher"
        Expected: "Protocol: TLSv1.3" and "Cipher: TLS_AES_256_GCM_SHA384"
  - [ ] SSL Labs test: Navigate to ssllabs.com/ssltest/ and enter
        patient.meddefense.com. Expected grade: A+.
        Wait for full scan (2-5 minutes).
  - [ ] Expiration check: openssl x509 -in /etc/letsencrypt/live/
        patient.meddefense.com/cert.pem -noout -enddate
        Expected: 90 days from today.
  - [ ] Automated renewal test: certbot renew --dry-run
        Expected: "No renewals were attempted" (if not due) OR successful
        simulation of renewal.
  - [ ] HSTS header present: curl -I https://patient.meddefense.com |
        grep Strict-Transport-Security
        Expected: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"

Rollback:

  - If validation fails at Step 9 (nginx won't start): restore backed-up
    nginx config: cp /backup/nginx.conf.$(date +%Y%m%d) /etc/nginx/nginx.conf
    systemctl reload nginx.
  - If validation fails after reload (certificate errors, TLS errors):
    same restore procedure. Old certificate is still valid until its
    expiration date (18 days).
  - MAXIMUM ACCEPTABLE DOWNTIME: 15 minutes.
  - ROLLBACK TRIGGER: If portal is not serving HTTPS with valid
    certificate within 10 minutes of nginx reload, initiate rollback.
  - Post-rollback: Document what failed. Schedule a root cause analysis
    before next maintenance window. The 18-day deadline still applies.

Maintenance Window:   Sunday 02:00-04:00 local time.
Communication:
  - Before: Email to IT Manager, CISO, Patient Services Manager:
    "Scheduled TLS upgrade on patient portal, Sunday 02:00-04:00.
     Portal may be intermittently unavailable for up to 15 minutes."
  - After (success): Email to same recipients: "TLS upgrade complete.
     Patient portal now running TLS 1.3 with automated certificate
     renewal. No further 18-day expiry risk."
  - After (failure + rollback): Email + phone call to IT Manager and
     CISO immediately. "TLS upgrade failed and was rolled back. Portal
     is operational on previous TLS configuration. RCA scheduled."


================================================================================
ACTION #2: DISABLE DES AND RC4 IN KERBEROS - ENFORCE AES-256 ONLY
================================================================================

Priority:            IMMEDIATE (CRYPTO-005, T16 Attack 4 - Kerberoasting)
System Affected:     All Domain Controllers (dc01.meddefense.local,
                     dc02.meddefense.local)
Service:             Active Directory Kerberos Authentication
Impact:              All domain authentication. A misconfiguration could
                     lock out all users. HIGHEST CAUTION REQUIRED.

Prerequisites:
  [ ] Domain Admin credentials verified and tested on dc01.
  [ ] Current Group Policy Object (GPO) configuration documented:
      Get-GPO -Name "Default Domain Policy" | Get-GPOReport -ReportType HTML
      -Path C:\backup\DefaultDomainPolicy_$(Get-Date -Format yyyyMMdd).html
  [ ] All Domain Controllers confirmed replicating:
      repadmin /replsummary (Expected: no failures)
  [ ] Test user account created: svc_krb_test with known password.
  [ ] Maintenance window: Sunday 03:00-05:00 local time.

Steps:

  1. STOP. Verify all prerequisites. This change affects ALL domain
     authentication. Have a Domain Admin account with a known-good
     password ready on a domain-joined workstation. Do not log out
     of your Domain Admin session.

  2. Test Kerberos encryption types currently in use. From a domain-joined
     workstation, request a TGS ticket for the test account and check
     the encryption type:
     klist get host/dc01.meddefense.local
     klist
     Expected: You will see tickets with etype RC4-HMAC or DES-CBC-CRC.
     Document the current etype for rollback reference.

  3. Open Group Policy Management Console (gpmc.msc) on dc01.

  4. Navigate to: Forest > Domains > meddefense.local > Default Domain Policy.
     Right-click > Edit.

  5. Navigate to: Computer Configuration > Policies > Windows Settings >
     Security Settings > Local Policies > Security Options.

  6. Locate policy: "Network security: Configure encryption types allowed
     for Kerberos"
     Current state: Likely all types checked (DES, RC4, AES128, AES256).

  7. UNCHECK the following (disable them):
     [ ] DES_CBC_CRC
     [ ] DES_CBC_MD5
     [ ] RC4_HMAC_MD5
     [ ] AES128_HMAC_SHA1 (recommended to also remove for maximum security;
         if legacy systems require AES128, leave it checked temporarily)

  8. ENSURE the following REMAIN CHECKED:
     [x] AES256_HMAC_SHA1
     [x] Future encryption types (if present)

  9. Apply the policy. Close the GPO editor.

  10. From the Domain Controller, force policy update:
      gpupdate /force

  11. Wait 5 minutes for replication. Then force replication:
      repadmin /syncall /AdeP

  12. From a domain-joined workstation (not the DC), run:
      gpupdate /force
      Restart the workstation (or wait for background refresh: 90-120 minutes
      by default, but force reboot is faster for testing).

  13. After reboot, log in as the test user. Request a new Kerberos ticket:
      klist purge
      klist get host/dc01.meddefense.local
      klist
      Expected: The new ticket shows etype AES-256-CTS-HMAC-SHA1-96.
      Verify NO tickets have etype RC4-HMAC or DES-CBC-CRC.

Validation:

  - [ ] Test user can log in and access network resources (file share,
        intranet).
  - [ ] klist shows AES256 etype. No RC4, no DES.
  - [ ] Domain Admin account can log in and access all domain resources.
  - [ ] Key services: Verify SQL Server (ehr-db-01), MySQL
        (billing-srv-01), and file shares are accessible with service
        accounts. Service accounts will pick up the new policy at
        next ticket renewal (default: 10 hours). For immediate testing,
        restart the services.
  - [ ] Event Viewer on dc01: Security log. Look for Event ID 4769
        (Kerberos TGS request). Verify Ticket Encryption Type field
        shows 0x12 (AES256) instead of 0x17 (RC4) or 0x01 (DES).

Rollback:

  - If users or services cannot authenticate: Re-open GPO editor,
    re-check the disabled encryption types (DES, RC4, AES128),
    apply, force gpupdate /force on DC, wait for replication,
    reboot affected workstations/servers.
  - ROLLBACK TRIGGER: If ANY production service (ehr-db-01, billing-srv-01,
    file servers) fails authentication within 30 minutes of policy
    application, initiate rollback.
  - POST-ROLLBACK: The DES/RC4 vulnerability remains. Schedule
    investigation into which service/application failed and why.
    Legacy applications may need to be upgraded or isolated.
  - MAXIMUM ACCEPTABLE AUTHENTICATION IMPACT: 30 minutes. After
    rollback, all services must authenticate within 10 minutes.

Maintenance Window:   Sunday 03:00-05:00 local time (overlaps with
                      Action #1 maintenance window; coordinate).
Communication:
  - Before: Email to IT Manager, all IT staff: "Kerberos encryption
    type hardening, Sunday 03:00-05:00. Domain authentication may be
    impacted. Do not deploy any other changes during this window."
  - After (success): Email to IT Manager, Security Team: "Kerberos
    now enforces AES256 only. DES and RC4 disabled. Kerberoasting
    attack surface significantly reduced."
  - After (failure): Email + phone to IT Manager and all IT staff:
    "Kerberos change rolled back. Authentication restored. Do not
    deploy any further changes until RCA is complete."


================================================================================
ACTION #3: DEPLOY POSTGRESQL TRANSPARENT DATA ENCRYPTION (TDE)
================================================================================

Priority:            IMMEDIATE (CRYPTO-001, T19 HIPAA - most critical gap)
System Affected:     ehr-db-01 (10.10.10.30)
Service:             PostgreSQL 15.2, database: meddefense_ehr
Impact:              50,000 patient records. Database encryption adds
                     CPU overhead (estimated 3-8% for AES-NI capable CPUs).
                     Service restart required.

Prerequisites:
  [ ] AWS KMS Customer Master Key (CMK) created in AWS KMS (us-east-1).
      Key ARN documented: arn:aws:kms:us-east-1:123456789:key/xxx-xxx-xxx
  [ ] IAM role created for ehr-db-01 with permissions:
      - kms:Decrypt
      - kms:GenerateDataKey
      - kms:DescribeKey
      IAM role attached to ehr-db-01 EC2 instance profile.
  [ ] PostgreSQL pg_tde extension installed: apt-get install postgresql-15-pgtde
      (or compiled from source if not in repos).
  [ ] Full database backup completed and verified:
      pg_dumpall > /backup/meddefense_ehr_full_$(date +%Y%m%d).sql
      pg_verify_checksums /backup/meddefense_ehr_full_$(date +%Y%m%d).sql
  [ ] pg_tde configuration parameters reviewed and documented.
  [ ] Maintenance window: Sunday 01:00-05:00 local time (4-hour window
      due to potential re-encryption time for 50,000 records).

Steps:

  1. STOP. Verify backup is complete and restorable. This is non-negotiable.
     If the backup fails or cannot be restored in a test environment, DO NOT
     PROCEED. The database contains 50,000 patient records.

  2. Verify AWS KMS key is accessible from ehr-db-01:
     aws kms describe-key --key-id alias/meddefense-ehr-tde-master
     Expected: Key metadata returned. Key state: Enabled.
     aws kms generate-data-key --key-id alias/meddefense-ehr-tde-master
     --key-spec AES_256
     Expected: Plaintext and CiphertextBlob returned. This confirms
     ehr-db-01 can reach KMS and perform crypto operations.

  3. Stop the application service that connects to the database to ensure
     no active transactions during encryption:
     systemctl stop meddefense-app

  4. Verify no active connections to PostgreSQL:
     psql -U postgres -c "SELECT count(*) FROM pg_stat_activity WHERE
     datname = 'meddefense_ehr';"
     Expected: 0 or 1 (your current session).

  5. Load the pg_tde extension (if not already loaded):
     psql -U postgres -d meddefense_ehr -c "CREATE EXTENSION IF NOT
     EXISTS pg_tde;"

  6. Configure pg_tde to use AWS KMS as the key provider. Add to
     postgresql.conf:
     pg_tde.key_provider = 'aws-kms'
     pg_tde.aws_kms_key_arn = 'arn:aws:kms:us-east-1:123456789:key/xxx-xxx-xxx'
     pg_tde.aws_kms_region = 'us-east-1'
     pg_tde.default_algorithm = 'aes-256-gcm'

  7. Restart PostgreSQL to apply configuration changes:
     systemctl restart postgresql

  8. Verify PostgreSQL started successfully:
     systemctl status postgresql
     psql -U postgres -c "SELECT version();"
     Expected: PostgreSQL 15.2 running.

  9. Enable TDE on the patient data tablespace. Create an encrypted
     tablespace and move tables:
     psql -U postgres -d meddefense_ehr -c "
       CREATE TABLESPACE ehr_encrypted_tbs
       LOCATION '/var/lib/postgresql/15/data/encrypted'
       WITH (encryption = true, key_provider = 'aws-kms');
     "

  10. Move all tables to the encrypted tablespace:
      psql -U postgres -d meddefense_ehr -c "
        DO \$\$
        DECLARE
          r RECORD;
        BEGIN
          FOR r IN SELECT tablename FROM pg_tables
                   WHERE schemaname = 'public'
          LOOP
            EXECUTE 'ALTER TABLE ' || quote_ident(r.tablename) ||
                    ' SET TABLESPACE ehr_encrypted_tbs';
          END LOOP;
        END \$\$;
      "
      This operation will take time proportional to database size.
      For 50,000 patient records with associated clinical data,
      estimate 30-90 minutes.

  11. Monitor progress (in a separate SSH session):
      psql -U postgres -c "SELECT relname, relpages FROM pg_class
      WHERE reltablespace = (SELECT oid FROM pg_tablespace
      WHERE spcname = 'ehr_encrypted_tbs');"

  12. After all tables are moved, verify the tablespace:
      psql -U postgres -d meddefense_ehr -c "
        SELECT tablename, tablespace FROM pg_tables
        WHERE schemaname = 'public';"
      Expected: All tables show tablespace 'ehr_encrypted_tbs'.

  13. Test data read/write with encryption:
      psql -U postgres -d meddefense_ehr -c "
        SELECT * FROM patients LIMIT 5;"
      Expected: Data returned normally. Encryption is transparent.
      psql -U postgres -d meddefense_ehr -c "
        INSERT INTO patients (name, dob) VALUES ('TEST_ENCRYPTION', '2000-01-01');
        DELETE FROM patients WHERE name = 'TEST_ENCRYPTION';"
      Expected: Insert and delete succeed.

  14. Restart the application service:
      systemctl start meddefense-app

  15. Verify application connectivity:
      Check application logs for database connection errors.
      Expected: No errors. Application functions normally.

Validation:

  - [ ] AWS CloudTrail logs show GenerateDataKey and Decrypt events from
        ehr-db-01's IAM role.
  - [ ] Direct file inspection shows encrypted data:
        strings /var/lib/postgresql/15/data/encrypted/* | grep -i "patient_name"
        Expected: No plaintext patient data found. Output is garbled/encrypted.
  - [ ] Application: Log into EHR system, search for a patient, view their
        record. All data displayed correctly.
  - [ ] Performance: Compare query response times from application monitoring
        before and after encryption. Acceptable degradation: <10% increase
        in query latency.
  - [ ] pg_tde logs: tail -f /var/log/postgresql/postgresql-15.log | grep pg_tde
        Expected: "pg_tde initialized successfully" or similar. No errors.

Rollback:

  - If PostgreSQL fails to start after enabling pg_tde:
    Comment out pg_tde configuration in postgresql.conf, restart PostgreSQL.
    Re-enable after debugging the issue with pg_tde logs.
  - If encryption causes application errors or severe performance degradation:
    Move tables back to the default (unencrypted) tablespace using the same
    ALTER TABLE ... SET TABLESPACE pg_default command. Restart app.
  - ROLLBACK TRIGGER: If application cannot read patient data within 1 hour
    of Step 14, initiate rollback.
  - DATA INTEGRITY: If rollback is required, restore from the pre-encryption
    backup (Step 1 prerequisite) to ensure no data corruption occurred.
  - MAXIMUM ACCEPTABLE DOWNTIME: 4 hours total maintenance window.

Maintenance Window:   Sunday 01:00-05:00 local time.
Communication:
  - Before: Email to IT Manager, CISO, Clinical Operations Director:
    "Scheduled database encryption on EHR system, Sunday 01:00-05:00.
     EHR system will be UNAVAILABLE during this window. Clinical staff
     must use downtime procedures (paper forms) for any urgent needs."
  - Before (48 hours prior): Email to ALL clinical staff: "EHR system
    maintenance Sunday 01:00-05:00. System unavailable. Downtime
    procedures in effect. Contact IT Help Desk with questions."
  - After (success): Email to same recipients: "EHR database encryption
    complete. Patient data now protected at rest with AES-256-GCM.
    System is operational."
  - After (failure): Email + phone to IT Manager, CISO, Clinical Ops
    Director. "EHR encryption failed and was rolled back. System
    operational on previous configuration. Patient data is intact.
    RCA scheduled. New maintenance window TBD."


================================================================================
ACTION #4: DEPLOY LUKS VOLUME ENCRYPTION ON NAS-01 BACKUP STORAGE
================================================================================

Priority:            IMMEDIATE (CRYPTO-003, T12 LUKS Implementation)
System Affected:     nas-01 (10.10.10.60)
Service:             Synology NAS providing SMB/NFS backup storage
Impact:              All backup data (copies of ePHI). LUKS encryption
                     will require volume recreation. ALL EXISTING BACKUPS
                     WILL BE DESTROYED. New encrypted volume must be
                     re-populated with fresh backups.

Prerequisites:
  [ ] All current backups verified as restorable (test restore on a
      separate system before proceeding).
  [ ] New backup jobs defined and tested to run after encryption is
      in place.
  [ ] All users/applications disconnected from NAS shares.
  [ ] LUKS2 tools installed: cryptsetup --version (Expected: 2.x).
  [ ] Maintenance window: Saturday 22:00 - Sunday 06:00 (8-hour window
      due to volume destruction and backup re-seeding).

Steps:

  1. STOP. Verify ALL existing backups are restorable. Test-restore a
     random patient record from the current NAS backup to a separate
     test system. If restore fails, STOP. Fix backup integrity before
     destroying anything.

  2. Disconnect all clients from NAS-01. On the NAS management console,
     verify no active SMB/NFS sessions:
     smbstatus -p (on NAS CLI)
     Expected: No active connections.

  3. Document the current disk layout:
     lsblk -f
     fdisk -l /dev/sda
     Save this output to /backup/pre-encryption-disk-layout.txt

  4. If the NAS has a dedicated backup volume (e.g., /dev/sdb1 mounted
     at /mnt/backups), we encrypt that volume. If the entire NAS data
     partition must be encrypted, identify the correct partition.
     For this playbook, we assume: /dev/sdb1 is the backup volume.

  5. UNMOUNT the backup volume:
     umount /mnt/backups

  6. WARNING: THE NEXT STEP DESTROYS ALL DATA ON /dev/sdb1.
     Confirm you are targeting the correct device:
     blkid /dev/sdb1
     Compare UUID with the pre-documented layout from Step 3.
     If unsure, STOP. Do not proceed.

  7. Format the partition with LUKS2 and AES-256-XTS:
     cryptsetup luksFormat --type luks2 \
       --cipher aes-xts-plain64 --key-size 512 \
       --hash sha512 --pbkdf argon2id \
       --iter-time 5000 /dev/sdb1
     You will be prompted: "Are you sure? (Type uppercase yes):"
     Type: YES
     Enter a strong LUKS passphrase (minimum 20 characters, generated
     by password manager). SAVE THIS PASSPHRASE IN THE PASSWORD MANAGER
     AND IN THE PHYSICAL SAFE (dual control). THIS IS THE RECOVERY KEY.

  8. Open the encrypted volume:
     cryptsetup luksOpen /dev/sdb1 backup_encrypted
     Enter the passphrase from Step 7.

  9. Create a filesystem on the encrypted volume:
     mkfs.ext4 /dev/mapper/backup_encrypted

  10. Mount the encrypted volume:
      mount /dev/mapper/backup_encrypted /mnt/backups

  11. Verify encryption:
      cryptsetup status backup_encrypted
      Expected: "type: LUKS2", "cipher: aes-xts-plain64", "key size: 512 bits"

  12. Verify mount:
      df -h /mnt/backups
      Expected: Filesystem mounted, size matches expected backup volume.

  13. Configure automatic unlock at boot using TPM or Tang/Clevis
      (if available; otherwise, manual passphrase entry at boot is
      acceptable with documented procedure).

  14. Re-create backup directory structure and initiate a fresh full backup:
      /opt/meddefense/backup-scripts/full-backup.sh
      (This script must be verified separately before this maintenance.)

  15. Monitor the backup job. For NAS-01 with historical backups, a full
      re-seed may take several hours. Verify backup job completes without
      errors:
      tail -f /var/log/backup/full-backup-$(date +%Y%m%d).log

Validation:

  - [ ] Encrypted volume shows correct cipher: cryptsetup status
        backup_encrypted | grep cipher
  - [ ] Data is encrypted at rest: strings /dev/sdb1 | grep -i "patient"
        (run on the RAW device, not the mounted filesystem)
        Expected: No plaintext patient data.
  - [ ] Mounted filesystem: Create a test file, unmount, remount with
        passphrase. Verify test file is intact: cat /mnt/backups/test.txt
  - [ ] Backup job completes successfully. Log shows no errors.
  - [ ] Test restore from the new encrypted backup: Restore a random
        file to a test system. Verify content integrity.

Rollback:

  - Pre-encryption data on /dev/sdb1 is DESTROYED by Step 7. There is
    no rollback of the encryption itself. The rollback plan is:
    RESTORE FROM THE PRE-ENCRYPTION BACKUP.
  - If the LUKS passphrase is lost: Use the physical safe copy.
    Ensure dual control access is functional before starting.
  - If the encrypted volume cannot be opened after reboot: Boot from
    rescue media, use cryptsetup luksOpen with the recovery passphrase.
  - ROLLBACK TRIGGER: If the backup job (Step 14) fails to complete
    or verify within the maintenance window, STOP. Do not leave the
    weekend without valid backups. Investigate and retry immediately.
  - MAXIMUM ACCEPTABLE BACKUP GAP: 24 hours. If backups are not running
    by Monday 06:00, escalate to CISO for risk acceptance decision.

Maintenance Window:   Saturday 22:00 - Sunday 06:00 local time.
Communication:
  - Before: Email to IT Manager, CISO, Backup Administrator: "NAS-01
    backup volume encryption, Saturday 22:00 - Sunday 06:00. All backup
    data will be destroyed and re-created. Backups will be unavailable
    during this window. No restore requests can be fulfilled."
  - After (success): Email to same recipients: "NAS-01 backup volume
    encrypted with LUKS2 AES-256-XTS. Fresh full backup completed.
    Backups operational."
  - After (failure): Email + phone to IT Manager, CISO: "NAS-01
    encryption incomplete. Backups are NOT operational. Restoration
    in progress. No restore requests available until resolved."


================================================================================
ACTION #5: ENABLE DICOM TLS BETWEEN MRI WORKSTATION AND PACS SERVER
================================================================================

Priority:            PHASE 1 (CRYPTO-004, T16 Attack 5 - On-Path MITM)
System Affected:     mri-ws-01 (10.10.10.45) and pacs-srv-01 (10.10.10.50)
Service:             DICOM communication on TCP port 11112
Impact:              Medical imaging workflow. DICOM TLS must be enabled
                     on both endpoints simultaneously. Downtime during
                     configuration: estimated 30-60 minutes.

Prerequisites:
  [ ] Internal CA operational and accessible (from T17 Certificate
      Lifecycle, Policy Rule 4).
  [ ] Server certificate issued for pacs-srv-01 (CN: pacs.meddefense.local,
      SAN: DNS:pacs.meddefense.local, IP:10.10.10.50). Key usage: serverAuth.
  [ ] Client certificate issued for mri-ws-01 (CN: mri-ws-01.meddefense.local,
      SAN: DNS:mri-ws-01.meddefense.local, IP:10.10.10.45). Key usage: clientAuth.
  [ ] Both certificates signed by MedDefense Internal CA, SHA-256, RSA 2048-bit.
  [ ] Certificates deployed to respective servers:
      pacs-srv-01: /etc/dicom/certs/server.crt, /etc/dicom/certs/server.key
      mri-ws-01:  /etc/dicom/certs/client.crt, /etc/dicom/certs/client.key
  [ ] Internal CA root certificate deployed to both servers:
      /etc/dicom/certs/internal-ca.crt
  [ ] DICOM application vendor documentation reviewed for TLS configuration.
  [ ] Test DICOM image file ready: /test/test_dicom_tls.dcm
  [ ] Maintenance window: Wednesday 20:00-22:00 local time (non-peak imaging).

Steps:

  1. STOP. Verify both certificates are valid and signed by the Internal CA:
     openssl verify -CAfile /etc/dicom/certs/internal-ca.crt \
       /etc/dicom/certs/server.crt
     openssl verify -CAfile /etc/dicom/certs/internal-ca.crt \
       /etc/dicom/certs/client.crt
     Expected: "OK" for both.

  2. Notify radiology staff: MRI imaging will be unavailable during the
     maintenance window. No new scans should be initiated.

  3. On pacs-srv-01: Enable DICOM TLS in the PACS application configuration.
     The exact method depends on the PACS vendor. Common approach:
     - Edit dicom.ini or similar configuration file.
     - Set: TLS_ENABLED = TRUE
     - Set: TLS_CERTIFICATE = /etc/dicom/certs/server.crt
     - Set: TLS_PRIVATE_KEY = /etc/dicom/certs/server.key
     - Set: TLS_CA_CERTIFICATE = /etc/dicom/certs/internal-ca.crt
     - Set: TLS_CIPHER_SUITES = TLS_AES_256_GCM_SHA384
     - Set: TLS_MIN_VERSION = TLSv1.2
     - Set: TLS_MUTUAL_AUTH = REQUIRED
     - Set: TLS_VERIFY_CLIENT = TRUE

  4. Restart the PACS DICOM service:
     systemctl restart dicom-pacs

  5. Verify PACS service is listening with TLS:
     openssl s_client -connect 10.10.10.50:11112 -tls1_2 \
       -cert /etc/dicom/certs/client.crt \
       -key /etc/dicom/certs/client.key \
       -CAfile /etc/dicom/certs/internal-ca.crt
     Expected: "Verify return code: 0 (ok)" and DICOM A-ASSOCIATE
     response (or connection established, depending on DICOM handshake).

  6. On mri-ws-01: Enable DICOM TLS in the MRI workstation configuration.
     Same approach:
     - Edit DICOM configuration file.
     - Set: TLS_ENABLED = TRUE
     - Set: TLS_CERTIFICATE = /etc/dicom/certs/client.crt
     - Set: TLS_PRIVATE_KEY = /etc/dicom/certs/client.key
     - Set: TLS_CA_CERTIFICATE = /etc/dicom/certs/internal-ca.crt
     - Set: TLS_CIPHER_SUITES = TLS_AES_256_GCM_SHA384
     - Set: TLS_MIN_VERSION = TLSv1.2
     - Set: PACS_SERVER = pacs.meddefense.local
     - Set: PACS_PORT = 11112

  7. Restart the MRI workstation DICOM service:
     systemctl restart dicom-mri-ws

  8. Test DICOM communication with TLS:
     On mri-ws-01, run a DICOM C-ECHO (ping) to the PACS server:
     echoscu -v -aet MRI_WS -aec PACS_SERVER pacs.meddefense.local 11112 \
       --tls --tls-cert /etc/dicom/certs/client.crt \
       --tls-key /etc/dicom/certs/client.key \
       --tls-ca /etc/dicom/certs/internal-ca.crt
     Expected: "C-ECHO Response: Success" (status 0x0000).

  9. Test a full image transmission:
     On mri-ws-01, send a test DICOM image to PACS:
     storescu -v -aet MRI_WS -aec PACS_SERVER pacs.meddefense.local 11112 \
       /test/test_dicom_tls.dcm \
       --tls --tls-cert /etc/dicom/certs/client.crt \
       --tls-key /etc/dicom/certs/client.key \
       --tls-ca /etc/dicom/certs/internal-ca.crt
     Expected: "C-STORE Response: Success" (status 0x0000).

  10. Verify the image is retrievable from PACS:
      On a DICOM viewer workstation, query PACS for the test image.
      Expected: Image displayed correctly.

Validation:

  - [ ] DICOM C-ECHO succeeds over TLS: status 0x0000.
  - [ ] DICOM C-STORE (image send) succeeds over TLS.
  - [ ] Image retrievable and viewable in PACS viewer.
  - [ ] Packet capture (tcpdump) shows encrypted traffic on port 11112:
        tcpdump -i eth0 port 11112 -c 10 -X
        Expected: No plaintext DICOM headers visible. Data is garbled.
  - [ ] MRI workstation can send a real patient scan (perform a test scan
        or resend a recent scan). Radiologist confirms image quality.

Rollback:

  - If C-ECHO fails: Verify certificates are valid, paths are correct,
    and both services have TLS enabled. Check PACS/mri-ws-01 logs for
    TLS errors. Common issue: certificate CN/SAN mismatch. Verify the
    CN matches the hostname used in the connection string.
  - If image transmission fails: Disable TLS on both endpoints, restart
    services, re-test with unencrypted DICOM. Unencrypted DICOM was the
    original state and will function.
  - ROLLBACK TRIGGER: If DICOM C-ECHO fails after 30 minutes of
    troubleshooting, OR if radiologist reports image quality issues
    after TLS is enabled, initiate rollback.
  - POST-ROLLBACK: DICOM traffic returns to cleartext. The MITM
    vulnerability (CRYPTO-004) persists. Schedule follow-up with
    PACS/MRI vendor if TLS compatibility is the issue.
  - MAXIMUM ACCEPTABLE DOWNTIME: 2 hours (entire maintenance window).

Maintenance Window:   Wednesday 20:00-22:00 local time.
Communication:
  - Before: Email to Radiology Manager, Clinical Engineering, IT Manager:
    "DICOM TLS encryption deployment, Wednesday 20:00-22:00. MRI imaging
    will be UNAVAILABLE during this window. No emergency scans can be
    performed. Use alternative imaging modalities if urgent."
  - After (success): Email to same recipients: "DICOM TLS deployed. All
    MRI-to-PACS communication now encrypted. Imaging operational."
  - After (failure): Email + phone to Radiology Manager, IT Manager:
    "DICOM TLS deployment failed and was rolled back. Imaging is
    operational on previous configuration. Unencrypted traffic risk
    accepted pending vendor engagement."


================================================================================
POST-IMPLEMENTATION: GLOBAL VALIDATION CHECKLIST
================================================================================

After ALL 5 actions are complete, run these global validation checks:

[ ] Patient Portal: Access https://patient.meddefense.com from an external
    network. Login. View a test patient record. Expected: No warnings,
    TLS 1.3 padlock, data displays correctly. (Action #1)

[ ] Kerberos: From a domain workstation, run klist. Verify AES256 etype
    on all tickets. Attempt to access a file share. Expected: Access
    granted, no authentication errors. (Action #2)

[ ] Database: Via the EHR application, search for a patient, create a
    new patient record, update an existing record. Expected: All
    operations succeed. Performance within acceptable range. (Action #3)

[ ] Backups: Verify the overnight backup job completed successfully.
    Perform a test restore of a random file from the encrypted NAS-01
    volume. Expected: File restored, content intact. (Action #4)

[ ] DICOM: Radiologist performs a test MRI scan and sends to PACS.
    Image is viewable in PACS viewer. Expected: No errors, image
    quality unchanged. (Action #5)

[ ] SSL Labs: Re-scan patient.meddefense.com. Expected: Grade A+.
    (Action #1 verification ongoing)

[ ] SIEM: Verify all new crypto events (KMS API calls, certificate
    renewals, DICOM TLS connections) are appearing in the SIEM
    dashboard. Expected: Events flowing. (Actions #1, #3, #5)

[ ] Certificate Inventory (T17): Update the certificate inventory with
    the new Let's Encrypt certificate (ID-01), the new internal CA
    certificates for DICOM TLS (IDs 06, 07), and any new service
    certificates. Set expiry alerts. Expected: All new certs tracked.


================================================================================
INCIDENT RESPONSE CONTACT LIST
================================================================================

+------------------+------------------+------------------+------------------+
| Role             | Name             | Phone            | Email            |
+------------------+------------------+------------------+------------------+
| IT Manager       | Robert Kim       | [REDACTED]       | rkim@meddefense  |
+------------------+------------------+------------------+------------------+
| CISO             | James Chen       | [REDACTED]       | jchen@meddefense |
+------------------+------------------+------------------+------------------+
| Security Team    | Sarah Park       | [REDACTED]       | spark@meddefense |
+------------------+------------------+------------------+------------------+
| Security Analyst | [Your Name]      | [REDACTED]       | [your@meddefense]|
+------------------+------------------+------------------+------------------+
| DBA              | [TBD]            | [REDACTED]       | dba@meddefense   |
+------------------+------------------+------------------+------------------+
| Network Engineer | [TBD]            | [REDACTED]       | neteng@meddefense|
+------------------+------------------+------------------+------------------+
| Clinical Eng.    | [TBD]            | [REDACTED]       | clineng@meddefense|
+------------------+------------------+------------------+------------------+
| Radiology Mgr.   | [TBD]            | [REDACTED]       | radiology@meddefense|
+------------------+------------------+------------------+------------------+


================================================================================
REFERENCES
================================================================================

- T10 TLS Configuration Task
- T12 LUKS Implementation Task
- T13 Encryption Levels Recommendation
- T14 Key Management Plan
- T15 Crypto Posture Audit
- T16 Cryptographic Attack Surface
- T17 Certificate Lifecycle Management Plan
- T19 HIPAA Crypto Checkpoint
- PostgreSQL pg_tde Documentation
- DICOM PS3.15: Security and System Management Profiles
- cryptsetup(8) man page
- certbot(1) man page


================================================================================
END OF IMPLEMENTATION PLAYBOOK
================================================================================
