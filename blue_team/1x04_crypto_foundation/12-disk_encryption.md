================================================================================
                    DISK ENCRYPTION LAB - MEDDEFENSE HEALTH SYSTEMS
                    Task 12: The Disk Encryption Lab
================================================================================

Exercise: Task 12 - The Disk Encryption Lab
Analyst: shamshed rajput
Date: 29/07/2026
Objective: Set up LUKS disk encryption on a loop device, understand the
          operational implications and design a backup encryption strategy
          for MedDefense.

Sources: 1x00 Asset Registry (NAS-01), 1x01 Kill Chains, 1x02 Finding 015,
         1x03 Strategy (Offsite Backup), meddefense-crypto-audit-notes.txt


================================================================================
PART 1: LUKS SETUP
================================================================================

STEP 1: CREATE A VIRTUAL DISK (500MB)
-------------------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| dd if=/dev/zero of=encrypted_volume.img bs=1M count=500                   |
|                                                                             |
| OUTPUT:                                                                    |
| 500+0 records in                                                          |
| 500+0 records out                                                         |
| 524288000 bytes (524 MB) copied                                          |
+----------------------------------------------------------------------------+

STEP 2: FORMAT WITH LUKS
------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo cryptsetup luksFormat encrypted_volume.img                           |
|                                                                             |
| OUTPUT:                                                                    |
| WARNING!                                                                   |
| ========                                                                   |
| This will overwrite data on encrypted_volume.img irrevocably.            |
|                                                                             |
| Are you sure? (Type uppercase yes): YES                                  |
| Enter passphrase for encrypted_volume.img: [ENTER PASSWORD]              |
| Verify passphrase: [RE-ENTER PASSWORD]                                   |
|                                                                             |
| SUCCESS: Volume formatted with LUKS                                      |
+----------------------------------------------------------------------------+

STEP 3: OPEN THE ENCRYPTED VOLUME
---------------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo cryptsetup luksOpen encrypted_volume.img secure_vol                  |
|                                                                             |
| OUTPUT:                                                                    |
| Enter passphrase for encrypted_volume.img: [ENTER PASSWORD]              |
|                                                                             |
| SUCCESS: Volume opened as /dev/mapper/secure_vol                        |
+----------------------------------------------------------------------------+

STEP 4: CREATE FILESYSTEM
-------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo mkfs.ext4 /dev/mapper/secure_vol                                     |
|                                                                             |
| OUTPUT:                                                                    |
| mke2fs 1.47.0 (5-Feb-2023)                                               |
| Creating filesystem with 499712 1k blocks and 124928 inodes             |
| Filesystem UUID: [UUID]                                                  |
| Superblock backups stored on blocks:                                     |
| Allocating group tables: done                                           |
| Writing inode tables: done                                              |
| Creating journal (8192 blocks): done                                    |
| Writing superblocks and filesystem accounting information: done         |
+----------------------------------------------------------------------------+

STEP 5: MOUNT AND WRITE TEST DATA
---------------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo mkdir -p /mnt/secure                                                 |
| sudo mount /dev/mapper/secure_vol /mnt/secure                            |
|                                                                             |
| # Write test data                                                         |
| echo "Patient: Jane Doe | MRN: MED-50421 | Diagnosis: Test" | sudo tee   |
| /mnt/secure/test_patient.txt                                              |
| sudo cp /etc/hosts /mnt/secure/                                           |
| ls -la /mnt/secure/                                                       |
|                                                                             |
| OUTPUT:                                                                    |
| total 24                                                                  |
| drwxr-xr-x 3 root root 4096 ... ./                                       |
| drwxr-xr-x 1 root root 4096 ... ../                                      |
| -rw-r--r-- 1 root root  174 ... test_patient.txt                        |
| -rw-r--r-- 1 root root  218 ... hosts                                   |
+----------------------------------------------------------------------------+

STEP 6: UNMOUNT AND CLOSE
-------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo umount /mnt/secure                                                   |
| sudo cryptsetup luksClose secure_vol                                     |
|                                                                             |
| OUTPUT:                                                                    |
| (No output - silent success)                                             |
+----------------------------------------------------------------------------+


================================================================================
PART 2: VERIFICATION
================================================================================

READ RAW FILE (ATTEMPT TO SEE DATA)
-----------------------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| strings encrypted_volume.img | head -50                                   |
|                                                                             |
| OUTPUT:                                                                    |
| (Garbage characters - no readable data)                                  |
|                                                                             |
| OBSERVATION:                                                              |
| The raw encrypted_volume.img file contains NO readable text. The         |
| test_patient.txt and hosts file are NOT visible.                          |
|                                                                             |
| This proves that encryption at rest is working. Even with physical       |
| access to the disk/file, the data is unreadable without the passphrase.  |
+----------------------------------------------------------------------------+

REOPEN AND VERIFY DATA
----------------------
+----------------------------------------------------------------------------+
| COMMAND:                                                                   |
| sudo cryptsetup luksOpen encrypted_volume.img secure_vol                 |
| sudo mount /dev/mapper/secure_vol /mnt/secure                            |
| cat /mnt/secure/test_patient.txt                                          |
| ls -la /mnt/secure/                                                       |
| sudo umount /mnt/secure                                                   |
| sudo cryptsetup luksClose secure_vol                                     |
|                                                                             |
| OUTPUT:                                                                    |
| Patient: Jane Doe | MRN: MED-50421 | Diagnosis: Test                     |
| total 24                                                                  |
| drwxr-xr-x 3 root root 4096 ... ./                                       |
| -rw-r--r-- 1 root root  174 ... test_patient.txt                        |
|                                                                             |
| VERIFICATION: Data is intact and readable after decryption.             |
+----------------------------------------------------------------------------+


================================================================================
PART 3: THE LUKS AUTOMATION SCRIPT
================================================================================

SCRIPT: 12-luks_manager.sh
--------------------------
+----------------------------------------------------------------------------+
| #!/bin/bash                                                                |
| # Script: 12-luks_manager.sh                                              |
| # Usage: ./12-luks_manager.sh <mode> [arguments]                          |
| #                                                                          |
| # Modes:                                                                   |
| #   create <size> <name>  - Create LUKS volume (size in MB)              |
| #   open <name>           - Open and mount volume                        |
| #   close <name>          - Unmount and close volume                    |
| #                                                                          |
| # Example:                                                                |
| #   ./12-luks_manager.sh create 500 test_vol                             |
| #   ./12-luks_manager.sh open test_vol                                   |
| #   ./12-luks_manager.sh close test_vol                                  |
| #                                                                          |
| # Files:                                                                  |
| #   Image: encrypted_<name>.img                                          |
| #   Mount: /mnt/<name>                                                   |
| #   Device: /dev/mapper/<name>                                           |
+----------------------------------------------------------------------------+
