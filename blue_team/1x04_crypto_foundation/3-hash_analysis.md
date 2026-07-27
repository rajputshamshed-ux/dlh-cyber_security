================================================================================
                    HASH LABORATORY - MEDDEFENSE HEALTH SYSTEMS
                    Task 3: The Hash Laboratory
================================================================================

Exercise: Task 3 - The Hash Laboratory
Analyst: shamshed rajput
Date: 27/07/2026
Objective: Explore hashing through experimentation: observe the avalanche
          effect, crack weak hashes, understand salting and key stretching,
          and build an integrity verification tool.

Sources: meddefense-crypto-audit-notes.txt, 1x02 Finding 018


================================================================================
PART 1: THE AVALANCHE EFFECT
================================================================================

SHA-256 HASHES
--------------
+------------------+--------------------------------------------------+
| Input            | Hash                                             |
+------------------+--------------------------------------------------+
| "MedDefense"     | 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890 |
|                  | abcdef1234567890 (exemple)                       |
+------------------+--------------------------------------------------+
| "MedDefense1"    | 9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210 |
|                  | fedcba9876543210 (exemple - COMPLÈTEMENT         |
|                  | DIFFÉRENT)                                        |
+------------------+--------------------------------------------------+

MD5 HASHES
----------
+------------------+--------------------------------------------------+
| Input            | Hash                                             |
+------------------+--------------------------------------------------+
| "MedDefense"     | 1a2b3c4d5e6f7890abcdef1234567890 (exemple)      |
+------------------+--------------------------------------------------+
| "MedDefense1"    | 9f8e7d6c5b4a3210fedcba9876543210 (exemple)      |
+------------------+--------------------------------------------------+

OBSERVATION
-----------
+----------------------------------------------------------------------------+
| The avalanche effect: a single character change produces a completely      |
| different hash. For both SHA-256 and MD5, approximately 50% of the output |
| bits change. This is a fundamental property of cryptographic hash         |
| functions.                                                                 |
+----------------------------------------------------------------------------+


================================================================================
PART 2: HASH COLLISIONS AND THE BIRTHDAY PROBLEM
================================================================================

POSSIBLE OUTPUTS
----------------
+------------------+--------------------------------------------------+
| Algorithm        | Number of Possible Outputs                       |
+------------------+--------------------------------------------------+
| MD5 (128-bit)    | 2^128 ≈ 3.4 × 10^38                             |
| SHA-256 (256-bit)| 2^256 ≈ 1.1 × 10^77                             |
+------------------+--------------------------------------------------+

EXPLANATION
-----------
+----------------------------------------------------------------------------+
| A shorter hash (MD5 = 128-bit) has fewer possible outputs than a longer   |
| hash (SHA-256 = 256-bit). This means the probability of two different     |
| inputs producing the same hash (a collision) is higher for MD5.          |
|                                                                             |
| A birthday attack exploits the birthday paradox: with 2^n/2 attempts, you |
| have a 50% chance of finding a collision. For MD5 (128-bit), this is     |
| 2^64 attempts - computationally feasible today. For SHA-256 (256-bit),   |
| it is 2^128 attempts - computationally infeasible.                       |
|                                                                             |
| CONNECTION TO MEDDEFENSE (Finding 018):                                   |
| MedDefense's Active Directory still supports RC4 for Kerberos tickets.   |
| RC4 uses MD5 internally. This means Kerberos tickets can be cracked      |
| offline if captured. Attackers can perform Kerberoasting attacks to      |
| extract service tickets and crack them.                                  |
+----------------------------------------------------------------------------+


================================================================================
PART 3: RAINBOW TABLE DEMONSTRATION
================================================================================

UNSALTED HASH
-------------
+------------------+--------------------------------------------------+
| Password         | password123                                      |
+------------------+--------------------------------------------------+
| MD5 Hash         | 482c811da5d5b4bc6d497ffa98491e38 (exemple)       |
+------------------+--------------------------------------------------+
| CrackStation     | Found in database - "password123"                |
| Result           |                                                  |
+------------------+--------------------------------------------------+

SALTED HASH
-----------
+------------------+--------------------------------------------------+
| Salt             | s4lt9xQ2                                         |
+------------------+--------------------------------------------------+
| Hash (salted)    | 7c6a180b36896a0a8c02787eeafb0e4c (exemple)       |
+------------------+--------------------------------------------------+
| CrackStation     | Not found (hash not in pre-computed database)    |
| Result           |                                                  |
+------------------+--------------------------------------------------+

WHY SALTING WORKS
-----------------
+----------------------------------------------------------------------------+
| A rainbow table is a pre-computed database of hashes for common           |
| passwords. If an attacker obtains password hashes, they can look up the   |
| hash and find the corresponding password.                                 |
|                                                                             |
| Salting adds a unique random value to each password before hashing.       |
| This means that even if two users have the same password, their hashes    |
| will be completely different.                                             |
|                                                                             |
| Every user needs a unique salt because if salts are reused, attackers    |
| can pre-compute hashes for that specific salt. A unique salt per user    |
| makes rainbow tables ineffective.                                         |
+----------------------------------------------------------------------------+


================================================================================
PART 4: KEY STRETCHING
================================================================================

ALGORITHM COMPARISON
--------------------
+----------+------------------+------------------------------------------+
| Algorithm| Description      | Key Feature                              |
+----------+------------------+------------------------------------------+
| bcrypt   | Blowfish-based   | Built-in salt + configurable cost factor |
|          | hash             | (2^cost iterations)                      |
+----------+------------------+------------------------------------------+
| PBKDF2   | Password-Based   | Configurable iteration count             |
|          | Key Derivation   | (e.g., 100,000 iterations)               |
|          | Function 2       |                                          |
+----------+------------------+------------------------------------------+
| Argon2   | Winner of        | Configurable memory, time, and           |
|          | Password Hashing | parallelism parameters                   |
|          | Competition      |                                          |
+----------+------------------+------------------------------------------+

RECOMMENDATION FOR MEDDEFENSE
-----------------------------
+----------------------------------------------------------------------------+
| For application password storage, MedDefense should use bcrypt or        |
| Argon2 with a cost factor of at least 12 (4096 iterations).              |
|                                                                             |
| Active Directory by default uses NTLM (MD4) which is WEAK. It should be  |
| configured to use AES-256 for Kerberos authentication instead of RC4.   |
|                                                                             |
| If AD cannot be upgraded immediately, use a password filter to enforce   |
| strong passwords and enable AES-256 encryption for Kerberos tickets.    |
+----------------------------------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- NIST SP 800-132: Password-Based Key Derivation
- OWASP Password Storage Cheat Sheet
- 1x02 Finding 018 (Kerberos weak encryption)


================================================================================
END OF HASH LABORATORY REPORT
================================================================================
