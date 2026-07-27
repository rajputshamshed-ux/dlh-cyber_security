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
| "MedDefense"     | 39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03 |
|                  | aca51db35c8671098                                |
+------------------+--------------------------------------------------+
| "MedDefense1"    | 97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bd |
|                  | b616732ba9bf17b92                                |
+------------------+--------------------------------------------------+

COMMANDS:
+----------------------------------------------------------------------------+
| echo -n "MedDefense" | sha256sum                                        |
| echo -n "MedDefense1" | sha256sum                                       |
+----------------------------------------------------------------------------+

MD5 HASHES
----------
+------------------+--------------------------------------------------+
| Input            | Hash                                             |
+------------------+--------------------------------------------------+
| "MedDefense"     | 75d47fd4b4d183456d0f98fd9ba6ae4d                  |
+------------------+--------------------------------------------------+
| "MedDefense1"    | 0d2aed72043f78c2935e61ba8520306d                  |
+------------------+--------------------------------------------------+

COMMANDS:
+----------------------------------------------------------------------------+
| echo -n "MedDefense" | md5sum                                           |
| echo -n "MedDefense1" | md5sum                                          |
+----------------------------------------------------------------------------+

OBSERVATION
-----------
+----------------------------------------------------------------------------+
| The avalanche effect: a single character change (adding "1") produces a   |
| completely different hash. For both SHA-256 and MD5, the output is        |
| entirely different, demonstrating that approximately 50% of the output    |
| bits change. This is a fundamental property of cryptographic hash         |
| functions.                                                                 |
+----------------------------------------------------------------------------+

CHARACTER COMPARISON
--------------------
+----------------------------------------------------------------------------+
| SHA-256: The two 64-character hashes share NO visible pattern.           |
| MD5:     The two 32-character hashes share NO visible pattern.           |
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
| Command          | echo -n "password123" | md5sum                   |
+------------------+--------------------------------------------------+
| MD5 Hash         | 482c811da5d5b4bc6d497ffa98491e38                  |
+------------------+--------------------------------------------------+
| CrackStation     | Go to crackstation.net and search the hash       |
| Result           | The hash is found in the database. The password  |
|                  | is "password123". This shows that unsalted MD5   |
|                  | hashes are easily cracked using rainbow tables. |
+------------------+--------------------------------------------------+

SALTED HASH
-----------
+------------------+--------------------------------------------------+
| Salt             | s4lt9xQ2                                         |
+------------------+--------------------------------------------------+
| Password         | password123                                      |
+------------------+--------------------------------------------------+
| Command          | echo -n "s4lt9xQ2:password123" | md5sum          |
+------------------+--------------------------------------------------+
| Salted MD5 Hash  | 6d537fa53f1db2c22b0451ef4ef9fbe8                  |
+------------------+--------------------------------------------------+
| CrackStation     | Go to crackstation.net and search the hash       |
| Result           | The hash is NOT found in the database. This      |
|                  | demonstrates that salting defeats rainbow tables |
|                  | because the salt makes the hash unique.         |
+------------------+--------------------------------------------------+

WHY SALTING WORKS
-----------------
+----------------------------------------------------------------------------+
| A rainbow table is a pre-computed database of hashes for common           |
| passwords. If an attacker obtains password hashes, they can look up the   |
| hash on crackstation.net and find the corresponding password.             |
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
- crackstation.net - Online hash cracking tool


================================================================================
END OF HASH LABORATORY REPORT
================================================================================
