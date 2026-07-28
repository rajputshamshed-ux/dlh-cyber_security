================================================================================
                    KEY EXCHANGE - MEDDEFENSE HEALTH SYSTEMS
                    Task 4: The Key Exchange
================================================================================

Exercise: Task 4 - The Key Exchange
Analyst: shamshed rajput
Date: 28/07/2026
Objective: Simulate a Diffie-Hellman key exchange with OpenSSL to understand
          how two parties agree on a shared secret over an insecure channel,
          then analyze the man-in-the-middle vulnerability that certificates
          exist to solve.

Sources: meddefense-crypto-audit-notes.txt, 1x00 Threat Landscape


================================================================================
PART 1: THE DH SIMULATION
================================================================================

STEP 1: GENERATE SHARED DH PARAMETERS
-------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl dhparam -out dhparams.pem 2048           |
+------------------+--------------------------------------------------+
| Output           | Generating DH parameters, 2048 bit long safe     |
|                  | prime, generator 2                               |
|                  | This is going to take a long time...            |
|                  | [DH parameters generated]                        |
+------------------+--------------------------------------------------+
| File Created     | dhparams.pem                                     |
+------------------+--------------------------------------------------+
| Explanation      | Shared parameters (prime p and generator g)      |
|                  | are created. Both parties use the SAME           |
|                  | parameters. This is public information.          |
+------------------+--------------------------------------------------+

STEP 2: ALICE GENERATES HER KEY PAIR
------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl genpkey -paramfile dhparams.pem -out     |
| (Private Key)    | alice_private.pem                                |
+------------------+--------------------------------------------------+
| Output           | ................++++++                           |
|                  | ................++++++                           |
+------------------+--------------------------------------------------+
| Command          | openssl pkey -in alice_private.pem -pubout -out  |
| (Public Key)     | alice_public.pem                                 |
+------------------+--------------------------------------------------+

STEP 3: BOB GENERATES HIS KEY PAIR
----------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl genpkey -paramfile dhparams.pem -out     |
| (Private Key)    | bob_private.pem                                  |
+------------------+--------------------------------------------------+
| Output           | ................++++++                           |
|                  | ................++++++                           |
+------------------+--------------------------------------------------+
| Command          | openssl pkey -in bob_private.pem -pubout -out    |
| (Public Key)     | bob_public.pem                                   |
+------------------+--------------------------------------------------+

STEP 4: ALICE DERIVES SHARED SECRET (USING BOB'S PUBLIC KEY)
-------------------------------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl pkeyutl -derive -inkey alice_private.pem |
|                  | -peerkey bob_public.pem -out alice_secret.bin    |
+------------------+--------------------------------------------------+
| Output           | No output (silent success)                       |
+------------------+--------------------------------------------------+

STEP 5: BOB DERIVES SHARED SECRET (USING ALICE'S PUBLIC KEY)
-------------------------------------------------------------
+------------------+--------------------------------------------------+
| Command          | openssl pkeyutl -derive -inkey bob_private.pem   |
|                  | -peerkey alice_public.pem -out bob_secret.bin    |
+------------------+--------------------------------------------------+
| Output           | No output (silent success)                       |
+------------------+--------------------------------------------------+

STEP 6: COMPARE THE TWO SECRETS
-------------------------------
+------------------+--------------------------------------------------+
| Command          | diff alice_secret.bin bob_secret.bin             |
+------------------+--------------------------------------------------+
| Output           | (No output - files are identical)                |
+------------------+--------------------------------------------------+
| Command          | hexdump -C alice_secret.bin | head -4           |
|                  | hexdump -C bob_secret.bin | head -4            |
+------------------+--------------------------------------------------+
| Result           | Both files contain the SAME 256-byte shared      |
|                  | secret. Alice and Bob now have the same key!     |
+------------------+--------------------------------------------------+


================================================================================
PART 2: THE EXPLANATION (FOR THE CFO)
================================================================================

+----------------------------------------------------------------------------+
| EXPLANATION FOR ROBERT KIM (CFO)                                           |
|                                                                             |
| Imagine Alice and Bob are in separate rooms and need to agree on a color   |
| without anyone else knowing it. They both have a public color (the DH     |
| parameters) that everyone can see. Alice picks a secret color (her        |
| private key), mixes it with the public color, and sends the result to     |
| Bob. Bob does the same. When they mix their private colors with each     |
| other's public result, they both end up with the EXACT same color         |
| (the shared secret). Eve, who was listening, only saw the public colors   |
| and the results of the mixing. She never saw the private colors, so she   |
| cannot recreate the final color. This is the magic of Diffie-Hellman:    |
| two parties who have never met can agree on a secret key without ever    |
| sending the key itself over the network. The math guarantees that Alice  |
| and Bob get the same result, while Eve gets nothing useful.              |
+----------------------------------------------------------------------------+


================================================================================
PART 3: THE MITM ATTACK
================================================================================

WHAT IS A MAN-IN-THE-MIDDLE (MITM) ATTACK?
-------------------------------------------
+----------------------------------------------------------------------------+
| Eve does not just listen - she INTERCEPTS and MODIFIES.                   |
|                                                                             |
| Alice sends her public key to Bob. Eve intercepts it.                     |
| Eve creates her OWN key pair and sends her public key to Bob.            |
| Bob thinks he is talking to Alice, but he is actually talking to Eve.     |
| Eve does the SAME with Alice.                                             |
|                                                                             |
| Result:                                                                    |
| - Alice and Eve share secret #1                                            |
| - Bob and Eve share secret #2                                              |
| - Alice and Bob think they share a secret (they don't)                    |
| - Eve can decrypt, read, and re-encrypt all traffic                      |
+----------------------------------------------------------------------------+

VISUAL DIAGRAM
--------------
+----------------------------------------------------------------------------+
| WITHOUT MITM PROTECTION:                                                   |
|                                                                             |
| Alice ──[public key]───────────────► Bob                                 |
|    │                                    │                                  |
|    └───[derive shared secret]───────────┘                                  |
|                                                                             |
| WITH MITM (Eve intercepts):                                                 |
|                                                                             |
| Alice ──[public key]──► Eve ──[Eve's public key]──► Bob                 |
|    │                    │                    │                             |
|    └──[secret A-E]─────┘                    └──[secret E-B]──────────────┘ |
|                                                                             |
| Eve can read everything.                                                    |
+----------------------------------------------------------------------------+

MEDDEFENSE SCENARIO
-------------------
+----------------------------------------------------------------------------+
| CONNECTION TO MEDDEFENSE:                                                   |
|                                                                             |
| The VPN tunnel between Central and Westside uses IPSec with Diffie-       |
| Hellman key exchange. If the tunnel does NOT use certificate-based        |
| authentication, an attacker on the network path could:                    |
|                                                                             |
| 1. Intercept the DH key exchange between Central and Westside            |
| 2. Act as a proxy between both ends                                      |
| 3. Establish TWO separate encrypted tunnels (Central ↔ Attacker,        |
|    Westside ↔ Attacker)                                                  |
| 4. Decrypt, read, and modify ALL traffic between sites                  |
| 5. This includes patient data, PHI, and credentials                     |
|                                                                             |
| CERTIFICATES PREVENT THIS:                                                 |
|                                                                             |
| Certificates provide AUTHENTICATION. When Alice and Bob exchange         |
| public keys, they also present a certificate that proves their identity. |
| Eve cannot impersonate Alice because she does not have Alice's           |
| private key. The certificate is signed by a trusted Certificate         |
| Authority (CA) that both parties trust.                                 |
|                                                                             |
| With certificates:                                                         |
| - Alice's certificate proves she is REALLY Alice                         |
| - Bob's certificate proves he is REALLY Bob                             |
| - Eve cannot impersonate either party                                    |
| - The shared secret is actually shared between Alice and Bob            |
+----------------------------------------------------------------------------+


================================================================================
SUMMARY TABLE
================================================================================

+----------+------------------+--------------------------------------------------+
| Step     | Command          | Purpose                                          |
+----------+------------------+--------------------------------------------------+
| 1        | openssl dhparam  | Generate shared parameters (public)              |
|          | -out dhparams    |                                                  |
+----------+------------------+--------------------------------------------------+
| 2        | openssl genpkey  | Alice generates her private key                  |
|          | -paramfile       |                                                  |
+----------+------------------+--------------------------------------------------+
| 3        | openssl pkey     | Alice extracts her public key                    |
|          | -pubout          |                                                  |
+----------+------------------+--------------------------------------------------+
| 4        | openssl genpkey  | Bob generates his private key                    |
|          | -paramfile       |                                                  |
+----------+------------------+--------------------------------------------------+
| 5        | openssl pkey     | Bob extracts his public key                      |
|          | -pubout          |                                                  |
+----------+------------------+--------------------------------------------------+
| 6        | openssl pkeyutl  | Alice derives shared secret using Bob's public  |
|          | -derive          | key                                               |
+----------+------------------+--------------------------------------------------+
| 7        | openssl pkeyutl  | Bob derives shared secret using Alice's public  |
|          | -derive          | key                                               |
+----------+------------------+--------------------------------------------------+
| 8        | diff             | Compare the two secrets (should be identical)    |
+----------+------------------+--------------------------------------------------+


================================================================================
REFERENCES
================================================================================

- meddefense-crypto-audit-notes.txt
- OpenSSL man pages: man openssl-dhparam, man openssl-genpkey, man openssl-pkeyutl
- NIST SP 800-56A: Recommendation for Pair-Wise Key Establishment

Cross-References:
- Crypto Inventory (1x04 T0)
- Asymmetric Analysis (1x04 T2)


================================================================================
END OF KEY EXCHANGE REPORT
================================================================================
