# Implementation of a Trustless Communication System Using HMAC and Zero-Knowledge Proofs

This project focuses on implementing a trustless communication system by integrating the Hash-based Message Authentication Code (HMAC) algorithm with zero-knowledge proofs (ZKPs) using elliptic curve cryptography. The system ensures data integrity, authenticity, and privacy without revealing any sensitive information or relying on a trusted third party.

## Core Concept and Working

### HMAC Generation

The HMAC algorithm is used to generate a unique hash for each message. This is done using a secret key shared between the communicating parties.
The HMAC ensures that the message has not been altered and verifies the sender's identity.

### Zero-Knowledge Proofs (ZKPs) Implementation

#### Original Protocol

Given an elliptic curve \( E \) over a field \( F_n \), a generator point \( G \in E/F_n \), and \( B \in E/F_n \), the prover (P) wants to prove knowledge of \( x \) such that \( B = x \cdot G \) without revealing \( x \).

**Steps:**

1. P generates a random \( r \in F_n \) and computes \( A = r \cdot G \).
2. P sends \( A \) to the verifier (V).
3. V flips a coin and informs P of the outcome.
4. If HEADS, P sends \( r \) to V, who checks that \( r \cdot G = A \).
5. If TAILS, P sends \( m = x + r \mod n \) to V, who checks that \( m \cdot G = A + B \).

These steps are repeated until V is convinced that P knows \( x \) with a high probability.

#### Improved Protocol (Elliptic Curve Schnorr’s Protocol)

Given \( E \) over a field \( F_n \), a generator \( G \in E/F_n \), and \( B \in E/F_n \), P wants to prove knowledge of \( x \) such that \( B = x \cdot G \) without revealing \( x \).

**Steps:**

1. P generates a random \( r \in F_n \) and computes \( A = r \cdot G \).
2. P sends \( A \) to V.
3. V computes a random \( c = \text{HASH}(G, B, A) \) and sends \( c \) to P.
4. P computes \( m = r + c \cdot x \mod n \) and sends \( m \) to V.
5. V checks that \( P = m \cdot G - c \cdot B = r \cdot G = A \).

### Integration with HMAC

By combining HMAC with these zero-knowledge proofs, the system can verify the integrity and authenticity of messages without revealing the actual data or the secret key.
The verifier can trust that the message is genuine and untampered without knowing the content, ensuring robust security and privacy.

### Benefits

- **Security:** Ensures data integrity and authenticity using HMACs.
- **Privacy:** Uses zero-knowledge proofs to maintain data confidentiality.
- **Trustlessness:** Eliminates the need for a trusted third party, reducing central points of failure.

### Applications

- **Secure Messaging:** Protects messages exchanged on the Ethereum network.
- **Smart Contracts:** Secures contract interactions.
- **Decentralized Applications (DApps):** Enhances user data security and privacy in DApps.

### Reference Research Papers

- [Overview and Applications of Zero Knowledge Proof (ZKP)](https://d1wqtxts1xzle7.cloudfront.net/63348598/Overview-and-Applications-of-Zero-Knowledge-Proof-ZKP20200518-20172-1ev7qkn-libre.pdf?1589809015=&response-content-disposition=inline%3B+filename%3DOverview_and_Applications_of_Zero_Knowle.pdf&Expires=1716305949&Signature=OaeV7BIxdv8peMeHFdzhXxRagctDLQENlAwmOG87BXNzUyfec09q3NTjBJbaNESHNYv83UonuxwR1JyKl5l85b4QcpQVqLw8d2UGzUvvpFC8RBRIN22VPEc~kjPUaEDvFz~qHJdRa2dA2sVNU9OWxf4igl6X8zgQ6AcGLIjRcAYVjTzPvl5M3akV88PlwVqJcxDKb42DG6TF6x4qgN-JquQ9aZP4aoozW0Ucxzze-7~KqidgJuf-ljzNBkDKAMK07WU~-8EbrzudXO5OrtnGTdLaW4jhugCq63yUvMmcP8rXh-FVTZN3vCxQWAS3w-GR64YJRNg5259V1zkffHhOHg__&Key-Pair-Id=APKAJLOHF5GGSLRBV4ZA)

- [HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/pdfrfc/rfc2104.txt.pdf)

- [Elliptic Curve Based Zero Knowledge Proofs and Their Applicability on Resource Constrained Devices](https://arxiv.org/pdf/1107.1626)



