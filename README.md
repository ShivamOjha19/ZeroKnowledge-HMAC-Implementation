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
