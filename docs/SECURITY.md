# Security Model, Threat Analysis & Assumptions

## 1. Threat Model

The platform addresses security considerations across the quantum simulation and classical network layers:

| Vector | Threat | Mitigation |
|---|---|---|
| **Eavesdropping (Quantum)** | Eve intercepts single qubits on the channel. | Quantum No-Cloning theorem dictates Eve must measure in an assumed basis, disturbing ~25% of sifted bits. QBER threshold detects Eve and aborts key derivation. |
| **Ciphertext Tampering** | Attacker alters ciphertext bits in transit. | Authenticated Encryption with Associated Data (AES-256-GCM) calculates an HMAC/GHASH tag. Any modified byte causes immediate authentication rejection. |
| **Nonce Reuse Attack** | Nonce reuse in AES-GCM allows key recovery or forgery. | A fresh 96-bit cryptographically secure pseudorandom nonce (`secrets.token_bytes(12)`) is generated per encryption. |
| **Key Reuse & Staleness** | Reusing symmetric keys across many files risks cryptanalysis. | The Adaptive Key Manager enforces strict TTL (time-based) and Max-Uses (count-based) lifecycle policies. |
| **Path Traversal / Arbitrary File Overwrite** | Malicious filenames in upload forms (e.g. `../../etc/passwd`). | Filenames are strictly sanitized to alphanumeric basenames, stored in a managed `storage/` directory, and mapped via unique transfer IDs. |
| **Information Leakage via Error Sampling** | Revealing sifted bits during QBER check leaks key material. | The sample bits compared publicly for error estimation are discarded. Only remaining unrevealed bits are retained. |

## 2. Key Handling & Entropy Requirements
- **Entropy Reality**: Applying SHA-256 or HKDF to a short key material does not create additional secret entropy. The analyzer checks that the number of unrevealed, sifted secret bits meets minimum length constraints before derivation.
- **Memory Erasure in Python**: In CPython, garbage collection and string immutability mean secret byte arrays can linger in RAM until deallocated. To reduce this window, revoked keys explicitly drop references (`record._raw_key = None`).

## 3. Assumptions & Academic Disclaimers
1. **Simulation vs Hardware**: This software simulates the BB84 protocol using Qiskit Aer statevectors and random number generators. It does not interface with physical single-photon avalanche diodes (SPADs) or pulsed laser diodes.
2. **Authenticated Classical Channel**: The BB84 sifting phase assumes Alice and Bob communicate their basis choices over an authenticated classical channel (e.g., using pre-shared authentication tags).
