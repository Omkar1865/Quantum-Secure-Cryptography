# Architecture & System Design: Quantum-Secure Cryptography Platform

## 1. Overview
The **Quantum-Secure Cryptography Platform** is a full-stack cybersecurity application integrating a simulated BB84 Quantum Key Distribution (QKD) protocol with AES-256-GCM authenticated encryption, an adaptive key manager, and live security telemetry.

```mermaid
graph TD
    subgraph Frontend ["Client Dashboard (HTML5 / Vanilla CSS / JavaScript)"]
        UI_Dash[Overview Dashboard]
        UI_QKD[BB84 QKD Lab]
        UI_Transfer[File Transfer Workflow]
        UI_KM[Adaptive Key Manager]
        UI_Analytics[Security Analytics]
    end

    subgraph API ["FastAPI Application Gateway"]
        Auth[Auth Service & JWT Sessions]
        Routes[REST Endpoints & Static Files]
    end

    subgraph Core ["Security & Cryptography Modules"]
        QKD[QKDQualityAnalyzer (Qiskit Aer)]
        KM[AdaptiveKeyManager (TTL & Max-Uses)]
        Crypto[RobustEncryptionEngine (AES-256-GCM)]
        Transfer[SecureTransferService]
        Exp[ExperimentRunner]
    end

    subgraph Storage ["Storage Layer"]
        LocalStore[(Ephemeral Temporary Storage)]
        KeyMem[(In-Memory Key Vault & Audit Log)]
    end

    Frontend -->|HTTP / JSON & Multipart| API
    API --> Core
    KM --> KeyMem
    Transfer --> Crypto
    Transfer --> KM
    Transfer --> LocalStore
    QKD --> KM
```

## 2. Component Boundaries

### A. QKD Quality Analyzer (`qkd_analyzer.py`)
- Emulates Alice preparing random qubits in rectilinear (`+`) and diagonal (`x`) bases.
- Simulates quantum channel transmission with optional depolarizing noise and Eve Intercept-Resend eavesdropping.
- Performs Bob measurement and basis reconciliation (sifting).
- **Security Invariant**: Separates error estimation bits from raw secret material. Publicly revealed sample bits are discarded to eliminate leakage.
- Calculates Quantum Bit Error Rate (QBER). Rounds exceeding the threshold (default: 11%) are aborted.

### B. Adaptive Key Manager (`adaptive_key_manager.py`)
- Enforces time-to-live (TTL) expiration and maximum-use limits per key.
- Never discloses raw secret key bytes to the presentation layer or logs.
- Maintains cryptographic fingerprints (SHA-256 prefixes) and audit logs.
- Supports administrative revocations and automatic state transitions (`ACTIVE`, `EXPIRED`, `DEPLETED`, `REVOKED`).

### C. Robust Cryptographic Engine (`crypto_engine.py`)
- Standardizes on authenticated symmetric encryption using **AES-256-GCM**.
- Generates a cryptographically random, unique 96-bit (12-byte) initialization vector/nonce for every file transfer.
- Produces a 128-bit authentication tag ensuring ciphertext integrity.
- Provides backward compatibility with Fernet.

### D. Secure File Transfer Service (`file_transfer_service.py`)
- Validates uploads (size restrictions up to 15MB, filename sanitization, path-traversal prevention).
- Coordinates encryption with active or freshly derived quantum keys.
- Verifies SHA-256 origin checksums against decrypted output before exposing download links.
