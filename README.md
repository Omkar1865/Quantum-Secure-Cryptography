# Quantum-Secure Cryptography Platform
### BB84 QKD Simulation, Adaptive Key Management & Authenticated AES-256-GCM Transfer

A full-stack, research-grade cybersecurity platform demonstrating Quantum Key Distribution (QKD) principles, basis reconciliation, Quantum Bit Error Rate (QBER) analysis, lifecycle-controlled key management, and authenticated per-file AES-256-GCM encryption.

---

## Key Features

1. **Light-Theme Cyber Dashboard**: Modern, clean, responsive UI built with semantic HTML, CSS design tokens, and modular vanilla JavaScript.
2. **BB84 QKD Simulation (Qiskit Aer)**:
   - Configurable qubit count (16 to 128), channel noise, and basis choices.
   - Separate error-estimation sampling (revealed sample bits are discarded to eliminate information leakage).
   - QBER threshold validation against eavesdropping and channel disturbance.
3. **Adaptive Key Manager**:
   - Time-to-Live (TTL) expiration and maximum-use policies.
   - In-memory key tracking, SHA-256 fingerprinting, and audit logging.
   - Strict avoidance of secret exposure in browser, API responses, or logs.
4. **Authenticated AES-256-GCM File Transfer**:
   - Unique 96-bit nonce generated per file.
   - 128-bit authentication tag with integrity verification before allowing download.
   - Sender-to-receiver workflow with upload validation (max 15MB) and path traversal protection.
5. **Security Analytics & Benchmarks**:
   - Multi-trial channel noise impact analysis.
   - Intercept-Resend (Eve) attack detection rate measurements (~25% theoretical disturbance).
   - AES-256-GCM vs Fernet encryption throughput benchmarks.
6. **Production-Ready & Tested**:
   - Full FastAPI backend with JWT session authentication.
   - 15 automated pytest suites covering simulation, crypto, key manager, transfer, and API endpoints.
   - Ready for one-click deployment on Render via `render.yaml`.

---

## Project Structure

```
├── adaptive_key_manager.py     # Adaptive Key Manager with TTL & max-use controls
├── auth_service.py             # User authentication, bcrypt hashing, JWT tokens
├── crypto_engine.py            # AES-256-GCM authenticated encryption engine
├── experiment_runner.py        # Automated reproducible security benchmarks
├── file_transfer_service.py    # Secure sender-to-receiver file transfer pipeline
├── main.py                     # FastAPI application routes & static server
├── qkd_analyzer.py             # Qiskit Aer BB84 protocol simulation & QBER analyzer
├── requirements.txt            # Python dependencies
├── render.yaml                 # Render Blueprint configuration
├── .env.example                # Safe environment variable template
├── docs/
│   ├── ARCHITECTURE.md         # System design and Mermaid diagrams
│   ├── SECURITY.md             # Threat model, assumptions, and limits
│   ├── EXPERIMENTS.md          # Benchmark results & trial measurements
│   └── DEPLOYMENT.md           # Render deployment steps
├── static/                     # Light-theme frontend assets
│   ├── index.html              # Single-page application dashboard
│   ├── styles.css              # Modern light-theme design system
│   └── app.js                  # Frontend workflow controller
└── tests/
    ├── test_comprehensive.py   # Full test suite (QKD, Crypto, KM, Transfer, API)
    └── test_core.py            # Baseline compatibility tests
```

---

## Local Installation & Execution

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- `pip` package manager

### 2. Setup Virtual Environment
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at: **`http://127.0.0.1:8000`**

- **Default Username**: `admin`
- **Default Password**: `QuantumAdmin2026!`

---

## Running Automated Tests

Run the complete test suite with pytest:
```bash
pytest tests/ -v
```

---


## Academic & Experimental Notice
This software utilizes Qiskit Aer statevector circuits to simulate the BB84 protocol. It demonstrates quantum key sifting, error estimation, and cryptographic key usage. It is not a hardware optical quantum device.
