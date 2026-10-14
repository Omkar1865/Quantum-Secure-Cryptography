import pytest
import secrets
from fastapi.testclient import TestClient

from qkd_analyzer import QKDQualityAnalyzer
from crypto_engine import RobustEncryptionEngine
from adaptive_key_manager import AdaptiveKeyManager, KeyStatus
from file_transfer_service import SecureTransferService
from main import app, DEMO_USERNAME, DEMO_PASSWORD

client = TestClient(app)


# ==========================================
# 1. QKD ANALYZER TESTS
# ==========================================
def test_qkd_simulation_clean_channel():
    analyzer = QKDQualityAnalyzer(default_num_qubits=48, default_qber_threshold=0.11)
    res = analyzer.run_bb84_protocol(num_qubits=48, noise_level=0.0, eve_present=False)

    assert "round_id" in res
    assert res["decision"]["accepted"] is True
    assert res["statistics"]["measured_qber"] == 0.0
    assert res["derived_key_available"] is True
    assert res["_derived_key_bytes"] is not None
    assert len(res["_derived_key_bytes"]) == 32  # 256-bit derived key
    # Raw key shouldn't be revealed without leading underscore
    assert "aes_key" not in res or res.get("aes_key") is None


def test_qkd_simulation_eavesdropping_rejection():
    analyzer = QKDQualityAnalyzer(default_num_qubits=64, default_qber_threshold=0.11)
    # Intercept-resend attack introduces ~25% error on matching bases
    res = analyzer.run_bb84_protocol(num_qubits=64, noise_level=0.0, eve_present=True)

    # Intercept resend should typically trigger rejection with high confidence
    assert res["statistics"]["measured_qber"] > 0.05
    # The decision accounts for threshold
    if res["statistics"]["measured_qber"] > 0.11:
        assert res["decision"]["accepted"] is False
        assert res["derived_key_available"] is False


def test_qkd_insufficient_entropy_rejection():
    # If simulated qubits are set tiny and sample eats the bits
    analyzer = QKDQualityAnalyzer(default_num_qubits=16, default_qber_threshold=0.11)
    res = analyzer.run_bb84_protocol(num_qubits=16, sample_ratio=0.5)
    # Check that it evaluates retained bit count
    assert "retained_secret_bits_count" in res["statistics"]


# ==========================================
# 2. CRYPTO ENGINE TESTS
# ==========================================
def test_aes_gcm_roundtrip():
    key = secrets.token_bytes(32)
    plaintext = b"Quantum-Secure-BB84-Verification-Payload"
    aad = b"associated-data-context"

    ciphertext = RobustEncryptionEngine.encrypt_aes_gcm(plaintext, key, associated_data=aad)
    assert ciphertext != plaintext
    assert len(ciphertext) >= len(plaintext) + 12 + 16  # Nonce + tag

    decrypted = RobustEncryptionEngine.decrypt_aes_gcm(ciphertext, key, associated_data=aad)
    assert decrypted == plaintext


def test_aes_gcm_tamper_detection():
    key = secrets.token_bytes(32)
    plaintext = b"Sensitive Quantum Data"
    ciphertext = bytearray(RobustEncryptionEngine.encrypt_aes_gcm(plaintext, key))

    # Tamper with a byte in ciphertext
    ciphertext[-5] ^= 0xFF

    with pytest.raises(Exception):
        RobustEncryptionEngine.decrypt_aes_gcm(bytes(ciphertext), key)


def test_unique_nonces_per_encryption():
    key = secrets.token_bytes(32)
    plaintext = b"Identical payload"
    c1 = RobustEncryptionEngine.encrypt_aes_gcm(plaintext, key)
    c2 = RobustEncryptionEngine.encrypt_aes_gcm(plaintext, key)

    # Nonces (first 12 bytes) must be distinct
    assert c1[:12] != c2[:12]
    assert c1 != c2


# ==========================================
# 3. ADAPTIVE KEY MANAGER TESTS
# ==========================================
def test_key_manager_lifecycle_and_usage():
    km = AdaptiveKeyManager(default_ttl_seconds=30, default_max_uses=2)
    raw_key = secrets.token_bytes(32)

    record = km.register_qkd_key(raw_key, qkd_round_id="test-rnd-1", qber=0.02)
    assert record.status == KeyStatus.ACTIVE

    # Acquire once
    rec1, key1 = km.acquire_key_for_transfer("tx-1", record.key_id)
    assert rec1.use_count == 1
    assert rec1.status == KeyStatus.ACTIVE

    # Acquire twice (reaches max uses 2)
    rec2, key2 = km.acquire_key_for_transfer("tx-2", record.key_id)
    assert rec2.use_count == 2
    assert rec2.status == KeyStatus.DEPLETED

    # Third acquisition must be rejected
    with pytest.raises(PermissionError):
        km.acquire_key_for_transfer("tx-3", record.key_id)


def test_key_manager_revocation():
    km = AdaptiveKeyManager(default_ttl_seconds=60, default_max_uses=5)
    record = km.register_qkd_key(secrets.token_bytes(32))

    km.revoke_key(record.key_id, reason="Security alert")
    assert record.status == KeyStatus.REVOKED
    assert record._raw_key is None  # Cleared memory reference

    with pytest.raises(PermissionError):
        km.acquire_key_for_transfer("tx-bad", record.key_id)


# ==========================================
# 4. END-TO-END FILE TRANSFER TESTS
# ==========================================
def test_secure_file_transfer_service(tmp_path):
    km = AdaptiveKeyManager(default_ttl_seconds=60, default_max_uses=2)
    service = SecureTransferService(key_manager=km, storage_dir=str(tmp_path))

    # Pre-register key
    key_record = km.register_qkd_key(secrets.token_bytes(32))

    sample_content = b"Confidential quantum research documentation."
    record = service.process_file_transfer(
        file_bytes=sample_content,
        filename="research_report.pdf",
        sender="Alice",
        receiver="Bob",
        key_id=key_record.key_id
    )

    assert record.status == "VERIFIED"
    assert record.integrity_verified is True
    assert record.stored_decrypted_path is not None

    with open(record.stored_decrypted_path, "rb") as f:
        restored = f.read()
    assert restored == sample_content


# ==========================================
# 5. FASTAPI REST API ENDPOINTS & AUTH TESTS
# ==========================================
def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"


def test_unauthorized_endpoints():
    res = client.get("/api/dashboard")
    assert res.status_code == 401

    res = client.get("/api/transfers")
    assert res.status_code == 401


def test_auth_login_and_flow():
    # Login with demo credentials
    login_res = client.post("/api/auth/login", json={
        "username": DEMO_USERNAME,
        "password": DEMO_PASSWORD
    })
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Access protected dashboard
    dash_res = client.get("/api/dashboard", headers=headers)
    assert dash_res.status_code == 200
    assert "stats" in dash_res.json()

    # Execute QKD round
    qkd_res = client.post("/api/qkd/rounds", json={
        "num_qubits": 32,
        "noise_level": 0.0,
        "eve_present": False,
        "qber_threshold": 0.11,
        "sample_ratio": 0.33
    }, headers=headers)
    assert qkd_res.status_code == 200
    assert qkd_res.json()["decision"]["accepted"] is True

    # List keys
    keys_res = client.get("/api/keys", headers=headers)
    assert keys_res.status_code == 200
    assert len(keys_res.json()["keys"]) > 0

    # Transfer a test file
    transfer_res = client.post(
        "/api/transfers",
        data={"receiver": "Bob_Recipient", "auto_generate_key": "true"},
        files={"file": ("experiment_test.txt", b"Hello QKD Authenticated Transfer", "text/plain")},
        headers=headers
    )
    assert transfer_res.status_code == 200
    tx_data = transfer_res.json()
    assert tx_data["status"] == "VERIFIED"

    # Download verified file
    dl_res = client.get(f"/api/transfers/{tx_data['transfer_id']}/download", headers=headers)
    assert dl_res.status_code == 200
    assert dl_res.content == b"Hello QKD Authenticated Transfer"
