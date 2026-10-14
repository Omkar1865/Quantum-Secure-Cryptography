import os
import time
import secrets
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from qkd_analyzer import QKDQualityAnalyzer
from adaptive_key_manager import AdaptiveKeyManager, KeyStatus
from file_transfer_service import SecureTransferService
from experiment_runner import ExperimentRunner
from auth_service import (
    get_current_user,
    verify_password,
    hash_password,
    create_access_token,
    USERS_DB,
    DEMO_USERNAME,
    DEMO_PASSWORD
)

# Initialize Core Services
app = FastAPI(
    title="Quantum-Secure Cryptography Platform",
    description="BB84 QKD Simulation, Adaptive Key Management & Authenticated AES-256-GCM Transfer",
    version="2.0.0"
)

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

qkd_analyzer = QKDQualityAnalyzer(default_num_qubits=48, default_qber_threshold=0.11)
key_manager = AdaptiveKeyManager(default_ttl_seconds=60, default_max_uses=2)
transfer_service = SecureTransferService(key_manager=key_manager, storage_dir="storage")
experiment_runner = ExperimentRunner(analyzer=qkd_analyzer)

# History of QKD rounds
qkd_rounds_history: List[dict] = []

# Pydantic Schemas
class LoginRequest(BaseModel):
    username: str
    password: str

class QKDRoundRequest(BaseModel):
    num_qubits: int = Field(default=48, ge=16, le=128)
    noise_level: float = Field(default=0.0, ge=0.0, le=0.50)
    eve_present: bool = Field(default=False)
    qber_threshold: float = Field(default=0.11, ge=0.01, le=0.50)
    sample_ratio: float = Field(default=0.33, ge=0.10, le=0.50)

class KeyPolicyUpdateRequest(BaseModel):
    default_ttl_seconds: Optional[int] = Field(default=60, ge=5, le=3600)
    default_max_uses: Optional[int] = Field(default=2, ge=1, le=50)


# ==========================================
# PUBLIC HEALTH ENDPOINT
# ==========================================
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "Quantum-Secure Cryptography API",
        "version": "2.0.0",
        "timestamp": time.time(),
        "active_keys": len([k for k in key_manager.keys.values() if k.is_usable()[0]]),
        "transfers_count": len(transfer_service.transfers),
        "qkd_simulator": "Qiskit Aer Ready"
    }


# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================
@app.post("/api/auth/login")
def login(creds: LoginRequest, response: Response):
    user = USERS_DB.get(creds.username)
    if not user or not verify_password(creds.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(user["username"], user.get("role", "user"))
    # Set HTTP-only cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("ENVIRONMENT") == "production",
        max_age=86400
    )
    return {
        "success": True,
        "token": token,
        "user": {
            "username": user["username"],
            "role": user.get("role", "user")
        }
    }

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"success": True, "message": "Successfully logged out"}

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {"user": current_user}


# ==========================================
# DASHBOARD OVERVIEW ENDPOINT
# ==========================================
@app.get("/api/dashboard")
def get_dashboard_summary(current_user: dict = Depends(get_current_user)):
    all_transfers = list(transfer_service.transfers.values())
    successful_transfers = sum(1 for t in all_transfers if t.status == "VERIFIED")
    failed_transfers = sum(1 for t in all_transfers if t.status == "FAILED")

    total_rounds = len(qkd_rounds_history)
    accepted_rounds = sum(1 for r in qkd_rounds_history if r["decision"]["accepted"])
    rejected_rounds = total_rounds - accepted_rounds

    avg_enc_time = (
        sum(t.encryption_time_ms for t in all_transfers) / len(all_transfers)
        if all_transfers else 0.0
    )
    avg_dec_time = (
        sum(t.decryption_time_ms for t in all_transfers) / len(all_transfers)
        if all_transfers else 0.0
    )

    active_keys = sum(1 for k in key_manager.keys.values() if k.is_usable()[0])
    recent_events = key_manager.audit_log[-10:]

    return {
        "stats": {
            "total_transfers": len(all_transfers),
            "successful_transfers": successful_transfers,
            "failed_transfers": failed_transfers,
            "total_qkd_rounds": total_rounds,
            "accepted_qkd_rounds": accepted_rounds,
            "rejected_qkd_rounds": rejected_rounds,
            "qkd_acceptance_rate_pct": round((accepted_rounds / total_rounds * 100), 1) if total_rounds > 0 else 0.0,
            "active_keys": active_keys,
            "avg_encryption_time_ms": round(avg_enc_time, 2),
            "avg_decryption_time_ms": round(avg_dec_time, 2),
        },
        "recent_activity": recent_events,
        "recent_transfers": transfer_service.list_transfers()[:5]
    }


# ==========================================
# QKD LAB ENDPOINTS
# ==========================================
@app.post("/api/qkd/rounds")
def execute_qkd_round(req: QKDRoundRequest, current_user: dict = Depends(get_current_user)):
    result = qkd_analyzer.run_bb84_protocol(
        num_qubits=req.num_qubits,
        noise_level=req.noise_level,
        eve_present=req.eve_present,
        qber_threshold=req.qber_threshold,
        sample_ratio=req.sample_ratio
    )

    # Store round metadata in history
    round_meta = {
        "round_id": result["round_id"],
        "timestamp": time.time(),
        "parameters": result["parameters"],
        "statistics": result["statistics"],
        "alice": result["alice"],
        "bob": result["bob"],
        "eve": result["eve"],
        "decision": result["decision"],
        "key_fingerprint": result["key_fingerprint"],
        "simulation_notice": result["simulation_notice"]
    }
    qkd_rounds_history.append(round_meta)

    # If key was generated successfully and accepted, register into KeyManager
    if result["derived_key_available"] and result["_derived_key_bytes"]:
        key_manager.register_qkd_key(
            raw_key=result["_derived_key_bytes"],
            qkd_round_id=result["round_id"],
            qber=result["statistics"]["measured_qber"]
        )

    # Return safe response (excluding raw secret key bytes)
    safe_response = {k: v for k, v in result.items() if not k.startswith("_")}
    return safe_response

@app.get("/api/qkd/rounds")
def list_qkd_rounds(current_user: dict = Depends(get_current_user)):
    return list(reversed(qkd_rounds_history[-30:]))

@app.get("/api/qkd/rounds/{round_id}")
def get_qkd_round(round_id: str, current_user: dict = Depends(get_current_user)):
    for r in qkd_rounds_history:
        if r["round_id"] == round_id:
            return r
    raise HTTPException(status_code=404, detail="QKD round not found")


# ==========================================
# KEY MANAGER ENDPOINTS
# ==========================================
@app.get("/api/keys")
def get_keys(current_user: dict = Depends(get_current_user)):
    return {
        "keys": key_manager.list_keys_metadata(),
        "policy": {
            "default_ttl_seconds": key_manager.default_ttl,
            "default_max_uses": key_manager.default_max_uses
        },
        "audit_log": list(reversed(key_manager.audit_log[-20:]))
    }

@app.post("/api/keys/policy")
def update_key_policy(req: KeyPolicyUpdateRequest, current_user: dict = Depends(get_current_user)):
    if req.default_ttl_seconds is not None:
        key_manager.default_ttl = req.default_ttl_seconds
    if req.default_max_uses is not None:
        key_manager.default_max_uses = req.default_max_uses
    key_manager.log_event("POLICY_UPDATED", "SYSTEM", f"New TTL: {key_manager.default_ttl}s, Max Uses: {key_manager.default_max_uses}")
    return {
        "success": True,
        "default_ttl_seconds": key_manager.default_ttl,
        "default_max_uses": key_manager.default_max_uses
    }

@app.post("/api/keys/{key_id}/revoke")
def revoke_key(key_id: str, reason: str = Query("Manual administrative revocation"), current_user: dict = Depends(get_current_user)):
    if key_id not in key_manager.keys:
        raise HTTPException(status_code=404, detail="Key not found")
    key_manager.revoke_key(key_id, reason=reason)
    return {"success": True, "key_id": key_id, "status": "REVOKED"}


# ==========================================
# SECURE FILE TRANSFER ENDPOINTS
# ==========================================
@app.get("/api/transfers")
def list_transfers(current_user: dict = Depends(get_current_user)):
    return transfer_service.list_transfers()

@app.post("/api/transfers")
async def initiate_file_transfer(
    file: UploadFile = File(...),
    receiver: str = Form("Alice_Receiver"),
    key_id: Optional[str] = Form(None),
    auto_generate_key: bool = Form(True),
    current_user: dict = Depends(get_current_user)
):
    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Cannot transfer an empty file.")
    if len(contents) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum 15MB limit.")

    # Generator fallback if no specific key_id is chosen
    def key_generator():
        # Executes QKD simulation round
        sim_res = qkd_analyzer.run_bb84_protocol(num_qubits=48, noise_level=0.0, eve_present=False)
        qkd_rounds_history.append({
            "round_id": sim_res["round_id"],
            "timestamp": time.time(),
            "parameters": sim_res["parameters"],
            "statistics": sim_res["statistics"],
            "alice": sim_res["alice"],
            "bob": sim_res["bob"],
            "eve": sim_res["eve"],
            "decision": sim_res["decision"],
            "key_fingerprint": sim_res["key_fingerprint"],
            "simulation_notice": sim_res["simulation_notice"]
        })
        if not sim_res["decision"]["accepted"] or not sim_res["_derived_key_bytes"]:
            raise ValueError(f"QKD round rejected during key generation: {sim_res['decision']['reasons']}")
        return sim_res

    try:
        record = transfer_service.process_file_transfer(
            file_bytes=contents,
            filename=file.filename or "uploaded.dat",
            sender=current_user["username"],
            receiver=receiver,
            key_id=key_id if (key_id and key_id.strip()) else None,
            key_generator_func=key_generator if auto_generate_key else None
        )
        return transfer_service.get_transfer_summary(record.transfer_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/transfers/{transfer_id}")
def get_transfer_status(transfer_id: str, current_user: dict = Depends(get_current_user)):
    summary = transfer_service.get_transfer_summary(transfer_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Transfer record not found")
    return summary

@app.get("/api/transfers/{transfer_id}/download")
def download_decrypted_file(transfer_id: str, current_user: dict = Depends(get_current_user)):
    record = transfer_service.transfers.get(transfer_id)
    if not record:
        raise HTTPException(status_code=404, detail="Transfer record not found")
    if not record.integrity_verified or not record.stored_decrypted_path:
        raise HTTPException(status_code=400, detail="Cannot download unverified or failed transfer")

    path = Path(record.stored_decrypted_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")

    return FileResponse(
        path=str(path),
        filename=record.original_filename,
        media_type="application/octet-stream"
    )


# ==========================================
# EXPERIMENTS & BENCHMARKS ENDPOINTS
# ==========================================
@app.post("/api/experiments/noise")
def run_noise_experiment(current_user: dict = Depends(get_current_user)):
    return experiment_runner.run_noise_benchmark()

@app.post("/api/experiments/eavesdropping")
def run_eavesdropping_experiment(current_user: dict = Depends(get_current_user)):
    return experiment_runner.run_eavesdropping_benchmark()

@app.post("/api/experiments/crypto")
def run_crypto_experiment(current_user: dict = Depends(get_current_user)):
    return experiment_runner.run_crypto_performance_benchmark()


# Mount Static Files for Web Dashboard Frontend
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
