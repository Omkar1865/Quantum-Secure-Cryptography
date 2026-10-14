import os
import time
import secrets
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path
from crypto_engine import RobustEncryptionEngine
from adaptive_key_manager import AdaptiveKeyManager


@dataclass
class TransferRecord:
    transfer_id: str
    original_filename: str
    file_size_bytes: int
    content_hash_original: str
    content_hash_decrypted: Optional[str]
    status: str  # QUEUED, ENCRYPTING, TRANSFERRED, DECRYPTING, VERIFIED, FAILED
    key_id: str
    encryption_algorithm: str
    sender_user: str
    receiver_user: str
    created_at: float
    completed_at: Optional[float]
    encryption_time_ms: float
    decryption_time_ms: float
    transfer_duration_ms: float
    integrity_verified: bool
    error_message: Optional[str] = None
    stored_decrypted_path: Optional[str] = None


class SecureTransferService:
    """
    Coordinates secure sender-to-receiver file transfers.
    - Uses AES-256-GCM authenticated encryption.
    - Integrates with AdaptiveKeyManager.
    - Validates file payloads, limits size (default max 15MB to prevent memory exhaustion).
    - Protects path traversals.
    - Verifies SHA-256 integrity hash before allowing download.
    - Provides automatic temporary cleanup.
    """

    def __init__(self, key_manager: AdaptiveKeyManager, storage_dir: str = "storage"):
        self.key_manager = key_manager
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.transfers: Dict[str, TransferRecord] = {}

    def sanitize_filename(self, filename: str) -> str:
        # Strip directory path separators and dangerous characters
        clean = Path(filename).name
        clean = "".join(c for c in clean if c.isalnum() or c in "._- ")
        if not clean:
            clean = f"file_{secrets.token_hex(4)}.dat"
        return clean

    def process_file_transfer(
        self,
        file_bytes: bytes,
        filename: str,
        sender: str,
        receiver: str,
        key_id: Optional[str] = None,
        key_generator_func = None
    ) -> TransferRecord:
        """
        Executes end-to-end file encryption, simulated transport, decryption, and verification.
        """
        start_time = time.perf_counter()
        transfer_id = f"tx-{secrets.token_hex(6)}"
        safe_filename = self.sanitize_filename(filename)
        file_size = len(file_bytes)

        # 1. Enforce size limits
        if file_size > 15 * 1024 * 1024:
            raise ValueError(f"File size {file_size} exceeds maximum permitted 15MB limit.")

        original_hash = hashlib.sha256(file_bytes).hexdigest()

        # 2. Acquire or Generate Key
        if key_id:
            key_record, raw_key = self.key_manager.acquire_key_for_transfer(transfer_id, key_id=key_id)
        else:
            if not key_generator_func:
                raise ValueError("Neither key_id nor key_generator_func was provided")
            key_record, raw_key, gen_status = self.key_manager.get_active_or_generate(key_generator_func)
            # associate with transfer
            key_record.record_usage(transfer_id)
            self.key_manager.log_event("KEY_USED", key_record.key_id, f"Associated with transfer {transfer_id} ({gen_status})")

        # 3. Encrypt payload
        enc_start = time.perf_counter()
        aad = f"transfer:{transfer_id}:sender:{sender}:receiver:{receiver}".encode()
        encrypted_payload = RobustEncryptionEngine.encrypt_aes_gcm(file_bytes, raw_key, associated_data=aad)
        enc_duration = (time.perf_counter() - enc_start) * 1000

        # 4. Decrypt at receiver side (demonstrating receiver with matching key)
        dec_start = time.perf_counter()
        try:
            decrypted_bytes = RobustEncryptionEngine.decrypt_aes_gcm(encrypted_payload, raw_key, associated_data=aad)
            dec_duration = (time.perf_counter() - dec_start) * 1000
            decrypted_hash = hashlib.sha256(decrypted_bytes).hexdigest()
            integrity_ok = (original_hash == decrypted_hash)
        except Exception as e:
            dec_duration = (time.perf_counter() - dec_start) * 1000
            record = TransferRecord(
                transfer_id=transfer_id,
                original_filename=safe_filename,
                file_size_bytes=file_size,
                content_hash_original=original_hash,
                content_hash_decrypted=None,
                status="FAILED",
                key_id=key_record.key_id,
                encryption_algorithm="AES-256-GCM",
                sender_user=sender,
                receiver_user=receiver,
                created_at=time.time(),
                completed_at=time.time(),
                encryption_time_ms=round(enc_duration, 2),
                decryption_time_ms=round(dec_duration, 2),
                transfer_duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                integrity_verified=False,
                error_message=f"Decryption / Authentication failed: {str(e)}"
            )
            self.transfers[transfer_id] = record
            return record

        # 5. Persist decrypted file securely for receiver download
        dest_filename = f"{transfer_id}_{safe_filename}"
        dest_path = self.storage_dir / dest_filename
        with open(dest_path, "wb") as f:
            f.write(decrypted_bytes)

        total_duration = (time.perf_counter() - start_time) * 1000

        record = TransferRecord(
            transfer_id=transfer_id,
            original_filename=safe_filename,
            file_size_bytes=file_size,
            content_hash_original=original_hash,
            content_hash_decrypted=decrypted_hash,
            status="VERIFIED" if integrity_ok else "FAILED",
            key_id=key_record.key_id,
            encryption_algorithm="AES-256-GCM",
            sender_user=sender,
            receiver_user=receiver,
            created_at=time.time(),
            completed_at=time.time(),
            encryption_time_ms=round(enc_duration, 2),
            decryption_time_ms=round(dec_duration, 2),
            transfer_duration_ms=round(total_duration, 2),
            integrity_verified=integrity_ok,
            stored_decrypted_path=str(dest_path) if integrity_ok else None
        )
        self.transfers[transfer_id] = record
        return record

    def get_transfer_summary(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        record = self.transfers.get(transfer_id)
        if not record:
            return None
        return {
            "transfer_id": record.transfer_id,
            "filename": record.original_filename,
            "file_size": record.file_size_bytes,
            "status": record.status,
            "key_id": record.key_id,
            "encryption_algorithm": record.encryption_algorithm,
            "sender": record.sender_user,
            "receiver": record.receiver_user,
            "created_at": record.created_at,
            "completed_at": record.completed_at,
            "encryption_time_ms": record.encryption_time_ms,
            "decryption_time_ms": record.decryption_time_ms,
            "transfer_duration_ms": record.transfer_duration_ms,
            "integrity_verified": record.integrity_verified,
            "content_hash_original": record.content_hash_original,
            "content_hash_decrypted": record.content_hash_decrypted,
            "download_available": record.stored_decrypted_path is not None and record.integrity_verified,
            "error_message": record.error_message
        }

    def list_transfers(self) -> List[Dict[str, Any]]:
        return [self.get_transfer_summary(tid) for tid in reversed(list(self.transfers.keys()))]

    def cleanup_old_files(self, max_age_seconds: int = 3600):
        """Removes temporary files older than max_age_seconds"""
        now = time.time()
        for p in self.storage_dir.glob("*"):
            if p.is_file():
                try:
                    if now - p.stat().st_mtime > max_age_seconds:
                        p.unlink()
                except OSError:
                    pass
