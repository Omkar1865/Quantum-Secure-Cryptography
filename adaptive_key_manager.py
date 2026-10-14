import time
import secrets
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    DEPLETED = "DEPLETED"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"


@dataclass
class KeyRecord:
    key_id: str
    fingerprint: str
    created_at: float
    expires_at: float
    max_uses: int
    use_count: int = 0
    status: KeyStatus = KeyStatus.ACTIVE
    associated_transfers: List[str] = field(default_factory=list)
    qkd_round_id: Optional[str] = None
    qber_at_generation: float = 0.0
    _raw_key: Optional[bytes] = None

    def is_usable(self) -> Tuple[bool, Optional[str]]:
        now = time.time()
        if self.status != KeyStatus.ACTIVE:
            return False, f"Key status is {self.status.value}"
        if now >= self.expires_at:
            self.status = KeyStatus.EXPIRED
            return False, f"Key expired {round(now - self.expires_at, 1)}s ago"
        if self.use_count >= self.max_uses:
            self.status = KeyStatus.DEPLETED
            return False, f"Key usage limit reached ({self.use_count}/{self.max_uses})"
        return True, None

    def record_usage(self, transfer_id: str):
        self.use_count += 1
        self.associated_transfers.append(transfer_id)
        if self.use_count >= self.max_uses:
            self.status = KeyStatus.DEPLETED


class AdaptiveKeyManager:
    """
    Manages QKD-derived session keys with strict lifecycle policies:
    - Time-based expiration
    - Usage-limit enforcement
    - Audit logging of creation, access, expiration, and revocations
    - Safe metadata exposure (never returns raw key material in public summaries)
    """

    def __init__(self, default_ttl_seconds: int = 60, default_max_uses: int = 2):
        self.default_ttl = default_ttl_seconds
        self.default_max_uses = default_max_uses
        self.keys: Dict[str, KeyRecord] = {}
        self.audit_log: List[Dict[str, Any]] = []

    def log_event(self, action: str, key_id: str, details: str, level: str = "INFO"):
        event = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "action": action,
            "key_id": key_id,
            "details": details,
            "level": level
        }
        self.audit_log.append(event)
        # Keep log trimmed to last 200 events
        if len(self.audit_log) > 200:
            self.audit_log.pop(0)

    def register_qkd_key(
        self,
        raw_key: bytes,
        qkd_round_id: Optional[str] = None,
        qber: float = 0.0,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None
    ) -> KeyRecord:
        """
        Registers newly sifted & authenticated quantum key material.
        """
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        limit = max_uses if max_uses is not None else self.default_max_uses
        key_id = f"qk-{secrets.token_hex(6)}"
        fingerprint = hashlib.sha256(raw_key).hexdigest()[:16]

        record = KeyRecord(
            key_id=key_id,
            fingerprint=fingerprint,
            created_at=now,
            expires_at=now + ttl,
            max_uses=limit,
            use_count=0,
            status=KeyStatus.ACTIVE,
            qkd_round_id=qkd_round_id,
            qber_at_generation=qber,
            _raw_key=raw_key
        )
        self.keys[key_id] = record
        self.log_event(
            "KEY_CREATED",
            key_id,
            f"Created key with TTL={ttl}s, MaxUses={limit}, QBER={qber*100:.2f}%",
            "INFO"
        )
        return record

    def get_active_or_generate(
        self,
        generator_func,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None
    ) -> Tuple[KeyRecord, bytes, str]:
        """
        Checks for an existing active key that can be reused under policy.
        If none exists, executes generator_func to obtain new key material.
        Returns: (KeyRecord, raw_key_bytes, "REUSED" | "NEW")
        """
        now = time.time()
        # Look for valid active key
        for key_id, record in reversed(list(self.keys.items())):
            valid, _ = record.is_usable()
            if valid and record._raw_key is not None:
                self.log_event("KEY_REUSED", key_id, f"Reused key (Use {record.use_count + 1}/{record.max_uses})")
                return record, record._raw_key, "REUSED"

        # Otherwise generate a new key
        result = generator_func()
        raw_key = result.get("_derived_key_bytes") or result.get("aes_key")
        if not raw_key:
            raise ValueError("Key generator did not produce valid key bytes")

        qkd_round_id = result.get("round_id")
        qber = result.get("statistics", {}).get("measured_qber", 0.0)

        record = self.register_qkd_key(
            raw_key=raw_key,
            qkd_round_id=qkd_round_id,
            qber=qber,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses
        )
        return record, raw_key, "NEW"

    def acquire_key_for_transfer(self, transfer_id: str, key_id: Optional[str] = None) -> Tuple[KeyRecord, bytes]:
        """
        Acquires a key for a specific transfer, validating policy and incrementing use.
        """
        if key_id:
            record = self.keys.get(key_id)
            if not record:
                raise KeyError(f"Key {key_id} not found")
        else:
            # Find first usable key
            usable = [r for r in self.keys.values() if r.is_usable()[0]]
            if not usable:
                raise ValueError("No active, usable quantum keys available")
            record = usable[-1]

        valid, reason = record.is_usable()
        if not valid:
            self.log_event("POLICY_VIOLATION", record.key_id, f"Attempted to use invalid key: {reason}", "WARN")
            raise PermissionError(f"Key {record.key_id} cannot be used: {reason}")

        record.record_usage(transfer_id)
        self.log_event("KEY_USED", record.key_id, f"Associated with transfer {transfer_id} (Use {record.use_count}/{record.max_uses})")
        return record, record._raw_key

    def revoke_key(self, key_id: str, reason: str = "Manual revocation"):
        if key_id in self.keys:
            record = self.keys[key_id]
            record.status = KeyStatus.REVOKED
            # Clear secret key memory reference
            record._raw_key = None
            self.log_event("KEY_REVOKED", key_id, f"Revoked: {reason}", "WARN")

    def list_keys_metadata(self) -> List[Dict[str, Any]]:
        """
        Returns list of safe metadata representations of all managed keys.
        CRITICAL: Never includes `_raw_key`.
        """
        now = time.time()
        summaries = []
        for r in reversed(list(self.keys.values())):
            # Update expired state dynamically
            usable, reason = r.is_usable()
            summaries.append({
                "key_id": r.key_id,
                "fingerprint": r.fingerprint,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
                "remaining_seconds": max(0, int(r.expires_at - now)),
                "max_uses": r.max_uses,
                "use_count": r.use_count,
                "remaining_uses": max(0, r.max_uses - r.use_count),
                "status": r.status.value,
                "is_usable": usable,
                "policy_note": reason or "Ready for encryption/decryption",
                "associated_transfers_count": len(r.associated_transfers),
                "associated_transfers": r.associated_transfers[-5:],
                "qkd_round_id": r.qkd_round_id,
                "qber_at_generation": r.qber_at_generation
            })
        return summaries
