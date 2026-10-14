import os
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import base64


class RobustEncryptionEngine:
    """
    Cryptographic engine supporting both Authenticated Encryption (AES-256-GCM)
    and backward-compatible Fernet payloads.
    
    In AES-256-GCM:
    - 256-bit key
    - 96-bit (12-byte) cryptographic nonce generated uniquely per encryption.
    - 128-bit authentication tag appended to the ciphertext.
    - Associated authenticated data (AAD) binds the transfer metadata to prevent replay/tampering.
    """

    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypts plaintext using AES-256-GCM.
        Generates a fresh 96-bit nonce every time.
        Format: [12-byte nonce] + [ciphertext + 16-byte auth tag]
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 requires exactly 32 bytes key, got {len(key)}")
        
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext_and_tag

    @staticmethod
    def decrypt_aes_gcm(payload: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypts an AES-256-GCM payload.
        Extracts nonce from first 12 bytes and validates the authentication tag.
        """
        if len(key) != 32:
            raise ValueError(f"AES-256 requires exactly 32 bytes key, got {len(key)}")
        if len(payload) < 28: # 12 bytes nonce + 16 bytes tag minimum
            raise ValueError("Payload too short for valid AES-GCM ciphertext")

        nonce = payload[:12]
        ciphertext_and_tag = payload[12:]
        aesgcm = AESGCM(key)
        # Will raise cryptography.exceptions.InvalidTag if tampered
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)

    # Legacy Fernet compatibility
    @staticmethod
    def encrypt_fernet(plaintext: bytes, key: bytes) -> bytes:
        encoded_key = base64.urlsafe_b64encode(key[:32].ljust(32, b'\0'))
        return Fernet(encoded_key).encrypt(plaintext)

    @staticmethod
    def decrypt_fernet(ciphertext: bytes, key: bytes) -> bytes:
        encoded_key = base64.urlsafe_b64encode(key[:32].ljust(32, b'\0'))
        return Fernet(encoded_key).decrypt(ciphertext)
