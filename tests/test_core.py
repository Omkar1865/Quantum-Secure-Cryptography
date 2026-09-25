import unittest

from encryption import EncryptionEngine
from key_manager import KeyManager


class EncryptionEngineTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        engine = EncryptionEngine()
        raw_key = bytes(range(32))
        payload = b"quantum-secure-file-transfer"

        encrypted = engine.encrypt(payload, raw_key)

        self.assertNotEqual(encrypted, payload)
        self.assertEqual(engine.decrypt(encrypted, raw_key), payload)


class KeyManagerTests(unittest.TestCase):
    def test_key_is_reused_within_policy(self):
        manager = KeyManager(expiry_time=15, usage_limit=2)
        generated = []

        def generate_key():
            generated.append(object())
            return b"key"

        first = manager.get_key(generate_key)
        second = manager.get_key(generate_key)

        self.assertEqual(first["status"], "NEW")
        self.assertEqual(second["status"], "REUSED")
        self.assertEqual(second["usage"], 2)
        self.assertEqual(len(generated), 1)

    def test_key_is_regenerated_after_usage_limit(self):
        manager = KeyManager(expiry_time=15, usage_limit=1)
        generated = []

        def generate_key():
            key = f"key-{len(generated)}".encode()
            generated.append(key)
            return key

        first = manager.get_key(generate_key)
        second = manager.get_key(generate_key)

        self.assertEqual(first["key"], b"key-0")
        self.assertEqual(second["key"], b"key-1")
        self.assertEqual(second["status"], "NEW")
        self.assertEqual(len(generated), 2)


if __name__ == "__main__":
    unittest.main()
