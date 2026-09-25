from cryptography.fernet import Fernet
import base64


class EncryptionEngine:

    def prepare_key(self, raw_key):
        return base64.urlsafe_b64encode(raw_key)

    def encrypt(self, data, raw_key):

        key = self.prepare_key(raw_key)

        f = Fernet(key)

        return f.encrypt(data)

    def decrypt(self, encrypted_data, raw_key):

        key = self.prepare_key(raw_key)

        f = Fernet(key)

        return f.decrypt(encrypted_data)