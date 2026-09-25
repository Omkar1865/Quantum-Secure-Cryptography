
import time

class KeyManager:

    def __init__(self, expiry_time=15, usage_limit=2):

        self.key = None
        self.timestamp = 0
        self.usage_count = 0
        self.expiry_time = expiry_time
        self.usage_limit = usage_limit

    def get_key(self, generator_function):

        current_time = time.time()

        if self.key:

            time_valid = (current_time - self.timestamp) < self.expiry_time
            usage_valid = self.usage_count < self.usage_limit

            if time_valid and usage_valid:

                self.usage_count += 1
                return {
                    'key': self.key,
                    'status': 'REUSED',
                    'usage': self.usage_count,
                    'age': round(current_time - self.timestamp, 2)
                }

        self.key = generator_function()
        self.timestamp = current_time
        self.usage_count = 1

        return {
            'key': self.key,
            'status': 'NEW',
            'usage': self.usage_count,
            'age': 0
        }