import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class NinebotCrypto:
    def __init__(self, name):
        self._name = bytearray(16)
        self._random_ble_data = bytearray(16)
        self._fw_data = bytearray(16)  # Fill this with appropriate firmware data.
        self._sha1_key = bytearray(16)
        self._msg_it = 0

        # Copy name into _name
        name_bytes = name.encode('utf-8')
        self._name[:len(name_bytes)] = name_bytes
        self.calc_sha1_key(self._name, self._fw_data)

    def calc_sha1_key(self, data1, data2):
        """Generate a SHA1 key using two data arrays."""
        combined_data = data1 + data2
        sha1_hash = hashlib.sha1(combined_data).digest()
        self._sha1_key = sha1_hash[:16]

    def aes_ecb_encrypt(self, data, key):
        """AES encryption using ECB mode."""
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            return encrypted_data
        except Exception as e:
            raise RuntimeError("Encryption failed") from e

    def aes_ecb_decrypt(self, data, key):
        """AES decryption using ECB mode."""
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
            return decrypted_data
        except ValueError as e:
            raise ValueError("Decryption failed: possibly incorrect padding") from e
        except Exception as e:
            raise RuntimeError("Decryption failed") from e

    def xor16(self, data1, data2):
        """XOR two bytearrays."""
        return bytearray(a ^ b for a, b in zip(data1, data2))

    def crypto_first(self, data):
        """Encrypt the first message using a specific algorithm."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        if len(data) == 0:
            raise ValueError("Input data cannot be empty.")
        
        result = bytearray(len(data))
        byte_idx = 0
        payload_len = len(data)

        while payload_len > 0:
            tmp_len = min(payload_len, 16)

            xor_data_1 = bytearray(16)
            xor_data_1[:tmp_len] = data[byte_idx:byte_idx + tmp_len]

            aes_key = self.aes_ecb_encrypt(self._fw_data, self._sha1_key)
            xor_data_2 = aes_key[:16]
            xor_data = self.xor16(xor_data_1, xor_data_2)

            result[byte_idx:byte_idx + tmp_len] = xor_data[:tmp_len]
            payload_len -= tmp_len
            byte_idx += tmp_len

        return result

    def crypto_next(self, data, msg_it):
        """Encrypt the next message with message iteration."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        if len(data) == 0:
            raise ValueError("Input data cannot be empty.")

        result = bytearray(len(data))
        aes_enc_data = bytearray(16)
        aes_enc_data[0] = 1
        aes_enc_data[1] = (msg_it >> 24) & 0xFF
        aes_enc_data[2] = (msg_it >> 16) & 0xFF
        aes_enc_data[3] = (msg_it >> 8) & 0xFF
        aes_enc_data[4] = msg_it & 0xFF
        aes_enc_data[5:13] = self._random_ble_data[:8]
        aes_enc_data[15] = 0

        byte_idx = 0
        payload_len = len(data)

        while payload_len > 0:
            aes_enc_data[15] += 1
            tmp_len = min(payload_len, 16)

            xor_data_1 = bytearray(16)
            xor_data_1[:tmp_len] = data[byte_idx:byte_idx + tmp_len]

            aes_key = self.aes_ecb_encrypt(aes_enc_data, self._sha1_key)
            xor_data_2 = aes_key[:16]
            xor_data = self.xor16(xor_data_1, xor_data_2)

            result[byte_idx:byte_idx + tmp_len] = xor_data[:tmp_len]
            payload_len -= tmp_len
            byte_idx += tmp_len

        return result

    def calc_crc_first_msg(self, data):
        """Calculate CRC for the first message."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        
        crc = sum(data) & 0xFFFF
        crc = ~crc & 0xFFFF
        return bytearray([(crc & 0x00FF), (crc >> 8) & 0xFF])

    def calc_crc_next_msg(self, data, msg_it):
        """Calculate CRC for subsequent messages with message iteration."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        
        aes_enc_data = bytearray(16)
        aes_enc_data[0] = 89
        aes_enc_data[1] = (msg_it >> 24) & 0xFF
        aes_enc_data[2] = (msg_it >> 16) & 0xFF
        aes_enc_data[3] = (msg_it >> 8) & 0xFF
        aes_enc_data[4] = msg_it & 0xFF
        aes_enc_data[5:13] = self._random_ble_data[:8]
        aes_enc_data[15] = len(data) - 3

        aes_key = self.aes_ecb_encrypt(aes_enc_data, self._sha1_key)
        xor_data_2 = aes_key[:16]

        xor_data_1 = bytearray(16)
        xor_data_1[:3] = data[:3]
        xor_data = self.xor16(xor_data_1, xor_data_2)

        aes_key = self.aes_ecb_encrypt(xor_data, self._sha1_key)
        xor_data_2 = aes_key[:16]

        payload_len = len(data) - 3
        byte_idx = 3

        while payload_len > 0:
            tmp_len = min(payload_len, 16)

            xor_data_1 = bytearray(16)
            xor_data_1[:tmp_len] = data[byte_idx:byte_idx + tmp_len]

            xor_data = self.xor16(xor_data_1, xor_data_2)
            aes_key = self.aes_ecb_encrypt(xor_data, self._sha1_key)
            xor_data_2 = aes_key[:16]

            payload_len -= tmp_len
            byte_idx += tmp_len

        aes_enc_data[0] = 1
        aes_enc_data[15] = 0
        aes_key = self.aes_ecb_encrypt(aes_enc_data, self._sha1_key)

        xor_data = self.xor16(aes_key[:16], xor_data_2)

        return xor_data[:4]

    def decrypt(self, data):
        """Decrypt the message."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        if len(data) < 9:
            raise ValueError("Input data must be at least 9 bytes long.")
        
        decrypted = bytearray(len(data) - 6)
        decrypted[:3] = data[:3]

        new_msg_it = self._msg_it
        if (new_msg_it & 0x8000) and (data[-2] >> 7) == 0:
            new_msg_it += 0x10000

        new_msg_it = (new_msg_it & 0xFFFF0000) + ((data[-2] << 8) + data[-1])

        payload_len = len(data) - 9
        payload = bytearray(payload_len)
        payload[:payload_len] = data[3:3 + payload_len]

        if new_msg_it == 0:
            payload = self.crypto_first(payload)
            decrypted[3:3 + payload_len] = payload

            if decrypted[:6] == bytearray([0x5A, 0xA5, 0x1E, 0x21, 0x3E, 0x5B]):
                self._random_ble_data = decrypted[7:7 + 16]
                self.calc_sha1_key(self._name, self._random_ble_data)
        else:
            payload = self.crypto_next(payload, new_msg_it)
            decrypted[3:3 + payload_len] = payload
            self._msg_it = new_msg_it

        return decrypted

    def encrypt(self, data):
        """Encrypt the message."""
        if not isinstance(data, bytearray):
            raise ValueError("Input data must be a bytearray.")
        if len(data) < 4:
            raise ValueError("Input data must be at least 4 bytes long.")

        encrypted = bytearray(152)
        encrypted[:3] = data[:3]

        payload_len = len(data) - 3
        payload = bytearray(payload_len)
        payload[:payload_len] = data[3:3 + payload_len]

        if self._msg_it == 0:
            payload = self.crypto_first(payload)
            encrypted[3:3 + payload_len] = payload
            self.calc_crc_first_msg(encrypted)
        else:
            payload = self.crypto_next(payload, self._msg_it)
            encrypted[3:3 + payload_len] = payload
            self.calc_crc_next_msg(encrypted, self._msg_it)

        return encrypted

__all__ = ["NinebotCrypto"]