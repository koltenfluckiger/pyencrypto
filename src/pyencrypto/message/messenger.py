from typing import Union
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
import traceback
import base64


class Messenger:

    def __init__(self, keyer):
        self.public_key = keyer.public_key
        self.private_key = keyer.private_key

    def encrypt_message(self, message: Union[str, bytes], padding=OAEP(
        mgf=MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None
    ), send_safe: bool = True) -> None:
        """Encrypt a string with the key from the session.

        Parameters
        ----------
        message : Union[str,bytes]
            The message you want to encrypt either in string or bytes format.
        Returns
            None
        """
        try:
            if type(message) == str:
                message = message.encode()
            if send_safe:
                return self.encode_message(self.public_key.encrypt(message, padding)).decode()
            else:
                return self.public_key.encrypt(message, padding).decode()
        except Exception as err:
            traceback.print_exc()

    def decrypt_message(self, message: bytes, padding=OAEP(
        mgf=MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None
    ), send_safe: bool = True) -> str:
        try:
            if send_safe:
                message = self.decode_message(message)
            message = self.private_key.decrypt(message, padding)
            return message.decode()
        except Exception as err:
            traceback.print_exc()

    def encode_message(self, message: bytes):
        try:
            return base64.b64encode(message)
        except Exception as err:
            traceback.print_exc()

    def decode_message(self, message: bytes):
        try:
            return base64.b64decode(message)
        except Exception as err:
            traceback.print_exc()
