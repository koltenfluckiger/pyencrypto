import base64

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes

from ..keyer import Keyer

_DEFAULT_PADDING = OAEP(
    mgf=MGF1(algorithm=hashes.SHA512()),
    algorithm=hashes.SHA512(),
    label=None,
)


class Messenger:
    """Encrypt and decrypt string/bytes messages using RSA asymmetric keys.

    Wraps a Keyer's public/private key pair for simple message-level encryption
    with optional base64 encoding for transport safety.
    """

    public_key: RSAPublicKey
    private_key: RSAPrivateKey

    def __init__(self, keyer: Keyer):
        if not keyer.public_key or not keyer.private_key:
            raise ValueError("Keyer must have both public and private keys loaded.")
        if not isinstance(keyer.public_key, RSAPublicKey):
            raise TypeError("Messenger requires RSA keys. Got: " + type(keyer.public_key).__name__)
        if not isinstance(keyer.private_key, RSAPrivateKey):
            raise TypeError("Messenger requires RSA keys. Got: " + type(keyer.private_key).__name__)
        self.public_key = keyer.public_key
        self.private_key = keyer.private_key

    def encrypt_message(
        self,
        message: str | bytes,
        padding: OAEP = _DEFAULT_PADDING,
        send_safe: bool = True,
    ) -> str | bytes:
        """Encrypt a message.

        Returns a base64-encoded string if send_safe=True, raw encrypted bytes otherwise.
        """
        if isinstance(message, str):
            message = message.encode()
        encrypted = self.public_key.encrypt(message, padding)
        if send_safe:
            return base64.b64encode(encrypted).decode()
        return encrypted

    def decrypt_message(
        self,
        message: str | bytes,
        padding: OAEP = _DEFAULT_PADDING,
        send_safe: bool = True,
    ) -> str:
        """Decrypt a message back to a string.

        Expects base64-encoded input if send_safe=True.
        """
        raw: bytes = base64.b64decode(message) if send_safe else (
            message.encode() if isinstance(message, str) else message
        )
        decrypted = self.private_key.decrypt(raw, padding)
        return decrypted.decode()

    @staticmethod
    def encode_message(message: bytes) -> bytes:
        """Base64-encode bytes."""
        return base64.b64encode(message)

    @staticmethod
    def decode_message(message: str | bytes) -> bytes:
        """Base64-decode bytes."""
        return base64.b64decode(message)
