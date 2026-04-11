#!/usr/bin/env python3

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import hashes, serialization

from .exceptions import (
    EncryptoAlreadyEncryptedError,
    EncryptoAlreadyDecryptedError,
)
from ..keyer import Keyer

_DEFAULT_PADDING = OAEP(
    mgf=MGF1(algorithm=hashes.SHA512()),
    algorithm=hashes.SHA512(),
    label=None,
)


class Crypter:
    """Encrypt and decrypt files and byte data using asymmetric keys.

    Can be initialized with either a Keyer instance or a raw private key.
    Uses a magic-string signature to prevent double encryption/decryption.
    """

    def __init__(
        self,
        keyer: Keyer | None = None,
        private_key: str | bytes | PrivateKeyTypes | None = None,
        padding: OAEP = _DEFAULT_PADDING,
        magic_str: str = "pyencrypto",
    ):
        if keyer:
            self.private_key = keyer.private_key
            self.public_key = keyer.public_key
        else:
            self.private_key = private_key
            self.public_key = private_key.public_key() if private_key else None
        self.padding = padding
        self.magic_str = magic_str
        self._generate_sign()

    def _generate_sign(self) -> None:
        digest = hashes.Hash(hashes.SHA512())
        digest.update(self.magic_str.encode())
        self.signer = digest.finalize()

    def load_key_from_file(
        self, path: str | Path, password: bytes | None = None
    ) -> None:
        """Load a PEM private key from a file and set it as the active key."""
        resolved = Path(path).resolve()
        key_bytes = resolved.read_bytes()
        private_key = serialization.load_pem_private_key(key_bytes, password=password)
        self.set_key_session(private_key)

    def set_key_session(self, key: PrivateKeyTypes) -> None:
        """Set the active private key and derive the public key from it."""
        self.private_key = key
        self.public_key = self.private_key.public_key()

    def already_encrypted(self, bits: bytes) -> bool:
        """Check if data has already been signed (encrypted)."""
        return bits[: len(self.signer)] == self.signer

    def already_decrypted(self, bits: bytes) -> bool:
        """Check if data lacks a signature (is decrypted/plaintext)."""
        return bits[: len(self.signer)] != self.signer

    def sign(self, bits: bytes) -> bytes:
        """Prepend the magic signature to bytes.

        Raises EncryptoAlreadyEncryptedError if signature is already present.
        """
        if self.already_encrypted(bits):
            raise EncryptoAlreadyEncryptedError("Object is already encrypted.")
        return b"".join([self.signer, bits])

    def remove_sign(self, signed_bytes: bytes) -> bytes:
        """Remove the magic signature from bytes.

        Raises EncryptoAlreadyDecryptedError if signature is not present.
        """
        if self.already_decrypted(signed_bytes):
            raise EncryptoAlreadyDecryptedError("Object already decrypted.")
        return signed_bytes[len(self.signer) :]

    def encrypt_bytes(self, bits: bytes) -> bytes:
        """Encrypt bytes using the public key."""
        if not self.public_key:
            raise ValueError("No public key set. Load or generate a key first.")
        return self.public_key.encrypt(bits, self.padding)

    def decrypt_bytes(self, bits: bytes) -> bytes:
        """Decrypt bytes using the private key."""
        if not self.private_key:
            raise ValueError("No private key set. Load or generate a key first.")
        return self.private_key.decrypt(bits, self.padding)

    def encrypt(self, path: str | Path) -> None:
        """Encrypt a file in-place. Signs the result to prevent double encryption."""
        if not self.public_key:
            raise ValueError("No public key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        self.sign(raw_bytes)  # raises if already encrypted
        encrypted_bytes = self.encrypt_bytes(raw_bytes)
        signed_bytes = self.sign(encrypted_bytes)
        resolved.write_bytes(signed_bytes)

    def decrypt(self, path: str | Path) -> None:
        """Decrypt a file in-place. Removes the signature before decrypting."""
        if not self.private_key:
            raise ValueError("No private key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        unsigned_bytes = self.remove_sign(raw_bytes)  # raises if not encrypted
        decrypted_bytes = self.decrypt_bytes(unsigned_bytes)
        resolved.write_bytes(decrypted_bytes)

    def switch_encryption(self, path: str | Path) -> None:
        """Toggle encryption state of a file: encrypt if plain, decrypt if encrypted."""
        if not self.private_key and not self.public_key:
            raise ValueError("No key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        if self.already_encrypted(raw_bytes):
            self.decrypt(resolved)
        else:
            self.encrypt(resolved)
