#!/usr/bin/env python3

import base64
import binascii
import os
import stat
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

from .exceptions import (
    EncryptoAlreadyEncryptedError,
    EncryptoAlreadyDecryptedError,
    EncryptoDecryptionError,
)
from ..keyer import Keyer

_DEFAULT_PADDING = OAEP(
    mgf=MGF1(algorithm=hashes.SHA512()),
    algorithm=hashes.SHA512(),
    label=None,
)

# v2 file layout (all v2 data starts with signer_v2 + one mode byte):
#   MODE_RSA:       signer_v2 | 0x01 | u16 len | RSA-OAEP(AES key) | nonce | AES-GCM(data)
#   MODE_SYMMETRIC: signer_v2 | 0x02 | nonce | AES-GCM(data)
# Everything before the ciphertext is authenticated as AES-GCM associated data.
MODE_RSA = 0x01
MODE_SYMMETRIC = 0x02
_NONCE_SIZE = 12
_AES_KEY_BYTES = 32
_MAX_AESGCM_BYTES = 2**31 - 1


class Crypter:
    """Encrypt and decrypt files and byte data.

    Can be initialized with a Keyer instance, a raw private key, and/or a
    symmetric key. File data is encrypted with AES-256-GCM; in RSA mode the
    per-file AES key is wrapped with the RSA public key (hybrid encryption),
    in symmetric mode the symmetric key is used directly.
    Uses a magic-string signature to prevent double encryption/decryption.
    Files written by the legacy raw-RSA format (v1) can still be decrypted.
    """

    def __init__(
        self,
        keyer: Keyer | None = None,
        private_key: str | bytes | PrivateKeyTypes | None = None,
        padding: OAEP = _DEFAULT_PADDING,
        magic_str: str = "pyencrypto",
        symmetric_key: str | bytes | None = None,
    ):
        if keyer:
            self.private_key = keyer.private_key
            self.public_key = keyer.public_key
        else:
            self.private_key = private_key
            self.public_key = private_key.public_key() if private_key else None
        self.padding = padding
        self.magic_str = magic_str
        self.symmetric_key = (
            self._decode_symmetric_key(symmetric_key) if symmetric_key else None
        )
        self._generate_sign()

    def _generate_sign(self) -> None:
        digest = hashes.Hash(hashes.SHA512())
        digest.update(self.magic_str.encode())
        self.signer = digest.finalize()
        digest_v2 = hashes.Hash(hashes.SHA512())
        digest_v2.update(f"{self.magic_str}:v2".encode())
        self.signer_v2 = digest_v2.finalize()

    @staticmethod
    def _decode_symmetric_key(key: str | bytes) -> bytes:
        """Accept a raw 32-byte key or its urlsafe-base64 form."""
        key_bytes = key.encode() if isinstance(key, str) else key
        if len(key_bytes) == _AES_KEY_BYTES:
            return key_bytes
        try:
            decoded = base64.urlsafe_b64decode(key_bytes.strip())
        except (binascii.Error, ValueError) as err:
            raise ValueError("Symmetric key is not valid base64.") from err
        if len(decoded) != _AES_KEY_BYTES:
            raise ValueError(
                f"Symmetric key must be {_AES_KEY_BYTES} bytes, got {len(decoded)}."
            )
        return decoded

    @staticmethod
    def generate_symmetric_key() -> bytes:
        """Generate a new random AES-256 key, urlsafe-base64 encoded."""
        return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256))

    @staticmethod
    def generate_symmetric_key_write_to_file(
        path: str | Path, overwrite: bool = False
    ) -> Path:
        """Generate a symmetric key and write it to a file readable only by the owner."""
        resolved = Path(path).resolve()
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        try:
            fd = os.open(resolved, flags, 0o600)
        except FileExistsError as err:
            raise FileExistsError(
                f"Key file already exists: {resolved}. Set overwrite=True to overwrite."
            ) from err
        with os.fdopen(fd, "wb") as fh:
            fh.write(Crypter.generate_symmetric_key() + b"\n")
        return resolved

    def load_symmetric_key_from_file(self, path: str | Path) -> None:
        """Load a symmetric key file and set it as the active symmetric key."""
        resolved = Path(path).resolve()
        self.symmetric_key = self._decode_symmetric_key(resolved.read_bytes().strip())

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
        """Check if data has already been signed (encrypted), in either format."""
        head = bits[: len(self.signer)]
        return head == self.signer or head == self.signer_v2

    def already_decrypted(self, bits: bytes) -> bool:
        """Check if data lacks a signature (is decrypted/plaintext)."""
        return not self.already_encrypted(bits)

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
        """Encrypt bytes using the public key (raw RSA, small payloads only)."""
        if not self.public_key:
            raise ValueError("No public key set. Load or generate a key first.")
        return self.public_key.encrypt(bits, self.padding)

    def decrypt_bytes(self, bits: bytes) -> bytes:
        """Decrypt bytes using the private key (raw RSA, small payloads only)."""
        if not self.private_key:
            raise ValueError("No private key set. Load or generate a key first.")
        return self.private_key.decrypt(bits, self.padding)

    def encrypt_data(self, bits: bytes) -> bytes:
        """Encrypt data of any size into the signed v2 format.

        Uses the symmetric key when one is set, otherwise RSA hybrid mode.
        Raises EncryptoAlreadyEncryptedError if data is already encrypted.
        """
        if self.already_encrypted(bits):
            raise EncryptoAlreadyEncryptedError("Object is already encrypted.")
        if len(bits) > _MAX_AESGCM_BYTES:
            raise ValueError(
                f"Data is too large to encrypt ({len(bits)} bytes, max {_MAX_AESGCM_BYTES})."
            )
        if self.symmetric_key:
            data_key = self.symmetric_key
            header = self.signer_v2 + bytes([MODE_SYMMETRIC])
        else:
            if not self.public_key:
                raise ValueError("No public key set. Load or generate a key first.")
            if not isinstance(self.public_key, RSAPublicKey):
                raise TypeError(
                    "RSA mode requires an RSA key. Got: " + type(self.public_key).__name__
                )
            data_key = AESGCM.generate_key(bit_length=256)
            wrapped_key = self.public_key.encrypt(data_key, self.padding)
            header = b"".join(
                [
                    self.signer_v2,
                    bytes([MODE_RSA]),
                    struct.pack(">H", len(wrapped_key)),
                    wrapped_key,
                ]
            )
        nonce = os.urandom(_NONCE_SIZE)
        header += nonce
        return header + AESGCM(data_key).encrypt(nonce, bits, header)

    def decrypt_data(self, bits: bytes) -> bytes:
        """Decrypt data produced by encrypt_data (v2) or the legacy v1 format.

        Raises EncryptoAlreadyDecryptedError if data is not encrypted and
        EncryptoDecryptionError on a wrong key or corrupted data.
        """
        if bits[: len(self.signer_v2)] != self.signer_v2:
            # Legacy v1: signer + raw RSA ciphertext (or plaintext -> raises).
            unsigned_bytes = self.remove_sign(bits)
            try:
                return self.decrypt_bytes(unsigned_bytes)
            except ValueError as err:
                if not self.private_key:
                    raise
                raise EncryptoDecryptionError(
                    "Decryption failed: wrong key or corrupted data."
                ) from err

        offset = len(self.signer_v2)
        if len(bits) <= offset:
            raise EncryptoDecryptionError("Encrypted data is truncated.")
        mode = bits[offset]
        offset += 1

        if mode == MODE_RSA:
            if not self.private_key:
                raise ValueError(
                    "Data was encrypted with an RSA key. Load the private key to decrypt."
                )
            if not isinstance(self.private_key, RSAPrivateKey):
                raise TypeError(
                    "RSA mode requires an RSA key. Got: " + type(self.private_key).__name__
                )
            if len(bits) < offset + 2:
                raise EncryptoDecryptionError("Encrypted data is truncated.")
            (wrapped_len,) = struct.unpack_from(">H", bits, offset)
            offset += 2
            wrapped_key = bits[offset : offset + wrapped_len]
            offset += wrapped_len
            try:
                data_key = self.private_key.decrypt(wrapped_key, self.padding)
            except ValueError as err:
                raise EncryptoDecryptionError(
                    "Decryption failed: wrong private key or corrupted data."
                ) from err
        elif mode == MODE_SYMMETRIC:
            if not self.symmetric_key:
                raise ValueError(
                    "Data was encrypted with a symmetric key. Load the symmetric key to decrypt."
                )
            data_key = self.symmetric_key
        else:
            raise EncryptoDecryptionError(f"Unknown encryption mode byte: {mode:#04x}.")

        nonce = bits[offset : offset + _NONCE_SIZE]
        offset += _NONCE_SIZE
        if len(nonce) != _NONCE_SIZE:
            raise EncryptoDecryptionError("Encrypted data is truncated.")
        header, ciphertext = bits[:offset], bits[offset:]
        try:
            return AESGCM(data_key).decrypt(nonce, ciphertext, header)
        except InvalidTag as err:
            raise EncryptoDecryptionError(
                "Decryption failed: wrong key or corrupted data."
            ) from err

    @staticmethod
    def _write_atomic(target: Path, data: bytes, mode: int | None = None) -> None:
        """Write data to target via a temp file + rename so a failure never truncates it."""
        fd, tmp_name = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if mode is not None:
                os.chmod(tmp_name, stat.S_IMODE(mode))
            os.replace(tmp_name, target)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    def encrypt(self, path: str | Path, output: str | Path | None = None) -> None:
        """Encrypt a file in-place, or into output when given.

        Signs the result to prevent double encryption.
        """
        if not self.public_key and not self.symmetric_key:
            raise ValueError("No public key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        encrypted_bytes = self.encrypt_data(raw_bytes)  # raises if already encrypted
        target = Path(output).resolve() if output else resolved
        self._write_atomic(target, encrypted_bytes, resolved.stat().st_mode)

    def decrypt(self, path: str | Path, output: str | Path | None = None) -> None:
        """Decrypt a file in-place, or into output when given.

        Removes the signature before decrypting.
        """
        if not self.private_key and not self.symmetric_key:
            raise ValueError("No private key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        decrypted_bytes = self.decrypt_data(raw_bytes)  # raises if not encrypted
        target = Path(output).resolve() if output else resolved
        self._write_atomic(target, decrypted_bytes, resolved.stat().st_mode)

    def switch_encryption(
        self, path: str | Path, output: str | Path | None = None
    ) -> None:
        """Toggle encryption state of a file: encrypt if plain, decrypt if encrypted."""
        if not self.private_key and not self.public_key and not self.symmetric_key:
            raise ValueError("No key set. Load or generate a key first.")
        resolved = Path(path).resolve()
        raw_bytes = resolved.read_bytes()
        if self.already_encrypted(raw_bytes):
            self.decrypt(resolved, output)
        else:
            self.encrypt(resolved, output)
