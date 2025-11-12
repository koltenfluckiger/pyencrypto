#!/usr/bin/env python3

from typing import Union
import pathlib
from pathlib import Path as PathType
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import hashes, serialization
from .exceptions import (
    EncryptoAlreadyEncryptedError,
    EncryptoAlreadyDecryptedError,
)

import traceback
from ..keyer import Keyer


class Crypter:
    """Class to help you easily encrypt and decrypt objects/files/messages with keys

    Parameters
    ----------
    key : bytes
        Key to decrypt and encrypte files in bytes. (the default is None).
    Attributes
    ----------
    key : bytes
        Key to decrypt and encrypte files in bytes. (the default is None).
    """

    def __init__(
        self,
        keyer: Union[None, Keyer] = None,
        private_key: Union[str, bytes, PrivateKeyTypes, None] = None,
        padding=OAEP(
            mgf=MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None
        ),
        magic_str: str = "pyencrypto",
    ):
        """Constructs all the necessary attributes for the crypter object.

        Parameters
        ----------
        private_key : str,bytes
            The key in bytes if you already know it or the path to the private key (the default is None).
        magic_str : str
            This is an appended string at the beginning of an encrypted file. This is checked for to make sure that you don't encrypt an already encrypted file.
        Returns
        -------
        Crypter
            Crypter object

        Raises
        ------
        ExceptionName
            Why the exception is raised.

        """
        if keyer:
            self.private_key = keyer.private_key
            self.public_key = keyer.public_key
        else:
            self.private_key = private_key
            self.public_key = private_key.public_key() if private_key else None
        self.padding = padding
        self.magic_str = magic_str
        self.generate_sign()

    def generate_sign(self):
        try:
            digest = hashes.Hash(hashes.SHA512())
            digest.update(self.magic_str.encode())
            msg = digest.finalize()
            self.signer = msg
        except Exception as err:
            traceback.print_exc()

    def load_key_from_file(
        self, path: Union[str, PathType], password: Union[bytes, None] = None
    ):
        """Short summary.

        Parameters
        ----------
        path : str
            The path of which you want to load the key from.

        Returns
        -------
        None
        """
        try:
            path = pathlib.Path(path).resolve()
            with open(path, "rb") as file:
                key_bytes = file.read()
                private_key = serialization.load_pem_private_key(
                    key_bytes,
                    password=password,
                )
                self.set_key_session(private_key)
        except Exception as err:
            traceback.print_exc()

    def set_key_session(
        self, key: Union[str, bytes, PrivateKeyTypes, None] = None
    ) -> None:
        """Set the key to the Fernet session either from self or through parameter.

        Parameters
        ----------
        key : bytes
            The key in bytes (the default is None).

        Returns
        -------
        None

        Raises
        ------
        Exception
            No key was provided into the session.
        """
        try:
            self.private_key = key
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(f"set_key_session: {err}")

    def already_encrypted(self, bits):
        try:
            self.sign(bits)
            return False
        except Exception as err:
            return True

    def already_decrypted(self, bits):
        try:
            self.remove_sign(bits)
            return False
        except Exception as err:
            return True

    def sign(self, bits: bytes):
        """Sign the bytes with a custom hash

        Parameters
        ----------
        bytes : bytes
            Bytes you want to sign.

        Returns
        -------
        bytes
            Bytes object with the signed hash.

        Raises
        ------
        EncryptoAlreadyEncryptedError
            If the file is already encrypted with the same hash it won't let you encrypt it again.
        """
        if bits[: len(self.signer)] == self.signer:
            raise EncryptoAlreadyEncryptedError("Object is already encrypted.")
        else:
            return b"".join([self.signer, bits])

    def remove_sign(self, signed_bytes: bytes):
        """Removed the custom hash from the bytes
        Parameters
        ----------
        bytes : bytes
            Bytes you want to unsign or unhash.

        Returns
        -------
        bytes
            Bytes object with the unsigned hash or None
        Raises
        """
        if signed_bytes[0: len(self.signer)] == self.signer:
            return signed_bytes[(len(self.signer)):]
        else:
            raise EncryptoAlreadyDecryptedError("Object already decrypted.")

    def write_bytes_at_path(self, path: Union[str, PathType], bits: bytes) -> None:
        """Short summary.

        Parameters
        ----------
        path : str
            Path you would like to write the bytes to.
        bytes : bytes
            Description of parameter `bytes`.

        Returns
        -------
        None

        Raises
        ------
        ExceptionName
            Why the exception is raised.

        """
        try:
            with open(path, "wb") as file:
                file.write(bits)
        except Exception as err:
            traceback.print_exc()

    def read_bytes_at_path(self, path: Union[str, PathType]) -> bytes:
        """Short summary.

        Parameters
        ----------
        path : str
            Description of parameter `path`.

        Returns
        -------
        type
            Description of returned object.

        Raises
        ------
        ExceptionName
            Why the exception is raised.

        """
        try:
            with open(path, "rb") as file:
                bytes = file.read()
                return bytes
        except Exception as err:
            traceback.print_exc()

    def encrypt_bytes(self, bits: bytes) -> bytes:
        """Encrypt the bytes and sign it with the key that is set to the session.

        Parameters
        ----------
        bytes : bytes
            The object in `bytes`.
        Returns
        -------
        bytes
            Returns the bytes that have been encrypted with the key.
        """
        try:
            encrypted_bytes = self.public_key.encrypt(bits, self.padding)
            return encrypted_bytes
        except Exception as err:
            traceback.print_exc()

    def decrypt_bytes(self, bits: bytes) -> bytes:
        """Decrypt the bytes and sign it with the key that is set to the session.

        Parameters
        ----------
        bytes : bytes
            The object in `bytes`.
        Returns
        -------
        bytes
            Returns the bytes that have been decrypted with the key.
        """
        try:
            decrypted_bytes = self.private_key.decrypt(bits, self.padding)
            return decrypted_bytes
        except Exception as err:
            traceback.print_exc()

    def encrypt(self, path: Union[str, PathType]) -> None:
        """Encrypt the object at the path. This encrypts the bytes with the key, then writes the bytes to the path.

        Parameters
        ----------
        path : str
            Description of parameter `path`.
        Returns
        -------
        None
            Returns none as it writes the bytes to the path.
        Raises
        ------
        Exception
            Will raise an exception if you have not set the key before encrypting.
        """
        try:
            if not self.public_key:
                raise Exception(
                    "You haven't set a key yet to encrypt with. Please generate a key and make sure you save it."
                )
            path = pathlib.Path(path).resolve()
            read_bytes = self.read_bytes_at_path(path)
            if self.sign(read_bytes):
                encrypted_bytes = self.encrypt_bytes(read_bytes)
                signed_bytes = self.sign(encrypted_bytes)
                self.write_bytes_at_path(path, signed_bytes)
        except Exception as err:
            traceback.print_exc()
            pass

    def decrypt(self, path: Union[str, PathType]) -> None:
        """Decrypt the object at the path. This decrypts the bytes with the key, then writes the bytes to the path.

        Parameters
        ----------
        path : str
            Description of parameter `path`.
        Returns
        -------
        None
            Returns none as it writes the bytes to the path.
        Raises
        ------
        Exception
            Will raise an exception if you have not set the key before decrypting.
        """
        try:
            if not self.private_key:
                raise Exception(
                    "You haven't set a key yet to decrypt with. Please generate a key and make sure you save it."
                )
            path = pathlib.Path(path).resolve()
            read_bytes = self.read_bytes_at_path(path)
            unsigned_bytes = self.remove_sign(read_bytes)
            if unsigned_bytes:
                decrypted_bytes = self.decrypt_bytes(unsigned_bytes)
                self.write_bytes_at_path(path, decrypted_bytes)
            else:
                decrypted_bytes = self.decrypt_bytes(read_bytes)
                self.write_bytes_at_path(path, decrypted_bytes)
        except Exception as err:
            traceback.print_exc()
            pass

    def switch_encryption(self, path: Union[str, PathType]) -> None:
        try:
            if not self.private_key and not self.public_key:
                raise Exception(
                    "You haven't set a key yet to decrypt with. Please generate a key and make sure you save it."
                )
            path = pathlib.Path(path).resolve()
            read_bytes = self.read_bytes_at_path(path)
            if self.already_encrypted(read_bytes):
                self.decrypt(path)
            else:
                self.encrypt(path)
        except Exception as err:
            traceback.print_exc()
