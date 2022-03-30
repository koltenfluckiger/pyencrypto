#!/usr/bin/env python3
from typing import Union
import pathlib
import base64
from pathlib import Path as PathType
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from .exceptions import EncryptoMissingKeyError, EncryptoAlreadyEncryptedError


class Crypter:
    """Class to help you easily encrypt and decrypt objects/files/messages

    Parameters
    ----------
    key : bytes
        Key to decrypt and encrypte files in bytes. (the default is None).
    Attributes
    ----------
    key : bytes
        Key to decrypt and encrypte files in bytes. (the default is None).
    """

    def __init__(self, key: bytes = None, magic_str: str = "pyencrypto"):
        """Constructs all the necessary attributes for the crypter object.

        Parameters
        ----------
        key : bytes
            The key in bytes if you already know it. (the default is None).
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

        self.key = key
        self.magic_str = magic_str
        self.generate_sign()

    def generate_sign(self):
        try:
            digest = hashes.Hash(hashes.SHA512())
            digest.update(self.magic_str.encode())
            msg = digest.finalize()
            self.signer = msg
        except Exception as err:
            print(err)

    def generate_key(self, write: bool = False, path: Union[str, PathType] = None, overwrite: bool = False):
        """Generates a key to use for your current session. I would recommend saving this key somewhere as you can't access files encrypted without it.
        Parameters

        Parameters
        ----------
        write : bool
            Write key to a file.
        path : str
            Path you would like to write the file to.
        overwrite : bool
            Overwrite the file if it already exists at `path`.
        Returns
        -------
        None
        """
        try:
            key = Fernet.generate_key()
            if path and write:
                path = pathlib.Path(path)
                if path.exists() and overwrite:
                    with open(path, "wb") as file:
                        file.write(key)
            return key
        except Exception as err:
            print(err)

    def load_key_from_file(self, path: Union[str, PathType]):
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
                self.set_key_session(key_bytes)
        except Exception as err:
            print(err)

    def set_key_session(self, key: Union[str, bytes] = None) -> None:
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
            if self.key:
                self.session = Fernet(self.key)
            elif key:
                self.session = Fernet(key)
            else:
                raise EncryptoMissingKeyError(
                    "No key provided in set key session...")
        except Exception as err:
            print(f"set_key_session: {err}")

    def sign(self, bytes: bytes):
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
        if bytes[:len(self.signer)] == self.signer:
            raise EncryptoAlreadyEncryptedError(
                "Object is already encrypted. Quitting...")
        else:
            return b''.join([self.signer, bytes])

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
        try:
            if signed_bytes[0:len(self.signer)] == self.signer:
                return signed_bytes[(len(self.signer)):]
            else:
                return None
        except Exception as err:
            print(f"remove_sign: {err}")

    def write_bytes_at_path(self, path: Union[str, PathType], bytes: bytes) -> None:
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
                file.write(bytes)
        except Exception as err:
            print(err)

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
            print(err)

    def encrypt_bytes(self, bytes: bytes) -> bytes:
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
            encrypted_bytes = self.session.encrypt(bytes)
            return encrypted_bytes
        except Exception as err:
            print(err)

    def decrypt_bytes(self, bytes: bytes) -> bytes:
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
            decrypted_bytes = self.session.decrypt(bytes)
            return decrypted_bytes
        except Exception as err:
            print(err)

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
            if not self.session:
                raise Exception(
                    "You haven't set a key yet to encrypt with. Please generate a key and make sure you save it.")
                exit()
            path = pathlib.Path(path).resolve()
            read_bytes = self.read_bytes_at_path(path)
            if self.sign(read_bytes):
                encrypted_bytes = self.encrypt_bytes(read_bytes)
                signed_bytes = self.sign(encrypted_bytes)
                self.write_bytes_at_path(path, signed_bytes)
        except Exception as err:
            print(err)
            exit()

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
            if not self.session:
                raise Exception(
                    "You haven't set a key yet to decrypt with. Please generate a key and make sure you save it.")
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
            print(err)
            exit()
