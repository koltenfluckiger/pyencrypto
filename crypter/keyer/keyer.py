from mimetypes import init
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from pathlib import Path
from ..crypter import EncryptoMissingKeyError


class Keyer:

    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    def generate_rsa_key(self, public_exponent=65537, bits=4096):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=public_exponent, key_size=bits)
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(err)

    def generate_ed25519_key(self):
        try:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(err)

    def generate_rsa_key_write_to_file(self, private_path, public_path, public_exponent=65537, bits=4096, overwrite: bool = False):
        try:

            private_path, public_path = Path(
                private_path).resolve(), Path(public_path).resolve()

            if overwrite == False and private_path.exists() and public_path.exists():
                raise FileExistsError(
                    "File already exists. Set overwrite to True to overwrite the file.")
            else:
                self.generate_rsa_key(public_exponent,  bits)

                with open(private_path, "wb+") as private_key:
                    serialzed_bytes = self.serialize_private_key_to_bytes(
                        "rsa", serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                    private_key.write(serialzed_bytes)
                with open(public_path, "wb+") as public_key:
                    serialzed_bytes = self.serialize_public_key_to_bytes(
                        "rsa", serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    public_key.write(serialzed_bytes)
        except Exception as err:
            print(err)

    def generate_ed25519_key_write_to_file(self, private_path, public_path):
        try:
            self.generate_ed25519_key()
            private_path, public_path = Path(
                private_path).resolve(), Path(public_path).resolve()
            with open(private_path, "wb+") as private_key:
                serialzed_bytes = self.serialize_private_key_to_bytes(
                    "rsa", serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                private_key.write(serialzed_bytes)
            with open(public_path, "wb+") as public_key:
                serialzed_bytes = self.serialize_public_key_to_bytes(
                    "rsa", serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                public_key.write(serialzed_bytes)
        except Exception as err:
            print(err)

    def serialize_private_key_to_bytes(self, key_type, encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algo=serialization.NoEncryption()):
        try:
            private_bytes = self.private_key.private_bytes(
                encoding, format, encryption_algo)
            match key_type:
                case "rsa":
                    return private_bytes
                case "ed25519":
                    return private_bytes
        except Exception as err:
            print(err)

    def serialize_public_key_to_bytes(self, key_type, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo, encryption_algo=serialization.NoEncryption()):
        try:
            public_bytes = self.public_key.public_bytes(
                encoding, format)
            match key_type:
                case "rsa":
                    return public_bytes
                case "ed25519":
                    return public_bytes
        except Exception as err:
            print(err)

    def load_private_key(self, key: bytes = None, key_path: Union[str, Path] = None, password: str = None):
        try:
            if type(key_path) == str:
                key_path = Path(key_path).resolve()
            elif type(key_path) == Path:
                key_path = key_path.resolve()
            if key:
                self.private_key = serialization.load_pem_private_key(
                    key, password)
                self.public_key = self.private_key.public_key()
                return self.private_key
            elif key_path:
                with open(key_path, "rb") as key_file:
                    self.private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=password,
                    )
                    self.public_key = self.private_key.public_key()
                    return self.private_key
            else:
                raise EncryptoMissingKeyError("Missing key or keypath...")
        except Exception as err:
            print(err)
