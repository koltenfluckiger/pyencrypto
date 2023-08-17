import traceback
from mimetypes import init
from pathlib import Path
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from ..crypter import EncryptoMissingKeyError
from .keytype import ACCESS, KEYTYPE


class Keyer:

    def __init__(self, public_key=None, private_key=None, private_key_path=None, public_key_path=None, password=None):
        if private_key_path:
            self.load_private_key(key_path=private_key_path, password=password)
        elif private_key:
            self.private_key = private_key
        if self.private_key and not self.public_key:
            self.load_public_key(self.private_key)
        elif public_key_path:
            self.load_public_key(public_key_path)
        else:
            self.public_key = public_key

    def generate_rsa_key(self, public_exponent=65537, bits=4096):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=public_exponent, key_size=bits)
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(traceback.format_exc())

    def generate_ed25519_key(self):
        try:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(traceback.format_exc())

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
                    serialized_bytes = self.serialize_private_key_to_bytes(
                        "rsa", serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                    private_key.write(serialized_bytes)
                with open(public_path, "wb+") as public_key:
                    serialized_bytes = self.serialize_public_key_to_bytes(
                        "rsa", serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    public_key.write(serialized_bytes)
        except Exception as err:
            print(traceback.format_exc())

    def generate_ed25519_key_write_to_file(self, private_path, public_path):
        try:
            self.generate_ed25519_key()
            private_path, public_path = Path(
                private_path).resolve(), Path(public_path).resolve()
            with open(private_path, "wb+") as private_key:
                serialized_bytes = self.serialize_private_key_to_bytes(
                    "rsa", serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                private_key.write(serialized_bytes)
            with open(public_path, "wb+") as public_key:
                serialized_bytes = self.serialize_public_key_to_bytes(
                    "rsa", serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                public_key.write(serialized_bytes)
        except Exception as err:
            print(traceback.format_exc())

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
            print(traceback.format_exc())

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
            print(traceback.format_exc())

    def load_private_key(self, key: Union[bytes, None] = None, key_path: Union[str, Path, None] = None, password: Union[str, None] = None):
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
            print(traceback.format_exc())

    def load_public_key(self, key: Union[bytes, None] = None, key_path: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            if key or key_path:
                self.load_private_key(key, key_path, password)
            self.public_key = self.private_key.public_key()
            return self.public_key
        except Exception as err:
            print(traceback.format_exc())

    def convert(self, to: KEYTYPE, private_key_bytes: Union[bytes, None] = None, private_key: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                case KEYTYPE.PKCS12:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS12, serialization.NoEncryption())
                case KEYTYPE.DER:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                case _:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            return key
        except Exception as err:
            print(traceback.format_exc())

    def write_convert(self, to: KEYTYPE, key_path: Union[str, Path], private_key_bytes: Union[bytes, None] = None, private_key: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                case KEYTYPE.PKCS12:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS12, serialization.NoEncryption())
                case KEYTYPE.DER:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                case _:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())

    def convert_public(self, to: KEYTYPE, private_key_bytes: Union[bytes, None] = None, private_key: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                case _:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.Raw)
            return key
        except Exception as err:
            print(traceback.format_exc())

    def write_convert_public(self, to: KEYTYPE, key_path: Union[str, Path], private_key_bytes: Union[bytes, None] = None, private_key: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            current_key_type = self.private_key.__class__.__name__.lower()
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.Raw)
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.PKCS8)
                case KEYTYPE.PKCS12:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.PKCS12)
                case KEYTYPE.DER:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.Raw)
                case _:
                    key: Union[bytes, None] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.Raw)
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())

    @staticmethod
    def sconvert(to: KEYTYPE, key_path: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            private_key = None
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password)
            current_key_type = private_key.__class__.__name__.lower()
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                case KEYTYPE.PKCS12:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS12, serialization.NoEncryption())
                case KEYTYPE.DER:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                case _:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            return key
        except Exception as err:
            print(traceback.format_exc())

    @staticmethod
    def swrite_convert(to: KEYTYPE, key_path: Union[str, Path], private_key_bytes: Union[bytes, None] = None, private_key: Union[str, Path, None] = None, password: Union[str, None] = None):
        try:
            private_key = None
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password)
            current_key_type = private_key.__class__.__name__.lower()
            match to:
                case KEYTYPE.PEM:
                    key: Union[bytes, None] = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                case KEYTYPE.PKCS8:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                case KEYTYPE.PKCS12:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS12, serialization.NoEncryption())
                case KEYTYPE.DER:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                case _:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())
