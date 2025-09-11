import traceback
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from .exceptions import EncryptoMissingKeyError
from .keytype import ACCESS, KEYEXT, KEYFORMAT


class Keyer:

    private_key = None
    public_key = None

    def __init__(
        self,
        public_key=None,
        private_key=None,
        private_key_path=None,
        public_key_path=None,
        password=None,
        key_type=None
    ):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path

        if self.private_key_path:
            self.load_private_key(key_path=self.private_key_path, password=password, fmt=key_type)
            self.load_public_key()
        elif private_key:
            self.private_key = self.load_private_key(private_key, password=password, fmt=key_type)
            self.load_public_key()
        elif public_key:
            self.load_public_key(key=public_key, password=password)
        elif self.public_key_path and not self.private_key_path:
            self.load_public_key(key_path=self.public_key_path, password=password)

    def generate_rsa_key(self, public_exponent=65537, bits=4096):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=public_exponent, key_size=bits
            )
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(traceback.format_exc())

    def generate_ed25519_key(self):
        try:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        except Exception as err:
            print(traceback.format_exc())

    def generate_rsa_key_write_to_file(
        self,
        private_path=None,
        public_path=None,
        public_exponent=65537,
        bits=4096,
        overwrite: bool = False,
    ):
        try:
            if self.public_key_path and self.private_key_path:
                private_path, public_path = (
                    Path(self.private_key_path).resolve(),
                    Path(self.public_key_path).resolve(),
                )
            else:
                private_path, public_path = (
                    Path(private_path).resolve(),
                    Path(public_path).resolve(),
                )
            if not overwrite and private_path.exists() and public_path.exists():
                raise FileExistsError(
                    "File already exists. Set overwrite to True to overwrite the file."
                )
            self.generate_rsa_key(public_exponent, bits)

            with open(private_path, "wb+") as private_key:
                serialized_bytes = self.serialize_private_key_to_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
                private_key.write(serialized_bytes)
            with open(public_path, "wb+") as public_key:
                serialized_bytes = self.serialize_public_key_to_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                public_key.write(serialized_bytes)
        except Exception as err:
            print(traceback.format_exc())

    def load_key_by_type(
        self,
        key: bytes,
        password: Union[str, bytes, None] = None,
        fmt: KEYFORMAT = KEYFORMAT.RSA,
    ):
        try:
            passwd = password.encode() if type(password) == str else password
            if fmt == KEYFORMAT.RSA:
                return serialization.load_pem_private_key(key, passwd)  # type: ignore
            elif fmt == KEYFORMAT.OPENSSH:
                return serialization.load_ssh_private_key(key, passwd)  # type: ignore
        except Exception as err:
            traceback.print_exc()

    def generate_ed25519_key_write_to_file(self, private_path, public_path, overwrite=False):
        try:
            self.generate_ed25519_key()
            private_path, public_path = (
                Path(private_path).resolve(),
                Path(public_path).resolve(),
            )
            if overwrite:
                with open(private_path, "wb+") as private_key:
                    serialized_bytes = self.serialize_private_key_to_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                    private_key.write(serialized_bytes)
                with open(public_path, "wb+") as public_key:
                    serialized_bytes = self.serialize_public_key_to_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    public_key.write(serialized_bytes)
            elif private_path.exists() or public_path.exists() and not overwrite:
                print("Overwrite flag is false, not regenerating keys.")

        except Exception as err:
            print(traceback.format_exc())

    def serialize_private_key_to_bytes(
        self,
        encoding=serialization.Encoding.Raw,
        key_format=serialization.PrivateFormat.Raw,
        encryption_algo=serialization.NoEncryption(),
    ):
        try:
            private_bytes = self.private_key.private_bytes(
                encoding, key_format, encryption_algo
            )
            return private_bytes

        except Exception as err:
            print(traceback.format_exc())

    def serialize_public_key_to_bytes(
        self,
        encoding=serialization.Encoding.PEM,
        key_format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        try:
            public_bytes = self.public_key.public_bytes(encoding, key_format)
            return public_bytes

        except Exception as err:
            print(traceback.format_exc())

    def serialize_key_into_str(
        self, key: Union[bytes, None] = None, key_path: Union[str, Path, None] = None
    ):
        try:

            if key:
                return key.decode()
            elif key_path:
                with open(key_path, "rb") as key_file:
                    return key_file.read().decode()
        except Exception as err:
            print(traceback.format_exc())

    def load_private_key(
        self,
        key: Union[bytes, None] = None,
        key_path: Union[str, Path, None] = None,
        password: Union[str, bytes, None] = None,
        fmt: Union[KEYFORMAT, None] = None,
    ):
        try:

            if type(key_path) == str:
                key_path = Path(key_path).resolve()
            elif type(key_path) == Path:
                key_path = key_path.resolve()
            if key:
                self.private_key = serialization.load_pem_private_key(key, password)
                self.private_key_str = str(key).replace("\n", r"\n")
                return self.private_key
            elif key_path:
                with open(key_path, "r") as key_file:
                    self.private_key_str = key_file.read().replace("\n", r"\n")
                with open(key_path, "rb") as key_file:
                    self.private_key = self.load_key_by_type(
                        key_file.read(), password, fmt
                    )
                return self.private_key
            else:
                raise EncryptoMissingKeyError("Missing key or keypath...")
        except Exception as err:
            print(traceback.format_exc())

    def load_public_key(
        self,
        key: Union[bytes, None] = None,
        key_path: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            if self.public_key:
                return self.public_key
            elif self.private_key and not self.public_key:
                self.public_key = self.private_key.public_key()
                return self.public_key
            else:
                if key:
                    self.public_key = serialization.load_pem_public_key(key)
                    return self.public_key
                elif key_path:
                    with open(key_path, "r") as key_file:
                        self.public_key_str = key_file.read().replace("\n", r"\n")
                    with open(key_path, "rb") as key_file:
                        self.public_key = serialization.load_pem_public_key(
                            key_file.read()
                        )
                        return self.public_key
        except Exception as err:
            print(traceback.format_exc())

    def convert(
        self,
        to: KEYEXT,
        private_key_bytes: Union[bytes, None] = None,
        private_key: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYEXT.PEM:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS8:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS12:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS12,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.DER:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                case _:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
            return key
        except Exception as err:
            print(traceback.format_exc())

    def write_convert(
        self,
        to: KEYEXT,
        key_path: Union[str, Path],
        private_key_bytes: Union[bytes, None] = None,
        private_key: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYEXT.PEM:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS8:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS12:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS12,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.DER:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                case _:
                    key: Union[bytes, None] = self.private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())

    def convert_public(
        self,
        to: KEYEXT,
        private_key_bytes: Union[bytes, None] = None,
        private_key: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            match to:
                case KEYEXT.PEM:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                case KEYEXT.PKCS8:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                case _:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.Raw
                    )
            return key
        except Exception as err:
            print(traceback.format_exc())

    def write_convert_public(
        self,
        to: KEYEXT,
        key_path: Union[str, Path],
        private_key_bytes: Union[bytes, None] = None,
        private_key: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            if not self.private_key:
                self.load_private_key(private_key_bytes, private_key, password)
            current_key_type = self.private_key.__class__.__name__.lower()
            match to:
                case KEYEXT.PEM:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.Raw,
                    )
                case KEYEXT.PKCS7:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
                    )
                case KEYEXT.PKCS12:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
                    )
                case KEYEXT.DER:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.Raw
                    )
                case _:
                    key: Union[
                        bytes, None
                    ] = self.private_key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.Raw
                    )
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())

    @staticmethod
    def sconvert(
        to: KEYEXT,
        key_path: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            private_key = None
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password
                )
            current_key_type = private_key.__class__.__name__.lower()
            match to:
                case KEYEXT.PEM:
                    key: Union[bytes, None] = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS8:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS12:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS12,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.DER:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                case _:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
            return key
        except Exception as err:
            print(traceback.format_exc())

    @staticmethod
    def swrite_convert(
        to: KEYEXT,
        key_path: Union[str, Path],
        private_key_bytes: Union[bytes, None] = None,
        private_key: Union[str, Path, None] = None,
        password: Union[str, None] = None,
    ):
        try:
            private_key = None
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password
                )
            current_key_type = private_key.__class__.__name__.lower()
            match to:
                case KEYEXT.PEM:
                    key: Union[bytes, None] = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS8:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.PKCS12:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS12,
                        serialization.NoEncryption(),
                    )
                case KEYEXT.DER:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                case _:
                    key: Union[bytes, None] = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
            new_key_path = Path(key_path).joinpath(to.value).resolve()
            with open(new_key_path, "wb+") as key_file:
                key_file.write(key)
        except Exception as err:
            print(traceback.format_exc())
