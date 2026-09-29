from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from .exceptions import EncryptoMissingKeyError
from .keytype import ACCESS, KEYEXT, KEYFORMAT

# Mapping from KEYEXT to (encoding, private_format) for private key conversion
_PRIVATE_KEY_FORMAT_MAP: dict[KEYEXT, tuple[serialization.Encoding, serialization.PrivateFormat]] = {
    KEYEXT.PEM: (serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL),
    KEYEXT.PKCS8: (serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8),
    KEYEXT.DER: (serialization.Encoding.DER, serialization.PrivateFormat.PKCS8),
}

# Mapping from KEYEXT to (encoding, public_format) for public key conversion
_PUBLIC_KEY_FORMAT_MAP: dict[KEYEXT, tuple[serialization.Encoding, serialization.PublicFormat]] = {
    KEYEXT.PEM: (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    KEYEXT.PKCS8: (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    KEYEXT.DER: (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
}


def _convert_private_key(private_key: PrivateKeyTypes, to: KEYEXT) -> bytes:
    """Convert a private key to the specified format."""
    encoding, fmt = _PRIVATE_KEY_FORMAT_MAP.get(
        to, (serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL)
    )
    return private_key.private_bytes(
        encoding=encoding,
        format=fmt,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _convert_public_key(public_key: PublicKeyTypes, to: KEYEXT) -> bytes:
    """Convert a public key to the specified format."""
    encoding, fmt = _PUBLIC_KEY_FORMAT_MAP.get(
        to, (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return public_key.public_bytes(encoding=encoding, format=fmt)


def _load_public_key_bytes(key_bytes: bytes) -> PublicKeyTypes:
    """Load a public key from PEM or OpenSSH (e.g. ``ssh-rsa AAAA...``) bytes."""
    if key_bytes.lstrip().startswith((b"ssh-", b"ecdsa-")):
        return serialization.load_ssh_public_key(key_bytes)
    return serialization.load_pem_public_key(key_bytes)


class Keyer:

    private_key: PrivateKeyTypes | None = None
    public_key: PublicKeyTypes | None = None

    def __init__(
        self,
        public_key: PublicKeyTypes | None = None,
        private_key: PrivateKeyTypes | bytes | None = None,
        private_key_path: str | Path | None = None,
        public_key_path: str | Path | None = None,
        password: str | bytes | None = None,
        key_type: KEYFORMAT | None = None,
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

    def generate_rsa_key(self, public_exponent: int = 65537, bits: int = 4096) -> None:
        self.private_key = rsa.generate_private_key(
            public_exponent=public_exponent, key_size=bits
        )
        self.public_key = self.private_key.public_key()

    def generate_ed25519_key(self) -> None:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def generate_rsa_key_write_to_file(
        self,
        private_path: str | Path | None = None,
        public_path: str | Path | None = None,
        public_exponent: int = 65537,
        bits: int = 4096,
        overwrite: bool = False,
    ) -> None:
        if self.public_key_path and self.private_key_path:
            private_path = Path(self.private_key_path).resolve()
            public_path = Path(self.public_key_path).resolve()
        elif private_path and public_path:
            private_path = Path(private_path).resolve()
            public_path = Path(public_path).resolve()
        else:
            raise ValueError("Must provide both private_path and public_path, or set them on the instance.")

        if not overwrite and (private_path.exists() or public_path.exists()):
            raise FileExistsError(
                "Key file already exists. Set overwrite=True to overwrite."
            )

        self.generate_rsa_key(public_exponent, bits)
        self._write_key_pair(private_path, public_path)

    def generate_ed25519_key_write_to_file(
        self,
        private_path: str | Path | None = None,
        public_path: str | Path | None = None,
        overwrite: bool = False,
    ) -> None:
        if private_path and public_path:
            private_path = Path(private_path).resolve()
            public_path = Path(public_path).resolve()
        else:
            raise ValueError("Must provide both private_path and public_path.")

        if not overwrite and (private_path.exists() or public_path.exists()):
            raise FileExistsError(
                "Key file already exists. Set overwrite=True to overwrite."
            )

        self.generate_ed25519_key()
        self._write_key_pair(
            private_path,
            public_path,
            private_format=serialization.PrivateFormat.PKCS8,
        )

    def _write_key_pair(
        self,
        private_path: Path,
        public_path: Path,
        private_format: serialization.PrivateFormat = serialization.PrivateFormat.TraditionalOpenSSL,
    ) -> None:
        private_bytes = self.serialize_private_key_to_bytes(
            serialization.Encoding.PEM,
            private_format,
            serialization.NoEncryption(),
        )
        public_bytes = self.serialize_public_key_to_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)

    def load_key_by_type(
        self,
        key: bytes,
        password: str | bytes | None = None,
        fmt: KEYFORMAT | None = KEYFORMAT.RSA,
    ) -> PrivateKeyTypes:
        passwd = password.encode() if isinstance(password, str) else password
        if fmt == KEYFORMAT.OPENSSH:
            return serialization.load_ssh_private_key(key, passwd)  # type: ignore
        return serialization.load_pem_private_key(key, passwd)  # type: ignore

    def serialize_private_key_to_bytes(
        self,
        encoding: serialization.Encoding = serialization.Encoding.PEM,
        key_format: serialization.PrivateFormat = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algo: serialization.KeySerializationEncryption = serialization.NoEncryption(),
    ) -> bytes:
        if not self.private_key:
            raise EncryptoMissingKeyError("No private key loaded.")
        return self.private_key.private_bytes(encoding, key_format, encryption_algo)

    def serialize_public_key_to_bytes(
        self,
        encoding: serialization.Encoding = serialization.Encoding.PEM,
        key_format: serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo,
    ) -> bytes:
        if not self.public_key:
            raise EncryptoMissingKeyError("No public key loaded.")
        return self.public_key.public_bytes(encoding, key_format)

    def load_private_key(
        self,
        key: bytes | None = None,
        key_path: str | Path | None = None,
        password: str | bytes | None = None,
        fmt: KEYFORMAT | None = None,
    ) -> PrivateKeyTypes:
        if key_path:
            key_path = Path(key_path).resolve()
            key_bytes = key_path.read_bytes()
            self.private_key = self.load_key_by_type(key_bytes, password, fmt)
            return self.private_key
        elif key:
            passwd = password.encode() if isinstance(password, str) else password
            self.private_key = serialization.load_pem_private_key(key, passwd)
            return self.private_key
        else:
            raise EncryptoMissingKeyError("Must provide either key bytes or key_path.")

    def load_public_key(
        self,
        key: bytes | str | PublicKeyTypes | None = None,
        key_path: str | Path | None = None,
        password: str | None = None,
    ) -> PublicKeyTypes:
        if self.public_key:
            return self.public_key
        elif self.private_key:
            self.public_key = self.private_key.public_key()
            return self.public_key
        elif key:
            if isinstance(key, (bytes, str)):
                key_bytes = key.encode() if isinstance(key, str) else key
                self.public_key = _load_public_key_bytes(key_bytes)
            else:
                self.public_key = key
            return self.public_key
        elif key_path:
            key_bytes = Path(key_path).resolve().read_bytes()
            self.public_key = _load_public_key_bytes(key_bytes)
            return self.public_key
        else:
            raise EncryptoMissingKeyError("No key source available to load public key.")

    def convert(
        self,
        to: KEYEXT,
        private_key_bytes: bytes | None = None,
        private_key: str | Path | None = None,
        password: str | None = None,
    ) -> bytes:
        if not self.private_key:
            self.load_private_key(private_key_bytes, private_key, password)
        return _convert_private_key(self.private_key, to)

    def write_convert(
        self,
        to: KEYEXT,
        key_path: str | Path,
        private_key_bytes: bytes | None = None,
        private_key: str | Path | None = None,
        password: str | None = None,
    ) -> None:
        key_bytes = self.convert(to, private_key_bytes, private_key, password)
        out_path = Path(key_path).with_suffix(to.value).resolve()
        out_path.write_bytes(key_bytes)

    def convert_public(
        self,
        to: KEYEXT,
        private_key_bytes: bytes | None = None,
        private_key: str | Path | None = None,
        password: str | None = None,
    ) -> bytes:
        if not self.private_key:
            self.load_private_key(private_key_bytes, private_key, password)
        return _convert_public_key(self.private_key.public_key(), to)

    def write_convert_public(
        self,
        to: KEYEXT,
        key_path: str | Path,
        private_key_bytes: bytes | None = None,
        private_key: str | Path | None = None,
        password: str | None = None,
    ) -> None:
        key_bytes = self.convert_public(to, private_key_bytes, private_key, password)
        out_path = Path(key_path).with_suffix(to.value).resolve()
        out_path.write_bytes(key_bytes)

    @staticmethod
    def sconvert(
        to: KEYEXT,
        key_path: str | Path,
        password: str | bytes | None = None,
    ) -> bytes:
        key_data = Path(key_path).resolve().read_bytes()
        passwd = password.encode() if isinstance(password, str) else password
        private_key = serialization.load_pem_private_key(key_data, passwd)
        return _convert_private_key(private_key, to)

    @staticmethod
    def swrite_convert(
        to: KEYEXT,
        key_path: str | Path,
        password: str | bytes | None = None,
    ) -> None:
        key_bytes = Keyer.sconvert(to, key_path, password)
        out_path = Path(key_path).with_suffix(to.value).resolve()
        out_path.write_bytes(key_bytes)
