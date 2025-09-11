from enum import Enum


class KEYEXT(Enum):
    DER = ".cer"
    PEM = ".pem"
    PKCS7 = ".p7b"
    PKCS8 = ".p8"
    PKCS12 = ".p12"


class ACCESS(Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


class KEYFORMAT(Enum):

    OPENSSH = "openssh"
    RSA = "rsa"
