

class Message:

    def __init__(self):
        pass

    def encrypt_message(self, message: Union[str, bytes]) -> None:
        """Encrypt a string with the key from the session.

        Parameters
        ----------
        message : Union[str,bytes]
            The message you want to encrypt either in string or bytes format.
        Returns
            None
        """
        try:
            if type(message) == str:
                message = message.encode()
            hash = hmac.HMAC(self.key, hashes.SHA256())
            hash.update(message)
            signature = h.finalize()
        except Exception as err:
            print(err)

    def decrypt_message(self, message: bytes) -> str:
        try:
            pass
        except Exception as err:
            print(err)
