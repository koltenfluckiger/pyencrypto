class EncryptoAlreadyEncryptedError(Exception):

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class EncryptoMissingKeyError(Exception):

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
