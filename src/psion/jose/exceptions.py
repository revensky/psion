class JoseError(Exception):
    """
    Base error class for the exceptions of the JOSE implementation.

    :cvar error: Default error message of the exception.
    """

    error: str = None

    def __init__(self, error: str = None) -> None:
        super().__init__(error or self.error)


class InvalidKey(JoseError):
    error: str = "The provided key is invalid or contains invalid parameters."


class InvalidKeySet(JoseError):
    error: str = "The provided key set is invalid or contain invalid keys."


class InvalidSignature(JoseError):
    error: str = "The provided signature does not match the provided data."


class UnsupportedAlgorithm(JoseError):
    error = "The provided algorithm is not supported."


class UnsupportedParsingMethod(JoseError):
    error: str = "The provided parsing method is not supported."
