from __future__ import annotations

import inspect
from typing import Callable
from psion.jose.exceptions import (
    InvalidJWSHeader,
    InvalidJWSSerialization,
    InvalidKey,
    UnsupportedAlgorithm,
)

from psion.jose.jwa.jws import (
    JWSAlgorithm,
    none,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
)
from psion.jose.jwk import JsonWebKey
from psion.webtools import (
    FullDict,
    base64url_decode,
    base64url_encode,
    json_dumps,
    json_loads,
)


class JsonWebSignatureHeader(dict):
    """
    Implementation of RFC 7515.

    This is the implementation of the Header of the Json Web Signature.
    It provides validation for the default parameters of the JWS header.

    The JWS Header is a JSON object that provides information on how to
    manipulate the payload of the message, such as permitted algorithms
    and the keys to be used in signing and verifying the payload.

    TODO: Add support for RFC 7797.

    :cvar ``__algorithms__``: Algorithms supported by the JWS.

    :param header: Dictionary containing the parameters of the JWS header.
    :type header: dict
    """

    __algorithms__: dict[str, JWSAlgorithm] = {
        none.__algorithm__: none,
        HS256.__algorithm__: HS256,
        HS384.__algorithm__: HS384,
        HS512.__algorithm__: HS512,
        RS256.__algorithm__: RS256,
        RS384.__algorithm__: RS384,
        RS512.__algorithm__: RS512,
        ES256.__algorithm__: ES256,
        ES384.__algorithm__: ES384,
        ES512.__algorithm__: ES512,
        PS256.__algorithm__: PS256,
        PS384.__algorithm__: PS384,
        PS512.__algorithm__: PS512,
    }

    def __init__(self, header: dict):
        if not header or not isinstance(header, dict):
            raise InvalidJWSHeader

        validators: list[Callable[[dict], None]] = [
            method
            for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
            if name.startswith("validate_")
        ]

        for validator in validators:
            validator(header)

        if (alg := header.get("alg")) not in self.__algorithms__.keys():
            raise InvalidJWSHeader(f'Unknown JWS algorithm "{alg}".')

        self.algorithm = self.__algorithms__[alg]
        super().__init__(FullDict(header))

    def validate_alg(self, header: dict) -> None:
        """
        The alg parameter is mandatory, and **MUST** be a registered algorithm.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Did not find "alg".
        :raises UnsupportedAlgorithm: The algorithm is not supported.
        """

        if "alg" not in header.keys():
            raise InvalidJWSHeader('Missing parameter "alg".')

        if (alg := header.get("alg")) not in self.__algorithms__.keys():
            raise UnsupportedAlgorithm(f'Unsupported algorithm "{alg}".')

    def validate_jku(self, header: dict) -> None:
        pass

    def validate_jwk(self, header: dict) -> None:
        pass

    def validate_kid(self, header: dict) -> None:
        """
        ID of the JWK used by this JWS. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Key ID is invalid.
        """

        if "kid" in header.keys():
            # pylint: disable=E0601
            if not (kid := header.get("kid")) or not isinstance(kid, str):
                raise InvalidJWSHeader('Invalid parameter "kid".')

    def validate_x5u(self, header: dict):
        pass

    def validate_x5c(self, header: dict):
        pass

    def validate_x5t(self, header: dict):
        pass

    def validate_x5tS256(self, header: dict):
        pass

    def validate_typ(self, header: dict):
        """
        Type of the JWS. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: The type is not a string.
        """

        if "typ" in header.keys():
            # pylint: disable=E0601
            if not (typ := header.get("typ")) or not isinstance(typ, str):
                raise InvalidJWSHeader('Invalid parameter "typ".')

    def validate_cty(self, header: dict):
        """
        Type of the payload. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Content Type is not a string.
        """

        if "cty" in header.keys():
            # pylint: disable=E0601
            if not (cty := header.get("cty")) or not isinstance(cty, str):
                raise InvalidJWSHeader('Invalid parameter "cty".')

    def validate_crit(self, header: dict):
        """
        Critical parameters of the JWS header. If present, MUST be a list of strings.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Not a list of strings,
            or the critical parameter was not found in the JWS header.
        """

        if "crit" in header.keys():
            # Ensures the type safety of the parameter.
            # pylint: disable=E0601
            if not (crit := header.get("crit")) or not isinstance(crit, list):
                raise InvalidJWSHeader('Invalid parameter "crit".')

            # Ensures that each critical parameter is a VALID string.
            if any(not item or not isinstance(item, str) for item in crit):
                raise InvalidJWSHeader('Invalid parameter "crit".')

            for item in crit:
                if not header.get(item):
                    raise InvalidJWSHeader(f'The parameter "{item}" is required.')


class JsonWebSignature:
    """
    Implementation of RFC 7515.

    The JWS is used for transporting data on the network, providing a signature
    that guarantees the integrity of the information received.

    This implementation provides a set of attributes (described below) to represent
    the state of the information, as well as segregating the header from the payload,
    which in turn facilitates the use of any of them.

    It provides an algorithm attribute as well. The algorithm is used to sign
    and verify the data of the JWS.

    TODO: Add JSON Serialization.

    :ivar header: The header of the JWS.
    :ivar payload: The data that is being handled.

    :param payload: Data to be used by the JWS. MUST be a bytes sequence.
    :type payload: bytes

    :param header: Dictionary that comprise the JWS Header.
    :type header: JsonWebSignatureHeader
    """

    def __init__(self, payload: bytes, header: JsonWebSignatureHeader):
        if not isinstance(header, JsonWebSignatureHeader):
            header = JsonWebSignatureHeader(header)

        self.header = header
        self.payload = payload

    def serialize(self, key: JsonWebKey) -> bytes:
        """
        Serializes the content of the current JsonWebSignature.

        It serializes the header into a Base64Url version of its JSON representation,
        and serializes the payload into a Base64Url format, allowing the compatibility
        of the payload in different systems.

        It creates a byte string message of the following format::

            Base64Url(UTF-8(header)).Base64Url(payload)

        It then signs the message using the provided key, and imbues the signature
        into the message, resulting in the following token::

            Base64Url(UTF-8(header)).Base64Url(payload).Base64Url(signature)

        The above token is then returned to the application.

        :param key: Key used to sign the message.
        :type key: JsonWebKey

        :raises InvalidKey: The provided key is invalid.

        :return: Signed token representing the content of the JWS.
        :rtype: bytes
        """

        _validate_key(key, self.header)

        message = b".".join(
            [base64url_encode(json_dumps(self.header)), base64url_encode(self.payload)]
        )

        signature = self.header.algorithm.sign(message, key)
        return b".".join([message, signature])

    @classmethod
    def deserialize(
        cls,
        token: bytes,
        key: JsonWebKey,
        algorithm: str = None,
        validate: bool = True,
    ) -> JsonWebSignature:
        """
        Deserializes a token checking if its signature matches its content.

        Despite being optional, it is recommended to provide an algorithm
        to prevent the "none attack" and the misuse of a public key
        as secret key.

        The algorithm specified at the header of the token
        **MUST** match the provided algorithm, if any.

        :param token: Token to be deserialized.
        :type token: bytes

        :param key: Key used to validate the token's signature.
        :type key: JsonWebKey

        :param algorithm: Expected algorithm of the token.
        :type algorithm: str

        :param validate: Defines if the deserialization should validate the signature.
            Defaults to True.
        :type validate: bool, optional

        :raises InvalidJWSSerialization: The provided JWS token is invalid.
        :raises InvalidKey: The provided key is invalid.
        :raises InvalidSignature: Unmatching token signature and content.

        :return: Instance of a JsonWebSignature.
        :rtype: JsonWebSignature
        """

        try:
            header, payload, signature = token.split(b".")
        except (AttributeError, ValueError):
            raise InvalidJWSSerialization

        jws_header = JsonWebSignatureHeader(json_loads(base64url_decode(header)))

        if algorithm:
            if (alg := jws_header.get("alg")) != algorithm:
                raise InvalidJWSSerialization(
                    f'Expected algorithm "{algorithm}". Got "{alg}".'
                )

        if validate:
            _validate_key(key, jws_header)
            jws_header.algorithm.verify(signature, b".".join([header, payload]), key)

        return cls(base64url_decode(payload), jws_header)


def _validate_key(key: JsonWebKey, header: JsonWebSignatureHeader):
    """
    Validates the provided key against the header
    algorithm's specifications and restrictions.

    :param key: JWK to be validated.
    :type key: JsonWebKey

    :param header: JWS Header used to validate the key against.
    :type header: JsonWebSignatureHeader

    :raises InvalidKey: The provided key is invalid.
    """

    if not isinstance(key, JsonWebKey):
        raise InvalidKey

    if key.data.get("alg"):
        if key.data.get("alg") != header.get("alg"):
            raise InvalidKey(
                f'This key cannot be used by the algorithm "{header.get("alg")}".'
            )

    if header.get("kid"):
        if key.data.get("kid") != header.get("kid"):
            raise InvalidKey("The key ID does not match the specified on the header.")

    if key.data.get("use"):
        if key.data.get("use") != "sig":
            raise InvalidKey("This key cannot be used to sign a JWS.")

    if key.data.get("key_ops"):
        if any(op not in ("sign", "verify") for op in key.data.get("key_ops")):
            raise InvalidKey("This key cannot be used to sign a JWS.")
