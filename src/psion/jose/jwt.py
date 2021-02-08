from __future__ import annotations

from datetime import datetime

from psion.jose.exceptions import ExpiredToken, InvalidJWTClaim, NotYetValidToken
from psion.jose.jwk import JsonWebKey
from psion.jose.jws import JsonWebSignature, JsonWebSignatureHeader
from psion.webtools import FullDict, json_dumps, json_loads, to_bytes, to_string


class JsonWebTokenClaims(dict):
    """
    Implementation of RFC 7519.

    It provides validation for the default parameters of the JWT claims.

    The JWT Claims is a JSON object that contains information about
    an application, system or user.

    :param claims: Dictionary containing the parameters
        of the payload of the JWT.
    :type claims: dict

    :param options: Options used to validate the claims.
    :type options: dict[str, dict]
    """

    def __init__(self, claims: dict, options: dict[str, dict] = None) -> None:
        if not claims or not isinstance(claims, dict):
            raise InvalidJWTClaim("The claims object MUST be a valid dict.")

        self.options = options or {}

        self._validate_default_claims(claims)

        if isinstance(options, dict):
            self._validate_claims(claims)

        super().__init__(FullDict(claims))

    def _validate_default_claims(self, claims: dict) -> None:
        # Used to validate the date attributes.
        now = int(datetime.utcnow().timestamp())

        # Validate aud
        if aud := claims.get("aud"):
            if aud is not None and not isinstance(aud, (str, list)):
                raise InvalidJWTClaim('Invalid claim "aud".')

            if isinstance(aud, list):
                if any(not isinstance(item, str) for item in aud):
                    raise InvalidJWTClaim('Invalid claim "aud".')

        # Validate exp
        if exp := claims.get("exp"):
            if exp is not None and type(exp) is not int:
                raise InvalidJWTClaim('Invalid claim "exp".')

            if now >= exp:
                raise ExpiredToken

        # Validate iat
        if iat := claims.get("iat"):
            if iat is not None and type(iat) is not int:
                raise InvalidJWTClaim('Invalid claim "iat".')

            if now < iat:
                raise InvalidJWTClaim('Invalid claim "iat".')

        # Validate iss
        if claims.get("iss") is not None and not isinstance(claims.get("iss"), str):
            raise InvalidJWTClaim('Invalid claim "iss".')

        # Validate jti
        if claims.get("jti") is not None and not isinstance(claims.get("jti"), str):
            raise InvalidJWTClaim('Invalid claim "jti".')

        # Validate nbf
        if nbf := claims.get("nbf"):
            if nbf is not None and type(nbf) is not int:
                raise InvalidJWTClaim('Invalid claim "nbf".')

            if now < nbf:
                raise NotYetValidToken

        # Validate sub
        if claims.get("sub") is not None and not isinstance(claims.get("sub"), str):
            raise InvalidJWTClaim('Invalid claim "sub".')

    def _validate_claims(self, claims: dict) -> None:
        """
        Validates the provided claims using the declared options.

        :param claims: Dictionary containing the parameters
            of the payload of the JWT.
        :type claims: dict

        :raises InvalidJWTClaim: The requested claim does not meet the requirements.
        """

        for claim, option in self.options.items():
            if not isinstance(option, dict):
                continue

            value = claims.get(claim)

            if option.get("essential") and value is None:
                raise InvalidJWTClaim(f'Missing required claim "{claim}".')

            if option.get("value") and value != option.get("value"):
                raise InvalidJWTClaim(
                    f'Mismatching expected value "{option.get("value")}". Got "{value}".'
                )

            if option.get("values"):
                if not isinstance(option["values"], list):
                    raise InvalidJWTClaim('Expected a list for the attribute "values".')

                if isinstance(value, list) and any(
                    item in option["values"] for item in value
                ):
                    break

                for expected_value in option["values"]:
                    if value == expected_value:
                        break
                else:
                    raise InvalidJWTClaim(
                        f'Mismatching any of expected values {option["values"]}. Got "{value}".'
                    )


class JsonWebToken:
    """
    Implementation of RFC 7519.

    The JWT is used for transporting claims over the network,
    providing a signature that guarantees the integrity of the information received.

    This implementation provides a set of attributes (described below) to represent
    the state of the information, as well as segregating the header from the payload,
    which in turn facilitates the use of any of them.

    It can be used with either a JWS or a JWE. The most common way of representing
    a JWT is through the JWS Compact Serialization, which gives a small token
    that is digitally signed.

    The claims are represented via a JSON object that contains information about
    an application, system or user. Since this information is digitally signed,
    the receiver can then use the respective key to validate the token and can
    trust that the information is legit.

    TODO: Add support for JWE headers.

    :param claims: Claims about the entity represented by the token.
    :type claims: dict

    :param header: Dictionary that comprise the header of the token.
    :type header: dict

    :param options: Optional validation options for the claims of the token.
    :type options: dict[str, dict]
    """

    def __init__(self, claims: JsonWebTokenClaims, header: dict):
        self.header = JsonWebSignatureHeader(header)
        self.claims = JsonWebTokenClaims(claims)
        self._jws = JsonWebSignature(to_bytes(json_dumps(self.claims)), self.header)

    def __repr__(self):
        return f"<Header: {self.header}, Claims: {self.claims}>"

    def encode(self, key: JsonWebKey) -> str:
        """
        Encodes the internal representation of the current JWT object,
        signs it with the provided key and returns the respective token.

        :param key: Key used to sign and encode the token.
        :type key: JsonWebKey

        :return: Encoded Json Web Token header, payload and signature.
        :rtype: bytes
        """

        return to_string(self._jws.serialize(key))

    @classmethod
    def decode(
        cls,
        token: bytes | str,
        key: JsonWebKey,
        algorithm: str = None,
        validate: bool = True,
        options: dict[str, dict] = None,
    ) -> JsonWebToken:
        """
        Decodes a token checking if its signature matches its content.

        Despite being optional, it is recommended to provide an algorithm
        to prevent the "none attack" and the misuse of a public key
        as secret key.

        The algorithm specified at the header of the token **MUST** match
        the provided algorithm, if any.

        If the token has an Issued At (`iat`) parameter, it will verify the
        validity of the token against the provided `expiration` argument.

        :param token: Token to be verified.
        :type token: Union[bytes, str]

        :param key: Key used to validate the token's signature.
        :type key: JsonWebKey

        :param algorithm: Expected algorithm of the token, defaults to None.
        :type algorithm: str, optional

        :param validate: Defines if the decoding should validate the signature.
            Defaults to True.
        :type validate: bool, optional

        :param options: Optional validation options for the claims of the token.
        :type options: dict[str, dict]

        :return: Instance of a JsonWebToken.
        :rtype: JsonWebToken
        """

        jws = JsonWebSignature.deserialize(to_bytes(token), key, algorithm, validate)
        claims = JsonWebTokenClaims(
            json_loads(jws.payload), options if validate else None
        )

        return cls(claims, jws.header)
