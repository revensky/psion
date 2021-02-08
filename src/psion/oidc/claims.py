from psion.jose import JsonWebTokenClaims
from psion.jose.exceptions import InvalidJWTClaim


class IDToken(JsonWebTokenClaims):
    """
    Defines the claims of the ID Token.

    The parameters supported out-of-the-box by Guarani are described below.
    To get more information, please refer to the specification at
    `<https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_::

        * "iss" - Issuer of the response.
        * "sub" - ID of the Authenticated User.
        * "aud" - Audience of the ID Token. Its value is the ID of the Client.
        * "exp" - Expiration time of the ID Token.
        * "iat" - Time when the ID token was issued.
        * "auth_time" - Time when the User was authenticated.
        * "nonce" - String value used to associate a Client session with an ID Token,
            and to mitigate replay attacks.
        * "acr" - Authentication Context Class Reference.*
        * "amr" - Authentication Methods References.*
        * "azp" - Authorized party ID. Refers to the ID of the Client.*

        The following is a non-normative example of the Claims of an ID Token:

        {
            "iss": "https://server.example.com",
            "sub": "24400320",
            "aud": "s6BhdRkqt3",
            "nonce": "n-0S6_WzA2Mj",
            "exp": 1311281970,
            "iat": 1311280970,
            "auth_time": 1311280969,
            "acr": "urn:mace:incommon:iap:silver"
        }

        * Support in the future.
    """

    def _validate_default_claims(self, claims: dict) -> None:
        super()._validate_default_claims(claims)

        # Validate auth_time
        self._validate_auth_time(claims)

        # Validate nonce
        self._validate_nonce(claims)

    def _validate_auth_time(self, claims: dict) -> None:
        auth_time = claims.get("max_age")

        if claims.get("max_age") and not auth_time:
            raise InvalidJWTClaim('Invalid claim "auth_time".')

        if auth_time is not None and type(auth_time) is not int:
            raise InvalidJWTClaim('Invalid claim "auth_time".')

    def _validate_nonce(self, claims: dict) -> None:
        nonce = self.options.get("nonce")

        if nonce:
            if nonce != claims.get("nonce"):
                raise InvalidJWTClaim('Invalid claim "nonce".')
