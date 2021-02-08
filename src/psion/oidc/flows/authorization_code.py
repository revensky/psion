from datetime import datetime

from psion.jose import JsonWebToken
from psion.jose.jwk import JsonWebKey
from psion.oauth2.adapter import BaseAdapter
from psion.oauth2.config import Config
from psion.oauth2.exceptions import InvalidRequest
from psion.oauth2.mixins import ClientMixin, UserMixin
from psion.oidc.claims import IDToken
from psion.webtools import create_half_hash


class AuthorizationCodeFlow:
    """
    Hook representing the Authorization Flow of OpenID Connect.

    :param adapter: Registerd adapter of the Provider.
    :type adapter: BaseAdapter

    :param config: Registered configuration of the Provider.
    :type config: Config
    """

    def __init__(self, adapter: BaseAdapter, config: Config):
        self.adapter = adapter
        self.config = config

    async def authorization_request(self, data: dict) -> dict:
        if nonce := data.get("nonce"):
            if not nonce or not isinstance(nonce, str):
                raise InvalidRequest(description='Invalid parameter "nonce".')

            return {"nonce": nonce}

    # pylint: disable=unused-argument
    async def token_response(
        self, token: dict, data: dict, client: ClientMixin, user: UserMixin
    ) -> dict:
        if "openid" in token["scope"]:
            id_token = await self._generate_id_token(token, client, user)
            return {"id_token": id_token}

    async def _generate_id_token(
        self, token: dict, client: ClientMixin, user: UserMixin
    ) -> str:
        """
        Generates an ID Token containing the claims of the currently authenticated User
        based on the scopes requested by the Client.

        This method **MUST** only be used if the scope `openid` has been requested,
        otherwise, it is ignored and treated as a normal OAuth 2.1 Authorization Request.

        :param token: Token containing the Access Token and the scopes.
        :type token: dict

        :param client: Client requesting authorization.
        :type client: ClientMixin

        :param user: Currently authenticated User.
        :type user:

        :return: JWT encoded ID Token containing the claims
            requested by the Client about the User.
        :rtype: str
        """

        key_info = await self.adapter.get_key_info()
        userinfo = await self.adapter.get_userinfo(user, token["scope"].split())
        now = int(datetime.utcnow().timestamp())

        key: JsonWebKey = key_info["key"]

        claims = IDToken(
            {
                "iss": self.config.issuer,
                "aud": client.get_client_id(),
                "exp": now + self.config.id_token_lifespan,
                "iat": now,
                "at_hash": create_half_hash(token["access_token"], key_info["alg"]),
                **userinfo,
            }
        )
        id_token = JsonWebToken(
            claims,
            {"alg": key_info["alg"], "typ": "JWT", "kid": key.data["kid"]},
        )

        return id_token.encode(key)
