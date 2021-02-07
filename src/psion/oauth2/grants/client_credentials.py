from __future__ import annotations

from psion.oauth2.exceptions import InvalidRequest
from psion.oauth2.mixins import ClientMixin

from .base import BaseGrant


class ClientCredentialsGrant(BaseGrant):
    """
    Implementation of the Client Credentials Grant described in the
    `OAuth 2.1 Spec <https://tools.ietf.org/html/draft-parecki-oauth-v2-1#section-4.2>`_.

    This grant **DOES NOT** have an authorization grant step. Therefore, its usage
    on the authorization endpoint **WILL** result in an error.

    It **ONLY** allows `confidential` or `credentialed` clients to use it,
    since it relies on the authentication of the client based on its credentials
    to issue an access token. It also **DOES NOT** issue refresh tokens.
    """

    __authentication_methods__: list[str] = [
        "client_secret_basic",
        "client_secret_post",
    ]
    __grant_type__: str = "client_credentials"

    async def token(self, data: dict, client: ClientMixin) -> dict:
        """
        Validates the `Client's Credential` to authenticate the `Client`
        and validates if the `Client` is allowed to use this `Grant`.

        It then issues a new `Access Token` to the `Client`, without a `Refresh Token`.
        From the specification at
        `<https://tools.ietf.org/html/draft-parecki-oauth-v2-1-03#section-4.2.3>`_::

            If the access token request is valid and authorized, the
            authorization server issues an access token as described in
            Section 5.1. A refresh token SHOULD NOT be included. If the request
            failed client authentication or is invalid, the authorization server
            returns an error response as described in Section 5.2.

            An example successful response:

            HTTP/1.1 200 OK
            Content-Type: application/json
            Cache-Control: no-store
            Pragma: no-cache

            {
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "Bearer",
                "expires_in": 3600,
                "example_parameter": "example_value"
            }

        :param data: Data of the Token Request.
        :type data: dict

        :param client: Client requesting a new Token.
        :type client: ClientMixin

        :return: Access Token and its metadata.
        :rtype: dict
        """

        data = self._validate_token_request(data)

        self._validate_requested_scopes(data["scopes"], client)

        scopes = client.get_allowed_scopes(data["scopes"])

        token = await self.adapter.create_access_token(client, client, scopes)

        return self._create_token(
            token,
            self.config.token_lifespan,
            None,
            scopes if scopes != data["scopes"] else None,
        )

    def _validate_token_request(self, data: dict) -> dict:
        """
        Validates the incoming data from the `Client` to ensure
        that **ALL** the required parameters were provided.

        From the specification at
        `<https://tools.ietf.org/html/draft-parecki-oauth-v2-1-03#section-4.2.2>`_::

            The client makes a request to the token endpoint by adding the
            following parameters using the "application/x-www-form-urlencoded"
            format per Appendix B with a character encoding of UTF-8 in the HTTP
            request entity-body:

            "grant_type": REQUIRED. Value MUST be set to "client_credentials".

            "scope": OPTIONAL. The scope of the access request as described by
                Section 3.3.

            The client MUST authenticate with the authorization server as
            described in Section 3.2.1.
            For example, the client makes the following HTTP request using
            transport-layer security (with extra line breaks for display purposes
            only):

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=client_credentials

            The authorization server MUST authenticate the client.

        :param data: Data of the Token Request.
        :type data: dict

        :return: Validated and reformatted Token Request data.
        :rtype: dict
        """

        scope: str = data.pop("scope", None)

        if scope:
            if not scope or not isinstance(scope, str):
                raise InvalidRequest(description='Invalid parameter "scope".')

        return {"scopes": scope.split() if scope else None}
