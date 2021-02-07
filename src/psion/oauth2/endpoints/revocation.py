from __future__ import annotations

from typing import Optional

from psion.oauth2.exceptions import InvalidClient, OAuth2Error, UnsupportedTokenType
from psion.oauth2.models import JSONResponse, Request

from .base import BaseEndpoint


class RevocationEndpoint(BaseEndpoint):
    """
    Endpoint used by the `Client` to revoke a token in its possession.

    If the Client succeeds to authenticate but provides a token that was
    not issued to itself, the `Provider` **DOES NOT** revoke the token,
    since the Client is not authorized to operate the token.

    If the token is already invalid, does not exist within the Provider
    or is otherwise unknown or invalid, it is also considered "revoked".

    :cvar `__authentication_methods__`: Allowed Client Authentication methods.
    :cvar `__supported_tokens__`: Token types supported by the endpoint.
    """

    __endpoint__: str = "revocation"
    __authentication_methods__: list[str] = None
    __supported_tokens__: list[str] = ["access_token", "refresh_token"]

    async def __call__(self, request: Request) -> JSONResponse:
        """
        Revokes a previously issued Token.

        First it validates the `Revocation Request` of the `Client`
        by making sure the required parameter "token" is present,
        and that the `Client` can authenticate with the allowed
        authentication methods.

        From the specification at
        `<https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1>`_::

            The client constructs the request by including the following
            parameters using the "application/x-www-form-urlencoded" format in
            the HTTP request entity-body:

            token REQUIRED. The token that the client wants to get revoked.

            token_type_hint OPTIONAL. A hint about the type of the token
                submitted for revocation. Clients MAY pass this parameter in
                order to help the authorization server to optimize the token
                lookup. If the server is unable to locate the token using
                the given hint, it MUST extend its search across all of its
                supported token types. An authorization server MAY ignore
                this parameter, particularly if it is able to detect the
                token type automatically. This specification defines two
                such values:

                * access_token: An access token as defined in [RFC6749],
                    Section 1.4

                * refresh_token: A refresh token as defined in [RFC6749],
                    Section 1.5

                Specific implementations, profiles, and extensions of this
                specification MAY define other values for this parameter
                using the registry defined in Section 4.1.2.

            For example, a client may request the revocation of a refresh token
            with the following request:

                POST /revoke HTTP/1.1
                Host: server.example.com
                Content-Type: application/x-www-form-urlencoded
                Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

                token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

        It then returns an empty response with a HTTP Status 200 OK,
        signaling that the provided token has been revoked by the server.

        From the specification at
        `<https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2>`_::

            The authorization server responds with HTTP status code 200 if the
            token has been revoked successfully or if the client submitted an
            invalid token.

            Note: invalid tokens do not cause an error response since the client
            cannot handle such an error in a reasonable way. Moreover, the
            purpose of the revocation request, invalidating the particular token,
            is already achieved.

            The content of the response body is ignored by the client as all
            necessary information is conveyed in the response code.

            An invalid token type hint value is ignored by the authorization
            server and does not influence the revocation response.

        This endpoint does not return any errors, except when the provided
        `token_type_hint` is not supported by the Provider.

        :raises UnsupportedTokenType: The provided token_type_hint is not supported.
        """

        try:
            client = await self.authenticate(request, self.__authentication_methods__)

            data = request.form()

            token: str = data.get("token")
            token_type_hint: Optional[str] = data.get("token_type_hint")

            if not token or not isinstance(token, str):
                return

            if token_type_hint:
                if token_type_hint not in self.__supported_tokens__:
                    raise UnsupportedTokenType

            await self.adapter.revoke_token(client, token, token_type_hint)

            return JSONResponse()
        except InvalidClient as exc:
            return JSONResponse(401, exc.headers, exc.dump())
        except OAuth2Error as exc:
            return JSONResponse(400, exc.headers, exc.dump())
