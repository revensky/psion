from __future__ import annotations

from typing import Optional, Union

from psion.oauth2.mixins import (
    AuthorizationCodeMixin,
    ClientMixin,
    RefreshTokenMixin,
    UserMixin,
)


class BaseAdapter:
    """
    Base Adapter class that contains common methods used throughout Guarani.

    These methods are used by multiple authentication methods, endpoints and/or grants,
    and therefore, to respect the DRY principle, they are defined in this class.

    The application **MUST** provide a concrete implementation of the methods
    defined in this class.
    """

    async def find_user(self, user_id: str) -> UserMixin:
        """
        Searches for a user in the application's storage
        and returns it if it succeeds, otherwise returns None.

        :param user_id: ID of the user being searched.
        :type user_id: str

        :return: User based on the provided ID.
        :rtype: UserMixin
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def find_client(self, client_id: str) -> ClientMixin:
        """
        Searches for a client in the application's storage
        and returns it if it succeeds, otherwise returns None.

        :param client_id: ID of the client being searched.
        :type client_id: str

        :return: Client based on the provided ID.
        :rtype: ClientMixin
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def save_authorization_code(
        self, code: str, data: dict, client: ClientMixin, user: UserMixin
    ) -> None:
        """
        Binds the `Authorization Code` to the `Client` and saves it for the Token part.

        It is **RECOMMENDED** that the application sets a lifetime for the code.

        :param code: Code to be associated with the Client.
        :type code: str

        :param data: Dictionary containing the data of the Authorization Request.
        :type data: dict

        :param client: Client being authorized.
        :type client: ClientMixin

        :param user: User granting authorization.
        :type user: UserMixin
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def get_authorization_code(self, code: str) -> AuthorizationCodeMixin:
        """
        Retrieves the data of an `Authorization Code`from
        the application's storage based on the provided `code`.

        :param code: Authorization Code to be fetched.
        :type code: str

        :return: Requested Authorization Code.
        :rtype: AuthorizationCodeMixin
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def delete_authorization_code(self, code: str) -> None:
        """
        Deletes the provided `Authorization Code` from the application's storage.

        :param code: Authorization Code to be deleted.
        :type code: str
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def create_access_token(
        self,
        client: ClientMixin,
        resource_owner: Union[ClientMixin, UserMixin],
        scopes: list[str],
    ) -> str:
        """
        Generates an `Access Token` that creates a tight coupling between the `Client`,
        the `Resource Owner` and the `Scopes` that the `Resource Owner`
        authorized the `Client` to access on its behalf.

        The structure of the `Access Token` is left undefined by this framework,
        but it is **RECOMMENDED** that the application uses `Json Web Token (JWT)`
        for the `Access Token`, followin the specifications at
        `JWT Profile for OAuth 2 Access Tokens
        <https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt>`_.

        The format of the `Access Token Response` is as follows, with values displayed
        as example only, not defining a format for any of the Tokens::

            {
                "access_token": "vlOa11kBoziWFBsQiUu59SjgHJbi7spU80Ew5xCTZ9UhZmWN",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "7eqGioGLs-O7ky3CgeAU87bfijRam6r5"
            }

        Since the `Refresh Token` is optional when the `Resource Owner`
        is separate from the `Client`, and not recommended
        when the `Client` is the `Resource Owner`, its presence
        in the final response is optional.

        :param client: Client that will use the issued Access Token.
        :type client: ClientMixin

        :param resource_owner: Resource Owner that the Client is acting on behalf of.
        :type resource_owner: Union[ClientMixin, UserMixin]

        :param scopes: Scopes of the Token granted by the Resource Owner to the Client.
        :type scopes: list[str]

        :return: Issued Access Token.
        :rtype: str
        """

        raise NotImplementedError("This method MUST be implemented.")

    async def get_userinfo(self, user: UserMixin, scopes: list[str]) -> dict:
        """
        Returns the information about the User based on the requested scopes.

        :param user: User subject of the Authentication Request.
        :type user: UserMixin

        :param scopes: Scopes requested by the Client.
        :type scopes: list[str]

        :return: Information about the User based on the requested scopes.
        :rtype: dict
        """

        raise NotImplementedError("Implement this method to support ID Tokens.")

    async def get_key_info(self) -> dict:
        """
        Returns the information necessary to create an ID Token.

        The dictionary returned **MUST** contain the following information::

            * "key": Key used to sign the ID Token.
            * "alg": Algorithm used to create the signature the ID Token.

        :return: Info to create an ID Token.
        :rtype: dict
        """

        raise NotImplementedError("Implement this method to support ID Tokens.")

    async def create_refresh_token(
        self, client: ClientMixin, user: UserMixin, scopes: list[str]
    ) -> str:
        """
        Generates a `Refresh Token` binding the `Client` and the `User`,
        together with the `Scopes` granted by the `User`, and sets its
        expiration to the value of the argument `expiration_in_days`.

        :param client: Client to whom the Refresh Token was issued to.
        :type client: ClientMixin

        :param user: User represented by the Client.
        :type user: UserMixin

        :param scopes: Scopes of the next Access Token issued by this Refresh Token.
        :type scopes: list[str]

        :return: Issued Refresh Token.
        :rtype: str
        """

        raise NotImplementedError("Implement this method to support Refresh Tokens.")

    async def get_refresh_token(self, refresh_token: str) -> RefreshTokenMixin:
        """
        Retrieves the data of a `Refresh Token` from the application's storage
        based on the provided `refresh_token`.

        :param refresh_token: Refresh Token to be fetched.
        :type refresh_token: str

        :return: Requested Refresh Token.
        :rtype: RefreshTokenMixin
        """

        raise NotImplementedError("Implement this method to support Refresh Tokens.")

    async def revoke_token(
        self, client: ClientMixin, token: str, token_type_hint: Optional[str] = None
    ) -> None:
        """
        Searches the application's storage for the provided token and revokes it.

        :param client: Client requesting a token revocation.
        :type client: ClientMixin

        :param token: Token to be revoked.
        :type token: str

        :param token_type_hint: Tells the server the type of the token, defaults to None.
        :type token_type_hint: str, optional
        """

        raise NotImplementedError("Implement this method to support Token Revocation.")
