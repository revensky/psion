from __future__ import annotations

from datetime import datetime

from psion.jose.jwk import JsonWebKey


class AuthorizationCodeMixin:
    """
    Defines the model of the `Authorization Code` used by this framework.

    The application's Authorization Code **MUST** inherit from this class
    and implement **ALL** the methods defined here.
    """

    def get_client_id(self) -> str:
        """
        Returns the `ID` of the `Client` that requested the `Authorization Grant`.

        :return: ID of the Client from this Authorization Code.
        :rtype: str
        """

        raise NotImplementedError

    def get_user_id(self) -> str:
        """
        Returns the `ID` of the `User` that issued the current `Authorization Grant`.

        :return: ID of the User from this Authorization Code.
        :rtype: str
        """

        raise NotImplementedError

    def get_redirect_uri(self) -> str:
        """
        Returns the `Redirect URI` of the current `Authorization Code`.

        :return: Redirect URI.
        :rtype: str
        """

        raise NotImplementedError

    def get_scopes(self) -> list[str]:
        """
        Returns the `Scopes` that were authorized by the `User` to the `Client`.

        :return: Authorized Scopes.
        :rtype: list[str]
        """

        raise NotImplementedError

    def get_code_challenge(self) -> str:
        """
        Returns the `Code Challenge` provided by the `Client`.

        :return: Code Challenge.
        :rtype: str
        """

        raise NotImplementedError

    def get_code_challenge_method(self) -> str:
        """
        Returns the `Code Challenge Method` used by the `Client`.

        :return: Code Challenge Method.
        :rtype: str
        """

        raise NotImplementedError

    def get_nonce(self) -> str:
        """
        Returns the value of the `nonce` provided by the `Client`
        in the `Authentication Request`.

        :return: Nonce value of the Client.
        :rtype: str
        """

        raise NotImplementedError

    def get_auth_time(self) -> int:
        """
        Returns the time of the authentication of the User.

        :return: Time of User authentication.
        :rtype: int
        """

        raise NotImplementedError

    def get_expiration(self) -> datetime:
        """
        Returns a datetime representing the expiration of the `Authorization Code`.

        :return: Time when the Authorization Code expires.
        :rtype: datetime
        """

        raise NotImplementedError


class ClientMixin:
    """
    Defines the model of the `Client` used by this framework.

    The application's Client **MUST** inherit from this class and implement
    **ALL** the methods defined here.
    """

    def get_client_id(self) -> str:
        """
        Returns the `ID` of the `Client`.

        :return: ID of the Client.
        :rtype: str
        """

        raise NotImplementedError

    def get_client_secret(self) -> str:
        """
        Returns the `Secret` of the `Client`.

        :return: Secret of the Client.
        :rtype: str
        """

        raise NotImplementedError

    def get_client_public_key(self, key_id: str) -> JsonWebKey:
        """
        Returns an instance of the Client's Public Key based on
        the provided Key ID or the default Public key.

        :param key_id: ID of the Public Key to be retrieved.
        :type key_id: str

        :return: Instance of the Client's (default) Public Key.
        :rtype: JsonWebKey
        """

        raise NotImplementedError

    def get_allowed_scopes(self, scopes: list[str]) -> list[str]:
        """
        Returns the `Scopes` that the `Client` is allowed to used
        based on the requested scopes.

        :param scopes: Requested scopes.
        :type scopes: list[str]

        :return: Scopes that the Client is allowed to request.
        :rtype: list[str]
        """

        raise NotImplementedError

    def get_redirect_uris(self) -> list[str]:
        """
        Returns a list of the `Redirect URIs` registered for the current `Client`.

        :return: Redirect URIs registered for the current Client.
        :rtype: list[str]
        """

        raise NotImplementedError

    def get_token_endpoint_auth_method(self) -> str:
        """
        Returns the `Token Endpoint Auth Method` of the `Client` stored in the database.

        :return: Token Endpoint Authentication Method of the Client.
        :rtype: str
        """

        raise NotImplementedError

    def get_grant_types(self) -> list[str]:
        """
        Returns a list of the `Grant Types` that the `Client` is allowed to request.

        :return: Grant Types that the Client is allowed to request.
        :rtype: list[str]
        """

        raise NotImplementedError

    def get_response_types(self) -> list[str]:
        """
        Returns a list of the `Response Types` that the `Client` is allowed to request.

        :return: Response Types that the Client is allowed to request.
        :rtype: list[str]
        """

        raise NotImplementedError


class RefreshTokenMixin:
    """
    Defines the model of the `Refresh Token` used by this framework.

    The application's Refresh Token **MUST** inherit from this class
    and implement **ALL** the methods defined here.
    """

    def get_refresh_token(self) -> str:
        """
        Returns the string that represents the `Refresh Token` object.

        :return: Refresh Token value.
        :rtype: str
        """

        raise NotImplementedError

    def get_client_id(self) -> str:
        """
        Returns the `ID` of the `Client` bound to the `Refresh Token`.

        :return: ID of the Client from this Refresh Token.
        :rtype: str
        """

        raise NotImplementedError

    def get_user_id(self) -> str:
        """
        Returns the `ID` of the `User` bound to the current `Refresh Token`.

        :return: ID of the User from this Refresh Token.
        :rtype: str
        """

        raise NotImplementedError

    def get_scopes(self) -> list[str]:
        """
        Returns the `Scopes` that were authorized by the `User` to the `Client`.

        :return: Authorized Scopes.
        :rtype: list[str]
        """

        raise NotImplementedError

    def get_expiration(self) -> datetime:
        """
        Returns a datetime representing the expiration of the `Refresh Token`.

        :return: Time when the Refresh Token expires.
        :rtype: datetime
        """

        raise NotImplementedError


class UserMixin:
    """
    Defines the model of the `User` used by this framework.

    The application's User **MUST** inherit from this class and implement
    **ALL** the methods defined here.
    """

    def get_user_id(self) -> str:
        """
        Returns the `ID` of the `User`.

        :return: ID of the User.
        :rtype: str
        """

        raise NotImplementedError
