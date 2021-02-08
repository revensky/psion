from __future__ import annotations

import abc
from collections.abc import AsyncGenerator
from typing import Any, Optional

from psion.oauth2.adapter import BaseAdapter
from psion.oauth2.config import Config
from psion.oauth2.exceptions import InvalidScope
from psion.oauth2.mixins import ClientMixin, UserMixin
from psion.webtools import FullDict


class BaseGrant:
    """
    Base class responsible for defining the interface of an OAuth 2.1 Grant.

    The `Grant` is responsible for generating `Access Tokens` and, in some cases,
    `Authorization Grants` for Clients that need access to a protected resource
    of a web application (REST API, Web App, GraphQL, etc).

    Clients that want to access those protected resources **MUST** first obtain
    the consent of the `Resource Owner` for the desired resources. The resources
    can be accessed if the authorization contains the required `Scope` for it.

    Once the `Resource Owner` has granted the authorization to the `Client`,
    this one can then obtain an `Access Token` from the `Authorization Server`.

    This `Access Token` contains the scopes granted by the `Resource Owner` and
    allows the client to access the resources without further interaction
    with the `Resource Owner`.

    It is important to note that the scopes are defined on the application level,
    since they reflect its resources and the `Access Policies` of the application.

    :cvar ``__authentication_methods__``: Allowed Client Authentication methods.
    :cvar ``__grant_type__``: Name of the Token Grant.
    :cvar ``__response_type__``: Name of the Authorization Grant.
    :cvar ``__hooks__``: Defines the hooks to be executed in the grant flow
        to provide custom functionalities to it.

    :param adapter: Instance of the adapter used by the application.
    :type adapter: BaseAdapter

    :param config: Configuration of the provider.
    :type config: Configuration
    """

    __authentication_methods__: list[str] = None
    __grant_type__: str = None
    __response_type__: str = None
    __hooks__: dict[str, set[Any]] = {
        "authorization_request": set(),
        "authorization_response": set(),
        "token_request": set(),
        "token_response": set(),
    }

    def __init__(self, adapter: BaseAdapter, config: Config):
        self.adapter = adapter
        self.config = config

    def _create_token(
        self,
        access_token: str,
        expires_in: int,
        refresh_token: Optional[str] = None,
        scopes: Optional[list[str]] = None,
    ) -> dict:
        """
        Creates a `Token Response` with the following format::

            {
                "access_token": "2YotnFZFEjr1zCsicMWpAA",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
                "scope": "scope1 scope2"
            }

        :param access_token: Access Token issued to the Client.
        :type access_token: str

        :param expires_in: Lifespan of the Access Token in seconds.
        :type expires_in: int

        :param refresh_token: Optional Refresh Token issued to the Client,
            defaults to None.
        :type refresh_token: str, optional

        :param scopes: Optional list of Scopes if the granted scopes are different
            than the scopes requested.
        :type scopes: list[str], optional

        :return: Bearer Token Response with the provided parameters.
        :rtype: dict
        """

        return FullDict(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token,
                "scope": " ".join(scopes) if scopes else None,
            }
        )

    async def _execute_hook(
        self, name: str, *args: Any, **kwargs: Any
    ) -> AsyncGenerator[dict]:
        """
        Executes all the registered hooks that contain the requested method name.

        :param name: Name of the checkpoint of the Grant flow.
        :type name: str

        :return: Async generator containing the results from the executed hooks.
        :rtype: AsyncGenerator[dict]
        """

        for checkpoint, hooks in self.__hooks__.items():
            if checkpoint == name:
                for hook in hooks:
                    method = getattr(hook, name)
                    yield await method(*args, **kwargs)

    def _validate_requested_scopes(
        self, scopes: list[str], client: ClientMixin, state: Optional[str] = None
    ) -> None:
        """
        Verifies if all of the requested `Scopes`
        are supported by the `Authorization Server`.

        :param scopes: Requested scopes.
        :type scopes: list[str]

        :param client: Client that requested the provided scopes.
        :type client: ClientMixin

        :param state: State of the request provided by the Client, defaults to None.
        :type state: str, optional

        :raises InvalidScope: The Authorization Server does not support
            one or more of the requested scopes.
        """

        if scopes is None:
            return

        for scope in scopes:
            if scope not in self.config.scopes:
                raise InvalidScope(
                    description=f'Unsupported scope "{scope}".', state=state
                )

        if not set(scopes).issubset(set(client.get_allowed_scopes(scopes))):
            raise InvalidScope(
                description="This client is not authorized to request this scope.",
                state=state,
            )

    @abc.abstractmethod
    async def authorize(self, data: dict, client: ClientMixin, user: UserMixin) -> str:
        """
        Validates the data provided by the `Client` in the `Authorization`
        portion of the `Grant` and creates the `Authorization Response`
        that will be returned to the `Client`.

        :param data: Data received from the Client's Authorization Request.
        :type data: dict

        :param client: Client requesting authorization.
        :type client: ClientMixin

        :param user: Currently authenticated user granting authorization to the Client.
        :type user: UserMixin

        :return: Encoded URL containing the response from the Authorization Grant.
        :rtype: str
        """

    @abc.abstractmethod
    async def token(self, data: dict, client: ClientMixin) -> dict:
        """
        Validates the data provided by the `Client` in the `Token`
        portion of the `Grant` and creates the `Token Response`
        that will be returned to the `Client`.

        :param data: Data received from the Client's Authorization Request.
        :type data: dict

        :param client: Client requesting authorization.
        :type client: ClientMixin

        :return: Dictionary containing the response from the Token Grant.
        :rtype: dict
        """
