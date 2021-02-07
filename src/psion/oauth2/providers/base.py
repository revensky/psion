from __future__ import annotations

import abc
from typing import Any, Type

from psion.jose import JsonWebKeySet
from psion.oauth2.adapter import BaseAdapter
from psion.oauth2.authentication import ClientAuthentication
from psion.oauth2.config import Config
from psion.oauth2.endpoints import (
    AuthorizationEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
)
from psion.oauth2.grants import BaseGrant
from psion.oauth2.models import Request, Response, Scope


class BaseProvider(abc.ABC):
    def __init__(
        self,
        issuer: str,
        *,
        adapter: Type[BaseAdapter],
        grants: list[Type[BaseGrant]],
        scopes: list[Scope],
        keyset: JsonWebKeySet,
        error_url: str,
        token_lifespan: int = 3600,
        id_token_lifespan: int = 36000,
    ) -> None:
        self.issuer = issuer
        self.scopes = scopes

        self.adapter = adapter()
        self.config = Config(
            issuer=issuer,
            scopes=scopes,
            token_lifespan=token_lifespan,
            id_token_lifespan=id_token_lifespan,
            keyset=keyset,
            error_url=error_url,
        )

        self.authenticate = ClientAuthentication(self.adapter.find_client)
        self.grants = [grant(self.adapter, self.config) for grant in grants]

        self.authorize = AuthorizationEndpoint(
            grants=self.grants,
            adapter=self.adapter,
            config=self.config,
            authenticate=self.authenticate,
        )

        self.revoke = RevocationEndpoint(
            adapter=self.adapter,
            config=self.config,
            authenticate=self.authenticate,
        )

        self.token = TokenEndpoint(
            grants=self.grants,
            adapter=self.adapter,
            config=self.config,
            authenticate=self.authenticate,
        )

    @abc.abstractmethod
    async def create_request(self, request: Any) -> Request:
        """
        Transforms the Web Server's request into an Request object.

        This method **MUST** be implemented in integrations.

        :param request: Web Server's specific request object.
        :type request: Any

        :return: Transformed request object.
        :rtype: Request
        """

    @abc.abstractmethod
    async def create_response(self, response: Response) -> Any:
        """
        Transforms the `Response` object into a Response of the integrated Web Server.

        This method **MUST** be implemented in integrations.

        :param response: Framework's Response.
        :type response: Response

        :return: Integrated Web Server Response.
        :rtype: Any
        """
