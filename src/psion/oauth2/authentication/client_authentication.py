from __future__ import annotations

from typing import Awaitable, Callable

from psion.oauth2.exceptions import InvalidClient
from psion.oauth2.mixins import ClientMixin
from psion.oauth2.models import Request

from .methods import BaseAuthentication


class ClientAuthentication:
    """
    Class that loads all the authentication methods implemented by Guarani
    and the custom methods implemented by the application.

    To authenticate a request, simply invoke the instance as a callable
    passing in the current request and, optionally, the allowed methods
    for the endpoint.

    If the Client uses more than one authentication method on the request,
    or if the Client is not allowed to use the requested method, this class
    will raise an InvalidClient error.

    :param find_client: Function used to search a Client on the application's storage.
    :type find_client: Callable[[str], Awaitable[ClientMixin]]
    """

    def __init__(self, find_client: Callable[[str], Awaitable[ClientMixin]]) -> None:
        self.auth_methods: list[BaseAuthentication] = [
            method(find_client) for method in BaseAuthentication.__subclasses__()
        ]

    async def __call__(
        self, request: Request, methods: list[str] = None
    ) -> ClientMixin:
        """
        Gets the client from the application's storage and validates its data.

        :param request: Current request being handled.
        :type request: Request

        :param methods: Methods allowed by the endpoint, defaults to None.
            If no value is provided, it tests against all registered methods.
        :type methods: list[str], optional

        :raises InvalidClient: The requested client is invalid.

        :return: Authenticated Client.
        :rtype: ClientMixin
        """

        for method in self.auth_methods:
            if methods and method.__method__ not in methods:
                continue

            client = await method.authenticate(request)

            if not client:
                continue

            request.client = client
            return client

        raise InvalidClient
