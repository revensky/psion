import abc
from typing import Awaitable, Callable

from psion.oauth2.mixins import ClientMixin
from psion.oauth2.models import Request


class BaseAuthentication(abc.ABC):
    """
    Base class for handling client authentication on an arbitrary endpoint.

    This package implements the default authentication methods described
    by the `token_endpoint_auth_method` metadata specified in
    `RFC 7591 <https://tools.ietf.org/html/rfc7591#section-2/>`_.

    To add custom client authentication flows, the application MUST inherit
    this base class and implement its abstract method :meth:`authenticate`.

    :cvar `__method__`: The name of the authentication method.

    :param find_client: Callable used to retrieve a Client
        from the application's storage.
    :type find_client: Callable[[str], Awaitable[ClientMixin]]
    """

    __method__: str = None

    def __init__(self, find_client: Callable[[str], Awaitable[ClientMixin]]) -> None:
        self.find_client = find_client

    @abc.abstractmethod
    async def authenticate(self, request: Request) -> ClientMixin:
        """
        Gets the client from the application's storage and validates its data.

        :param request: Current request being processed.
        :type request: Request

        :raises InvalidClient: The requested client is invalid.

        :return: Authenticated Client.
        :rtype: ClientMixin
        """
