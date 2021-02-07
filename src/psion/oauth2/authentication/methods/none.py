from psion.oauth2.exceptions import InvalidClient
from psion.oauth2.mixins import ClientMixin
from psion.oauth2.models import Request

from .base import BaseAuthentication


class None_(BaseAuthentication):
    """
    Implements the Client Authentication via the Body of the Request.

    If this workflow is enabled, it will look at the body of the request
    for a scheme similar to the following::

        client_id=client1

    The request's body often comes with more information that may pertain to
    a specific endpoint or authorization grant. In this case,
    the body will be similar to the following::

        key1=value1&key2=value2&client_id=client1

    In this workflow, if the client provides a client_secret,
    it will automatically fail, since it is intended to be used by public clients.
    """

    __method__: str = "none"

    async def authenticate(self, request: Request) -> ClientMixin:
        body = request.form()

        client_id, client_secret = body.get("client_id"), body.get("client_secret")

        if not client_id or client_secret is not None:
            return None

        client = await self.find_client(client_id)

        if not client:
            raise InvalidClient("Client not found.")

        if client.get_client_secret() != client_secret:
            raise InvalidClient("Mismatching Client Secret.")

        if client.get_token_endpoint_auth_method() != self.__method__:
            raise InvalidClient(
                f'This Client is not allowed to use the method "{self.__method__}".'
            )

        return client
