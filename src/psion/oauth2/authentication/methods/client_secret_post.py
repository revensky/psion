from psion.oauth2.exceptions import InvalidClient
from psion.oauth2.mixins import ClientMixin
from psion.oauth2.models import Request

from .base import BaseAuthentication


class ClientSecretPost(BaseAuthentication):
    """
    Implements the Client Authentication via the Body Post workflow.

    If this workflow is enabled, it will look at the Body of the request
    for a scheme similar to the following::

        client_id=client1&client_secret=client1secret

    The request's body often comes with more information that may pertain to
    a specific endpoint or authorization grant. In this case,
    the body will be similar to the following::

        key1=value1&key2=value2&client_id=client1&client_secret=client1secret

    This scheme contains the Client's ID and Secret issued upon creation.

    The usage of this scheme is **NOT RECOMMENDED** unless the client
    is unable to use another scheme.
    """

    __method__: str = "client_secret_post"

    async def authenticate(self, request: Request) -> ClientMixin:
        body = request.form()

        client_id, client_secret = body.get("client_id"), body.get("client_secret")

        if not client_id or not client_secret:
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
