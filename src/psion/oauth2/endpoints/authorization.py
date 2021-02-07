from __future__ import annotations

from typing import Any, Optional

from psion.oauth2.exceptions import (
    AccessDenied,
    FatalError,
    InvalidRequest,
    OAuth2Error,
    UnauthorizedClient,
    UnsupportedResponseType,
)
from psion.oauth2.grants.base import BaseGrant
from psion.oauth2.mixins import ClientMixin
from psion.oauth2.models.http import RedirectResponse, Request
from psion.oauth2.models.scopes import Scope
from psion.webtools import urlencode

from .base import BaseEndpoint


class AuthorizationEndpoint(BaseEndpoint):
    """
    Endpoint used to provide an Authorization Grant for the requesting Client
    on behalf of the authenticated User.

    Since the OAuth 2.1 Spec does not define the need for authentication when
    using this endpoint, it was left omitted. If there is a need for it in
    the application, feel free to subclass this endpoint and define the
    authentication methods that best suit your needs.

    :param grants: List of the grants supported by the Identity Provider.
    :type grants: list[BaseGrant]
    """

    __endpoint__: str = "authorize"

    def __init__(self, grants: list[BaseGrant], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.grants = grants

    async def __call__(self, request: Request) -> RedirectResponse:
        """
        Creates an Authorization Response via a Redirect Response.

        Whenever a :class:`FatalError` is raised, the Provider will redirect
        the User-Agent to the its own error page, since it is too risky
        to disclose any information to an untrusted Client.

        Any other type of error is safely redirected to the Redirect URI
        provided by the Client in the Authorization Request.

        If the flow of the endpoint results in a successful response,
        it will also redirect the User-Agent to the provided Redirect URI.

        This endpoint is to be used by Grants that have an Authorization Workflow,
        and it **REQUIRES** consent given by the Resource Owner (User),
        be it implicit or explicit.

        The means of which the application obtains the consent of the Resource Owner
        has to be defined in the Framework Integration, since it usually requires
        a redirection to an endpoint that is not supported by OAuth 2.1.

        If this method is hit, it assumes that the Resource Owner has given consent
        to whatever scopes were requested by the Client.

        :param request: Current request being processed.
        :type request: Request

        :return: Redirect Response to either the provided Redirect URI
            or the Provider's error page.
        :rtype: RedirectResponse
        """

        data = request.data

        try:
            self._validate_request(data)

            if (user := request.user) is None:
                raise AccessDenied

            grant = self._validate_response_type(
                response_type=data.pop("response_type"), state=data.get("state")
            )

            client = await self._validate_client(
                client_id=data["client_id"],
                redirect_uri=data["redirect_uri"],
                response_type=grant.__response_type__,
                state=data.get("state"),
            )

            url = await grant.authorize(data, client, user)
            return RedirectResponse(url)
        except FatalError as exc:
            url = urlencode(self.config.error_url, **exc.dump())
            return RedirectResponse(url, headers=exc.headers)
        except OAuth2Error as exc:
            url = urlencode(data["redirect_uri"], **exc.dump())
            return RedirectResponse(url, headers=exc.headers)

    async def get_consent_data(self, request: Request) -> dict:
        """
        Gets the Client and its allowed scopes from the ones requested
        and returns this data for the application to get the User's consent.

        :param request: Current request being handled.
        :type request: Request

        :return: Dictionary containing the client and the scopes.
        :rtype: dict
        """

        data = request.data

        try:
            self._validate_request(data)

            client = await self._validate_client(
                client_id=data["client_id"],
                redirect_uri=data["redirect_uri"],
                response_type=data["response_type"],
                state=data.get("state"),
            )

            # pylint: disable=E0601
            if not (scope := data.get("scope")) or not isinstance(scope, str):
                raise InvalidRequest('Missing required parameter "scope".')

            scopes: list[str] = scope.split()

            return {
                "client": client,
                "scopes": [Scope(scope) for scope in client.get_allowed_scopes(scopes)],
            }
        except FatalError as exc:
            url = urlencode(self.config.error_url, **exc.dump())
            return RedirectResponse(url, headers=exc.headers)
        except OAuth2Error as exc:
            url = urlencode(data["redirect_uri"], **exc.dump())
            return RedirectResponse(url, headers=exc.headers)

    def _validate_request(self, data: dict) -> None:
        """
        Validates the Request data to ensure that the required parameters are present.

        :param data: Data of the Authorization Request.
        :type data: dict
        """

        if not data:
            raise FatalError(
                error=InvalidRequest.error,
                description="Missing request parameters.",
            )

        redirect_uri: str = data.get("redirect_uri")
        client_id: str = data.get("client_id")
        response_type: str = data.get("response_type")

        if not redirect_uri or not isinstance(redirect_uri, str):
            raise FatalError(
                error=InvalidRequest.error,
                description='Missing required parameter "redirect_uri".',
            )

        if not client_id or not isinstance(client_id, str):
            raise FatalError(
                error=InvalidRequest.error,
                description='Missing required parameter "client_id".',
            )

        if not response_type or not isinstance(response_type, str):
            raise FatalError(
                error=InvalidRequest.error,
                description='Missing required parameter "response_type".',
            )

    def _validate_response_type(
        self, response_type: str, state: Optional[str] = None
    ) -> BaseGrant:
        """
        Validates the requested `response_type` against the set
        of registered Grants of the Provider.

        :param response_type: Response type to be validated.
        :type response_type: str

        :param state: State of the Client during the Request.
        :type state: str, optional

        :raises UnsupportedResponseType: The Provider does not support
            the requested `response_type` as an Authorization Grant.

        :return: Grant that represents the requested `response_type`.
        :rtype: BaseGrant
        """

        for grant in self.grants:
            if grant.__response_type__ == response_type:
                return grant
        else:
            raise UnsupportedResponseType(
                description=f'Unsupported response_type "{response_type}".',
                state=state,
            )

    async def _validate_client(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        state: Optional[str] = None,
    ) -> ClientMixin:
        """
        Validates the `client_id` parameter to ensure that a Client exists with this ID.

        Verifies if the Client is allowed to use the provided `redirect_uri`.
        Verifies if the Client is allowed to use the requested `response_type`.

        :param client_id: ID of the Client requesting authorization.
        :type client_id: str

        :param redirect_uri: Redirect URI provided by the Client in the Request.
        :type redirect_uri: str

        :param response_type: Authorization Grant requested by the Client.
        :type response_type: str

        :param state: Client State provided in the Request, defaults to None.
        :type state: str, optional

        :raises FatalError: Raised on any of the following conditions::
            - The provided Client is not registered within the Authorization Server.
            - The Client is not allowed to use the provided `redirect_uri`.
        :raises UnauthorizedClient: The Client is not allowed to use the requested Grant.

        :return: Validated Client.
        :rtype: ClientMixin
        """

        client = await self.adapter.find_client(client_id)

        if not client:
            raise FatalError(error=InvalidRequest.error, description="Invalid client.")

        if redirect_uri not in client.get_redirect_uris():
            raise FatalError(
                error=InvalidRequest.error, description="Invalid Redirect URI."
            )

        if response_type not in client.get_response_types():
            raise UnauthorizedClient(state=state)

        return client
