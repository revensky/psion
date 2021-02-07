from typing import Any, Optional

from psion.webtools import FullDict


class OAuth2Error(Exception):
    """
    Representation of the errors that can occur during the authorization process.

    This is a base class that provides the main attributes defined by
    `<https://tools.ietf.org/html/draft-parecki-oauth-v2-1-03#section-4.1.2.1>`_ and
    `<https://tools.ietf.org/html/draft-parecki-oauth-v2-1-03#section-5.2>`_,
    which are::

        * "error": Denotes the code of the error.
        * "error_description": Human readable description with the details of the error.
        * "error_uri": URI containing more information about the error.
        * "state": String representing the state of the Client before the request.

    :param description: Contains the description of the error.
    :type description: str

    :param uri: Contains the URI that describes the error.
    :type uri: str

    :param state: State of the Client provided in the Request.
    :type state: str, optional

    :param headers: Optional headers attribute mainly used for Basic Authentication.
    :type headers: dict, optional
    """

    error: str = None

    def __init__(
        self,
        description: str = None,
        uri: str = None,
        state: Optional[str] = None,
        headers: Optional[dict] = None,
    ):
        self.description = description
        self.uri = uri
        self.state = state
        self.headers = headers or {}

    def dump(self) -> dict:
        """
        Returns a dictionary representation of the error.

        :return: Error as a dictionary.
        :rtype: dict
        """

        return FullDict(
            error=self.error,
            error_description=self.description,
            error_uri=self.uri,
            state=self.state,
        )


class FatalError(OAuth2Error):
    """
    Returned when the Authorization Endpoint **MUST NOT** redirect the User-Agent
    back to the provided Redirect URI, if any.

    This error **MUST** be re-raised to any of the other errors defined by Guarani,
    since it is not supported by the OAuth 2.1 Spec.
    """

    def __init__(self, error: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.error = error


class InvalidRequest(OAuth2Error):
    error: str = "invalid_request"


class InvalidClient(OAuth2Error):
    error: str = "invalid_client"


class InvalidGrant(OAuth2Error):
    error: str = "invalid_grant"


class UnauthorizedClient(OAuth2Error):
    error: str = "unauthorized_client"


class AccessDenied(OAuth2Error):
    error: str = "access_denied"


class UnsupportedResponseType(OAuth2Error):
    error: str = "unsupported_response_type"


class UnsupportedGrantType(OAuth2Error):
    error: str = "unsupported_grant_type"


class UnsupportedTokenType(OAuth2Error):
    error: str = "unsupported_token_type"


class InvalidScope(OAuth2Error):
    error: str = "invalid_scope"


class ServerError(OAuth2Error):
    error: str = "server_error"


class TemporarilyUnavailable(OAuth2Error):
    error: str = "temporarily_unavailable"
