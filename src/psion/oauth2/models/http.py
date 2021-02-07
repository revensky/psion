from __future__ import annotations

import copy
from typing import Any
from urllib.parse import quote_plus, urlparse

from psion.webtools import FullDict, json_dumps, to_bytes, to_string, urldecode

from psion.oauth2.mixins import ClientMixin, UserMixin


class Request:
    """
    Implementation of the OAuth 2.1 Request.

    It has roughly the same attributes and methods of a request of a web framework.

    It is provided as a framework-agnostic version of the request to allow
    for multiple integrations without breaking functionality.

    :param method: HTTP Method of the current request.
    :type method: str

    :param url: URL of the current request.
    :type url: str

    :param headers: Headers of the current request.
    :type headers: dict

    :param body: Body of the current request, defaults to None.
    :type body: bytes, optional

    :param user: Currently authenticated user, defaults to None.
    :type user: Any, optional

    :ivar method: Method of the current request. Only `GET` and `POST` are supported.
    :ivar url: Full URL of the current request.
    :ivar path: Path string of the URL.
    :ivar query: Query parameters of the URL.
    :ivar fragment: Fragment parameters of the URL.
    :ivar headers: Headers of the current request.
    :ivar user: Currently authenticated user.
    :ivar client: Client that made the OAuth 2.1 request, resolved on execution.
    :ivar data: Data of the current request. Parses the query and then the form.
    """

    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, Any],
        body: bytes = None,
        user: UserMixin = None,
    ) -> None:
        if method.lower() not in ("get", "post"):
            raise RuntimeError(f'The method "{method}" is not supported.')

        self.method = method
        self.url = url
        self.path = urlparse(url).path
        self.query = urldecode(urlparse(url).query)
        self.fragment = urldecode(urlparse(url).fragment)
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.user: UserMixin = user
        self.client: ClientMixin = None

        self._body = body

        # Data of the current request.
        self.data = copy.deepcopy(self.query)
        self.data.update(self.form())

    def form(self) -> dict:
        """
        Parses the body as **application/x-www-form-encoded**
        and returns a dictionary of the parameters of the form.

        :return: Dictionary of the parsed body.
        :rtype: dict
        """

        return urldecode(to_string(self._body))


class Response:
    """
    Implementation of the OAuth 2.1 Response.

    It has roughly the same attributes and methods of a response of a web framework.

    It is provided as a framework-agnostic version of the response to allow
    for multiple integrations without breaking functionality.

    :cvar media_type: Media type of the response.

    :param status_code: HTTP Status Code of the Response, defaults to 200.
    :type status_code: int

    :param headers: HTTP Headers of the Response, defaults to None.
    :type headers: dict, optional

    :param body: HTTP Body of the Response, defaults to None.
    :type body: Any, optional
    """

    media_type: str = None

    def __init__(
        self, status_code: int = 200, headers: dict = None, body: Any = None
    ) -> None:
        self.status_code = status_code
        self.headers = self.parse_headers(headers)
        self.body = self.parse_body(body)

    def parse_headers(self, headers: dict) -> dict:
        """
        Parses the headers of the response.

        If no header is provided, it returns an empty dictionary.

        :param headers: Headers of the response.
        :type headers: dict

        :return: Parsed headers with the optional media type of the response.
        :rtype: dict
        """

        if headers is None:
            headers = {}

        return FullDict({"Content-Type": self.media_type}, **headers)

    def parse_body(self, body: Any = None) -> bytes:
        """
        Parses the body of the response.

        If no body is provided, it returns an empty byte-string.

        :param body: Object representing the body of the response, defaults to None.
        :type body: Any, optional

        :return: Parsed body as a byte-string.
        :rtype: bytes
        """

        return to_bytes(body) or b""


class JSONResponse(Response):
    """
    Representation of a JSON Response.

    The body of the Response **MUST** be JSON Encodable.

    :cvar media_type: `application/json`
    """

    media_type: str = "application/json"

    def parse_body(self, body: Any = None) -> bytes:
        """
        Returns a bytes representation of the JSON Encodable body of the Response.

        :param body: JSON Encodable object representing the body of the response,
            defaults to None.
        :type body: Any, optional

        :return: Byte-string of the JSON representation of the Response Body.
        :rtype: bytes
        """

        return to_bytes(json_dumps(body))


class RedirectResponse(Response):
    """
    Representation of a Redirect Response.

    It will return a redirect-ready object to the provided URL.
    No body object is to be provided.

    :param url: URL to be redirected.
    :type url: str

    :param status_code: HTTP Status Code of the Redirection, defaults to 303.
    :type status_code: int, optional

    :param headers: HTTP Headers of the Redirection, defaults to None.
    :type headers: dict, optional
    """

    def __init__(self, url: str, status_code: int = 303, headers: dict = None) -> None:
        super().__init__(status_code=status_code, headers=headers, body=b"")
        self.headers["Location"] = quote_plus(url, safe=":/%#?&=@[]!$&'()*+,;")
