from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates

from psion.webtools import urlencode

from example.provider import provider
from example.settings import BASEDIR


templates = Jinja2Templates(BASEDIR / "templates")


class AuthorizationEndpoint(HTTPEndpoint):
    async def get(self, request: Request):
        if not request.user:
            url = urlencode(str(request.url_for("auth:login")), next=str(request.url))
            return RedirectResponse(url, 303)

        request = await provider.create_request(request)
        response = await provider.authorize(request)
        return await provider.create_response(response)


class ErrorEndpoint(HTTPEndpoint):
    async def get(self, request: Request):
        error_description = request.query_params.get("error_description")
        error = request.query_params.get("error")

        return templates.TemplateResponse(
            "error.j2",
            {
                "request": request,
                "title": "Error",
                "error_description": error_description,
                "error": error,
            },
        )


class RevocationEndpoint(HTTPEndpoint):
    async def post(self, request: Request):
        request = await provider.create_request(request)
        response = await provider.revoke(request)
        return await provider.create_response(response)


class TokenEndpoint(HTTPEndpoint):
    async def post(self, request: Request):
        request = await provider.create_request(request)
        response = await provider.token(request)
        return await provider.create_response(response)
