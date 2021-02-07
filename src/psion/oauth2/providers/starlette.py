from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from psion.oauth2.models import Request, Response

from .base import BaseProvider


class StarletteProvider(BaseProvider):
    async def create_request(self, request: StarletteRequest) -> Request:
        return Request(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            body=await request.body(),
            user=request.user,
        )

    async def create_response(self, response: Response) -> StarletteResponse:
        return StarletteResponse(response.body, response.status_code, response.headers)
