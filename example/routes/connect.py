from starlette.routing import Route

from example.views.connect import (
    AuthorizationEndpoint,
    ErrorEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
)


routes = [
    Route("/authorize", AuthorizationEndpoint, name="authorization"),
    Route("/error", ErrorEndpoint, name="error"),
    Route("/revoke", RevocationEndpoint, name="revocation"),
    Route("/token", TokenEndpoint, name="token"),
]
