from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette_wtf import CSRFProtectMiddleware
from tortoise.contrib.starlette import register_tortoise

from example.middlewares.authentication import SessionAuthBackend
from example.routes import auth, connect, home
from example.settings import BASEDIR, DATABASE_URL, SECRET_KEY


middleware = [
    Middleware(SessionMiddleware, secret_key=SECRET_KEY),
    Middleware(AuthenticationMiddleware, backend=SessionAuthBackend()),
    Middleware(CSRFProtectMiddleware, csrf_secret=SECRET_KEY),
]

routes = [
    Route("/", home, methods=["GET"], name="home"),
    Mount("/static", StaticFiles(directory=BASEDIR / "static"), name="static"),
    Mount("/auth", routes=auth.routes, name="auth"),
    Mount("/connect", routes=connect.routes, name="connect"),
]

app = Starlette(middleware=middleware, routes=routes)


register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={
        "models": [
            "example.models.clients",
            "example.models.sessions",
            "example.models.tokens",
            "example.models.users",
        ],
    },
    generate_schemas=True,
)
