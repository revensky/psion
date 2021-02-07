import asyncio

from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates

from psion.webtools import secret_token

from example.forms.login import LoginForm
from example.models.sessions import Session
from example.models.tokens import RefreshToken
from example.models.users import User
from example.settings import BASEDIR


templates = Jinja2Templates(BASEDIR / "templates")


class LoginView(HTTPEndpoint):
    async def get(self, request: Request):
        if request.user:
            return RedirectResponse(request.url_for("home"), 303)

        form = LoginForm(request)

        return templates.TemplateResponse(
            "login.j2",
            {
                "request": request,
                "title": "Login",
                "form": form,
                "login_and_next": str(request.url),
            },
        )

    async def post(self, request: Request):
        if request.user:
            return RedirectResponse(request.url_for("home"), 303)

        form: LoginForm = await LoginForm.from_formdata(request)

        if not await form.validate_on_submit():
            return templates.TemplateResponse(
                "login.j2",
                {
                    "request": request,
                    "title": "Login",
                    "form": form,
                    "login_and_next": str(request.url),
                },
            )

        user = await User.filter(email=form.email.data).first()

        if not user:
            return templates.TemplateResponse(
                "login.j2",
                {
                    "request": request,
                    "title": "Login",
                    "form": form,
                    "validation_error": "Invalid Credentials.",
                    "login_and_next": str(request.url),
                },
            )

        if user.password != form.password.data:
            return templates.TemplateResponse(
                "login.j2",
                {
                    "request": request,
                    "title": "Login",
                    "form": form,
                    "validation_error": "Invalid Credentials.",
                    "login_and_next": str(request.url),
                },
            )

        session = await Session.filter(user_id=user.id).first()

        if not session:
            session = Session(id=secret_token(32), user_id=user.id)
            await session.save()

        request.session["psion"] = {
            "user_id": str(user.id),
            "session_id": str(session.id),
        }

        redirect = request.query_params.get("next") or request.url_for("home")

        return RedirectResponse(redirect, 303)


class LogoutView(HTTPEndpoint):
    async def get(self, request: Request):
        if not request.user:
            return RedirectResponse(request.url_for("auth:login"), 303)

        user_id = request.session["psion"]["user_id"]

        await asyncio.gather(
            RefreshToken.filter(user_id=user_id).delete(),
            Session.filter(user_id=user_id).delete(),
        )

        return RedirectResponse(request.url_for("auth:login"), 303)

    async def post(self, request: Request):
        return RedirectResponse(request.url_for("auth:logout"), 303)
