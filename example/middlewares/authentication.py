from starlette.authentication import (
    AuthenticationBackend,
    AuthenticationError,
    AuthCredentials,
)
from starlette.requests import HTTPConnection

from example.models.sessions import Session


class SessionAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        session = conn.session.get("psion")

        if not session:
            return None, None

        data: Session = await Session.get_or_none(
            id=session.get("session_id"),
            user_id=session.get("user_id"),
        ).prefetch_related("user")

        if not data:
            return None, None

        if not data.user:
            raise AuthenticationError("Invalid user.")

        return AuthCredentials(["authenticated"]), data.user
