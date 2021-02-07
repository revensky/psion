from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, Union

from psion.jose.jwk import JsonWebKey
from psion.jose.jwt import JsonWebToken
from psion.oauth2.adapter import BaseAdapter
from psion.webtools import FullDict, secret_token

from example.models.clients import Client
from example.models.tokens import AuthorizationCode, RefreshToken
from example.models.users import User


SECRET_KEY = JsonWebKey.parse(
    b"super_secret_key_that_no_one_will_be_able_to_guess",
    "oct",
    False,
    format="der",
    kid="secret_key_id",
)


class Adapter(BaseAdapter):
    async def find_user(self, user_id: str) -> User:
        return await User.get_or_none(id=user_id)

    async def find_client(self, client_id: str) -> Client:
        return await Client.get_or_none(id=client_id)

    async def save_authorization_code(
        self, code: str, data: dict, client: Client, user: User
    ) -> None:
        await AuthorizationCode.create(
            id=code,
            client_id=client.get_client_id(),
            user_id=user.get_user_id(),
            redirect_uri=data["redirect_uri"],
            scopes=data["scopes"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            nonce=data["nonce"],
            expires_at=datetime.utcnow() + timedelta(seconds=86400),
        )

    async def get_authorization_code(self, code: str) -> AuthorizationCode:
        return await AuthorizationCode.get_or_none(id=code)

    async def delete_authorization_code(self, code: str) -> None:
        if obj := await AuthorizationCode.get_or_none(id=code):
            await obj.delete()

    async def create_access_token(
        self,
        client: Client,
        resource_owner: Union[User, Client],
        scopes: list[str],
    ) -> str:
        resource_owner_id = (
            str(resource_owner.id)
            if isinstance(resource_owner, User)
            else str(resource_owner.id)
        )

        now = int(datetime.utcnow().timestamp())

        access_token = JsonWebToken(
            FullDict(
                {
                    "iss": "http://localhost:8000",
                    "exp": now + 3600,
                    "sub": resource_owner_id,
                    "iat": now,
                    "jti": secret_token(),
                    "client_id": client.get_client_id(),
                    "scope": " ".join(scopes),
                }
            ),
            {"alg": "HS256", "typ": "at+jwt"},
        ).encode(SECRET_KEY)

        return access_token

    async def get_userinfo(self, user: User, scopes: list[str]) -> dict:
        data = {"sub": str(user.id)}

        if "profile" in scopes:
            data.update(
                {
                    "given_name": user.given_name,
                    "middle_name": user.middle_name,
                    "family_name": user.family_name,
                    "nickname": user.nickname,
                    "preferred_username": user.preferred_username,
                    "profile": user.profile,
                    "picture": user.picture,
                    "website": user.website,
                    "gender": user.gender.value if user.gender else None,
                    "birthdate": user.birthdate.isoformat() if user.birthdate else None,
                    "zoneinfo": user.zoneinfo,
                    "locale": user.locale,
                    "created_at": int(user.created_at.timestamp()),
                    "updated_at": int(user.updated_at.timestamp()),
                }
            )

        if "email" in scopes:
            data.update({"email": user.email, "email_verified": user.email_verified})

        if "address" in scopes:
            data.update({"address": user.address})

        if "phone" in scopes:
            data.update(
                {
                    "phone_number": user.phone_number,
                    "phone_number_verified": user.phone_number_verified,
                }
            )

        return FullDict(data)

    async def get_key_info(self) -> dict:
        return {"key": SECRET_KEY, "alg": "HS256"}

    async def create_refresh_token(
        self,
        client: Client,
        resource_owner: User,
        scopes: list[str],
    ) -> str:
        token = await RefreshToken.get_or_create(
            defaults={
                "refresh_token": secret_token(),
                "scopes": scopes,
                "audience": "Guarani",
                "expires": datetime.utcnow() + timedelta(days=14),
            },
            client_id=client.id,
            user_id=resource_owner.id,
        )

        return token[0].refresh_token

    async def get_refresh_token(self, refresh_token: str) -> RefreshToken:
        return await RefreshToken.get_or_none(refresh_token=refresh_token)

    async def revoke_token(
        self, client: Client, token: str, token_type_hint: Optional[str] = None
    ):
        token = await RefreshToken.get_or_none(refresh_token=token, client_id=client.id)

        if token:
            await token.delete()
