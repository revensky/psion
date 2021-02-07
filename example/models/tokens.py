from __future__ import annotations

from datetime import datetime

from tortoise import Model, fields

from psion.oauth2.mixins import AuthorizationCodeMixin, RefreshTokenMixin

from example.models.clients import Client
from example.models.users import User


class AuthorizationCode(Model, AuthorizationCodeMixin):
    id = fields.CharField(64, pk=True)
    client: fields.ForeignKeyRelation[Client] = fields.ForeignKeyField("models.Client")
    user: fields.ForeignKeyRelation[User] = fields.ForeignKeyField("models.User")
    redirect_uri = fields.TextField()
    scopes = fields.JSONField()
    code_challenge = fields.CharField(128)
    code_challenge_method = fields.CharField(16)
    nonce = fields.CharField(256, null=True)
    auth_time = fields.DatetimeField(null=True)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "authorization_codes"

    def get_client_id(self) -> str:
        return str(self.client_id)  # pylint: disable=no-member

    def get_user_id(self) -> str:
        return str(self.user_id)  # pylint: disable=no-member

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scopes(self) -> list[str]:
        return self.scopes

    def get_code_challenge(self) -> str:
        return self.code_challenge

    def get_code_challenge_method(self) -> str:
        return self.code_challenge_method

    def get_nonce(self) -> str:
        return self.nonce

    def get_auth_time(self) -> int:
        return int(self.auth_time.timestamp())

    def get_expiration(self) -> datetime:
        return self.expires_at.replace(tzinfo=None)


class RefreshToken(Model, RefreshTokenMixin):
    refresh_token = fields.CharField(32, pk=True)
    client: fields.ForeignKeyRelation[Client] = fields.ForeignKeyField("models.Client")
    user: fields.ForeignKeyRelation[User] = fields.ForeignKeyField("models.User")
    audience = fields.CharField(128)
    scopes = fields.JSONField()
    expires = fields.DatetimeField()

    class Meta:
        table = "refresh_tokens"
        unique_together = ("client_id", "user_id")

    def get_refresh_token(self) -> str:
        return self.refresh_token

    def get_client_id(self) -> str:
        return str(self.client_id)  # pylint: disable=no-member

    def get_user_id(self) -> str:
        return str(self.user_id)  # pylint: disable=no-member

    def get_scopes(self) -> list[str]:
        return self.scopes

    def get_expiration(self) -> datetime:
        return self.expires
