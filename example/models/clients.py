from __future__ import annotations

from tortoise import Model, fields

from psion.jose.jwk import JsonWebKey
from psion.oauth2.mixins import ClientMixin


class Client(Model, ClientMixin):
    id = fields.UUIDField(pk=True)
    secret = fields.CharField(80, null=True)
    name = fields.CharField(32, unique=True)
    redirect_uris = fields.JSONField()
    scopes = fields.JSONField()
    token_endpoint_auth_method = fields.CharField(128, default="client_secret_basic")
    grant_types = fields.JSONField(default=lambda: ["authorization_code"])
    response_types = fields.JSONField(default=lambda: ["code"])
    client_uri = fields.CharField(256, null=True)
    logo_uri = fields.CharField(256, null=True)
    contacts = fields.JSONField(null=True)
    tos_uri = fields.CharField(256, null=True)
    policy_uri = fields.CharField(256, null=True)
    jwks_uri = fields.CharField(256, null=True)
    jwks = fields.JSONField(null=True)
    software_id = fields.UUIDField(unique=True, null=True)
    software_version = fields.CharField(32, null=True)

    class Meta:
        table = "clients"

    def get_client_id(self) -> str:
        return str(self.id)

    def get_client_secret(self) -> str:
        return self.secret

    def get_client_public_key(self, key_id: str) -> JsonWebKey:
        if self.jwks is None:
            return None

        return JsonWebKey(self.jwks)

    def get_allowed_scopes(self, scopes: list[str]) -> list[str]:
        if scopes is None:
            return self.scopes

        return [scope for scope in self.scopes if scope in scopes]

    def get_redirect_uris(self) -> list[str]:
        return self.redirect_uris

    def get_token_endpoint_auth_method(self) -> str:
        return self.token_endpoint_auth_method

    def get_grant_types(self) -> list[str]:
        return self.grant_types

    def get_response_types(self) -> list[str]:
        return self.response_types
