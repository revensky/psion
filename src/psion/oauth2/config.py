from __future__ import annotations

from dataclasses import dataclass

from psion.jose.jwk import JsonWebKeySet

from psion.oauth2.models import Scope


@dataclass
class Config:
    issuer: str
    scopes: list[Scope]
    token_lifespan: int
    id_token_lifespan: int
    keyset: JsonWebKeySet
    error_url: str
