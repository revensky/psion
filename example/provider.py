from psion.jose import JsonWebKey, JsonWebKeySet
from psion.oauth2.grants import (
    AuthorizationCodeGrant,
    ClientCredentialsGrant,
    RefreshTokenGrant,
)
from psion.oauth2.models import Scope
from psion.oauth2.providers import StarletteProvider
from psion.oidc import AuthorizationCodeFlow
from psion.webtools import to_bytes

from example.adapter import Adapter
from example.settings import SECRET_KEY


provider = StarletteProvider(
    "http://localhost:8000",
    adapter=Adapter,
    grants=[AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant],
    scopes=[
        Scope("openid", "OpenID of the User."),
        Scope("profile", "Returns the profile of the user."),
        Scope("email", "Returns the email information of the user."),
        Scope("phone", "Returns the phone information of the user."),
        Scope("address", "Returns the address information of the user."),
    ],
    keyset=JsonWebKeySet(
        [JsonWebKey.parse(to_bytes(SECRET_KEY), "oct", False, format="der", kid="key1")]
    ),
    error_url="/connect/error",
)

provider.add_hook(AuthorizationCodeGrant, AuthorizationCodeFlow)
