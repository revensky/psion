import unittest
from datetime import datetime

from psion.jose.exceptions import ExpiredToken, InvalidJWTClaim, NotYetValidToken
from psion.jose.jwt import JsonWebTokenClaims


def now() -> int:
    return int(datetime.utcnow().timestamp())


def future() -> int:
    return now() + 3600


def past() -> int:
    return now() - 3600


class TestJWTClaims(unittest.TestCase):
    def test_instantiate(self):
        self.assertIsInstance(JsonWebTokenClaims({"sub": "someid"}), JsonWebTokenClaims)
        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, "")

    def test_validate_aud(self):
        claims = JsonWebTokenClaims({"aud": "Valid Audience"})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        claims = JsonWebTokenClaims({"aud": ["Valid Audience 1", "Valid Audience 2"]})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"aud": 123})
        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"aud": [1, 2, 3]})

    def test_validate_exp(self):
        claims = JsonWebTokenClaims({"exp": future()})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(ExpiredToken, JsonWebTokenClaims, {"exp": past()})
        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"exp": True})

    def test_validate_iat(self):
        claims = JsonWebTokenClaims({"iat": past()})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"iat": True})

    def test_validate_iss(self):
        claims = JsonWebTokenClaims({"iss": "http://localhost:8000"})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"iss": {}})

    def test_validate_jti(self):
        claims = JsonWebTokenClaims({"jti": "T5CbNGVDcILMuqpb"})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"jti": {}})

    def test_validate_nbf(self):
        claims = JsonWebTokenClaims({"nbf": past()})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(NotYetValidToken, JsonWebTokenClaims, {"nbf": future()})
        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"nbf": True})

    def test_validate_sub(self):
        claims = JsonWebTokenClaims({"sub": "7zODKKvaU-PJETxIcm03gOk63S8rYCag"})
        self.assertIsInstance(claims, JsonWebTokenClaims)

        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, {"sub": object()})
