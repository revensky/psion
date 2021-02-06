import unittest

from psion.jose.exceptions import InvalidJWSHeader, UnsupportedAlgorithm
from psion.jose.jwk import JsonWebKey
from psion.jose.jws import JsonWebSignature, JsonWebSignatureHeader

from tests.jose.utils import load_json


class TestJsonWebSignatureHeader(unittest.TestCase):
    def test_instantiate(self):
        self.assertRaises(InvalidJWSHeader, JsonWebSignatureHeader, "")

    def test_validate_alg(self):
        self.assertRaises(InvalidJWSHeader, JsonWebSignatureHeader, {})
        self.assertRaises(
            UnsupportedAlgorithm,
            JsonWebSignatureHeader,
            {"alg": "whatkindofalgorithmisthisagain"},
        )

    def test_validate_crit(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "typ": "JWT", "crit": ["typ"]})

        self.assertEqual(header.get("typ"), "JWT")
        self.assertEqual(header.get("crit"), ["typ"])

        self.assertRaises(
            InvalidJWSHeader, JsonWebSignatureHeader, {"alg": "HS256", "crit": []}
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64", 14, "typ"]},
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64", "", "typ"]},
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64"]},  # Missing parameter "b64".
        )

    def test_validate_cty(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "cty": "at+json"})

        self.assertEqual(header.get("cty"), "at+json")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "cty": ["foo", "bar"]},
        )

    def test_validate_kid(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "kid": "key0"})

        self.assertEqual(header.get("kid"), "key0")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "kid": 0x1237742},
        )

    def test_validate_typ(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "typ": "JWT"})

        self.assertEqual(header.get("typ"), "JWT")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "typ": False},
        )


# TODO: Add tests that fail.
class TestJsonWebSignature(unittest.TestCase):
    def test_instantiate(self):
        jws = JsonWebSignature(b"Super important message.", {"alg": "HS256"})

        self.assertEqual(jws.header.get("alg"), "HS256")
        self.assertRaises(InvalidJWSHeader, JsonWebSignature, b"Lorem ipsum...", {})

    def test_serialize(self):
        key = JsonWebKey(load_json("oct"))
        jws = JsonWebSignature(b"Super important message.", {"alg": "HS256"})
        token = (
            b"eyJhbGciOiAiSFMyNTYifQ."
            b"U3VwZXIgaW1wb3J0YW50IG1lc3NhZ2Uu."
            b"hcKC9ON7r55CL1bekT5KlYN37Dwx_3yGNlhexf89-1Y"
        )

        self.assertEqual(jws.serialize(key), token)

    def test_deserialize(self):
        key = JsonWebKey(load_json("oct"))
        token = (
            b"eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJIUzI1NiJ9."
            b"eyJzdWIiOiAic29tZS1yYW5kb20tdXVpZCIsICJpYXQiOiAxNjUyMzAxNDc4fQ."
            b"PZd5gLOfNTv3x8Qci1DM7hxjY91bUhmfnOQgojhFv6I"
        )

        expected_header = {"typ": "JWT", "alg": "HS256"}
        expected_payload = b'{"sub": "some-random-uuid", "iat": 1652301478}'

        deserialized = JsonWebSignature.deserialize(token, key, "HS256")

        self.assertEqual(deserialized.header, expected_header)
        self.assertEqual(deserialized.payload, expected_payload)
