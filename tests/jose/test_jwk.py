import unittest

from psion.jose.exceptions import (
    InvalidKey,
    InvalidKeySet,
    UnsupportedAlgorithm,
    UnsupportedParsingMethod,
)
from psion.jose.jwk import JsonWebKey, JsonWebKeySet

from tests.jose.utils import load_json, load_pem


class TestJsonWebKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ec_private_json, cls.ec_public_json = load_json("ec")
        cls.oct_secret_json = load_json("oct")
        cls.rsa_private_json, cls.rsa_public_json = load_json("rsa")

        cls.ec_private_pem, cls.ec_public_pem = load_pem("ec")
        cls.oct_secret_pem = load_pem("oct")
        cls.rsa_private_pem, cls.rsa_public_pem = load_pem("rsa")

    def test_dump(self):
        data = dict(**self.ec_public_json, use="sig", kid="some_id")
        key = JsonWebKey(data)

        self.assertDictEqual(key.dump(), data)

    def test_generate(self):
        key = JsonWebKey.generate("RSA", 2048, use="sig", kid="key_id")
        data = key.dump()

        self.assertEqual(data.get("kty"), "RSA")
        self.assertEqual(data.get("use"), "sig")
        self.assertEqual(data.get("kid"), "key_id")

    def test_instantiate(self):
        key = JsonWebKey(self.oct_secret_json)

        self.assertDictContainsSubset(self.oct_secret_json, key.dump(False))
        self.assertRaises(InvalidKey, JsonWebKey, {})
        self.assertRaises(UnsupportedAlgorithm, JsonWebKey, {"kty": ""})
        self.assertRaises(UnsupportedAlgorithm, JsonWebKey, {"kty": "tutstuts"})

    def test_parse(self):
        private_key = JsonWebKey.parse(self.ec_private_pem, "EC", False, use="sig")
        public_key = JsonWebKey.parse(
            self.ec_public_pem, "EC", True, use="sig", kid="key_id"
        )

        self.assertDictEqual(
            private_key.dump(False), dict(**self.ec_private_json, use="sig")
        )

        self.assertDictEqual(
            public_key.dump(), dict(**self.ec_public_json, use="sig", kid="key_id")
        )

        self.assertRaises(
            UnsupportedAlgorithm,
            JsonWebKey.parse,
            self.rsa_private_pem,
            "tutstuts",
            False,
        )

        self.assertRaises(
            UnsupportedParsingMethod,
            JsonWebKey.parse,
            self.rsa_public_pem,
            "RSA",
            True,
            format="BaP(QUiEi'X",
        )

        self.assertRaises(InvalidKey, JsonWebKey.parse, self.ec_public_pem, "RSA", True)


class TestJsonWebKeySet(unittest.TestCase):
    def test_dump(self):
        k0 = JsonWebKey.parse(load_pem("rsa")[1], "RSA", True, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("ec")[1], "EC", True, use="sig", kid="key1")

        jwks = JsonWebKeySet([k0, k1])

        self.assertDictEqual(jwks.dump(), {"keys": [k0.dump(), k1.dump()]})

    def test_get_key(self):
        k0 = JsonWebKey.parse(load_pem("ec")[0], "EC", False, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("rsa")[0], "RSA", False, use="sig", kid="key1")

        jwks = JsonWebKeySet([k0, k1])

        self.assertEqual(jwks.get_key("key0"), k0)
        self.assertIsNone(jwks.get_key("idontknow"))

    def test_instantiate(self):
        k0 = JsonWebKey.parse(load_pem("ec")[1], "EC", True, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("rsa")[1], "RSA", True, use="sig", kid="key1")
        k2 = JsonWebKey.generate("RSA", 2048)

        jwks0 = JsonWebKeySet([k0, k1])

        self.assertListEqual(jwks0.keys, [k0, k1])
        self.assertRaises(InvalidKeySet, JsonWebKeySet, [k0, k1, k2])

        k30 = JsonWebKey.generate("EC", "P-256", kid="key2")
        k31 = JsonWebKey.generate("RSA", 2048, kid="key2")

        self.assertRaises(InvalidKeySet, JsonWebKeySet, [k30, k31])
