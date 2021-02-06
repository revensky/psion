import unittest

from psion.jose.jwa.jws import none, HS256, RS256, ES256, PS256
from psion.jose.jwk import JsonWebKey

from tests.jose.utils import load_json


class TestJWSAlgorithms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        oct_secret = load_json("oct")
        rsa_private, rsa_public = load_json("rsa")
        ec_private, ec_public = load_json("ec")

        cls.oct_secret = JsonWebKey(oct_secret)
        cls.rsa_private = JsonWebKey(rsa_private)
        cls.rsa_public = JsonWebKey(rsa_public)
        cls.ec_private = JsonWebKey(ec_private)
        cls.ec_public = JsonWebKey(ec_public)

        cls.data = b"This is a super secret message."

    def test_none(self):
        signature = none.sign(self.data)
        self.assertIsNone(none.verify(signature, self.data))

    def test_hmac(self):
        signature = HS256.sign(self.data, self.oct_secret)
        self.assertIsNone(HS256.verify(signature, self.data, self.oct_secret))

    def test_rsa_pkcs1v15(self):
        signature = RS256.sign(self.data, self.rsa_private)
        self.assertIsNone(RS256.verify(signature, self.data, self.rsa_public))

    def test_elliptic_curve(self):
        signature = ES256.sign(self.data, self.ec_private)
        self.assertIsNone(ES256.verify(signature, self.data, self.ec_public))

    def test_rsa_pss(self):
        signature = PS256.sign(self.data, self.rsa_private)
        self.assertIsNone(PS256.verify(signature, self.data, self.rsa_public))
