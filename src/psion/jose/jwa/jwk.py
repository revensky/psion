from __future__ import annotations

import abc
import base64
import enum
import os
import secrets
import warnings
from typing import Any, Literal, Optional, Sequence, Union

from cryptography.exceptions import InvalidSignature as BaseInvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from psion.jose.exceptions import InvalidKey, InvalidSignature, UnsupportedParsingMethod
from psion.webtools import (
    FullDict,
    b64_to_int,
    base64url_decode,
    base64url_encode,
    int_to_b64,
    to_bytes,
    to_string,
)


class ALGORITHMS(enum.Enum):
    """
    Enumeration of the supported Hash Algorithms.
    """

    SHA256 = hashes.SHA256()
    SHA384 = hashes.SHA384()
    SHA512 = hashes.SHA512()


AlgType = Union[str, ALGORITHMS]
RSAPadding = Literal["PKCS1v15", "PSS"]

EC_PRIVATE = ec.EllipticCurvePrivateKeyWithSerialization
EC_PUBLIC = ec.EllipticCurvePublicKey
RSA_PRIVATE = rsa.RSAPrivateKeyWithSerialization
RSA_PUBLIC = rsa.RSAPublicKey


def _get_alg(alg: AlgType) -> hashes.HashAlgorithm:
    """
    Auxiliar function used to translate a string into an ALGORITHMS item.

    :param alg: Name of the algorithm to be retrieved.
    :type alg: AlgType

    :return: Requested algorithm.
    """

    if isinstance(alg, str):
        return ALGORITHMS[alg].value

    return alg.value


def _parse_raw(path_or_secret: Union[os.PathLike, bytes]) -> bytes:
    try:
        with open(path_or_secret, "rb") as f:
            return f.read()
    except (FileNotFoundError, IsADirectoryError):
        return to_bytes(path_or_secret)


class JWKAlgorithm(abc.ABC):
    """
    Implementation of the Section 6 of RFC 7518.

    This base class provides the signatures of the methods used by the Json Web Key
    implementation regarding to the Key Algorithms usage.

    Implementations of custom Key Algorithms **MUST** inherit from this base class
    in order to be compliant with the rest of the library.

    :cvar ``__allowed_attributes__``: Defines the group of attributes
        supported by the Key Algorithm.
    :cvar kty: The name of the Key Algorithm.
    """

    __allowed_attributes__: Sequence[str] = None

    kty: str = None

    @classmethod
    @abc.abstractmethod
    def generate(cls, **kwargs: Any) -> JWKAlgorithm:
        """
        Generates a key on the fly based on the provided arguments.

        :return: Generated key as JWKAlgorithm.
        :rtype: JWKAlgorithm
        """

    @classmethod
    @abc.abstractmethod
    def parse(
        cls,
        path_or_secret: Union[os.PathLike, bytes],
        password: bytes = None,
        format: str = "pem",
    ) -> JWKAlgorithm:
        """
        Parses a raw key into a JWKAlgorithm.

        A raw symmetric key is simply its bytes string.
        A raw asymmetric key would be a PEM encoded key data.

        :param path_or_secret: The path of the raw key or its bytes representation.
        :type path_or_secret: Union[os.PathLike, bytes]

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to `pem`.
            If `pem`, assumes it is Base64 Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as a JWKAlgorithm.
        :rtype: JWKAlgorithm
        """

    @abc.abstractmethod
    def dump(self, public: bool = True) -> dict[str, Any]:
        """
        Returns a JSON-ready dictionary representation of the key's parameters.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

    @abc.abstractmethod
    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format if asymmetric, or Base64 if symmetric.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: Base64/PEM encoded key data.
        :rtype: bytes
        """

    @abc.abstractmethod
    def sign(self, data: bytes, algorithm: AlgType, **kwargs: Any) -> bytes:
        """
        Creates a digital signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param algorithm: Hash algorithm used to sign the data.
        :type algorithm: AlgType

        :return: Signature of the provided data.
        :rtype: bytes
        """

    @abc.abstractmethod
    def verify(
        self, signature: bytes, data: bytes, algorithm: AlgType, **kwargs: Any
    ) -> None:
        """
        Verifies the provided digital signature against the provided data.

        :param signature: Digital signature to be verified.
        :type signature: bytes

        :param data: Data used to verify the signature.
        :type data: bytes

        :param algorithm: Hash algorithm used to verify the signature.
        :type algorithm: AlgType

        :raises InvalidSignature: The signature does not match the data.
        """


class ECKey(JWKAlgorithm):
    """
    Implementation of the Elliptic Curve Asymmetric Key Algorithm.

    The standard curves are: "P-256", "P-384", "P-521".

    It is possible to add different curves, but they should be implemented
    by the application for a good support.

    :param crv: Name of the curve of the key.
    :type crv: str

    :param x: X coordinate of the Elliptic Curve.
    :type x: str

    :param y: Y coordinate of the Elliptic Curve.
    :type y: str

    :param d: Private value. **MANDATORY** if it is a private key.
    :type d: str, optional
    """

    __allowed_attributes__ = frozenset(("crv", "x", "y", "d"))

    kty: str = "EC"

    CURVES: dict[str, ec.EllipticCurve] = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }

    CURVES_NAMES: dict[str, str] = {
        ec.SECP256R1.name: "P-256",
        ec.SECP384R1.name: "P-384",
        ec.SECP521R1.name: "P-521",
    }

    def __init__(
        self, crv: str, x: str, y: str, d: Optional[str] = None, **ignore
    ) -> None:
        if crv not in self.CURVES.keys():
            raise InvalidKey(f'Unknown curve: "{crv}".')

        self._private = None
        self._public = None

        curve = self.CURVES[crv]
        x_coord = b64_to_int(x)
        y_coord = b64_to_int(y)

        public = ec.EllipticCurvePublicNumbers(x_coord, y_coord, curve)
        self._public: EC_PUBLIC = public.public_key(default_backend())

        if d:
            private_value = b64_to_int(d)
            private = ec.EllipticCurvePrivateNumbers(private_value, public)
            self._private: EC_PRIVATE = private.private_key(default_backend())

    @classmethod
    def generate(cls, curve: str) -> ECKey:
        """
        Generates a key on the fly based on the provided curve name.

        :param curve: Curve used to generate the key.
        :type curve: str

        :raises InvalidKey: Invalid parameters for the key.

        :return: Generated key as ECKey.
        :rtype: ECKey
        """

        if not (crv := cls.CURVES.get(curve)):
            raise InvalidKey(f'Unknown curve "{curve}".')

        key: EC_PRIVATE = ec.generate_private_key(crv, default_backend())

        private = key.private_numbers()
        public = key.public_key().public_numbers()

        return cls(
            crv=curve,
            x=to_string(int_to_b64(public.x)),
            y=to_string(int_to_b64(public.y)),
            d=to_string(int_to_b64(private.private_value)),
        )

    @classmethod
    def parse(
        cls,
        path_or_secret: Union[os.PathLike, bytes],
        password: bytes = None,
        format: str = "pem",
    ) -> ECKey:
        """
        Parses a raw key into an ECKey.

        :param path_or_secret: The path of the raw key or its bytes representation.
        :type path_or_secret: Union[os.PathLike, bytes]

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to `pem`.
            If `pem`, assumes it is PEM Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as ECKey.
        :rtype: ECKey
        """

        raw = _parse_raw(path_or_secret)

        if format == "pem":
            if b"PRIVATE" in raw:
                key: EC_PRIVATE = serialization.load_pem_private_key(
                    raw, password, default_backend()
                )

                if not isinstance(key, ec.EllipticCurvePrivateKey):
                    raise InvalidKey(
                        "The raw key is not an Elliptic Curve Private Key."
                    )

                private = key.private_numbers()
                public = key.public_key().public_numbers()

                return cls(
                    crv=cls.CURVES_NAMES.get(public.curve.name),
                    x=to_string(int_to_b64(public.x)),
                    y=to_string(int_to_b64(public.y)),
                    d=to_string(int_to_b64(private.private_value)),
                )

            if b"PUBLIC" in raw:
                key: EC_PUBLIC = serialization.load_pem_public_key(
                    raw, default_backend()
                )

                if not isinstance(key, ec.EllipticCurvePublicKey):
                    raise InvalidKey("The raw key is not an Elliptic Curve Public Key.")

                public = key.public_numbers()

                return cls(
                    crv=cls.CURVES_NAMES.get(public.curve.name),
                    x=to_string(int_to_b64(public.x)),
                    y=to_string(int_to_b64(public.y)),
                )

            raise InvalidKey("Unknown raw key format for Elliptic Curve.")

        raise UnsupportedParsingMethod

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key's parameters.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        numbers = self._public.public_numbers()
        data = {
            "kty": self.kty,
            "crv": self.CURVES_NAMES[numbers.curve.name],
            "x": to_string(int_to_b64(numbers.x)),
            "y": to_string(int_to_b64(numbers.y)),
        }

        if public:
            return data

        if not self._private:
            raise RuntimeError("This key is not a private key.")

        private_value = self._private.private_numbers().private_value
        return FullDict(data, d=to_string(int_to_b64(private_value)))

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: PEM encoded key data.
        :rtype: bytes
        """

        if not public:
            if self._private:
                return self._private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )

            raise InvalidKey("No private key found.")

        return self._public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes, algorithm: AlgType) -> bytes:
        """
        Returns a signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param algorithm: Hash algorithm used to sign the provided data.
        :type algorithm: AlgType

        :return: Signature of the provided data.
        :rtype: bytes
        """

        if not self._private:
            raise InvalidKey("Cannot sign with a public key.")

        return self._private.sign(data, ec.ECDSA(_get_alg(algorithm)))

    def verify(self, signature: bytes, data: bytes, algorithm: AlgType) -> None:
        """
        Compares the provided signature against the provided data.

        :param signature: Signature to be compared.
        :type signature: bytes

        :param data: Data to be compared against.
        :type data: bytes

        :param algorithm: Hash algorithm used to validate the data and the signature.
        :type algorithm: AlgType

        :raises InvalidSignature: The signature and data do not match.
        """

        try:
            self._public.verify(signature, data, ec.ECDSA(_get_alg(algorithm)))
        except BaseInvalidSignature:
            raise InvalidSignature


class OCTKey(JWKAlgorithm):
    """
    Implementation of a symmetric key.

    In this implementation, the same secret is used to perform all of the operations.

    It is **NOT RECOMMENDED** to disclose this type of key in a Json Web Key Set (JWKS),
    since it **COULD** lead to security issues.

    :param k: The secret used in this key. It is assumed that the secret will be
        a Base64UrlEncoded string and, thus, it will perform the necessary conversions.
    :type k: str
    """

    __allowed_attributes__ = frozenset(("k"))

    kty: str = "oct"

    def __init__(self, k: str, **ignore) -> None:
        self._secret = base64url_decode(to_bytes(k))

    @classmethod
    def generate(cls, size: int = 32) -> OCTKey:
        """
        Generates a secure random bytes sequence based on the provided size.

        :param size: Size of the secret in bytes, defaults to 32.
        :type size: int, optional

        :raises InvalidKey: Invalid parameters for the key.

        :return: Instance of an OCTKey.
        :rtype: OCTKey
        """

        if size < 32:
            raise InvalidKey("Size is too short. MUST be AT LEAST 32 bytes.")

        secret = base64url_encode(secrets.token_bytes(size))

        return cls(k=to_string(secret))

    @classmethod
    def parse(
        cls,
        path_or_secret: Union[os.PathLike, bytes],
        password: bytes = None,
        format: str = "pem",
    ) -> OCTKey:
        """
        Parses a raw secret into an OCTKey.

        :param path_or_secret: The path of the raw key or its bytes representation.
        :type path_or_secret: Union[os.PathLike, bytes]

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to `pem`.
            If `pem`, assumes it is Base64 Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as OCTKey.
        :rtype: OCTKey
        """

        raw = _parse_raw(path_or_secret)

        if format == "pem":
            invalid_strings = [
                b"-----BEGIN CERTIFICATE-----",
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN PUBLIC KEY-----",
                b"-----BEGIN RSA PUBLIC KEY-----",
                b"-----BEGIN EC PUBLIC KEY-----",
                b"ssh-rsa",
            ]

            if any(string in raw for string in invalid_strings):
                raise InvalidKey(
                    "The raw key is an asymmetric key or X.509 Certificate "
                    "and CANNOT be used as a symmetric key."
                )

            data = to_string(base64url_encode(base64.b64decode(raw)))
            return cls(data)

        if format == "der":
            data = to_string(base64url_encode(raw))
            return cls(data)

        raise UnsupportedParsingMethod

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key's parameters.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        if public:
            warnings.warn("Secret keys fo not have public info.", RuntimeWarning)

        return {"kty": self.kty, "k": to_string(base64url_encode(self._secret))}

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in Base64 format.

        :param public: Exports the public info, defaults to False.
        :type public: bool, optional

        :return: Base64 encoded key data.
        :rtype: bytes
        """

        if public:
            warnings.warn("Secret keys do not have public info.", RuntimeWarning)

        return base64.b64encode(base64url_decode(to_bytes(self._secret)))

    def sign(self, data: bytes, algorithm: AlgType) -> bytes:
        """
        Returns a signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param algorithm: Hash algorithm used to sign the provided data.
        :type algorithm: AlgType

        :return: Signature of the provided data.
        :rtype: bytes
        """

        signature = hmac.HMAC(self._secret, _get_alg(algorithm), default_backend())
        signature.update(data)
        return signature.finalize()

    def verify(self, signature: bytes, data: bytes, algorithm: AlgType) -> None:
        """
        Compares the provided signature against the provided data.

        :param signature: Signature to be compared.
        :type signature: bytes

        :param data: Data to be compared against.
        :type data: bytes

        :param algorithm: Hash algorithm used to validate the data and the signature.
        :type algorithm: AlgType

        :raises InvalidSignature: The signature and data do not match.
        """

        try:
            message = hmac.HMAC(self._secret, _get_alg(algorithm), default_backend())
            message.update(data)
            message.verify(signature)
        except BaseInvalidSignature:
            raise InvalidSignature


class RSAKey(JWKAlgorithm):
    """
    Implementation of the RSA Asymmetric Key Algorithm.

    This Key Algorithm requires the usage of a padding. Because of this requirement,
    the :meth:`sign` and :meth:`verify` methods require one more argument to be provided.

    :param n: Modulus of the key.
    :type n: str

    :param e: Public exponent.
    :type e: str

    :param d: Private exponent. **MANDATORY** if it is a private key.
    :type d: str, optional

    :param p: First prime coefficient.
    :type p: str, optional

    :param q: Second prime coefficient.
    :type q: str, optional

    :param dp: First prime CRT exponent.
    :type dp: str, optional

    :param dq: Second prime CRT exponent.
    :type dq: str, optional

    :param qi: First CRT coefficient.
    :type qi: str, optional
    """

    __allowed_attributes__ = frozenset(("n", "e", "d", "p", "q", "dp", "dq", "qi"))

    kty: str = "RSA"

    def __init__(
        self,
        n: str,
        e: str,
        d: Optional[str] = None,
        p: Optional[str] = None,
        q: Optional[str] = None,
        dp: Optional[str] = None,
        dq: Optional[str] = None,
        qi: Optional[str] = None,
        **ignore,
    ) -> None:
        self._private = None
        self._public = None

        modulus = b64_to_int(n)
        public_exponent = b64_to_int(e)

        public = rsa.RSAPublicNumbers(public_exponent, modulus)
        self._public: RSA_PUBLIC = public.public_key(default_backend())

        if d:
            private_exponent = b64_to_int(d)
            first_prime = b64_to_int(p)
            second_prime = b64_to_int(q)
            first_prime_crt = b64_to_int(dp)
            second_prime_crt = b64_to_int(dq)
            crt_coefficient = b64_to_int(qi)

            if not first_prime or not second_prime:
                first_prime, second_prime = rsa.rsa_recover_prime_factors(
                    modulus, public_exponent, private_exponent
                )

            if not first_prime_crt:
                first_prime_crt = rsa.rsa_crt_dmp1(private_exponent, first_prime)

            if not second_prime_crt:
                second_prime_crt = rsa.rsa_crt_dmq1(private_exponent, second_prime)

            if not crt_coefficient:
                crt_coefficient = rsa.rsa_crt_iqmp(first_prime, second_prime)

            private = rsa.RSAPrivateNumbers(
                first_prime,
                second_prime,
                private_exponent,
                first_prime_crt,
                second_prime_crt,
                crt_coefficient,
                public,
            )

            self._private: RSA_PRIVATE = private.private_key(default_backend())

    @classmethod
    def generate(cls, size: int = 2048) -> RSAKey:
        """
        Generates a key on the fly based on the provided module size.

        :param size: Size of the modulus in bits, defaults to 2048.
        :type size: int, optional

        :raises InvalidKey: Invalid parameters for the key.

        :return: Generated key as RSAKey.
        :rtype: RSAKey
        """

        if size < 512:
            raise InvalidKey("Size is too short. Must be AT LEAST 512 bits.")

        key = rsa.generate_private_key(65537, size, default_backend())

        private = key.private_numbers()
        public = key.public_key().public_numbers()

        return cls(
            n=to_string(int_to_b64(public.n)),
            e=to_string(int_to_b64(public.e)),
            d=to_string(int_to_b64(private.d)),
            p=to_string(int_to_b64(private.p)),
            q=to_string(int_to_b64(private.q)),
            dp=to_string(int_to_b64(private.dmp1)),
            dq=to_string(int_to_b64(private.dmq1)),
            qi=to_string(int_to_b64(private.iqmp)),
        )

    @classmethod
    def parse(
        cls,
        path_or_secret: Union[os.PathLike, bytes],
        password: bytes = None,
        format: str = "pem",
    ) -> RSAKey:
        """
        Parses a raw key into an RSAKey.

        :param path_or_secret: The path of the raw key or its bytes representation.
        :type path_or_secret: Union[os.PathLike, bytes]

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to `pem`.
            If `pem`, assumes it is PEM Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as RSAKey.
        :rtype: RSAKey
        """

        raw = _parse_raw(path_or_secret)

        if format == "pem":
            if b"PRIVATE" in raw:
                key: RSA_PRIVATE = serialization.load_pem_private_key(
                    raw, password, default_backend()
                )

                if not isinstance(key, rsa.RSAPrivateKey):
                    raise InvalidKey("The raw key is not an RSA Private Key.")

                private = key.private_numbers()
                public = key.public_key().public_numbers()

                return cls(
                    n=to_string(int_to_b64(public.n)),
                    e=to_string(int_to_b64(public.e)),
                    d=to_string(int_to_b64(private.d)),
                    p=to_string(int_to_b64(private.p)),
                    q=to_string(int_to_b64(private.q)),
                    dp=to_string(int_to_b64(private.dmp1)),
                    dq=to_string(int_to_b64(private.dmq1)),
                    qi=to_string(int_to_b64(private.iqmp)),
                )

            if b"PUBLIC" in raw:
                key: RSA_PUBLIC = serialization.load_pem_public_key(
                    raw, default_backend()
                )

                if not isinstance(key, rsa.RSAPublicKey):
                    raise InvalidKey("The raw key is not an RSA Public Key.")

                public = key.public_numbers()

                return cls(
                    n=to_string(int_to_b64(public.n)), e=to_string(int_to_b64(public.e))
                )

            raise InvalidKey("Unknown raw key format for RSA.")

        raise UnsupportedParsingMethod

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key's parameters.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        numbers = self._public.public_numbers()
        data = {
            "kty": self.kty,
            "n": to_string(int_to_b64(numbers.n)),
            "e": to_string(int_to_b64(numbers.e)),
        }

        if public:
            return data

        if not self._private:
            raise RuntimeError("This key is not a private key.")

        private = self._private.private_numbers()

        return FullDict(
            data,
            d=to_string(int_to_b64(private.d)),
            p=to_string(int_to_b64(private.p)),
            q=to_string(int_to_b64(private.q)),
            dp=to_string(int_to_b64(private.dmp1)),
            dq=to_string(int_to_b64(private.dmq1)),
            qi=to_string(int_to_b64(private.iqmp)),
        )

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: PEM encoded key data.
        :rtype: bytes
        """

        if not public:
            if self._private:
                return self._private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )

            raise InvalidKey("No private key found.")

        return self._public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes, algorithm: AlgType, rsa_padding: RSAPadding) -> bytes:
        """
        Returns a signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param algorithm: Hash algorithm used to sign the provided data.
        :type algorithm: AlgType

        :param rsa_padding: Padding used by the key.
        :type rsa_padding: RSAPadding

        :return: Signature of the provided data.
        :rtype: bytes
        """

        if not self._private:
            raise InvalidKey("Cannot sign with a public key.")

        alg = _get_alg(algorithm)

        if rsa_padding == "PKCS1v15":
            return self._private.sign(data, padding.PKCS1v15(), alg)

        if rsa_padding == "PSS":
            return self._private.sign(
                data, padding.PSS(padding.MGF1(alg), padding.PSS.MAX_LENGTH), alg
            )

        raise InvalidKey("Unsupported RSA padding.")

    def verify(
        self,
        signature: bytes,
        data: bytes,
        algorithm: AlgType,
        rsa_padding: RSAPadding,
    ) -> None:
        """
        Compares the provided signature against the provided data.

        :param signature: Signature to be compared.
        :type signature: bytes

        :param data: Data to be compared against.
        :type data: bytes

        :param algorithm: Hash algorithm used to validate the data and the signature.
        :type algorithm: AlgType

        :param rsa_padding: Padding used by the key.
        :type rsa_padding: RSAPadding

        :raises InvalidSignature: The signature and data do not match.
        """

        try:
            alg = _get_alg(algorithm)

            if rsa_padding == "PKCS1v15":
                return self._public.verify(signature, data, padding.PKCS1v15(), alg)

            if rsa_padding == "PSS":
                return self._public.verify(
                    signature,
                    data,
                    padding.PSS(padding.MGF1(alg), padding.PSS.MAX_LENGTH),
                    alg,
                )

            raise InvalidKey("Unsupported padding.")
        except BaseInvalidSignature:
            raise InvalidSignature
