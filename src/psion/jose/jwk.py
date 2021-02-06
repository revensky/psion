from __future__ import annotations
import os

from typing import Any
from psion.jose.exceptions import InvalidKey, InvalidKeySet, UnsupportedAlgorithm

from psion.jose.jwa.jwk import AlgType, ECKey, JWKAlgorithm, OCTKey, RSAKey
from psion.webtools import FullDict


class JsonWebKey:
    """
    Implementation of RFC 7517.

    It represents the keys used by the application via the algorithms
    defined at RFC 7518 and implemented as :class:`JWKAlgorithm` in this package.

    The usage of this representation instead of directly using the key is
    so that there is a well defined granularity regarding the usage of
    each key, as well as the allowed operations.

    It is possible to define an ID for each key as well, which helps identifying
    the key used at any point in the application.

    :cvar ``__algorithms__``: Dictionary of the supported algorithms and their names.

    TODO: Verify the possibility of conflict between the _data's kty
        and the algorithm dump's kty parameters when using this class' dump method.
    """

    __algorithms__: dict[str, JWKAlgorithm] = {
        "oct": OCTKey,
        "RSA": RSAKey,
        "EC": ECKey,
    }

    def __init__(self, data: dict) -> None:
        if not data or not isinstance(data, dict):
            raise InvalidKey

        if (kty := data.get("kty")) not in self.__algorithms__.keys():
            raise UnsupportedAlgorithm

        self.data = FullDict(data)
        self._algorithm: JWKAlgorithm = self.__algorithms__[kty](**data)

    @classmethod
    def generate(cls, algorithm: str, option: Any = None, **params: Any) -> JsonWebKey:
        """
        Generates a Json Web Key based on the provided algorithm.

        :param algorithm: Name of the JWK Algorithm used to generate the JWK.
        :type algorithm: str

        :param option: Option used to customize the key generation.
            MUST be supported by the :meth:`JWKAlgorithm.generate` of the algorithm.
            Defaults to None.
        :type option: Any

        :param params: Parameters that will compose the final JsonWebKey.
            **MUST** be supported by the JsonWebKey definition.

        :raises UnsupportedAlgorithm: Unsupported algorithm. 😒

        :return: Instance of a JsonWebKey.
        :rtype: JsonWebKey
        """

        if algorithm not in cls.__algorithms__.keys():
            raise UnsupportedAlgorithm

        alg: JWKAlgorithm = (
            cls.__algorithms__.get(algorithm).generate(option)
            if option
            else cls.__algorithms__.get(algorithm).generate()
        )

        attrs = FullDict(alg.dump(public=False), **params)

        return cls(attrs)

    @classmethod
    def parse(
        cls,
        path_or_secret: os.PathLike | bytes,
        algorithm: str,
        public: bool,
        password: bytes = None,
        format: str = "pem",
        **options: Any,
    ) -> JsonWebKey:
        """
        Parses a raw key into a JsonWebKey.

        A raw symmetric key is simply its bytes string.
        A raw asymmetric key would be a PEM encoded key data.

        :param path_or_secret: The path of the raw key or its bytes representation.
        :type path_or_secret: os.PathLike | bytes

        :param algorithm: JWK Algorithm used to parse the raw key.
        :type algorithm: str

        :param public: Defines if the key will be parsed as public or as private/secret.
        :type public: bool

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to pem.
            If `pem`, assumes it is Base64 Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :param optional: Keyword arguments of extra custom attributes of the key.

        :raises UnsupportedAlgorithm: Algorithm not supported.
        :raises UnsupportedParsingMethod: Method not supported (alg).
        :raises InvalidKey: The raw key type is different from the class' (alg).

        :return: Parsed key as JsonWebKey.
        :rtype: JsonWebKey
        """

        if not (method := cls.__algorithms__.get(algorithm)):
            raise UnsupportedAlgorithm

        jwk = method.parse(path_or_secret, password, format)
        key = jwk.dump(public)

        key.update(options)

        return cls(key)

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        data = {
            key: value
            for key, value in self.data.items()
            if key not in self._algorithm.__allowed_attributes__
        }
        data.update(self._algorithm.dump(public))

        return data

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format if asymmetric, or Base64 if symmetric.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: Base64/PEM encoded key data.
        :rtype: bytes
        """

        return self._algorithm.export(public)

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

        return self._algorithm.sign(data, algorithm, **kwargs)

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

        self._algorithm.verify(signature, data, algorithm, **kwargs)


class JsonWebKeySet:
    """
    Implementation of RFC 7517.

    The Json Web Key Set is a collection of Json Web Keys, providing a pool of
    keys accepted by the application. It is useful when there are multiple keys,
    each one having a specific usage.

    In order to be added into a key set, the key **MUST** have an ID,
    via the `kid` parameter, since there **SHOULD NOT** be
    any repeated keys within the set.

    The method :meth:`get_key` provides an easy way of retrieving a key via the ID.

    :ivar keys: A collection of the keys accepted by the JWKS.

    :param keys: A collection of the keys to be used by the application.
        Note that **ALL** the keys **MUST** have a valid unique ID assigned to itself.
    :type keys: list[JsonWebKey]
    """

    def __init__(self, keys: list[JsonWebKey]) -> None:
        if not keys or not isinstance(keys, list):
            raise InvalidKeySet

        if any(not isinstance(key, JsonWebKey) for key in keys):
            raise InvalidKeySet

        # Verifies if there are any repeated IDs.
        ids = [key.data.get("kid") for key in keys]

        if None in ids:
            raise InvalidKeySet("One or more keys do not have an ID.")

        if len(ids) != len(set(ids)):
            raise InvalidKeySet(
                "The usage of the same ID for multiple keys in a JWKS is forbidden."
            )

        self.keys = keys

    def load(self, keyset: dict[str, list[dict]]) -> JsonWebKeySet:
        """
        Loads a raw Key Set into a JsonWebKeySet object.

        :param keyset: Key Set to be loaded.
        :type keyset: dict[str, list[dict]]
        """

        if not keyset or not isinstance(keyset, dict):
            raise InvalidKeySet("Invalid JWKS format.")

        if list(keyset.keys()) != ["keys"]:
            raise InvalidKeySet("Invalid JWKS format.")

        return JsonWebKeySet([JsonWebKey(key) for key in keyset["keys"]])

    def dump(self, public: bool = True) -> dict[str, list[dict]]:
        """
        Returns the dict representation of the keys of the JWKS.

        :param public: Defines whether to return the public info of the key only,
            defaults to True.
        :type public: bool

        :return: Dict representation of the JWK Set and its JWKs.
        :rtype: dict
        """

        return {"keys": [key.dump(public) for key in self.keys]}

    def get_key(self, kid: str) -> JsonWebKey:
        """
        Returns the key identified by the provided ID.

        :param kid: ID of the key to be retrieved.
        :type kid: str

        :return: Instance of a Json Web Key.
        :rtype: JsonWebKey
        """

        # pylint: disable=W0212
        return next((key for key in self.keys if key.data["kid"] == kid), None)
