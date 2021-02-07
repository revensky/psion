from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import secrets
import string
import struct
from functools import reduce
from operator import concat
from typing import Any, Union
from urllib.parse import parse_qsl, urlencode as urlencode_


class FullDict(dict):
    """
    Dictionary without None values.
    """

    def __init__(self, data: dict = None, /, **kwargs: Any):
        _data = copy.deepcopy(data or {})
        _data.update(kwargs)
        super().__init__({k: v for k, v in _data.items() if v is not None})

    def __setitem__(self, key: Any, value: Any):
        if value is not None:
            super().__setitem__(key, value)


def to_bytes(data: Any, encoding: str = "utf-8") -> bytes:
    """
    Returns the bytes representation of the provided data.

    :param data: Data to be transformed.
    :type data: Any

    :param encoding: Encoding of the bytes encoding, defaults to "utf-8".
    :type encoding: str, optional

    :return: Bytes representation of the provided data.
    :rtype: bytes
    """

    if isinstance(data, bytes) or data is None:
        return data

    if isinstance(data, str):
        return data.encode(encoding)

    if isinstance(data, (int, float)):
        return str(data).encode(encoding)

    return bytes(data, encoding=encoding)


def to_string(data: Any, encoding: str = "utf-8") -> str:
    """
    Returns the string representation of the provided data.

    :param data: Data to be transformed.
    :type data: Any

    :param encoding: Encoding of the string encoding, defaults to "utf-8".
    :type encoding: str, optional

    :return: String representation of the provided data.
    :rtype: str
    """

    if isinstance(data, str) or data is None:
        return data

    if isinstance(data, bytes):
        try:
            return data.decode(encoding)
        except (TypeError, UnicodeDecodeError):
            return base64url_encode(data).decode(encoding)

    return str(data, encoding=encoding)


def base64url_decode(data: bytes) -> bytes:
    """
    Decodes a URL Safe Base64 encoded bytes string into its original contents.

    :param data: Data to be decoded.
    :type data: bytes

    :return: Original contents of the provided encoded data.
    :rtype: bytes
    """

    data += b"=" * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


def base64url_encode(data: Any) -> bytes:
    """
    Returns a URL Safe Base64 encoding representation of the provided data.

    :param data: Data to be encoded.
    :type data: Any

    :return: URL Safe Base64 encoded representation of the provided data.
    :rtype: bytes
    """

    return base64.urlsafe_b64encode(to_bytes(data)).rstrip(b"=")


def b64_to_int(data: Union[bytes, str]) -> int:
    """
    Decodes a URL Safe Base64 representation of an integer.

    :param data: Data to be decoded.
    :type data: Union[bytes, str]

    :raises TypeError: The provided data is not a valid URL Safe Base64 string.

    :return: Decoded Integer.
    :rtype: int
    """

    if data is None:
        return data

    if not isinstance(data, (bytes, str)):
        raise TypeError('The argument "data" MUST be a bytes or str object.')

    x = base64url_decode(to_bytes(data, "ascii"))
    buffer = struct.unpack("%sB" % len(x), x)

    return int("".join(["%02x" % byte for byte in buffer]), 16)


def int_to_b64(data: int) -> bytes:
    """
    Encodes an integer into a URL Safe Base64 bytes string.

    :param data: Integer to be encoded.
    :type data: int

    :raises ValueError: The data is not an integer.
    :raises ValueError: The data is not a natural number.

    :return: URL Safe Base64 encoded version of the integer.
    :rtype: bytes
    """

    if not isinstance(data, int):
        raise ValueError("Must be a natural number.")

    if data < 0:
        raise ValueError("Must be a natural number.")

    res = data.to_bytes((data.bit_length() + 7) // 8, "big", signed=False)
    return base64url_encode(res)


def json_dumps(data: dict) -> str:
    """
    Dumps a dictionary into a formated JSON string.

    :param data: Dictionary to be formatted.
    :type data: dict

    :return: JSON formatted string of the data.
    :rtype: str
    """

    return json.dumps(data, ensure_ascii=False)


def json_loads(data: Union[bytes, str]) -> dict:
    """
    Loads a JSON string into a dictionary.

    :param data: JSON string to be loaded.
    :type data: Union[bytes, str]

    :raises TypeError: The data is not a valid string.

    :return: Dictionary of the loaded JSON string.
    :rtype: dict
    """

    if not isinstance(data, (bytes, str)):
        raise TypeError("The data MUST be either a string or a bytes object.")

    return json.loads(to_string(data))


def secret_token(size: int = 32) -> str:
    """
    Generates a cryptographically secure, urlsafe random token based on the size.

    :param size: Size of the token, defaults to 32.
    :type size: int, optional

    :return: Token generated.
    :rtype: str
    """

    alphabet = f"{string.ascii_letters}{string.digits}-_"
    return reduce(concat, (secrets.choice(alphabet) for _ in range(size)))


def urlencode(url: str, **params) -> str:
    """
    Encodes keyword arguments into a x-www-form-urlencoded
    string and concatenates it into the provided url.

    :param url: Base URL.
    :type url: str

    :return: Encoded URL containing the parameters of the dictionary as a query string.
    :rtype: str
    """

    return f"{url}?{urlencode_(FullDict(params))}"


def urldecode(query_string: str) -> dict:
    """
    Decodes a x-www-form-urlencoded string into a dictionary.

    :param query_string: Query string to be decoded.
    :type query_string: str

    :return: Dictionary representation of the query string.
    :rtype: dict
    """

    return dict(parse_qsl(query_string))


def get_basic_authorization(headers: dict) -> tuple[str, str]:
    """
    Extracts the authentication credentials from a Basic authentication scheme.

    :param headers: Dictionary of the headers.
    :type headers: dict

    :return: Authentication credentials.
    :rtype: tuple[str, str]
    """

    auth: str = headers.get("authorization") or headers.get("Authorization")

    if not auth or not isinstance(auth, str) or " " not in auth:
        return None, None

    method, token = auth.split(None, 1)

    if method.lower() != "basic":
        return None, None

    try:
        credentials = to_string(base64.b64decode(token))
    except (binascii.Error, TypeError):
        return None, None

    if ":" not in credentials:
        return None, None

    try:
        client_id, client_secret = credentials.split(":", 1)
    except ValueError:
        return None, None

    return client_id, client_secret


def get_bearer_authorization(headers: dict) -> str:
    """
    Extracts a Bearer token from a Bearer authorization scheme.

    :param headers: Dictionary of the headers.
    :type headers: dict

    :return: Bearer token.
    :rtype: str
    """

    auth: str = headers.get("authorization") or headers.get("Authorization")

    if not auth or not isinstance(auth, str) or " " not in auth:
        return None

    method, token = auth.split(None, 1)

    if method.lower() != "bearer":
        return None

    return token


def create_half_hash(access_token: str, alg: str) -> str:
    """
    Creates a Base64UrlEncoded strinf of the left-most
    half of the hash of the Access Token.

    :param access_token: Access Token issued to the Client.
    :type access_token: str

    :param alg: Algorithm used to sign the Access Token.
    :type alg: str

    :return: Base64UrlEncoded half hash of the Access Token.
    :rtype: str
    """

    method = getattr(hashlib, f"sha{alg[2:]}")

    hash_bytes = method(to_bytes(access_token)).digest()
    half_length = int(len(hash_bytes) / 2)
    half_hash = base64url_encode(hash_bytes[:half_length])

    return to_string(half_hash)
