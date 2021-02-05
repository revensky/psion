from __future__ import annotations

import json
import os
from typing import Union


KEYS_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "keys")


def load_pem(alg: str) -> Union[bytes, tuple[bytes, bytes]]:
    if alg == "oct":
        with open(os.path.join(KEYS_PATH, "oct_secret_key.pem"), "rb") as secret:
            return secret.read()

    with open(os.path.join(KEYS_PATH, f"{alg}_private_key.pem"), "rb") as priv, open(
        os.path.join(KEYS_PATH, f"{alg}_public_key.pem"), "rb"
    ) as pub:
        return priv.read(), pub.read()


def load_json(alg: str) -> Union[dict, tuple[dict, dict]]:
    if alg == "oct":
        with open(os.path.join(KEYS_PATH, "oct_secret_key.json"), "r") as secret:
            return json.loads(secret.read())

    with open(os.path.join(KEYS_PATH, f"{alg}_private_key.json"), "r") as priv, open(
        os.path.join(KEYS_PATH, f"{alg}_public_key.json"), "r"
    ) as pub:
        return json.loads(priv.read()), json.loads(pub.read())
