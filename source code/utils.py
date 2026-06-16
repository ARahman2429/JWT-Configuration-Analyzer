# utils.py

import base64
import json
from datetime import datetime, timezone


class JWTDecodeError(Exception):
    pass


def validate_token_structure(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTDecodeError("Invalid JWT structure")
    return parts


def base64url_decode(input_str: str):

    padding = "=" * (-len(input_str) % 4)
    input_str += padding

    try:
        decoded = base64.urlsafe_b64decode(input_str)
        return decoded.decode("utf-8")
    except Exception:
        raise JWTDecodeError("Base64 decoding failed")


def decode_jwt(token: str):

    header_b64, payload_b64, signature = validate_token_structure(token)

    header_json = base64url_decode(header_b64)
    payload_json = base64url_decode(payload_b64)

    try:
        header = json.loads(header_json)
        payload = json.loads(payload_json)
    except Exception:
        raise JWTDecodeError("Invalid JSON inside JWT")

    return header, payload, signature


def current_timestamp():
    return datetime.now(timezone.utc).timestamp()