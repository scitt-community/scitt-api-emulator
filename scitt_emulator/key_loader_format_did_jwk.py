import base64
from typing import List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
import cryptography.hazmat.primitives.asymmetric.ec
from cryptography.hazmat.primitives import serialization

import jwcrypto.jwk

from scitt_emulator.did_helpers import DID_JWK_METHOD
from scitt_emulator.key_helper_dataclasses import VerificationKey


CONTENT_TYPE = "application/did+jwk"


def key_loader_format_did_jwk(
    unverified_issuer: str,
) -> List[VerificationKey]:
    if not unverified_issuer.startswith(DID_JWK_METHOD):
        return []
    key = jwcrypto.jwk.JWK.from_json(
        base64.urlsafe_b64decode(unverified_issuer[len(DID_JWK_METHOD):]).decode()
    )
    return [
        VerificationKey(
            transforms=[key],
            original=key,
            original_content_type=CONTENT_TYPE,
            original_bytes=unverified_issuer.encode("utf-8"),
            original_bytes_encoding="utf-8",
            usable=False,
            cwt=None,
            cose=None,
        )
    ]
