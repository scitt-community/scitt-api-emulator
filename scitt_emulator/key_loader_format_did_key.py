from typing import List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
import cryptography.hazmat.primitives.asymmetric.ec
from cryptography.hazmat.primitives import serialization

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.did_helpers import DID_KEY_METHOD, did_key_to_cryptography_key
from scitt_emulator.key_helper_dataclasses import VerificationKey


# TODO What is the correct content type? Should we differ if it's been expanded?
CONTENT_TYPE = "application/key+did"


def key_loader_format_did_key(
    unverified_issuer: str,
) -> List[VerificationKey]:
    if not unverified_issuer.startswith(DID_KEY_METHOD):
        return []
    key = did_key_to_cryptography_key(unverified_issuer)
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


def transform_key_instance_cryptography_ecc_public_to_jwcrypto_jwk(
    key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
) -> jwcrypto.jwk.JWK:
    if not isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        raise TypeError(key)
    return jwcrypto.jwk.JWK.from_pem(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
