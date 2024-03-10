import contextlib
import urllib.parse
import urllib.request
from typing import List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.did_helpers import did_web_to_url
from scitt_emulator.key_helper_dataclasses import VerificationKey

CONTENT_TYPE = "application/key+ssh"


def key_loader_format_url_referencing_ssh_authorized_keys(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return keys

    # Try loading ssh keys. Example: https://github.com/username.keys
    with contextlib.suppress(urllib.request.URLError):
        with urllib.request.urlopen(unverified_issuer) as response:
            while line := response.readline():
                with contextlib.suppress(
                    (ValueError, cryptography.exceptions.UnsupportedAlgorithm)
                ):
                    key = serialization.load_ssh_public_key(line)
                    keys.append(
                        VerificationKey(
                            transforms=[key],
                            original=key,
                            original_content_type=CONTENT_TYPE,
                            original_bytes=line,
                            original_bytes_encoding="utf-8",
                            usable=False,
                            cwt=None,
                            cose=None,
                        )
                    )

    return keys


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
