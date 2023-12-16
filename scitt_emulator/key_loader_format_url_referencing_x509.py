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


CONTENT_TYPE = "application/pkix-cert"


def key_loader_format_url_referencing_x509(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return keys

    with contextlib.suppress(urllib.request.URLError):
        with urllib.request.urlopen(unverified_issuer) as response:
            contents = response.read()
            with contextlib.suppress(
                (ValueError, cryptography.exceptions.UnsupportedAlgorithm)
            ):
                for certificate in cryptography.x509.load_pem_x509_certificates(
                    contents
                ):
                    keys.append(
                        VerificationKey(
                            transforms=[certificate, certificate.public_key()],
                            original=certificate,
                            original_content_type=CONTENT_TYPE,
                            original_bytes=contents,
                            original_bytes_encoding="utf-8",
                            usable=False,
                            cwt=None,
                            cose=None,
                        )
                    )

    return keys


def to_object_x509(verification_key: VerificationKey) -> dict:
    if verification_key.original_content_type != CONTENT_TYPE:
        return
    return {
        "content_type": verification_key.original_content_type,
        "certificate": {
            "subject": {
                attribute.rfc4514_attribute_name: attribute.value
                for attribute in verification_key.original.subject
            },
        },
    }
