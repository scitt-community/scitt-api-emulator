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


def key_loader_format_url_referencing_x509(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []

    cryptography_ssh_keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return pycose_cose_keys

    with contextlib.suppress(urllib.request.URLError):
        with urllib.request.urlopen(unverified_issuer) as response:
            contents = response.read()
            with contextlib.suppress(
                (ValueError, cryptography.exceptions.UnsupportedAlgorithm)
            ):
                for certificate in cryptography.x509.load_pem_x509_certificates(
                    contents
                ):
                    cryptography_ssh_keys.append(certificate.public_key())

    for cryptography_ssh_key in cryptography_ssh_keys:
        jwk_keys.append(
            jwcrypto.jwk.JWK.from_pem(
                cryptography_ssh_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        )

    for jwk_key in jwk_keys:
        cwt_cose_key = cwt.COSEKey.from_pem(
            jwk_key.export_to_pem(),
            kid=jwk_key.thumbprint(),
        )
        cwt_cose_keys.append(cwt_cose_key)
        cwt_ec2_key_as_dict = cwt_cose_key.to_dict()
        pycose_cose_key = pycose.keys.ec2.EC2Key.from_dict(cwt_ec2_key_as_dict)
        pycose_cose_keys.append((cwt_cose_key, pycose_cose_key))

    return pycose_cose_keys
