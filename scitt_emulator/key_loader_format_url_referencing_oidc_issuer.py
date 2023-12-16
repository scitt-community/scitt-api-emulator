import json
import contextlib
import urllib.parse
import urllib.request
from typing import List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.did_helpers import did_web_to_url
from scitt_emulator.key_helper_dataclasses import VerificationKey


CONTENT_TYPE = "application/jwk+json"


def key_loader_format_url_referencing_oidc_issuer(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return keys

    # TODO Logging for URLErrors
    # Check if OIDC issuer
    unverified_issuer_parsed_url = urllib.parse.urlparse(unverified_issuer)
    openid_configuration_url = unverified_issuer_parsed_url._replace(
        path="/.well-known/openid-configuration",
    ).geturl()
    with contextlib.suppress(urllib.request.URLError):
        with urllib.request.urlopen(openid_configuration_url) as response:
            if response.status == 200:
                openid_configuration = json.loads(response.read())
                jwks_uri = openid_configuration["jwks_uri"]
                with urllib.request.urlopen(jwks_uri) as response:
                    if response.status == 200:
                        jwks = json.loads(response.read())
                        for jwk_key_as_dict in jwks["keys"]:
                            jwk_key_as_string = json.dumps(jwk_key_as_dict)
                            jwk_key = jwcrypto.jwk.JWK.from_json(jwk_key_as_string)
                            keys.append(
                                VerificationKey(
                                    transforms=[jwk_key],
                                    original=jwk_key,
                                    original_content_type=CONTENT_TYPE,
                                    original_bytes=jwk_key_as_string.encode("utf-8"),
                                    original_bytes_encoding="utf-8",
                                    usable=False,
                                    cwt=None,
                                    cose=None,
                                )
                            )

    return keys


def transform_key_instance_jwcrypto_jwk_to_cwt_cose(
    key: jwcrypto.jwk.JWK,
) -> cwt.COSEKey:
    if not isinstance(key, jwcrypto.jwk.JWK):
        raise TypeError(key)
    return cwt.COSEKey.from_pem(
        key.export_to_pem(),
        kid=key.thumbprint(),
    )


def to_object_oidc_issuer(verification_key: VerificationKey) -> dict:
    if verification_key.original_content_type != CONTENT_TYPE:
        return

    return {
        **verification_key.original.export_public(as_dict=True),
        "use": "sig",
        "kid": verification_key.original.thumbprint(),
    }
