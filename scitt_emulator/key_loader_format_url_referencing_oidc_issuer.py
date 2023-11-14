import os
import sys
import json
import pathlib
import unittest
import traceback
import contextlib
import urllib.parse
import urllib.request
import importlib.metadata
from typing import Optional, Callable, List, Tuple

import jwt
import cbor2
import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
from pycose.messages import Sign1Message
from cryptography.hazmat.primitives import serialization

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.scitt import ClaimInvalidError, CWTClaims
from scitt_emulator.did_helpers import did_web_to_url


def key_loader_format_url_referencing_oidc_issuer(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    if "://" not in unverified_issuer or unverified_issuer.startswith("file://"):
        return pycose_cose_keys

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
                            jwk_keys.append(
                                jwcrypto.jwk.JWK.from_json(jwk_key_as_string),
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
