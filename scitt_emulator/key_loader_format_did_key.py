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
from scitt_emulator.did_helpers import DID_KEY_METHOD, did_web_to_url, did_key_to_cryptography_key


def key_loader_format_did_key(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []
    cryptography_keys = []

    if not unverified_issuer.startswith(DID_KEY_METHOD):
        return pycose_cose_keys

    cryptography_keys.append(did_key_to_cryptography_key(unverified_issuer))

    for cryptography_key in cryptography_keys:
        jwk_keys.append(
            jwcrypto.jwk.JWK.from_pem(
                cryptography_key.public_bytes(
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
