import os
import sys
import json
import pathlib
import unittest
import itertools
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

from scitt_emulator.did_helpers import did_web_to_url
from scitt_emulator.create_statement import CWTClaims


ENTRYPOINT_KEY_LOADERS = "scitt_emulator.verify_signature.key_loaders"


def verify_statement(
    msg: Sign1Message,
    *,
    key_loaders: Optional[
        List[Callable[[str], List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]]]
    ] = None,
) -> bool:
    """
    Resolve keys for statement issuer and verify signature on COSESign1
    statement and embedded CWT
    """
    if key_loaders is None:
        key_loaders = []
        # There is some difference in the return value of entry_points across
        # Python versions/envs (conda vs. non-conda). Python 3.8 returns a dict.
        entrypoints = importlib.metadata.entry_points()
        if isinstance(entrypoints, dict):
            for entrypoint in entrypoints.get(ENTRYPOINT_KEY_LOADERS, []):
                key_loaders.append(entrypoint.load())
        elif isinstance(entrypoints, getattr(importlib.metadata, "EntryPoints", list)):
            for entrypoint in entrypoints:
                if entrypoint.group == ENTRYPOINT_KEY_LOADERS:
                    key_loaders.append(entrypoint.load())
        else:
            raise TypeError(f"importlib.metadata.entry_points returned unknown type: {type(entrypoints)}: {entrypoints!r}")

    # Figure out what the issuer is
    cwt_cose_loads = cwt.cose.COSE()._loads
    cwt_unverified_protected = cwt_cose_loads(
        cwt_cose_loads(msg.phdr[CWTClaims]).value[2]
    )
    unverified_issuer = cwt_unverified_protected[1]

    # Load keys from issuer and attempt verification. Return keys used to verify
    # as tuple of cwt.COSEKey and pycose.keys formats
    for cwt_cose_key, pycose_cose_key in itertools.chain(
        *[key_loader(unverified_issuer) for key_loader in key_loaders]
    ):
        msg.key = pycose_cose_key
        with contextlib.suppress(Exception):
            verify_signature = msg.verify_signature()
        if verify_signature:
            return cwt_cose_key, pycose_cose_key

    return None, None
