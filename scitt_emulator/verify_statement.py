import os
import itertools
import contextlib
import dataclasses
import urllib.parse
import urllib.request
import importlib.metadata
from typing import Optional, Callable, List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
from pycose.messages import Sign1Message

from scitt_emulator.did_helpers import did_web_to_url
from scitt_emulator.create_statement import CWTClaims
from scitt_emulator.key_helper_dataclasses import VerificationKey
from scitt_emulator.key_transforms import preform_verification_key_transforms


ENTRYPOINT_KEY_LOADERS = "scitt_emulator.verify_signature.key_loaders"


def verify_statement(
    msg: Sign1Message,
    *,
    key_loaders: Optional[List[Callable[[str], List[VerificationKey]]]] = None,
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

    # Load keys from issuer and attempt verification. Return key used to verify
    for verification_key in preform_verification_key_transforms(
        itertools.chain(
            *[key_loader(unverified_issuer) for key_loader in key_loaders]
        )
    ):
        # Skip keys that we couldn't derive COSE keys for
        if not verification_key.usable:
            # TODO Logging
            continue
        msg.key = verification_key.cose
        verify_signature = False
        with contextlib.suppress(Exception):
            verify_signature = msg.verify_signature()
        if verify_signature:
            return verification_key

    return None
