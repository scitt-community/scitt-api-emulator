import inspect
import itertools
import importlib.metadata
from typing import Optional, Callable, List, Tuple

import cwt
import pycose.keys.ec2

from scitt_emulator.key_helper_dataclasses import VerificationKey


ENTRYPOINT_KEY_TRANSFORMS_KEY_INSTANCES = "scitt_emulator.key_helpers.transforms_key_instances"


def preform_verification_key_transforms(
    verification_keys: List[VerificationKey],
    *,
    key_transforms: Optional[List[Callable[[VerificationKey], dict]]] = None,
) -> None:
    """
    Resolve keys for statement issuer and verify signature on COSESign1
    statement and embedded CWT
    """
    # In case of iterators since we have to loop multiple times
    verification_keys = list(verification_keys)

    if key_transforms is None:
        key_transforms = []
        # There is some difference in the return value of entry_points across
        # Python versions/envs (conda vs. non-conda). Python 3.8 returns a dict.
        entrypoints = importlib.metadata.entry_points()
        if isinstance(entrypoints, dict):
            for entrypoint in entrypoints.get(ENTRYPOINT_KEY_TRANSFORMS_KEY_INSTANCES, []):
                key_transforms.append(entrypoint.load())
        elif isinstance(entrypoints, getattr(importlib.metadata, "EntryPoints", list)):
            for entrypoint in entrypoints:
                if entrypoint.group == ENTRYPOINT_KEY_TRANSFORMS_KEY_INSTANCES:
                    key_transforms.append(entrypoint.load())
        else:
            raise TypeError(f"importlib.metadata.entry_points returned unknown type: {type(entrypoints)}: {entrypoints!r}")

    key_transform_types = tuple(
        [
            list(inspect.signature(key_transform).parameters.values())[0].annotation
            for key_transform in key_transforms
        ]
    )

    for verification_key in verification_keys:
        while not verification_key.usable:
            # Attempt key transforms
            for key_transform in key_transforms:
                key = verification_key.transforms[-1]
                if isinstance(key, list(inspect.signature(key_transform).parameters.values())[0].annotation):
                    transformed_key = key_transform(key)
                    if transformed_key:
                        verification_key.transforms.append(transformed_key)
            # Check if key is usable yet
            for key in reversed(verification_key.transforms):
                if not verification_key.cwt and isinstance(key, cwt.algs.ec2.EC2Key):
                    verification_key.cwt = key
                if (
                    not verification_key.cose
                    and isinstance(
                        key,
                        (
                            pycose.keys.ec2.EC2Key,
                        )
                    )
                ):
                    verification_key.cose = key
            if verification_key.cwt and verification_key.cose:
                verification_key.usable = True
                break
            # If we are unable to transform further, raise exception
            key = verification_key.transforms[-1]
            if not isinstance(key, key_transform_types):
                raise NotImplementedError(f"Unable to transform {type(key)} into CWT and COSE keys needed. Transforms available: {key_transforms}. Transform types accepted: {key_transform_types}. Transforms completed: {verification_key.transforms}")

    return verification_keys


def transform_key_instance_cwt_cose_ec2_to_pycose_ec2(
    key: cwt.algs.ec2.EC2Key,
) -> pycose.keys.ec2.EC2Key:
    if not isinstance(key, cwt.algs.ec2.EC2Key):
        raise TypeError(key)
    cwt_ec2_key_as_dict = key.to_dict()
    return pycose.keys.ec2.EC2Key.from_dict(cwt_ec2_key_as_dict)
