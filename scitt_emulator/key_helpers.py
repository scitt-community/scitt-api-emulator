import itertools
import importlib.metadata
from typing import Optional, Callable, List, Tuple

from scitt_emulator.key_helper_dataclasses import VerificationKey


ENTRYPOINT_KEY_TRANSFORMS_TO_OBJECT = "scitt_emulator.key_helpers.verification_key_to_object"


def verification_key_to_object(
    verification_key: VerificationKey,
    *,
    key_transforms: Optional[List[Callable[[VerificationKey], dict]]] = None,
) -> bool:
    """
    Resolve keys for statement issuer and verify signature on COSESign1
    statement and embedded CWT
    """
    if key_transforms is None:
        key_transforms = []
        # There is some difference in the return value of entry_points across
        # Python versions/envs (conda vs. non-conda). Python 3.8 returns a dict.
        entrypoints = importlib.metadata.entry_points()
        if isinstance(entrypoints, dict):
            for entrypoint in entrypoints.get(ENTRYPOINT_KEY_TRANSFORMS_TO_OBJECT, []):
                key_transforms.append(entrypoint.load())
        elif isinstance(entrypoints, getattr(importlib.metadata, "EntryPoints", list)):
            for entrypoint in entrypoints:
                if entrypoint.group == ENTRYPOINT_KEY_TRANSFORMS_TO_OBJECT:
                    key_transforms.append(entrypoint.load())
        else:
            raise TypeError(f"importlib.metadata.entry_points returned unknown type: {type(entrypoints)}: {entrypoints!r}")

    for key_transform in key_transforms:
        verification_key_as_object = key_transform(verification_key)
        # Skip keys that we couldn't derive COSE keys for
        if verification_key_as_object:
            return verification_key_as_object

    return None
