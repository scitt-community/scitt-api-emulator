# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Mapping
from scitt_emulator.scitt import SCITTServiceEmulator
from scitt_emulator.ccf import CCFSCITTServiceEmulator
from scitt_emulator.rkvst import RKVSTSCITTServiceEmulator

TREE_ALGS: Mapping[str, SCITTServiceEmulator] = {
    "CCF": CCFSCITTServiceEmulator,
    "RKVST": RKVSTSCITTServiceEmulator,
}
