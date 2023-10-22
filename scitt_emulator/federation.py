import json
import dataclasses
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional

from scitt_emulator.signals import SCITTSignals


class SCITTFederation(ABC):
    def __init__(self, app, signals: SCITTSignals, config_path: Path):
        self.app = app
        self.signals = signals
        self.config = {}
        if config_path and config_path.exists():
            self.config = json.loads(config_path.read_text())

    @abstractmethod
    def initialize_service(self):
        raise NotImplementedError

    @abstractmethod
    def created_entry(
        self,
        treeAlgorithm: str,
        entry_id: str,
        receipt: bytes,
        claim: bytes,
        public_service_parameters: bytes,
    ):
        raise NotImplementedError
