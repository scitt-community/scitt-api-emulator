from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional


class SCITTFederation(ABC):
    def __init__(
        self,
        config_path: Path,
        service_parameters_path: Path,
        storage_path: Optional[Path] = None,
    ):
        self.config_path = config_path
        self.service_parameters_path = service_parameters_path
        self.storage_path = storage_path

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
