from dataclasses import dataclass, field

import blinker


@dataclass
class SCITTSignalsFederationCreatedEntry:
    tree_alg: str
    entry_id: str
    receipt: bytes
    claim: bytes
    public_service_parameters: bytes


@dataclass
class SCITTSignalsFederation:
    _signal_namespace: blinker.Namespace = field(default_factory=blinker.Namespace)
    created_entry: blinker.Signal = field(init=False)
    submit_claim: blinker.Signal = field(init=False)

    def __post_init__(self):
        self.created_entry = self._signal_namespace.signal("create_entry")
        self.submit_claim = self._signal_namespace.signal("submit_claim")


@dataclass
class SCITTSignals:
    federation: SCITTSignalsFederation = field(default_factory=SCITTSignalsFederation)
