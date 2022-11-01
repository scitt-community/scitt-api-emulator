# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from typing import Optional
from abc import ABC, abstractmethod
from pathlib import Path
import time
import json

import cbor2
from cose.messages import CoseMessage, Sign1Message
import cose.headers
from cose.keys.ec2 import EC2Key
import cose.keys.curves

# temporary claim header labels, see draft-birkholz-scitt-architecture
COSE_Headers_Issuer = 391

# temporary receipt header labels, see draft-birkholz-scitt-receipts
COSE_Headers_Service_Id = "service_id"
COSE_Headers_Tree_Alg = "tree_alg"
COSE_Headers_Issued_At = "issued_at"


class ClaimInvalidError(Exception):
    pass


class EntryNotFoundError(Exception):
    pass


class SCITTServiceEmulator(ABC):
    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        self.storage_path = storage_path
        self.service_parameters_path = service_parameters_path

        if self.service_parameters_path.exists():
            with open(self.service_parameters_path) as f:
                self.service_parameters = json.load(f)

    @abstractmethod
    def initialize_service(self):
        raise NotImplementedError

    @abstractmethod
    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        raise NotImplementedError

    @abstractmethod
    def verify_receipt_contents(receipt_contents: list, countersign_tbi: bytes):
        raise NotImplementedError

    def get_claim(self, entry_id: str) -> bytes:
        claim_path = self.storage_path / f"{entry_id}.cose"
        try:
            with open(claim_path, "rb") as f:
                claim = f.read()
        except FileNotFoundError:
            raise EntryNotFoundError(f"Entry {entry_id} not found")
        return claim

    def submit_claim(self, claim: bytes):
        last_entry_path = self.storage_path / "last_entry_id.txt"
        if last_entry_path.exists():
            with open(last_entry_path, "r") as f:
                last_entry_id = int(f.read())
        else:
            last_entry_id = 0

        entry_id = last_entry_id + 1

        self._create_receipt(claim, entry_id)

        claim_path = self.storage_path / f"{entry_id}.cose"
        with open(claim_path, "wb") as f:
            f.write(claim)
        print(f"Claim written to {claim_path}")

        with open(last_entry_path, "w") as f:
            f.write(str(entry_id))

        return entry_id

    def _create_receipt(self, claim: Path, entry_id: str):
        # Validate claim
        # Note: This emulator does not verify the claim signature and does not apply
        # registration policies.
        try:
            msg = CoseMessage.decode(claim)
        except:
            raise ClaimInvalidError("Claim is not a valid COSE message")
        if not isinstance(msg, Sign1Message):
            raise ClaimInvalidError("Claim is not a COSE_Sign1 message")
        if cose.headers.Algorithm not in msg.phdr:
            raise ClaimInvalidError("Claim does not have an algorithm header parameter")
        if cose.headers.ContentType not in msg.phdr:
            raise ClaimInvalidError(
                "Claim does not have a content type header parameter"
            )
        if COSE_Headers_Issuer not in msg.phdr:
            raise ClaimInvalidError("Claim does not have an issuer header parameter")
        if not isinstance(msg.phdr[COSE_Headers_Issuer], str):
            raise ClaimInvalidError("Claim issuer is not a string")

        # Extract fields of COSE_Sign1 for countersigning
        outer = cbor2.loads(claim)
        [phdr, uhdr, payload, sig] = outer.value

        # Create countersigner protected header
        sign_protected = cbor2.dumps(
            {
                COSE_Headers_Service_Id: self.service_parameters["serviceId"],
                COSE_Headers_Tree_Alg: self.service_parameters["treeAlgorithm"],
                COSE_Headers_Issued_At: int(time.time()),
            }
        )

        # Compute countersign to-be-included
        countersign_tbi = create_countersign_to_be_included(
            phdr, sign_protected, payload, sig
        )

        # Tree algorithm receipt contents
        receipt_contents = self.create_receipt_contents(countersign_tbi, entry_id)

        # Create receipt
        receipt = cbor2.dumps([sign_protected, receipt_contents])

        # Store receipt
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        with open(receipt_path, "wb") as f:
            f.write(receipt)
        print(f"Receipt written to {receipt_path}")

    def get_receipt(self, entry_id: str):
        receipt_path = self.storage_path / f"{entry_id}.receipt.cbor"
        try:
            with open(receipt_path, "rb") as f:
                receipt = f.read()
        except FileNotFoundError:
            raise EntryNotFoundError(f"Entry {entry_id} not found")
        return receipt

    def verify_receipt(self, cose_path: Path, receipt_path: Path):
        with open(cose_path, "rb") as f:
            envelope = f.read()

        outer = cbor2.loads(envelope)
        assert outer.tag == Sign1Message.cbor_tag
        [phdr, uhdr, payload, sig] = outer.value

        with open(receipt_path, "rb") as f:
            receipt = cbor2.loads(f.read())

        [sign_protected, receipt_contents] = receipt

        countersign_tbi = create_countersign_to_be_included(
            phdr, sign_protected, payload, sig
        )

        sign_protected_decoded = cbor2.loads(sign_protected)
        tree_alg = sign_protected_decoded[COSE_Headers_Tree_Alg]
        assert tree_alg == self.tree_alg

        self.verify_receipt_contents(receipt_contents, countersign_tbi)


def create_claim(claim_path: Path, issuer: str, content_type: str, payload: str):
    # Create COSE_Sign1 structure
    protected = {
        cose.headers.Algorithm: "ES256",
        cose.headers.ContentType: content_type,
        COSE_Headers_Issuer: issuer,
    }
    msg = Sign1Message(phdr=protected, payload=payload.encode("utf-8"))

    # Create an ad-hoc key
    # Note: The emulator does not validate signatures, hence the short-cut.
    key = EC2Key.generate_key(cose.keys.curves.P256)

    # Sign
    msg.key = key
    claim = msg.encode(tag=True)

    with open(claim_path, "wb") as f:
        f.write(claim)
    print(f"Claim written to {claim_path}")


def create_countersign_to_be_included(
    body_protected, sign_protected, payload, signature
):
    context = "CounterSignatureV2"
    countersign_structure = [
        context,
        body_protected,
        sign_protected,
        b"",  # no external AAD
        payload,
        [signature],
    ]
    to_be_signed = cbor2.dumps(countersign_structure)
    return to_be_signed
