# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from typing import Optional
from abc import ABC, abstractmethod
from pathlib import Path
import contextlib
import time
import json
import uuid

import cbor2
from pycose.messages import CoseMessage, Sign1Message
import pycose.headers

from scitt_emulator.create_statement import CWTClaims
from scitt_emulator.verify_statement import verify_statement

# temporary receipt header labels, see draft-birkholz-scitt-receipts
COSE_Headers_Service_Id = "service_id"
COSE_Headers_Tree_Alg = "tree_alg"
COSE_Headers_Issued_At = "issued_at"

# permissive insert policy
MOST_PERMISSIVE_INSERT_POLICY = "*"
DEFAULT_INSERT_POLICY = MOST_PERMISSIVE_INSERT_POLICY


class ClaimInvalidError(Exception):
    pass


class EntryNotFoundError(Exception):
    pass


class OperationNotFoundError(Exception):
    pass


class PolicyResultDecodeError(Exception):
    pass


class SCITTServiceEmulator(ABC):
    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        self.storage_path = storage_path
        self.service_parameters_path = service_parameters_path

        if storage_path is not None:
            self.operations_path = storage_path / "operations"
            self.operations_path.mkdir(exist_ok=True)

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

    def get_operation(self, operation_id: str) -> dict:
        operation_path = self.operations_path / f"{operation_id}.json"
        try:
            with open(operation_path, "r") as f:
                operation = json.load(f)
        except FileNotFoundError:
            raise EntryNotFoundError(f"Operation {operation_id} not found")
        
        if operation["status"] == "running":
            # Pretend that the service finishes the operation after
            # the client having checked the operation status once.
            operation = self._finish_operation(operation)
        return operation

    def get_entry(self, entry_id: str) -> dict:
        try:
            self.get_claim(entry_id)
        except EntryNotFoundError:
            raise
        # More metadata to follow in the future.
        return { "entryId": entry_id }

    def get_claim(self, entry_id: str) -> bytes:
        claim_path = self.storage_path / f"{entry_id}.cose"
        try:
            with open(claim_path, "rb") as f:
                claim = f.read()
        except FileNotFoundError:
            raise EntryNotFoundError(f"Entry {entry_id} not found")
        return claim

    def submit_claim(self, claim: bytes, long_running=True) -> dict:
        insert_policy = self.service_parameters.get("insertPolicy", DEFAULT_INSERT_POLICY)

        if long_running:
            return self._create_operation(claim)
        elif insert_policy != MOST_PERMISSIVE_INSERT_POLICY:
            raise NotImplementedError(
                f"non-* insertPolicy only works with long_running=True: {insert_policy!r}"
            )
        else:
            return self._create_entry(claim)

    def _create_entry(self, claim: bytes) -> dict:
        last_entry_path = self.storage_path / "last_entry_id.txt"
        if last_entry_path.exists():
            with open(last_entry_path, "r") as f:
                last_entry_id = int(f.read())
        else:
            last_entry_id = 0

        entry_id = str(last_entry_id + 1)

        self._create_receipt(claim, entry_id)

        last_entry_path.write_text(entry_id)

        claim_path = self.storage_path / f"{entry_id}.cose"
        claim_path.write_bytes(claim)

        print(f"A COSE signed Claim was written to:  {claim_path}")
    
        entry = {"entryId": entry_id}
        return entry
    
    def _create_operation(self, claim: bytes):
        operation_id = str(uuid.uuid4())
        operation_path = self.operations_path / f"{operation_id}.json"
        claim_path = self.operations_path / f"{operation_id}.cose"

        operation = {
            "operationId": operation_id,
            "status": "running"
        }

        with open(operation_path, "w") as f:
            json.dump(operation, f)
        
        with open(claim_path, "wb") as f:
            f.write(claim)
        
        print(f"Operation {operation_id} created")
        print(f"A COSE signed Claim was written to:  {claim_path}")

        return operation

    def _sync_policy_result(self, operation: dict):
        operation_id = operation["operationId"]
        policy_insert_path = self.operations_path / f"{operation_id}.policy.insert"
        policy_denied_path = self.operations_path / f"{operation_id}.policy.denied"
        policy_failed_path = self.operations_path / f"{operation_id}.policy.failed"
        insert_policy = self.service_parameters.get("insertPolicy", DEFAULT_INSERT_POLICY)

        policy_result = {"status": operation["status"]}

        if insert_policy == MOST_PERMISSIVE_INSERT_POLICY:
            policy_result["status"] = "succeeded"
        if policy_insert_path.exists():
            policy_result["status"] = "succeeded"
            policy_insert_path.unlink()
        if policy_failed_path.exists():
            policy_result["status"] = "failed"
            if policy_failed_path.stat().st_size != 0:
                try:
                    policy_result_error = json.loads(policy_failed_path.read_text())
                except Exception as error:
                    raise PolicyResultDecodeError(operation_id) from error
                policy_result["error"] = policy_result_error
            policy_failed_path.unlink()
        if policy_denied_path.exists():
            policy_result["status"] = "denied"
            if policy_denied_path.stat().st_size != 0:
                try:
                    policy_result_error = json.loads(policy_denied_path.read_text())
                except Exception as error:
                    raise PolicyResultDecodeError(operation_id) from error
                policy_result["error"] = policy_result_error
            policy_denied_path.unlink()

        return policy_result

    def _finish_operation(self, operation: dict):
        operation_id = operation["operationId"]
        operation_path = self.operations_path / f"{operation_id}.json"
        claim_src_path = self.operations_path / f"{operation_id}.cose"

        policy_result = self._sync_policy_result(operation)
        if policy_result["status"] == "running":
            return operation
        if policy_result["status"] != "succeeded":
            operation["status"] = "failed"
            if "error" in policy_result:
                operation["error"] = policy_result["error"]
            operation_path.unlink()
            claim_src_path.unlink()
            return operation

        claim = claim_src_path.read_bytes()
        entry = self._create_entry(claim)
        claim_src_path.unlink()

        operation["status"] = "succeeded"
        operation["entryId"] = entry["entryId"]

        with open(operation_path, "w") as f:
            json.dump(operation, f)

        return operation

    def _create_receipt(self, claim: bytes, entry_id: str):
        # Validate claim
        # Note: This emulator does not verify the claim signature and does not apply
        # registration policies.
        try:
            msg = Sign1Message.decode(claim, tag=True)
        except:
            raise ClaimInvalidError("Claim is not a valid COSE message")
        if not isinstance(msg, Sign1Message):
            raise ClaimInvalidError("Claim is not a COSE_Sign1 message")
        if pycose.headers.Algorithm not in msg.phdr:
            raise ClaimInvalidError("Claim does not have an algorithm header parameter")
        if pycose.headers.ContentType not in msg.phdr:
            raise ClaimInvalidError(
                "Claim does not have a content type header parameter"
            )
        if CWTClaims not in msg.phdr:
            raise ClaimInvalidError("Claim does not have a CWTClaims header parameter")

        try:
            cwt_cose_key, _pycose_cose_key = verify_statement(msg)
        except Exception as e:
            raise ClaimInvalidError("Failed to verify signature on statement") from e
        if not cwt_cose_key:
            raise ClaimInvalidError("Failed to verify signature on statement")

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
