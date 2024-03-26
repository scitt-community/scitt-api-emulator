# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from archivist.archivist import Archivist
from typing import Optional
from pathlib import Path
import json
from pycose.messages import Sign1Message
import pycose.headers
import base64
from os import getenv
from . import rkvst_mocks

from scitt_emulator.scitt import SCITTServiceEmulator

class RKVSTSCITTServiceEmulator(SCITTServiceEmulator):
    tree_alg = "RKVST"

    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        super().__init__(service_parameters_path, storage_path)
        if storage_path is not None:
            self._service_private_key_path = (
                self.storage_path / "service_private_key.pem"
            )


    def initialize_service(self):
        #########################
        # One time initial set-up
        #########################

        # No permanent state to manage as yet

        ###################
        # Every time set-up
        ###################

        # Grab credentials from the environment
        # TODO: we should support unauthenticated connections for public read calls
        self.rkvst_network_fqdn = getenv("RKVST_SCITT_URL") or "https://app.rkvst.io"
        client_id = getenv("RKVST_SCITT_CLIENT_ID") or rkvst_mocks.mock_client_id
        client_secret = getenv("RKVST_SCITT_CLIENT_SECRET") or rkvst_mocks.mock_client_secret

        # Initialise RKVST session handler
        self.rkvst_connection = Archivist(
            self.rkvst_network_fqdn,
            (client_id, client_secret),
            max_time=300
        )

        # TODO: Download the countersign certificate from RKVST if/when verify is supported in the tool
        self.service_parameters = {
            "serviceId": "RKVST",
            "treeAlgorithm": self.tree_alg,
            "signatureAlgorithm": "ES256",
            "serviceCertificate": None,
        }

    def keys_as_jwks(self):
        return []

    def _event_id_to_operation_id(self, event_id: str):
        return event_id.replace('/', '_')

    def _operation_id_to_event_id(self, operation_id: str):
        return operation_id.replace('_', '/')

    def _feed_id_to_asset_id(self, feed_id: str):
        # TODO: Work out this mapping (explicit Feeds to be added in a future PR)
        return feed_id

    def _asset_id_to_feed_id(self, asset_id: str):
        # TODO: Work out this mapping (explicit Feeds to be added in a future PR)
        return asset_id

    def _claim_to_attrs(self, claim: bytes):
        cose_msg = Sign1Message.decode(claim)
        encoded_claim = base64.b64encode(claim)
        string_claim = encoded_claim.decode("UTF-8")
        attrs = {
            "arc_display_type": "SCITT Attestation",
            "scitt_claim_b64": string_claim
        }

        # If the claim payload has an understood type then pull out the bits for indexing
        if pycose.headers.ContentType in cose_msg.phdr and cose_msg.phdr[pycose.headers.ContentType] == 'application/json':
            # Try loading the payload as a JSON structure
            payload_str = cose_msg.payload.decode("utf-8")
            json_elements = json.loads(payload_str)
            # TODO: Make sure RKVST reserved elements aren't overwritten
            for k in json_elements.keys():
                if type(k) == str and type(json_elements[k]) == str:
                    attrs[k] = json_elements[k]

        return attrs

    def _submit_claim_sync(self, claim: bytes):
        raise NotImplementedError

    def _submit_claim_async(self, claim: bytes):
        # TODO: explicit Feed handling to be added in a future PR
        feed_id = rkvst_mocks.mock_feed_id
        asset_id = self._feed_id_to_asset_id(feed_id)
        asset_id = 'assets/a4be5d0c-02c4-4f67-b148-ceac5532e001'
        props = props = {
            "operation": "Record",
            "behaviour": "RecordEvidence",
        }
        attrs = self._claim_to_attrs(claim)
        asset_attrs = {}

        # Note: Confirm=True here only assures that the claim is accepted by the Transparency
        # Service. It does not wait for full commitment to the Merkle tree so this is still LRO
        event = self.rkvst_connection.events.create(asset_id, props, attrs, asset_attrs=asset_attrs, confirm=True)
        #event = rkvst_mocks.mock_event_lro_incomplete

        operation_id = self._event_id_to_operation_id(event["identity"])
        return {
            "operationId": operation_id,
            "status": "running"
        }

    def submit_claim(self, claim: bytes, long_running=True) -> dict:
        if long_running:
            return self._submit_claim_async(claim)
        else:
            return self._submit_claim_sync(claim)

    def get_claim(self, entry_id: str):
        # TODO: What should we do here? Our API currently takes a transaction ID and returns a magic
        # claim with the Event ID in, but I think that's wrong: we should take whatever the entryID
        # is deemed to be and return the claim from the Event attributes, countersigned by RKVST.
        # Big question here is how we deal with the submitted claim VS the transparent claim: the 
        # emulator isn't faithful to the spec here. TBD in a future PR
        rkvst_claim= self.rkvst_connection.post(
            f"{self.rkvst_network_fqdn}/archivist/v1/notary/claims/events",
            {"transaction_id": entry_id},
        )
        #rkvst_claim=rkvst_mocks.mock_claim

        return base64.b64decode(rkvst_claim["claim"])

    def get_operation(self, operation_id: str):
        # Operation IDs in our implementation are RKVST Event IDs so all we need to do
        # is fetch the Event record and see if it has a TxID yet. If it does, we're
        # ready. If not, it's still waiting for commitment to the tree
        event_id = self._operation_id_to_event_id(operation_id)
        event = self.rkvst_connection.events.read(event_id)
        #event = rkvst_mocks.mock_event_lro_complete

        if event['transaction_id']:
            return {
                "operationId": operation_id,
                "status": "succeeded",
                "entryId": event['transaction_id']
            }
        else:
            return {
                "operationId": operation_id,
                "status": "running"
            }

    def get_receipt(self, entry_id: str):
        # TODO: It looks like we got the interface wrong here: we don't need to get the claim
        # and submit it back in the body of the receipt call: we should be able to simply 
        # get the receipt direct from the entry ID (aka TransactionID).
        # For now we'll make the 2 round trips but this is probably unnecessarily wasteful
        rkvst_claim= self.rkvst_connection.post(
            f"{self.rkvst_network_fqdn}/archivist/v1/notary/claims/events",
            {"transaction_id": entry_id},
        )
        rkvst_receipt = self.rkvst_connection.post(
            f"{self.rkvst_network_fqdn}/archivist/v1/notary/receipts",
            {"claim": rkvst_claim["claim"]},
        )
        #rkvst_receipt = rkvst_mocks.mock_receipt

        # This is just neat debug. Get the JSON form of the receipt
        receipt_file_path = f'{entry_id}.receipt.json'
        with open(receipt_file_path, "w") as receipt_file:
            json.dump(rkvst_receipt, receipt_file)
        print(f"RKVST receipt written to {receipt_file_path}")
        receipt_data = str(base64.b64decode(rkvst_receipt["receipt"]))
        application_receipt = receipt_data.split('{"application_parameters"')
        compact_json = '{"application_parameters"' + application_receipt[1][:-1]
        receipt_structure = json.loads(compact_json)
        print(json.dumps(receipt_structure, sort_keys=True, indent=2))

        # Pull the receipt out of the JSON structure then B64 decode it
        return base64.b64decode(rkvst_receipt["receipt"])

    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        # This is required by the superclass signature but it's not necessary because
        # RKVST makes all the receipts in the back end
        raise NotImplementedError

    def verify_receipt_contents(self, receipt_contents: list, countersign_tbi: bytes):
        [signature, node_cert_der, proof, leaf_info] = receipt_contents
        [internal_hash, internal_data] = leaf_info

        # RKVST receipt verification is detailed at https://docs.rkvst.com
        # Although we could do a shallow verification of the receipt that could
        # be misleading, so return an error
        raise NotImplementedError('To verify RKVST receipts, visit: https://docs.rkvst.com')

