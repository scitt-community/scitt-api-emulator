# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from archivist.archivist import Archivist
from typing import Optional
from pathlib import Path
import json
import cbor2
#from cose.messages import CoseMessage
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

        # TODO: is there anything permanent? 
        # * Credentials? We refresh creds and conn each time.
        # * Feeds? Feed is claim-specific

        ###################
        # Every time set-up
        ###################

        # Grab credentials from the enviroment
        # TODO: we should support container storage and protected local file storage too
        # TODO: we shold support unauthenticated connections for public read calls
        # TODO: we should support pass-through JWT from the main client
        self.rkvst_network_fqdn = getenv("RKVST_SCITT_URL") or "https://app.rkvst.io"
        client_id = getenv("RKVST_SCITT_CLIENT_ID") or rkvst_mocks.mock_client_id
        client_secret = getenv("RKVST_SCITT_CLIENT_SECRET") or rkvst_mocks.mock_client_secret

        # Initialise RKVST session handler
        self.rkvst_connection = Archivist(
            self.rkvst_network_fqdn,
            (client_id, client_secret),
            max_time=300
        )

        # TODO: We can download the certificate from RKVST but do we actually need to?
        self.service_parameters = {
            "serviceId": "RKVST",
            "treeAlgorithm": self.tree_alg,
            "signatureAlgorithm": "ES256",
            "serviceCertificate": None,
        }

    def get_claim(self, entry_id: str):
        rkvst_claim= self.rkvst_connection.post(
            f"{self.rkvst_network_fqdn}/archivist/v1/notary/claims/events",
            {"transaction_id": entry_id},
        )
        #rkvst_claim=rkvst_mocks.mock_claim

        # TODO: This is just neat debug. Get the JSON form of the claim
        print(json.dumps(rkvst_claim))
        return base64.b64decode(rkvst_claim["claim"])

    def get_operation(self, operation_id: str):
        print(f'>>> Got Operation ID {operation_id}')

    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        # TODO: the emulator passes in the full countersigned thing but our interface
        # takes just the claim. Need to work out if this is the right place to strip
        # off the furniture or whether our receipt interface should change.
        # For the hackathon it's bodged to just pass the claim straight back in, and
        # we can work out how to do it properly during the event

        # TODO: There are a number of inconsistencies between RKVST Cose and client Cose encoding of these things:
        # * RKVST: CBORTag(18,                [b'\xa3\x01&\x03papplication/json\x19\x01\x87mapp.rkvst.com', {},                                                                       b'{"identity":"assets/71ae3f6e-6228-4e1b-9acb-7883d1b006ad/events/5b2bc2fc-929f-4858-964f-ff1d1ada6e5c"}',  b'\xd6\xfe\xb54<\xfd\xea\x11\xe0\xd5@)\xab\x9c_\x18\xa3n=\x85d\xf8\x01\xd1d\xd3z$c<\xa4\xc2W\xf0\xb0\x11\x8e\xa1o\xee[h\x80\xf7hMw\x8f|\xd0\\\x84x\xd6\xd5\x9f\xf1z\x1e\xe0o4\xa7L'])
        # * TBI:   ['CounterSignatureV2',      b'\xa3\x01&\x03papplication/json\x19\x01\x87mapp.rkvst.com',     b'\xa3jservice_ideRKVSThtree_algeRKVSTiissued_at\x1ad\x1e\x86"', b'', b'{"identity":"assets/71ae3f6e-6228-4e1b-9acb-7883d1b006ad/events/5b2bc2fc-929f-4858-964f-ff1d1ada6e5c"}', [b'\xd6\xfe\xb54<\xfd\xea\x11\xe0\xd5@)\xab\x9c_\x18\xa3n=\x85d\xf8\x01\xd1d\xd3z$c<\xa4\xc2W\xf0\xb0\x11\x8e\xa1o\xee[h\x80\xf7hMw\x8f|\xd0\\\x84x\xd6\xd5\x9f\xf1z\x1e\xe0o4\xa7L']]
        #
        # The important differences are: 
        #  * presence of a CBORTag outer envelope;
        #  * more entries in the countersign;
        #  * sigs are treated as a list in tbi, but a singleton in RKVST
        #
        # We beleive the RKVST implementation to be more correct so have left this here for compatibility until the emulator is fixed.
        [cstr, source, csissuer, phdr, payload, sig]=cbor2.loads(countersign_tbi)
        cose_contents=cbor2.loads(countersign_tbi)
        encoded_claim_str=countersign_tbi
        rkvst_claim_contents = [
            source,
            {},
            payload,
            sig[0],
        ]
        # TODO: b'\xd2' is a hack to get the CBORTag(18) onto the front
        rkvst_claim_cbor = b'\xd2' + cbor2.dumps(rkvst_claim_contents)
        encoded_claim = base64.b64encode(rkvst_claim_cbor)
        encoded_claim_str = str(encoded_claim)
        encoded_claim_str = encoded_claim_str[2:-1]
        
        rkvst_receipt = self.rkvst_connection.post(
            f"{self.rkvst_network_fqdn}/archivist/v1/notary/receipts",
            {"claim": encoded_claim_str},
        )
        #rkvst_receipt = rkvst_mocks.mock_receipt

        # TODO: This is just neat debug. Get the JSON form of the receipt
        receipt_file_path = f'{entry_id}.receipt.json'
        with open(receipt_file_path, "w") as receipt_file:
            json.dump(rkvst_receipt, receipt_file)
        print(f"RKVST receipt written to {receipt_file_path}")
        receipt_data = str(base64.b64decode(rkvst_receipt["receipt"]))
        application_receipt = receipt_data.split('{"application_parameters"')
        compact_json = '{"application_parameters"' + application_receipt[1][:-1]
        receipt_structure = json.loads(compact_json)
        print(json.dumps(receipt_structure, sort_keys=True, indent=2))

        # TODO: Make sure we return the right shape structure according to the superclass:
        # leaf_info = [internal_hash, internal_data]
        # receipt_contents = [signature, node_cert_der, proof, leaf_info]
        return base64.b64decode(rkvst_receipt["receipt"])

    def verify_receipt_contents(self, receipt_contents: list, countersign_tbi: bytes):
        [signature, node_cert_der, proof, leaf_info] = receipt_contents
        [internal_hash, internal_data] = leaf_info

        # Get RKVST to verify the receipts
        # TODO: later. Is this actiually needed since we have offline verification already

