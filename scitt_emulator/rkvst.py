# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from archivist.archivist import Archivist
from typing import Optional
from pathlib import Path
import json
from os import getenv


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

        # TODO is there anything permanent? We get the persistent creds from the environment.

        ###################
        # Every time set-up
        ###################

        # Grab credentials from the enviroment
        # TODO: we should support container storage and protected local file storage too
        # TODO: we shold support unauthenticated connections for public read calls
        client_id = getenv("RKVST_SCITT_CLIENT_ID")
        client_secret = getenv("RKVST_SCITT_CLIENT_SECRET")

        # Initialise RKVST session handler
        self.rkvst_connection = Archivist(
            "https://app.rkvst.io",
            (client_id, client_secret),
            max_time=300
        )

    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        # TODO: We don't have the receipt API yet so just make any call to RKVST
        #       and make sure it works consistently. Set RKVST_SCITT_ASSET_ID to
        #       the asset identity of any 'document' profile asset that is readable
        #       by the app registration you're using
        asset_id = getenv("RKVST_SCITT_ASSET_ID")
        test = self.rkvst_connection.assets.read(asset_id)

        # TODO: Make sure we return the right shape structure according to the superclass:
        #     leaf_info = [internal_hash, internal_data]
        #     receipt_contents = [signature, node_cert_der, proof, leaf_info]

        leaf_info = [
            test['attributes']['document_hash_value'],
            test['attributes']['arc_description']
        ]
        receipt_contents = [
            "deadbeef",
            "deadbeef",
            "deadbeef",
            leaf_info
        ]

        return receipt_contents

    def verify_receipt_contents(self, receipt_contents: list, countersign_tbi: bytes):
        [signature, node_cert_der, proof, leaf_info] = receipt_contents
        [internal_hash, internal_data] = leaf_info

        # Get RKVST to verify the receipts
        # TODO: we don't have the receipt API yet so just verify the Asset record
        #       and make sure it works consistently. Set RKVST_SCITT_ASSE_IDE to
        #       the asset identity of any 'document' profile asset that is readable
        #       by the app registration you're using
        asset_id = getenv("RKVST_SCITT_ASSET_ID")
        test = self.rkvst_connection.assets.read(asset_id)
        
        if inernalhash != test['attributes']['document_hash_value']:
            print(f"InternalHash error: ${inernalhash} is not ${test['attributes']['image_hash_sha256']}")
            raise Exception(
                "Receipt hash doesn't match Asset hash"
            )

        if internal_data != test['attributes']['arc_description']:
            print(f"InternalData error: ${internal_data} is not ${test['attributes']['arc_description']}")
            raise Exception(
                "Receipt data doesn't match Asset description"
            )

