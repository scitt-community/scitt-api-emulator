# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
import threading
from werkzeug.serving import make_server
from scitt_emulator import cli, server

issuer = "did:web:example.com"
content_type = "application/json"
payload = '{"foo": "bar"}'


def execute_cli(argv):
    return cli.main([str(v) for v in argv])


class Service:
    def __init__(self, config):
        self.config = config

    def __enter__(self):
        app = server.create_flask_app(self.config)
        self.service_parameters_path = app.service_parameters_path
        self.server = make_server("127.0.0.1", 8000, app)
        self.thread = threading.Thread(name="server", target=self.server.serve_forever)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join()


def test_client_cli(tmp_path):
    workspace_path = tmp_path / "workspace"

    claim_path = tmp_path / "claim.cose"
    receipt_path = tmp_path / "claim.receipt.cbor"
    entry_id_path = tmp_path / "claim.entry_id.txt"
    retrieved_claim_path = tmp_path / "claim.retrieved.cose"

    with Service(
        {
            "tree_alg": "CCF",
            "workspace": workspace_path,
            "error_rate": 0.1
        }
    ) as service:
        # create claim
        command = [
            "client",
            "create-claim",
            "--out",
            claim_path,
            "--issuer",
            issuer,
            "--content-type",
            content_type,
            "--payload",
            payload,
        ]
        execute_cli(command)
        assert os.path.exists(claim_path)

        # submit claim
        command = [
            "client",
            "submit-claim",
            "--claim",
            claim_path,
            "--out",
            receipt_path,
            "--out-entry-id",
            entry_id_path,
        ]
        execute_cli(command)
        assert os.path.exists(receipt_path)
        assert os.path.exists(entry_id_path)

        # verify receipt
        command = [
            "client",
            "verify-receipt",
            "--claim",
            claim_path,
            "--receipt",
            receipt_path,
            "--service-parameters",
            service.service_parameters_path,
        ]
        execute_cli(command)

        # retrieve claim
        with open(entry_id_path) as f:
            entry_id = f.read()

        command = [
            "client",
            "retrieve-claim",
            "--entry-id",
            entry_id,
            "--out",
            retrieved_claim_path,
        ]
        execute_cli(command)
        assert os.path.exists(retrieved_claim_path)

        with open(claim_path, "rb") as f:
            original_claim = f.read()
        with open(retrieved_claim_path, "rb") as f:
            retrieved_claim = f.read()
        assert original_claim == retrieved_claim

        # retrieve receipt
        receipt_path_2 = tmp_path / "claim.receipt2.cbor"
        command = [
            "client",
            "retrieve-receipt",
            "--entry-id",
            entry_id,
            "--out",
            receipt_path_2,
        ]
        execute_cli(command)
        assert os.path.exists(receipt_path_2)

        with open(receipt_path, "rb") as f:
            receipt = f.read()
        with open(receipt_path_2, "rb") as f:
            receipt_2 = f.read()
        assert receipt == receipt_2
