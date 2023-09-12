# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
import threading
import pytest
from werkzeug.serving import make_server
from scitt_emulator import cli, server

issuer = "did:web:example.com"
content_type = "application/json"
payload = '{"foo": "bar"}'


def execute_cli(argv):
    return cli.main([str(v) for v in argv])


class Service:
    def __init__(self, config, create_flask_app=None):
        self.config = config
        self.create_flask_app = (
            create_flask_app
            if create_flask_app is not None
            else server.create_flask_app
        )

    def __enter__(self):
        app = self.create_flask_app(self.config)
        if hasattr(app, "service_parameters_path"):
            self.service_parameters_path = app.service_parameters_path
        self.host = "127.0.0.1"
        self.server = make_server(self.host, 0, app)
        port = self.server.port
        self.url = f"http://{self.host}:{port}"
        app.url = self.url
        self.thread = threading.Thread(name="server", target=self.server.serve_forever)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join()

@pytest.mark.parametrize(
    "use_lro", [True, False],
)
def test_client_cli(use_lro: bool, tmp_path):
    workspace_path = tmp_path / "workspace"

    claim_path = tmp_path / "claim.cose"
    receipt_path = tmp_path / "claim.receipt.cbor"
    entry_id_path = tmp_path / "claim.entry_id.txt"
    retrieved_claim_path = tmp_path / "claim.retrieved.cose"

    with Service(
        {
            "tree_alg": "CCF",
            "workspace": workspace_path,
            "error_rate": 0.1,
            "use_lro": use_lro
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
            "--url",
            service.url
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
            "--url",
            service.url
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
            "--url",
            service.url
        ]
        execute_cli(command)
        assert os.path.exists(receipt_path_2)

        with open(receipt_path, "rb") as f:
            receipt = f.read()
        with open(receipt_path_2, "rb") as f:
            receipt_2 = f.read()
        assert receipt == receipt_2
