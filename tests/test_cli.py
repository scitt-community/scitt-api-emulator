# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
import json
import threading
import pytest
import jwt
import jwcrypto
from flask import Flask, jsonify
from werkzeug.serving import make_server
from scitt_emulator import cli, server
from scitt_emulator.oidc import OIDCAuthMiddleware

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


def create_flask_app_oidc_server(config):
    app = Flask("oidc_server")

    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def openid_configuration():
        return jsonify(
            {
                "issuer": app.url,
                "jwks_uri": f"{app.url}/.well-known/jwks",
                "response_types_supported": ["id_token"],
                "claims_supported": ["sub", "aud", "exp", "iat", "iss"],
                "id_token_signing_alg_values_supported": app.config["algorithms"],
                "scopes_supported": ["openid"],
            }
        )

    @app.route("/.well-known/jwks", methods=["GET"])
    def jwks():
        return jsonify(
            {
                "keys": [
                    {
                        **app.config["key"].export_public(as_dict=True),
                        "use": "sig",
                        "kid": app.config["key"].thumbprint(),
                    }
                ]
            }
        )

    return app


def test_client_cli_token(tmp_path):
    workspace_path = tmp_path / "workspace"

    claim_path = tmp_path / "claim.cose"
    receipt_path = tmp_path / "claim.receipt.cbor"
    entry_id_path = tmp_path / "claim.entry_id.txt"
    retrieved_claim_path = tmp_path / "claim.retrieved.cose"

    key = jwcrypto.jwk.JWK.generate(kty="RSA", size=2048)
    algorithm = "RS256"
    audience = "scitt.example.org"

    with Service(
        {"key": key, "algorithms": [algorithm]},
        create_flask_app=create_flask_app_oidc_server,
    ) as oidc_service:
        os.environ["no_proxy"] = ",".join(
            os.environ.get("no_proxy", "").split(",") + [oidc_service.host]
        )
        middleware_config_path = tmp_path / "oidc-middleware-config.json"
        middleware_config_path.write_text(
            json.dumps({"issuers": [oidc_service.url], "audience": audience})
        )
        with Service(
            {
                "middleware": OIDCAuthMiddleware,
                "middleware_config_path": middleware_config_path,
                "tree_alg": "CCF",
                "workspace": workspace_path,
                "error_rate": 0.1,
                "use_lro": False,
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

            # submit claim without token
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
                service.url,
            ]
            check_error = None
            try:
                execute_cli(command)
            except Exception as error:
                check_error = error
            assert check_error
            assert not os.path.exists(receipt_path)
            assert not os.path.exists(entry_id_path)

            # create token
            token = jwt.encode(
                {"iss": oidc_service.url, "aud": audience},
                key.export_to_pem(private_key=True, password=None),
                algorithm=algorithm,
                headers={"kid": key.thumbprint()},
            )
            # submit claim with token
            command += [
                "--token",
                token,
            ]
            execute_cli(command)
            assert os.path.exists(receipt_path)
            assert os.path.exists(entry_id_path)
