# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import os
import io
import json
import types
import socket
import pathlib
import asyncio
import aiohttp
import functools
import threading
import traceback
import contextlib
import unittest.mock
import multiprocessing
import pytest
import jwt
import jwcrypto

from quart import Quart, jsonify, send_file
import hypercorn.config

import bovine.utils
from scitt_emulator import cli, server
from scitt_emulator.oidc import OIDCAuthMiddleware

import logging

logger = logging.getLogger(__name__)

content_type = "application/json"
payload = '{"foo": "bar"}'
subject = "repo:scitt-community/scitt-api-emulator:ref:refs/heads/main"

old_socket_getaddrinfo = socket.getaddrinfo
old_create_sockets = hypercorn.config.Config.create_sockets
old_webfinger_response_json = bovine.utils.webfinger_response_json


def load_services_from_services_path(services, host):
    if isinstance(services, (str, pathlib.Path)):
        services_path = pathlib.Path(services)
        if not services_path.exists():
            raise socket.gaierror(f"{host} has not bound yet")
        services_content = services_path.read_text()
        services_dict = json.loads(services_content)
        services = {
            handle_name: types.SimpleNamespace(**service_dict)
            for handle_name, service_dict in services_dict.items()
        }
        print("services:", services)
    return services


def socket_getaddrinfo_map_service_ports(services, host, *args, **kwargs):
    # Map f"scitt.{handle_name}.example.com" to various local ports
    if "scitt." not in host:
        return old_socket_getaddrinfo(host, *args, **kwargs)
    _, handle_name, _, _ = host.split(".")
    services = load_services_from_services_path(services, host)
    if handle_name not in services:
        raise socket.gaierror(f"{host} has not bound yet")
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("127.0.0.1", services[handle_name].port),
        )
    ]


# TODO Remvoe, no need to mock if we set set scheme in domain on store.register
def http_webfinger_response_json(*args, **kwargs):
    webfinger_response_json = old_webfinger_response_json(*args, **kwargs)
    return webfinger_response_json
    # webfinger_response_json["links"][0]["href"] = webfinger_response_json["links"][0]["href"].replace("https://", "http://")


def make_MockClientRequest(services):
    class MockClientRequest(aiohttp.ClientRequest):
        def __init__(self, method, url, *args, **kwargs):
            nonlocal services
            if "scitt." in url.host:
                # uri = urllib.parse.urlparse(url)
                # host = uri.hostname
                host = url.host
                _, handle_name, _, _ = host.split(".")
                services = load_services_from_services_path(services, host)
                if handle_name not in services:
                    raise socket.gaierror(f"{host} has not bound yet")
                url = url.with_host("127.0.0.1")
                url = url.with_port(services[handle_name].port)
                kwargs.setdefault("headers", {})
                kwargs["headers"]["Host"] = f"http://{host}"
            super().__init__(method, url, *args, **kwargs)
            print("Is SSL?", self.is_ssl())
    return MockClientRequest

def execute_cli(argv):
    return cli.main([str(v) for v in argv])


class Service:
    def __init__(self, config, create_flask_app=None, services=None):
        self.config = config
        self.create_flask_app = (
            create_flask_app
            if create_flask_app is not None
            else server.create_flask_app
        )
        self.services = services

    def __enter__(self):
        self.app = self.create_flask_app(self.config)
        if hasattr(self.app, "service_parameters_path"):
            self.service_parameters_path = self.app.service_parameters_path
        self.host = "127.0.0.1"
        addr_queue = multiprocessing.Queue()
        self.process = multiprocessing.Process(name="server", target=self.server_process,
                                              args=(self.app, addr_queue,
                                                    self.services))
        self.process.start()
        self.host = addr_queue.get(True)
        self.port = addr_queue.get(True)
        self.url = f"http://{self.host}:{self.port}"
        self.app.url = self.url
        return self

    def __exit__(self, *args):
        self.process.terminate()
        self.process.join()

    @staticmethod
    def server_process(app, addr_queue, services):
        # os.environ["BUTCHER_ALLOW_HTTP"] = "1"
        try:
            with contextlib.ExitStack() as exit_stack:
                MockClientRequest = make_MockClientRequest(services)
                exit_stack.enter_context(
                    unittest.mock.patch(
                        "aiohttp.ClientRequest",
                        side_effect=MockClientRequest,
                    )
                )
                class MockConfig(hypercorn.config.Config):
                    def create_sockets(self, *args, **kwargs):
                        sockets = old_create_sockets(self, *args, **kwargs)
                        server_name, server_port = sockets.insecure_sockets[0].getsockname()
                        addr_queue.put(server_name)
                        addr_queue.put(server_port)
                        app.host = server_name
                        app.port = server_port
                        app.url = f"http://{app.host}:{app.port}"
                        # Ensure that connect calls to them resolve as we want
                        exit_stack.enter_context(
                            unittest.mock.patch(
                                "socket.getaddrinfo",
                                wraps=functools.partial(
                                    socket_getaddrinfo_map_service_ports,
                                    services,
                                )
                            )
                        )
                        return sockets

                exit_stack.enter_context(
                    unittest.mock.patch(
                        "quart.app.HyperConfig",
                        side_effect=MockConfig,
                    )
                )
                exit_stack.enter_context(
                    unittest.mock.patch(
                        "bovine.utils.webfinger_response_json",
                        wraps=http_webfinger_response_json,
                    )
                )
                exit_stack.enter_context(
                    unittest.mock.patch(
                        "bovine_herd.server.wellknown.webfinger_response_json",
                        wraps=http_webfinger_response_json,
                    )
                )
                app.run(port=0)
        except:
            # traceback.print_exc()
            pass

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
            "--subject",
            "test",
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
    app = Quart("oidc_server")

    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    # TODO For testing ssh key style issuers, not OIDC related needs to be moved
    @app.route("/", methods=["GET"])
    def ssh_public_keys():
        from cryptography.hazmat.primitives import serialization
        return send_file(
            io.BytesIO(
                serialization.load_pem_public_key(
                    app.config["key"].export_to_pem(),
                ).public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH,
                )
            ),
            mimetype="text/plain",
        )

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
            json.dumps(
                {
                    "issuers": [oidc_service.url],
                    "audience": audience,
                    "claim_schema": {
                        oidc_service.url: {
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "required": ["sub"],
                            "properties": {
                                "sub": {"type": "string", "enum": [subject]},
                            },
                        }
                    },
                }
            )
        )
        with Service(
            {
                "middleware": [OIDCAuthMiddleware],
                "middleware_config_path": [middleware_config_path],
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
                "--subject",
                "test",
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

            # create token without subject
            token = jwt.encode(
                {"iss": oidc_service.url, "aud": audience},
                key.export_to_pem(private_key=True, password=None),
                algorithm=algorithm,
                headers={"kid": key.thumbprint()},
            )
            # submit claim with token lacking subject
            command += [
                "--token",
                token,
            ]
            check_error = None
            try:
                execute_cli(command)
            except Exception as error:
                check_error = error
            assert check_error
            assert not os.path.exists(receipt_path)
            assert not os.path.exists(entry_id_path)

            # create token with subject
            token = jwt.encode(
                {"iss": oidc_service.url, "aud": audience, "sub": subject},
                key.export_to_pem(private_key=True, password=None),
                algorithm=algorithm,
                headers={"kid": key.thumbprint()},
            )
            # submit claim with token containing subject
            command[-1] = token
            execute_cli(command)
            assert os.path.exists(receipt_path)
            assert os.path.exists(entry_id_path)
