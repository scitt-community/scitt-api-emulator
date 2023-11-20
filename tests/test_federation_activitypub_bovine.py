# Copyright (c) SCITT Authors
# Licensed under the MIT License.
import os
import sys
import time
import json
import copy
import types
import socket
import asyncio
import pathlib
import tempfile
import textwrap
import threading
import functools
import itertools
import subprocess
import contextlib
import unittest.mock

import aiohttp
import pytest
import tomllib
import myst_parser.parsers.docutils_
import docutils.nodes
import docutils.utils
import bovine

from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.signals import SCITTSignals
from scitt_emulator.client import ClaimOperationError
from scitt_emulator.federation_activitypub_bovine import (
    SCITTFederationActivityPubBovine,
)

from .test_cli import (
    Service,
    content_type,
    payload,
    subject,
    execute_cli,
    socket_getaddrinfo_map_service_ports,
    make_MockClientRequest,
)
from .test_docs import (
    docutils_recursively_extract_nodes,
    docutils_find_code_samples,
)


repo_root = pathlib.Path(__file__).parents[1]
docs_dir = repo_root.joinpath("docs")


@pytest.mark.parametrize('anyio_backend', ['asyncio'])
async def test_docs_federation_activitypub_bovine(anyio_backend, tmp_path):
    claim_path = tmp_path / "claim.cose"
    receipt_path = tmp_path / "claim.receipt.cbor"
    entry_id_path = tmp_path / "claim.entry_id.txt"
    retrieved_claim_path = tmp_path / "claim.retrieved.cose"

    # Grab code samples from docs
    # TODO Abstract into abitrary docs testing code
    doc_path = docs_dir.joinpath("registration_policies.md")
    markdown_parser = myst_parser.parsers.docutils_.Parser()
    document = docutils.utils.new_document(str(doc_path.resolve()))
    parsed = markdown_parser.parse(doc_path.read_text(), document)
    nodes = docutils_recursively_extract_nodes(document)
    for name, content in docutils_find_code_samples(nodes).items():
        tmp_path.joinpath(name).write_text(content)

    services = {}
    bovine_clients = {}
    services_path = tmp_path / "services.json"

    MockClientRequest = make_MockClientRequest(services_path)

    class TestSCITTFederationActivityPubBovine(SCITTFederationActivityPubBovine):
        async def make_client_session(self):
            nonlocal MockClientRequest
            return aiohttp.ClientSession(trust_env=True,
                                         request_class=MockClientRequest)

    for handle_name, following in {
        "bob": {
            "alice": {
                "actor_id": "alice@scitt.alice.example.com",
                "domain": "http://scitt.alice.example.com",
            },
        },
        "alice": {
            "bob": {
                "actor_id": "bob@scitt.bob.example.com",
                "domain": "http://scitt.bob.example.com",
            },
        },
    }.items():
        middleware_config_path = (
            tmp_path
            / handle_name
            / "federation-activitypub-bovine-middleware-config.json"
        )
        middleware_config_path.parent.mkdir()
        middleware_config_path.write_text(
            json.dumps(
                {
                    "handle_name": handle_name,
                    "fqdn": f"http://scitt.{handle_name}.example.com",
                    "workspace": str(tmp_path / handle_name),
                    "bovine_db_url": f"sqlite://{(tmp_path / handle_name / 'bovine.sqlite3').resolve()}",
                    "following": following,
                }
            )
        )

        # ensure service parameters include methods service can federate by
        workspace_path = tmp_path / handle_name / "workspace"
        storage_path = workspace_path / "storage"
        storage_path.mkdir(parents=True)
        service_parameters_path = workspace_path / "service_parameters.json"
        tree_alg = "CCF"
        TREE_ALGS[tree_alg](
            signals=SCITTSignals(),
            storage_path=storage_path,
            service_parameters_path=service_parameters_path,
        ).initialize_service()
        service_parameters = json.loads(service_parameters_path.read_text())
        # TODO Decide on how we offer extensions for more federation protocols
        # and declare which version is in use. We would need an extension doc
        # which describes the format of this blob and how to intrepret it
        # https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/issues/79#issuecomment-1797016940
        service_parameters["federation"] = [
            {
                "protocol": "https://github.com/w3c/activitypub",
                "version": "https://github.com/w3c/activitypub/commit/cda0c902317f194daeeb50b2df0225bca5b06f52",
                "activitypub": {
                    "actors": {
                        handle_name: {
                            # SCITT_ALL_SUBJECTS would be a special value
                            # We'd want to have extension docs explain more
                            "subjects": "SCITT_ALL_SUBJECTS",
                        }
                    }
                }
            }
        ]
        service_parameters_path.write_text(json.dumps(service_parameters))

        services[handle_name] = Service(
            {
                "middleware": [TestSCITTFederationActivityPubBovine],
                "middleware_config_path": [middleware_config_path],
                "tree_alg": "CCF",
                "workspace": workspace_path,
                "error_rate": 0,
                "use_lro": False,
            },
            services=services_path,
        )


    # TODO __aexit__
    async_exit_stack = await contextlib.AsyncExitStack().__aenter__()

    with contextlib.ExitStack() as exit_stack:
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
        # Start all the services
        for handle_name, service in services.items():
            services[handle_name] = exit_stack.enter_context(service)
            # Test of resolution
            assert (
                socket.getaddrinfo(f"scitt.{handle_name}.example.com", 0)[0][-1][-1]
                == services[handle_name].port
            )

        # Serialize services
        services_path.write_text(
            json.dumps(
                {
                    handle_name: {"port": service.port}
                    for handle_name, service in services.items()
                }
            )
        )
        exit_stack.enter_context(
            unittest.mock.patch(
                "aiohttp.client_reqrep.ClientRequest",
                side_effect=make_MockClientRequest(services),
            )
        )
        exit_stack.enter_context(
            unittest.mock.patch(
                "aiohttp.client.ClientRequest",
                side_effect=make_MockClientRequest(services),
            )
        )

        # Ensure we have a client for each service
        for handle_name, service in services.items():
            config_toml_path = tmp_path / handle_name / "config.toml"
            config_toml_obj = {}
            while not config_toml_path.exists() or len(config_toml_obj) == 0:
                await asyncio.sleep(0.1)
                if config_toml_path.exists():
                    config_toml_obj = tomllib.loads(config_toml_path.read_text())
            bovine_clients[handle_name] = await async_exit_stack.enter_async_context(
                bovine.BovineClient(**config_toml_obj[handle_name])
            )

        # Poll following endpoints until all services are following each other
        for handle_name, client in bovine_clients.items():
            count_accepts = 0
            while count_accepts != (len(bovine_clients) - 1):
                count_accepts = 0
                async for message in client.outbox():
                    if message["type"] == "Accept":
                        count_accepts += 1

        # Create claims in each instance
        claims = []
        for handle_name, service in services.items():
            # create claim
            command = [
                "client",
                "create-claim",
                "--out",
                claim_path,
                "--subject",
                subject,
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
                service.url,
            ]
            execute_cli(command)
            claim = claim_path.read_bytes()
            claim_path.unlink()
            assert os.path.exists(receipt_path)
            receipt_path.unlink()
            assert os.path.exists(entry_id_path)
            entry_id = entry_id_path.read_text()
            entry_id_path.unlink()

            claims.append(
                {
                    "entry_id": entry_id,
                    "claim": claim,
                    "service.handle_name": handle_name,
                }
            )

        # await asyncio.sleep(100)

        # Test that we can download claims from all instances federated with
        for handle_name, service in services.items():
            for claim in claims:
                entry_id = claim["entry_id"]
                original_handle_name = claim["service.handle_name"]
                # Do not test claim retrieval from submission service here, only
                # services federated with
                if original_handle_name == handle_name:
                    continue
                their_claim_path = claim_path.with_suffix(
                    f".federated.{original_handle_name}.to.{handle_name}"
                )
                command = [
                    "client",
                    "retrieve-claim",
                    "--entry-id",
                    entry_id,
                    "--out",
                    their_claim_path,
                    "--url",
                    service.url,
                ]
                # TODO Retry with backoff with cap
                # TODO Remove try except, fix federation
                error = None
                for i in range(0, 10):
                    try:
                        execute_cli(command)
                        break
                    except Exception as e:
                        if "urn:ietf:params:scitt:error:entryNotFound" in str(e):
                            error = e
                            time.sleep(1)
                        else:
                            raise
                if error:
                    raise error
                assert os.path.exists(their_claim_path)
                assert their_claim_path.read_bytes() == claim["claim"]
                their_claim_path.unlink()
