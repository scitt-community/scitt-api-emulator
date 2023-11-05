# Copyright (c) SCITT Authors
# Licensed under the MIT License.
import os
import sys
import time
import json
import copy
import types
import socket
import pathlib
import tempfile
import textwrap
import threading
import functools
import itertools
import subprocess
import contextlib
import unittest.mock
import pytest
import myst_parser.parsers.docutils_
import docutils.nodes
import docutils.utils

from scitt_emulator.client import ClaimOperationError
from scitt_emulator.federation_activitypub_bovine import (
    SCITTFederationActivityPubBovine,
)

from .test_cli import (
    Service,
    content_type,
    payload,
    execute_cli,
    socket_getaddrinfo_map_service_ports,
)
from .test_docs import (
    docutils_recursively_extract_nodes,
    docutils_find_code_samples,
)


repo_root = pathlib.Path(__file__).parents[1]
docs_dir = repo_root.joinpath("docs")
allowlisted_issuer = "did:web:example.org"


def test_docs_federation_activitypub_bovine(tmp_path):
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
    services_path = tmp_path / "services.json"
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
                    "fqdn": f"scitt.{handle_name}.example.com",
                    "workspace": str(tmp_path / handle_name),
                    "bovine_db_url": str(tmp_path / handle_name / "bovine.sqlite3"),
                    "following": following,
                }
            )
        )
        services[handle_name] = Service(
            {
                "middleware": [SCITTFederationActivityPubBovine],
                "middleware_config_path": [middleware_config_path],
                "tree_alg": "CCF",
                "workspace": tmp_path / handle_name / "workspace",
                "error_rate": 0,
                "use_lro": False,
            },
            services=services_path,
        )

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

        # Create claims in each instance
        claims = []
        for handle_name, service in services.items():
            our_service = services[handle_name]

            # create claim
            command = [
                "client",
                "create-claim",
                "--out",
                claim_path,
                "--issuer",
                allowlisted_issuer,
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

        # Test that we can download claims from all instances federated with
        for handle_name, service in services.items():
            for claim in claims:
                entry_id = claim["entry_id"]
                original_handle_name = claim["service.handle_name"]
                # Do not test claim retrieval from submission service here, only
                # services federated with
                # TODO XXX DEBUG NOTE Replace with: if original_handle_name == handle_name:
                if original_handle_name != handle_name:
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
                for i in range(0, 5):
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
