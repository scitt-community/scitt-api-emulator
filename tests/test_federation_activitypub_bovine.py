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
)
from .test_docs import (
    docutils_recursively_extract_nodes,
    docutils_find_code_samples,
)


repo_root = pathlib.Path(__file__).parents[1]
docs_dir = repo_root.joinpath("docs")
allowlisted_issuer = "did:web:example.org"
non_allowlisted_issuer = "did:web:example.com"
CLAIM_DENIED_ERROR = {"type": "denied", "detail": "content_address_of_reason"}
CLAIM_DENIED_ERROR_BLOCKED = {
    "type": "denied",
    "detail": textwrap.dedent(
        """
        'did:web:example.com' is not one of ['did:web:example.org']

        Failed validating 'enum' in schema['properties']['issuer']:
            {'enum': ['did:web:example.org'], 'type': 'string'}

        On instance['issuer']:
            'did:web:example.com'
        """
    ).lstrip(),
}


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
    for handle_name, following in {
        "bob": {
            "alice": {
                "actor_id": "alice@scitt.alice.example.com",
            },
        },
        "alice": {
            "bob": {
                "actor_id": "bob@scitt.bob.example.com",
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
                "error_rate": 0.1,
                "use_lro": True,
            }
        )

    old_socket_getaddrinfo = socket.getaddrinfo

    def socket_getaddrinfo_map_service_ports(host, *args, **kwargs):
        # Map f"scitt.{handle_name}.example.com" to various local ports
        nonlocal services
        if "scitt" not in host:
            return old_socket_getaddrinfo(host, *args, **kwargs)
        _, handle_name, _, _ = host.split(".")
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", services[handle_name].server.port),
            )
        ]

    with contextlib.ExitStack() as exit_stack:
        # Ensure that connect calls to them resolve as we want
        exit_stack.enter_context(
            unittest.mock.patch(
                "socket.getaddrinfo",
                wraps=socket_getaddrinfo_map_service_ports,
            )
        )
        # Start all the services
        for handle_name, service in services.items():
            services[handle_name] = exit_stack.enter_context(service)
            # Test of resolution
            assert (
                socket.getaddrinfo(f"scitt.{handle_name}.example.com", 0)[0][-1][-1]
                == services[handle_name].server.port
            )
            print(handle_name, "@", services[handle_name].server.port)
        # Test that if we submit to one claims end up in the others
        for handle_name, service in services.items():
            our_service = services[handle_name]
            their_services = {
                filter_services_handle_name: their_service
                for filter_services_handle_name, their_service in services.items()
                if handle_name != filter_services_handle_name
            }

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
            claim_path.unlink()
            assert os.path.exists(receipt_path)
            receipt_path.unlink()
            assert os.path.exists(entry_id_path)

            # download claim from every other service
            for their_handle_name, their_service in their_services.items():
                their_claim = (
                    claim_path.with_suffix(f"federated.{their_handle_name}"),
                )
                command = [
                    "client",
                    "retrieve-claim",
                    "--entry-id",
                    entry_id_path.read_text(),
                    "--out",
                    their_claim,
                    "--url",
                    their_service.url,
                ]
                # TODO Retry with backoff with cap
                execute_cli(command)
                assert os.path.exists(their_claim)
                their_claim.unlink()

            entry_id_path.unlink()
