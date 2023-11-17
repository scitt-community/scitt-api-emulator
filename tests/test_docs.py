# Copyright (c) SCITT Authors
# Licensed under the MIT License.
import os
import sys
import time
import json
import copy
import types
import pathlib
import tempfile
import textwrap
import threading
import itertools
import subprocess
import contextlib
import urllib.parse
import unittest.mock

import pytest
import myst_parser.parsers.docutils_
import docutils.nodes
import docutils.utils

import jwcrypto

from scitt_emulator.client import ClaimOperationError

from .test_cli import (
    Service,
    content_type,
    payload,
    execute_cli,
    create_flask_app_oidc_server,
)


repo_root = pathlib.Path(__file__).parents[1]
docs_dir = repo_root.joinpath("docs")
non_allowlisted_issuer = "did:web:denied.example.com"
CLAIM_DENIED_ERROR = {"type": "denied", "detail": "content_address_of_reason"}
CLAIM_DENIED_ERROR_BLOCKED = {
    "type": "denied",
    "detail": textwrap.dedent(
        """
        'did:web:denied.example.com' is not one of ['did:web:example.org']

        Failed validating 'enum' in schema['properties']['issuer']:
            {'enum': ['did:web:example.org'], 'type': 'string'}

        On instance['issuer']:
            'did:web:denied.example.com'
        """
    ).lstrip(),
}


class SimpleFileBasedPolicyEngine:
    def __init__(self, config):
        self.config = config

    def __enter__(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            name="policy",
            target=self.poll_workspace,
            args=[self.config, self.stop_event],
        )
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        self.thread.join()

    @staticmethod
    def poll_workspace(config, stop_event):
        operations_path = pathlib.Path(config["storage_path"], "operations")
        command_jsonschema_validator = [
            sys.executable,
            str(config["jsonschema_validator"].resolve()),
        ]
        command_enforce_policy = [
            sys.executable,
            str(config["enforce_policy"].resolve()),
        ]

        running = True
        while running:
            for cose_path in operations_path.glob("*.cose"):
                denial = copy.deepcopy(CLAIM_DENIED_ERROR)
                with open(cose_path, "rb") as stdin_fileobj:
                    env = {
                        **os.environ,
                        "SCHEMA_PATH": str(config["schema_path"].resolve()),
                        "PYTHONPATH": ":".join(
                            os.environ.get("PYTHONPATH", "").split(":")
                            + [str(pathlib.Path(__file__).parents[1].resolve())]
                        ),
                    }
                    exit_code = 0
                    try:
                        subprocess.check_output(
                            command_jsonschema_validator,
                            stdin=stdin_fileobj,
                            stderr=subprocess.STDOUT,
                            env=env,
                        )
                    except subprocess.CalledProcessError as error:
                        denial["detail"] = error.output.decode()
                        exit_code = error.returncode
                # EXIT_FAILRUE from validator == MUST block
                with tempfile.TemporaryDirectory() as tempdir:
                    policy_reason_path = pathlib.Path(tempdir, "reason.json")
                    policy_reason_path.write_text(json.dumps(denial))
                    env = {
                        **os.environ,
                        "POLICY_REASON_PATH": str(policy_reason_path),
                        "POLICY_ACTION": {
                            0: "insert",
                        }.get(exit_code, "denied"),
                    }
                    command = command_enforce_policy + [cose_path]
                    exit_code = subprocess.call(command, env=env)
            time.sleep(0.1)
            running = not stop_event.is_set()

def docutils_recursively_extract_nodes(node, samples = None):
    if samples is None:
        samples = []
    if isinstance(node, list):
        node = types.SimpleNamespace(children=node)
    return samples + list(itertools.chain(*[
        [
            child,
            *docutils_recursively_extract_nodes(child),
        ]
        for child in node.children
        if hasattr(child, "children")
    ]))

def docutils_find_code_samples(nodes):
    samples = {}
    for i, node in enumerate(nodes):
        # Look ahead for next literal allow with code sample. Pattern is:
        #
        # **strong.suffix**
        #
        # ```language
        # content
        # ````
        # TODO Gracefully handle expections to index out of bounds
        if (
            isinstance(node, docutils.nodes.strong)
            and isinstance(nodes[i + 3], docutils.nodes.literal_block)
        ):
            samples[node.astext()] = nodes[i + 3].astext()
    return samples

def url_to_did_web(url_string):
    url = urllib.parse.urlparse(url_string)
    return ":".join(
        [
            urllib.parse.quote(i)
            for i in ["did", "web", url.netloc, *filter(bool, url.path.split("/"))]
        ]
    )

def test_docs_registration_policies(tmp_path):
    workspace_path = tmp_path / "workspace"

    claim_path = tmp_path / "claim.cose"
    receipt_path = tmp_path / "claim.receipt.cbor"
    entry_id_path = tmp_path / "claim.entry_id.txt"
    retrieved_claim_path = tmp_path / "claim.retrieved.cose"
    private_key_pem_path = tmp_path / "notary-private-key.pem"

    # Grab code samples from docs
    # TODO Abstract into abitrary docs testing code
    doc_path = docs_dir.joinpath("registration_policies.md")
    markdown_parser = myst_parser.parsers.docutils_.Parser()
    document = docutils.utils.new_document(str(doc_path.resolve()))
    parsed = markdown_parser.parse(doc_path.read_text(), document)
    nodes = docutils_recursively_extract_nodes(document)
    for name, content in docutils_find_code_samples(nodes).items():
        tmp_path.joinpath(name).write_text(content)

    key = jwcrypto.jwk.JWK.generate(kty="EC", crv="P-384")
    # cwt_cose_key = cwt.COSEKey.generate_symmetric_key(alg=alg, kid=kid)
    private_key_pem_path.write_bytes(
        key.export_to_pem(private_key=True, password=None),
    )
    algorithm = "ES384"
    audience = "scitt.example.org"
    subject = "repo:scitt-community/scitt-api-emulator:ref:refs/heads/main"

    # tell jsonschema_validator.py that we want to assume non-TLS URLs for tests
    os.environ["DID_WEB_ASSUME_SCHEME"] = "http"

    with Service(
        {"key": key, "algorithms": [algorithm]},
        create_flask_app=create_flask_app_oidc_server,
    ) as oidc_service, Service(
        {
            "tree_alg": "CCF",
            "workspace": workspace_path,
            "error_rate": 0.1,
            "use_lro": True,
        }
    ) as service, SimpleFileBasedPolicyEngine(
        {
            "storage_path": service.server.app.scitt_service.storage_path,
            "enforce_policy": tmp_path.joinpath("enforce_policy.py"),
            "jsonschema_validator": tmp_path.joinpath("jsonschema_validator.py"),
            "schema_path": tmp_path.joinpath("allowlist.schema.json"),
        }
    ) as policy_engine:
        # set the policy to enforce
        service.server.app.scitt_service.service_parameters["insertPolicy"] = "external"

        # set the issuer to the did:web version of the OIDC / SSH keys service
        issuer = url_to_did_web(oidc_service.url)

        # create claim
        command = [
            "client",
            "create-claim",
            "--out",
            claim_path,
            "--issuer",
            issuer,
            "--subject",
            subject,
            "--content-type",
            content_type,
            "--payload",
            payload,
            "--private-key-pem",
            private_key_pem_path,
        ]
        execute_cli(command)
        assert os.path.exists(claim_path)

        # replace example issuer with test OIDC service issuer (URL) in error
        claim_denied_error_blocked = CLAIM_DENIED_ERROR_BLOCKED
        claim_denied_error_blocked["detail"] = claim_denied_error_blocked["detail"].replace(
            "did:web:denied.example.com", issuer,
        )

        # submit denied claim
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
        check_error = None
        try:
            execute_cli(command)
        except ClaimOperationError as error:
            check_error = error
        assert check_error
        assert "error" in check_error.operation
        assert check_error.operation["error"] == claim_denied_error_blocked
        assert not os.path.exists(receipt_path)
        assert not os.path.exists(entry_id_path)

        # replace example issuer with test OIDC service issuer in allowlist
        allowlist_schema_json_path = tmp_path.joinpath("allowlist.schema.json")
        allowlist_schema_json_path.write_text(
            allowlist_schema_json_path.read_text().replace(
                "did:web:example.org", issuer,
            )
        )

        # submit accepted claim using SSH authorized_keys lookup
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
        receipt_path.unlink()
        assert os.path.exists(entry_id_path)
        receipt_path.unlink(entry_id_path)

        # TODO Switch back on the OIDC routes
        # submit accepted claim using OIDC -> jwks lookup
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
        receipt_path.unlink()
        assert os.path.exists(entry_id_path)
        receipt_path.unlink(entry_id_path)
