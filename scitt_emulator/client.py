# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Optional
from pathlib import Path
import json
import time

import httpx

from scitt_emulator import create_statement
from scitt_emulator.tree_algs import TREE_ALGS

DEFAULT_URL = "http://127.0.0.1:8000"
CONNECT_RETRIES = 3
HTTP_RETRIES = 3
HTTP_DEFAULT_RETRY_DELAY = 1


class ClaimOperationError(Exception):
    def __init__(self, operation):
        self.operation = operation

    def __str__(self):
        error_type = self.operation.get("error", {}).get(
            "type", "error.type not present",
        )
        error_detail = self.operation.get("error", {}).get(
            "detail", "error.detail not present",
        )
        return f"Operation error {error_type}: {error_detail}"


def raise_for_status(response: httpx.Response):
    if response.is_success:
        return
    raise RuntimeError(f"HTTP error {response.status_code}: {response.text}")


def raise_for_operation_status(operation: dict):
    if operation["status"] != "failed":
        return
    raise ClaimOperationError(operation)


class HttpClient:
    def __init__(self, bearer_token: Optional[str] = None, cacert: Optional[Path] = None):
        headers = {}
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"
        verify = True if cacert is None else str(cacert)
        transport = httpx.HTTPTransport(retries=CONNECT_RETRIES, verify=verify)
        self.client = httpx.Client(transport=transport, headers=headers)

    def _request(self, *args, **kwargs):
        response = self.client.request(*args, **kwargs)
        retries = HTTP_RETRIES
        while retries >= 0 and response.status_code == 503:
            retries -= 1
            retry_after = int(
                response.headers.get("retry-after", HTTP_DEFAULT_RETRY_DELAY)
            )
            time.sleep(retry_after)
            response = self.client.request(*args, **kwargs)
        raise_for_status(response)
        return response

    def get(self, *args, **kwargs):
        return self._request("GET", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._request("POST", *args, **kwargs)


def submit_claim(
    url: str,
    claim_path: Path,
    receipt_path: Path,
    entry_id_path: Optional[Path],
    client: HttpClient,
):
    with open(claim_path, "rb") as f:
        claim = f.read()

    # Submit claim
    response = client.post(f"{url}/entries", content=claim, headers={
        "Content-Type": "application/cose"})

    post_response=response.json()

    if response.status_code == 201:
        entry = response.json()
        entry_id = entry["entryId"]

    elif response.status_code == 202:
        operation = response.json()

        # Wait for registration to finish
        while operation["status"] != "succeeded":
            retry_after = int(
                response.headers.get("retry-after", HTTP_DEFAULT_RETRY_DELAY)
            )
            time.sleep(retry_after)
            response = client.get(f"{url}/operations/{operation['operationId']}")
            operation = response.json()
            raise_for_operation_status(operation)

        entry_id = operation["entryId"]

    else:
        raise RuntimeError(f"Unexpected status code: {response.status_code}")

    # Fetch receipt
    response = client.get(f"{url}/entries/{entry_id}/receipt", timeout=15)
    receipt = response.content

    print("Claim Registered:")
    print(f"  json:     {post_response}")
    print(f"  Entry ID: {entry_id}")

    # Save receipt to file
    with open(receipt_path, "wb") as f:
        f.write(receipt)

    print(f"  Receipt:  ./{receipt_path}")

    # Save entry ID to file
    if entry_id_path:
        with open(entry_id_path, "w") as f:
            f.write(str(entry_id))

        print(f"Entry ID written to {entry_id_path}")


def retrieve_claim(url: str, entry_id: Path, claim_path: Path, client: HttpClient):
    response = client.get(f"{url}/entries/{entry_id}")
    claim = response.content

    with open(claim_path, "wb") as f:
        f.write(claim)

    print(f"A COSE signed Claim was written to: {claim_path}")


def retrieve_receipt(url: str, entry_id: Path, receipt_path: Path, client: HttpClient):
    response = client.get(f"{url}/entries/{entry_id}/receipt")
    receipt = response.content

    with open(receipt_path, "wb") as f:
        f.write(receipt)

    print(f"Receipt written to {receipt_path}")


def verify_receipt(cose_path: Path, receipt_path: Path, service_parameters_path: Path):
    with open(service_parameters_path) as f:
        service_parameters = json.load(f)

    clazz = TREE_ALGS[service_parameters["treeAlgorithm"]]
    service = clazz(service_parameters_path=service_parameters_path)
    service.verify_receipt(cose_path, receipt_path)
    print("Receipt verified")


def cli(fn):
    parser = fn(description="Execute client commands")
    sub = parser.add_subparsers(dest="cmd", help="Command to execute", required=True)

    create_statement.cli(sub.add_parser)

    p = sub.add_parser(
        "submit-claim", description="Submit a SCITT claim and retrieve the receipt"
    )
    p.add_argument("--claim", required=True, type=Path)
    p.add_argument(
        "--out", required=True, type=Path, help="Path to write the receipt to"
    )
    p.add_argument(
        "--out-entry-id",
        required=False,
        type=Path,
        help="Path to write the entry id to",
    )
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: submit_claim(
            args.url, args.claim, args.out, args.out_entry_id,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("retrieve-claim", description="Retrieve a SCITT claim")
    p.add_argument("--entry-id", required=True, type=str)
    p.add_argument("--out", required=True, type=Path, help="Path to write the claim to")
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: retrieve_claim(
            args.url, args.entry_id, args.out,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("retrieve-receipt", description="Retrieve a SCITT receipt")
    p.add_argument("--entry-id", required=True, type=str)
    p.add_argument(
        "--out", required=True, type=Path, help="Path to write the receipt to"
    )
    p.add_argument("--url", required=False, default=DEFAULT_URL)
    p.add_argument("--token", help="Bearer token to authenticate with")
    p.add_argument("--cacert", type=Path, help="CA certificate to verify host against")
    p.set_defaults(
        func=lambda args: retrieve_receipt(
            args.url, args.entry_id, args.out,
            HttpClient(args.token, args.cacert)
        )
    )

    p = sub.add_parser("verify-receipt", description="Verify a SCITT receipt")
    p.add_argument("--claim", required=True, type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--service-parameters", required=True, type=Path)
    p.set_defaults(
        func=lambda args: verify_receipt(
            args.claim, args.receipt, args.service_parameters
        )
    )

    return parser
