# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path
from io import BytesIO
import random

from flask import Flask, request, send_file, make_response, jsonify

from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.scitt import EntryNotFoundError, ClaimInvalidError, OperationNotFoundError


def make_error(code: str, msg: str, status_code: int):
    return make_response(
        {
            "type": f"urn:ietf:params:scitt:error:{code}",
            "detail": msg,
        },
        status_code,
    )


def make_unavailable_error():
    return make_error("serviceUnavailable", "Service unavailable, try again later", 503)


def create_flask_app(config):
    app = Flask(__name__)

    # See http://flask.pocoo.org/docs/latest/config/
    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    error_rate = app.config["error_rate"]
    use_lro = app.config["use_lro"]

    workspace_path = app.config["workspace"]
    storage_path = workspace_path / "storage"
    os.makedirs(storage_path, exist_ok=True)
    app.service_parameters_path = workspace_path / "service_parameters.json"

    clazz = TREE_ALGS[app.config["tree_alg"]]

    app.scitt_service = clazz(
        storage_path=storage_path, service_parameters_path=app.service_parameters_path
    )
    app.scitt_service.initialize_service()
    print(f"Service parameters: {app.service_parameters_path}")

    def is_unavailable():
        return random.random() <= error_rate

    @app.route("/service-parameters", methods=["GET"])
    def get_service_parameters():
        if is_unavailable():
            return make_unavailable_error()
        return jsonify(app.scitt_service.get_service_parameters())

    @app.route("/entries/<string:entry_id>/receipt", methods=["GET"])
    def get_receipt(entry_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            receipt = app.scitt_service.get_receipt(entry_id)
        except EntryNotFoundError as e:
            return make_error("entryNotFound", str(e), 404)
        return send_file(BytesIO(receipt), download_name=f"{entry_id}.receipt.cbor")

    @app.route("/entries/<string:entry_id>", methods=["GET"])
    def get_claim(entry_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            claim = app.scitt_service.get_claim(entry_id)
        except EntryNotFoundError as e:
            return make_error("entryNotFound", str(e), 404)
        return send_file(BytesIO(claim), download_name=f"{entry_id}.cose")

    @app.route("/entries", methods=["POST"])
    def submit_claim():
        if is_unavailable():
            return make_unavailable_error()
        try:
            if use_lro:
                result = app.scitt_service.submit_claim(request.get_data(), long_running=True)
                headers = {
                    "Location": f"{request.host_url}/operations/{result['operationId']}",
                    "Retry-After": "1"
                }
                status_code = 202
            else:
                result = app.scitt_service.submit_claim(request.get_data(), long_running=False)
                headers = {
                    "Location": f"{request.host_url}/entries/{result['entryId']}",
                }
                status_code = 201
        except ClaimInvalidError as e:
            return make_error("invalidInput", str(e), 400)
        return make_response(result, status_code, headers)

    @app.route("/operations/<string:operation_id>", methods=["GET"])
    def get_operation(operation_id: str):
        if is_unavailable():
            return make_unavailable_error()
        try:
            operation = app.scitt_service.get_operation(operation_id)
        except OperationNotFoundError as e:
            return make_error("operationNotFound", str(e), 404)
        headers = {}
        if operation["status"] == "running":
            headers["Retry-After"] = "1"
        return make_response(operation, 200, headers)

    return app


def cli(fn):
    parser = fn()
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--error-rate", type=float, default=0.01)
    parser.add_argument("--use-lro", action="store_true", help="Create operations for submissions")
    parser.add_argument("--tree-alg", required=True, choices=list(TREE_ALGS.keys()))
    parser.add_argument("--workspace", type=Path, default=Path("workspace"))

    def cmd(args):
        app = create_flask_app(
            {
                "tree_alg": args.tree_alg,
                "workspace": args.workspace,
                "error_rate": args.error_rate,
                "use_lro": args.use_lro
            }
        )
        app.run(host="0.0.0.0", port=args.port)

    parser.set_defaults(func=cmd)

    return parser
