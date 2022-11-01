# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path
from io import BytesIO

from flask import Flask, request, send_file, make_response

from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.scitt import EntryNotFoundError, ClaimInvalidError


def make_error(code: str, msg: str, status_code: int):
    return make_response(
        {
            "error": {
                "code": code,
                "message": msg,
            }
        },
        status_code,
    )


def create_flask_app(config):
    app = Flask(__name__)

    # See http://flask.pocoo.org/docs/latest/config/
    app.config.update(dict(DEBUG=True))
    app.config.update(config)

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

    @app.route("/entries/<string:entry_id>/receipt", methods=["GET"])
    def get_receipt(entry_id: str):
        try:
            receipt = app.scitt_service.get_receipt(entry_id)
        except EntryNotFoundError as e:
            return make_error("EntryNotFoundError", str(e), 404)
        return send_file(BytesIO(receipt), download_name=f"{entry_id}.receipt.cbor")

    @app.route("/entries/<string:entry_id>", methods=["GET"])
    def get_claim(entry_id: str):
        try:
            claim = app.scitt_service.get_claim(entry_id)
        except EntryNotFoundError as e:
            return make_error("EntryNotFoundError", str(e), 404)
        return send_file(BytesIO(claim), download_name=f"{entry_id}.cose")

    @app.route("/entries", methods=["POST"])
    def submit_claim():
        try:
            entry_id = app.scitt_service.submit_claim(request.get_data())
        except ClaimInvalidError as e:
            return make_error("ClaimInvalidError", str(e), 400)
        return make_response({"entry_id": entry_id})

    return app


def cli(fn):
    parser = fn()
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--tree-alg", required=True, choices=list(TREE_ALGS.keys()))
    parser.add_argument("--workspace", type=Path, default=Path("workspace"))

    def cmd(args):
        app = create_flask_app(
            {
                "tree_alg": args.tree_alg,
                "workspace": args.workspace,
            }
        )
        app.run(host="0.0.0.0", port=args.port)

    parser.set_defaults(func=cmd)

    return parser
