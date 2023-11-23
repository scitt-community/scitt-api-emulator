# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
from pathlib import Path
from io import BytesIO
import random
import logging

from quart import Quart, request, send_file, make_response
from blinker import Namespace

from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.plugin_helpers import entrypoint_style_load
from scitt_emulator.scitt import EntryNotFoundError, ClaimInvalidError, OperationNotFoundError
from scitt_emulator.signals import SCITTSignals
from scitt_emulator.signals import SCITTSignalsFederationCreatedEntry


async def make_error(code: str, msg: str, status_code: int):
    return await make_response(
        {
            "type": f"urn:ietf:params:scitt:error:{code}",
            "detail": msg,
        },
        status_code,
    )


async def make_unavailable_error():
    return await make_error("serviceUnavailable", "Service unavailable, try again later", 503)


def create_flask_app(config):
    app = Quart(__name__)

    # See http://flask.pocoo.org/docs/latest/config/
    app.config.update(dict(DEBUG=True))
    app.config.update(config)

    # See https://blinker.readthedocs.io/en/stable/#blinker.base.Signal.send
    app.signals = SCITTSignals(
        add_background_task=app.add_background_task,
    )

    for middleware, middleware_config_path in zip(app.config.get("middleware", []), app.config.get("middleware_config_path", [])):
        app.asgi_app = middleware(app, middleware_config_path)

    error_rate = app.config["error_rate"]
    use_lro = app.config["use_lro"]

    workspace_path = app.config["workspace"]
    storage_path = workspace_path / "storage"
    os.makedirs(storage_path, exist_ok=True)
    app.service_parameters_path = workspace_path / "service_parameters.json"

    clazz = TREE_ALGS[app.config["tree_alg"]]

    app.scitt_service = clazz(
        signals=app.signals,
        storage_path=storage_path,
        service_parameters_path=app.service_parameters_path,
    )
    app.scitt_service.initialize_service()
    print(f"Service parameters: {app.service_parameters_path}")

    def is_unavailable():
        return random.random() <= error_rate

    @app.route("/test", methods=["GET"])
    async def get_test():
        return await make_response({"OK": True}, 200, {})

    @app.route("/entries/<string:entry_id>/receipt", methods=["GET"])
    async def get_receipt(entry_id: str):
        if is_unavailable():
            return await make_unavailable_error()
        try:
            receipt = app.scitt_service.get_receipt(entry_id)
        except EntryNotFoundError as e:
            return await make_error("entryNotFound", str(e), 404)
        return await send_file(BytesIO(receipt), attachment_filename=f"{entry_id}.receipt.cbor")

    @app.route("/entries/<string:entry_id>", methods=["GET"])
    async def get_claim(entry_id: str):
        if is_unavailable():
            return await make_unavailable_error()
        try:
            claim = app.scitt_service.get_claim(entry_id)
        except EntryNotFoundError as e:
            return await make_error("entryNotFound", str(e), 404)
        return await send_file(BytesIO(claim), attachment_filename=f"{entry_id}.cose")

    @app.route("/entries", methods=["POST"])
    async def submit_claim():
        if is_unavailable():
            return await make_unavailable_error()
        try:
            # NOTE This got refactored to support content addressable claims
            result = await app.scitt_service.submit_claim(await request.get_data(), long_running=use_lro)
            if "operationId" in result:
                headers = {
                    "Location": f"{request.host_url}/operations/{result['operationId']}",
                    "Retry-After": "1"
                }
                status_code = 202
            else:
                headers = {
                    "Location": f"{request.host_url}/entries/{result['entryId']}",
                }
                status_code = 201
        except ClaimInvalidError as e:
            return await make_error("invalidInput", str(e), 400)
        return await make_response(result, status_code, headers)

    @app.route("/operations/<string:operation_id>", methods=["GET"])
    async def get_operation(operation_id: str):
        if is_unavailable():
            return await make_unavailable_error()
        try:
            operation = await app.scitt_service.get_operation(operation_id)
        except OperationNotFoundError as e:
            return await make_error("operationNotFound", str(e), 404)
        headers = {}
        if operation["status"] == "running":
            headers["Retry-After"] = "1"
        return await make_response(operation, 200, headers)

    return app


def cli(fn):
    parser = fn()
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--log", type=str, default="INFO")
    parser.add_argument("--error-rate", type=float, default=0.01)
    parser.add_argument("--use-lro", action="store_true", help="Create operations for submissions")
    parser.add_argument("--tree-alg", required=True, choices=list(TREE_ALGS.keys()))
    parser.add_argument("--workspace", type=Path, default=Path("workspace"))
    parser.add_argument(
        "--middleware",
        type=lambda value: list(entrypoint_style_load(value))[0],
        nargs="*",
        default=[],
    )
    parser.add_argument("--middleware-config-path", type=Path, nargs="*", default=[])

    def cmd(args):
        logging.basicConfig(level=getattr(logging, args.log.upper(), "INFO"))
        app = create_flask_app(
            {
                "port": args.port,
                "middleware": args.middleware,
                "middleware_config_path": args.middleware_config_path,
                "tree_alg": args.tree_alg,
                "workspace": args.workspace,
                "error_rate": args.error_rate,
                "use_lro": args.use_lro
            }
        )
        app.run(host="0.0.0.0", port=args.port)

    parser.set_defaults(func=cmd)

    return parser
