"""
#!/usr/bin/env bash
set -xeuo pipefail

rm -rf .venv && \
python -m venv .venv && \
. .venv/bin/activate && \
pip install -U pip setuptools wheel && \
pip install \
  toml \
  bovine{-store,-process,-pubsub,-herd,-tool} \
  'https://codeberg.org/pdxjohnny/bovine/archive/activitystreams_collection_helper_enable_multiple_iterations.tar.gz#egg=bovine&subdirectory=bovine' \
  'https://codeberg.org/pdxjohnny/mechanical_bull/archive/event_loop_on_connect_call_handlers.tar.gz#egg=mechanical-bull'

export HYPERCORN_PID=0
function kill_hypercorn() {
  kill "${HYPERCORN_PID}"
}
hypercorn app:app &
export HYPERCORN_PID=$!
trap kill_hypercorn EXIT
sleep 1

export HANDLE_NAME=alice
export BOVINE_NAME=$(python -m bovine_tool.register "${HANDLE_NAME}" --domain http://localhost:8000 | awk '{print $NF}')
python -m mechanical_bull.add_user --accept "${HANDLE_NAME}" http://localhost:8000
python -m bovine_tool.manage "${BOVINE_NAME}" --did_key key0 $(cat config.toml | python -c 'import sys, tomllib, bovine.crypto; print(bovine.crypto.private_key_to_did_key(tomllib.load(sys.stdin.buffer)[sys.argv[-1]]["secret"]))' "${HANDLE_NAME}")

python -c 'import sys, pathlib, toml; path = pathlib.Path(sys.argv[-3]); obj = toml.loads(path.read_text()); obj[sys.argv[-2]]["handlers"][sys.argv[-1]] = True; path.write_text(toml.dumps(obj))' config.toml "${HANDLE_NAME}" scitt_handler

PYTHONPATH=${PYTHONPATH:-''}:$PWD timeout 5s python -m mechanical_bull.run
"""
import sys
import json
import pprint
import socket
import inspect
import logging
import asyncio
import pathlib
import subprocess
from pathlib import Path
from typing import Optional

import toml
import bovine
from mechanical_bull.handlers import HandlerEvent, HandlerAPIVersion

from scitt_emulator.federation import SCITTFederation

logger = logging.getLogger(__name__)


class SCITTFederationActivityPubBovine(SCITTFederation):
    def __init__(
        self,
        config_path: Path,
        service_parameters_path: Path,
        storage_path: Optional[Path] = None,
    ):
        super().__init__(config_path, service_parameters_path, storage_path)
        self.config = {}
        if config_path and config_path.exists():
            self.config = json.loads(config_path.read_text())

        self.start_herd = self.config.get("start_herd", False)
        if self.start_herd:
            raise NotImplementedError("Please start bovine-herd manually")

        self.domain = self.config["domain"]
        self.handle_name = self.config["handle_name"]
        self.workspace = Path(self.config["workspace"])

        self.federate_created_entries_socket_path = self.workspace.joinpath(
            "federate_created_entries_socket",
        )

    def initialize_service(self):
        # read, self.write = multiprocessing.Pipe(duplex=False)
        # reader_process = multiprocessing.Process(target=self.reader, args=(read,))

        # TODO Avoid creating user if already exists
        cmd = [
            sys.executable,
            "-um",
            "mechanical_bull.add_user",
            "--accept",
            self.handle_name,
            domain,
        ]
        add_user_output = subprocess.check_output(
            cmd,
            cwd=self.workspace,
        )
        did_key = [
            word.replace("did:key:", "")
            for word in add_user_output.decode().strip().split()
            if word.startswith("did:key:")
        ][0]

        cmd = [
            sys.executable,
            "-um",
            "bovine_tool.register",
            self.handle_name,
            "--domain",
            domain,
        ]
        register_output = subprocess.check_output(
            cmd,
            cwd=self.workspace,
        )
        bovine_name = register_output.decode().strip().split()[-1]

        cmd = [
            sys.executable,
            "-um",
            "bovine_tool.manage",
            self.handle_name,
            "--did_key",
            "key0",
            did_key,
        ]
        subprocess.check_call(
            cmd,
            cwd=self.workspace,
        )

        # Enable handler() function in this file for this actor
        config_toml_path = pathlib.Path(self.workspace, "config.toml")
        config_toml_obj = toml.loads(config_toml_path.read_text())
        config_toml_obj[self.handle_name]["handlers"][
            inspect.getmodule(sys.modules[__name__]).__spec__.name
        ] = {
            "federate_created_entries_socket_path": self.federate_created_entries_socket_path,
        }
        config_toml_path.write_text(toml.dumps(config_toml_obj))

        cmd = [
            sys.executable,
            "-um",
            "mechanical_bull.run",
        ]
        self.mechanical_bull_proc = subprocess.Popen(
            cmd,
            cwd=self.workspace,
        )

    def created_entry(self, entry_id: str, receipt: bytes):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.federate_created_entries_socket_path)
            client.send(receipt)
            client.close()


async def handle(
    client: bovine.BovineClient,
    data: dict,
    federate_created_entries_socket_path: Path = None,
    handler_event: HandlerEvent = None,
    handler_api_version: HandlerAPIVersion = HandlerAPIVersion.unstable,
):
    try:
        logging.info(f"{__file__}:handle(handler_event={handler_event})")
        match handler_event:
            case HandlerEvent.OPENED:
                asyncio.create_task(
                    federate_created_entries(
                        client, federate_created_entries_socket_path
                    )
                )
            case HandlerEvent.CLOSED:
                return
            case HandlerEvent.DATA:
                pprint.pprint(data)
                if data.get("type") != "Create":
                    return

                # TODO Send federated claim / receipt to SCITT
                obj = data.get("object")
                if not isinstance(obj, dict):
                    return
    except Exception as ex:
        logger.error(ex)
        logger.exception(ex)
        logger.error(json.dumps(data))


async def federate_created_entries(
    client: bovine.BovineClient,
    socket_path: Path,
):
    async def federate_created_entry(reader, writer):
        receipt = await reader.read()
        note = (
            client.object_factory.note(
                content=base64.b64encode(receipt),
            )
            .as_public()
            .build()
        )
        activity = client.activity_factory.create(note).build()
        logger.info("Sending... %r", activity)
        await client.send_to_outbox(activity)

        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(
        federate_created_entry,
        path=str(socket_path.resolve()),
    )
    async with server:
        logger.info("Awaiting receipts to federate at %r", socket_path)
        while True:
            await asyncio.sleep(60)
