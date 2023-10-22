import sys
import json
import atexit
import base64
import socket
import inspect
import logging
import asyncio
import pathlib
import tempfile
import traceback
import contextlib
import subprocess
import dataclasses
import urllib.parse
from pathlib import Path
from typing import Optional

import tomli
import tomli_w
import bovine
import aiohttp
from bovine_herd import BovineHerd
from bovine_pubsub import BovinePubSub
from bovine.activitystreams import factories_for_actor_object
from bovine.clients import lookup_uri_with_webfinger
from mechanical_bull.handlers import HandlerEvent, HandlerAPIVersion

from scitt_emulator.scitt import SCITTServiceEmulator
from scitt_emulator.federation import SCITTFederation
from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.signals import SCITTSignalsFederationCreatedEntry

logger = logging.getLogger(__name__)

import pprint


@dataclasses.dataclass
class Follow:
    actor_id: str
    domain: str = None


async def get_actor_url(
    domain: str,
    handle_name: str = None,
    did_key: str = None,
    session: aiohttp.ClientSession = None,
):
    if did_key:
        lookup = did_key
    elif handle_name:
        # Get domain and port without protocol
        url_parse_result = urllib.parse.urlparse(domain)
        actor_id = f"{handle_name}@{url_parse_result.netloc}"
        lookup = f"acct:{actor_id}"
    else:
        raise ValueError(
            f"One of the following keyword arguments must be provided: handle_name, did_key"
        )
    async with contextlib.AsyncExitStack() as async_exit_stack:
        # Create session if not given
        if not session:
            session = await async_exit_stack.enter_async_context(
                aiohttp.ClientSession(trust_env=True),
            )
        url, _ = await lookup_uri_with_webfinger(session, lookup, domain=domain)
        return url


class SCITTFederationActivityPubBovine(SCITTFederation):
    def __init__(self, app, signals, config_path):
        super().__init__(app, signals, config_path)

        self.start_herd = self.config.get("start_herd", False)
        if self.start_herd:
            raise NotImplementedError("Please start bovine-herd manually")

        self.domain = self.config["domain"]
        self.handle_name = self.config["handle_name"]
        self.workspace = Path(self.config["workspace"]).expanduser()

        self.federate_created_entries_socket_path = self.workspace.joinpath(
            "federate_created_entries_socket",
        )

        BovinePubSub(app)
        BovineHerd(app)

        # self.initialize_service()

    def initialize_service(self):
        config_toml_path = pathlib.Path(self.workspace, "config.toml")
        if not config_toml_path.exists():
            logger.info("Actor client config does not exist, creating...")
            cmd = [
                sys.executable,
                "-um",
                "mechanical_bull.add_user",
                "--accept",
                self.handle_name,
                self.domain,
            ]
            subprocess.check_call(
                cmd,
                cwd=self.workspace,
            )
            logger.info("Actor client config created")

        config_toml_obj = tomli.loads(config_toml_path.read_text())
        # Enable handler() function in this file for this actor
        config_toml_obj[self.handle_name]["handlers"][
            inspect.getmodule(sys.modules[__name__]).__spec__.name
        ] = {
            "federate_created_entries_socket_path": str(
                self.federate_created_entries_socket_path.resolve()
            ),
            "following": self.config.get("following", {}),
        }
        config_toml_path.write_text(tomli_w.dumps(config_toml_obj))
        # Extract public key from private key in config file
        did_key = bovine.crypto.private_key_to_did_key(
            config_toml_obj[self.handle_name]["secret"],
        )

        # TODO This may not work if there is another instance of an event loop
        # running. There shouldn't be but can we come up with a workaround in
        # case that does happen?
        actor_url = asyncio.run(
            get_actor_url(
                self.domain,
                did_key=did_key,
            )
        )
        # TODO take BOVINE_DB_URL from config, populate env on call to tool if
        # NOT already set in env.
        # Create the actor in the database, set
        # BOVINE_DB_URL="sqlite://${HOME}/path/to/bovine.sqlite3" or see
        # https://codeberg.org/bovine/bovine/src/branch/main/bovine_herd#configuration
        # for more options.
        if actor_url:
            logger.info("Existing actor found. actor_url is %s", actor_url)
        else:
            logger.info("Actor not found, creating in database...")
            cmd = [
                sys.executable,
                "-um",
                "bovine_tool.register",
                self.handle_name,
                "--domain",
                self.domain,
            ]
            register_output = subprocess.check_output(
                cmd,
                cwd=self.workspace,
            )
            bovine_name = register_output.decode().strip().split()[-1]
            logger.info("Created actor with database name %s", bovine_name)

            cmd = [
                sys.executable,
                "-um",
                "bovine_tool.manage",
                bovine_name,
                "--did_key",
                "key0",
                did_key,
            ]
            subprocess.check_call(
                cmd,
                cwd=self.workspace,
            )
            logger.info("Actor key added in database")

        # Run client handlers
        cmd = [
            sys.executable,
            "-um",
            "mechanical_bull.run",
        ]
        self.mechanical_bull_proc = subprocess.Popen(
            cmd,
            cwd=self.workspace,
        )
        atexit.register(self.mechanical_bull_proc.terminate)

    def created_entry(
        self,
        scitt_service: SCITTServiceEmulator,
        created_entry: SCITTSignalsFederationCreatedEntry,
    ):
        return
        # NOTE Test of sending signal to submit federated claim -> self.signals.federation.submit_claim.send(self, claim=created_entry.claim)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.federate_created_entries_socket_path.resolve()))
            client.send(
                json.dumps(
                    {
                        "treeAlgorithm": created_entry.tree_alg,
                        "service_parameters": base64.b64encode(
                            created_entry.public_service_parameters
                        ).decode(),
                        "entry_id": created_entry.entry_id,
                        "receipt": base64.b64encode(created_entry.receipt).decode(),
                        "claim": base64.b64encode(created_entry.claim).decode(),
                    }
                ).encode()
            )
            client.close()


async def handle(
    client: bovine.BovineClient,
    data: dict,
    # config.toml arguments
    following: dict[str, Follow] = None,
    federate_created_entries_socket_path: Path = None,
    raise_on_follow_failure: bool = False,
    # handler arguments
    handler_event: HandlerEvent = None,
    handler_api_version: HandlerAPIVersion = HandlerAPIVersion.unstable,
):
    try:
        logging.info(f"{__file__}:handle(handler_event={handler_event})")
        match handler_event:
            case HandlerEvent.OPENED:
                # Listen for events from SCITT
                asyncio.create_task(
                    federate_created_entries(
                        client, federate_created_entries_socket_path
                    )
                )
                # Preform ActivityPub related init
                if following:
                    try:
                        async with asyncio.TaskGroup() as tg:
                            for key, value in following.items():
                                logging.info("Following... %r", value)
                                tg.create_task(init_follow(client, **value))
                    except (ExceptionGroup, BaseExceptionGroup) as error:
                        if raise_on_follow_failure:
                            raise
                        else:
                            logger.error("Failures while following: %r", error)
            case HandlerEvent.CLOSED:
                return
            case HandlerEvent.DATA:
                logger.info(
                    "Got new data in ActivityPub inbox: %s", pprint.pformat(data)
                )
                if data.get("type") != "Create":
                    return

                obj = data.get("object")
                if not isinstance(obj, dict):
                    return

                # Send federated claim / receipt to SCITT
                content_str = obj.get("content")
                content = json.loads(content_str)
                if not isinstance(content, dict):
                    return
                logger.info("Federation received new receipt: %r", content)

                treeAlgorithm = content["treeAlgorithm"]
                _entry_id = content["entry_id"]
                claim = base64.b64decode(content["claim"].encode())
                receipt = base64.b64decode(content["receipt"].encode())
                service_parameters = base64.b64decode(
                    content["service_parameters"].encode()
                )

                with tempfile.TemporaryDirectory() as tempdir:
                    receipt_path = Path(tempdir, "receipt")
                    receipt_path.write_bytes(receipt)
                    cose_path = Path(tempdir, "claim")
                    cose_path.write_bytes(claim)
                    service_parameters_path = Path(tempdir, "service_parameters")
                    service_parameters_path.write_bytes(service_parameters)

                    clazz = TREE_ALGS[treeAlgorithm]
                    service = clazz(service_parameters_path=service_parameters_path)
                    service.verify_receipt(cose_path, receipt_path)

                    logger.info("Receipt verified")

                    return
                    # TODO Announce that this entry ID was created via
                    # federation to avoid an infinate loop
                    scitt_emulator.client.submit_claim(
                        home_scitt_url,
                        claim,
                        str(Path(tempdir, "home_receipt").resolve()),
                        str(Path(tempdir, "home_entry_id").resolve()),
                        scitt_emulator.client.HttpClient(
                            home_scitt_token,
                            home_scitt_cacert,
                        ),
                    )
    except Exception as ex:
        logger.error(ex)
        logger.exception(ex)
        logger.error(json.dumps(data))


class WebFingerLookupNotFoundError(Exception):
    pass


async def _init_follow(client, actor_id: str, domain: str = None, retry: int = 5):
    url, _ = await lookup_uri_with_webfinger(
        client.session, f"acct:{actor_id}", domain=domain
    )
    if not url:
        raise WebFingerLookupNotFoundError(f"actor_id: {actor_id}, domain: {domain}")
    remote_data = await client.get(url)
    remote_inbox = remote_data["inbox"]
    activity = client.activity_factory.follow(
        url,
    ).build()
    logger.info("Sending follow to %s: %r", actor_id, activity)
    await client.send_to_outbox(activity)


async def init_follow(client, retry: int = 5, **kwargs):
    for i in range(0, retry):
        try:
            return await _init_follow(client, retry=retry, **kwargs)
        except WebFingerLookupNotFoundError as error:
            logger.error(repr(error))
            await asyncio.sleep(2**i)


async def federate_created_entries(
    client: bovine.BovineClient,
    socket_path: Path,
):
    async def federate_created_entry(reader, writer):
        try:
            logger.info("federate_created_entry() Reading... %r", reader)
            content_bytes = await reader.read()
            logger.info("federate_created_entry() Read: %r", content_bytes)
            note = (
                client.object_factory.note(
                    content=content_bytes.decode(),
                )
                .as_public()
                .build()
            )
            activity = client.activity_factory.create(note).build()
            logger.info("Sending... %r", activity)
            await client.send_to_outbox(activity)

            writer.close()
            await writer.wait_closed()

            # DEBUG NOTE Dumping outbox
            print("client:", client)
            outbox = client.outbox()
            print("outbox:", outbox)
            count_messages = 0
            async for message in outbox:
                count_messages += 1
                print(f"Message {count_messages} in outbox:", message)
            print(f"End of messages in outbox, total: {count_messages}")
        except:
            logger.error(traceback.format_exc())

    logger.info("Attempting UNIX bind at %r", socket_path)
    server = await asyncio.start_unix_server(
        federate_created_entry,
        path=str(Path(socket_path).resolve()),
    )
    async with server:
        logger.info("Awaiting receipts to federate at %r", socket_path)
        while True:
            await asyncio.sleep(60)
