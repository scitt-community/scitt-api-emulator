import sys
import json
import types
import atexit
import base64
import socket
import inspect
import logging
import asyncio
import pathlib
import tempfile
import functools
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
from bovine_store import BovineAdminStore
from bovine_herd import BovineHerd
from bovine_pubsub import BovinePubSub
from bovine.activitystreams import factories_for_actor_object
from bovine.clients import lookup_uri_with_webfinger
from mechanical_bull.handlers import HandlerEvent, HandlerAPIVersion

from scitt_emulator.scitt import SCITTServiceEmulator
from scitt_emulator.federation import SCITTFederation
from scitt_emulator.tree_algs import TREE_ALGS
from scitt_emulator.signals import SCITTSignals, SCITTSignalsFederationCreatedEntry

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

        self.handle_name = self.config["handle_name"]
        self.workspace = Path(self.config["workspace"]).expanduser()

        BovinePubSub(app)
        BovineHerd(app)

        app.before_serving(self.initialize_service)

    async def initialize_service(self):
        # TODO Better domain / fqdn building
        self.domain = f'http://127.0.0.1:{self.app.config["port"]}'

        config_toml_path = pathlib.Path(self.workspace, "config.toml")
        config_toml_path.unlink()
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
            "signals": self.signals,
            "following": self.config.get("following", {}),
        }
        # Extract public key from private key in config file
        did_key = bovine.crypto.private_key_to_did_key(
            config_toml_obj[self.handle_name]["secret"],
        )

        bovine_store = self.app.config["bovine_store"]
        _account, actor_url = await bovine_store.get_account_url_for_identity(did_key)
        if actor_url:
            logger.info("Existing actor found. actor_url is %s", actor_url)
        else:
            logger.info("Actor not found, creating in database...")
            bovine_store = BovineAdminStore(domain=self.domain)
            bovine_name = await bovine_store.register(self.handle_name)
            logger.info("Created actor with database name %s", bovine_name)
            await bovine_store.add_identity_string_to_actor(
                bovine_name,
                "key0",
                did_key,
            )
            logger.info("Actor key added in database")

        # Run client handlers
        async def mechanical_bull_loop(config):
            from mechanical_bull.event_loop import loop
            from mechanical_bull.handlers import load_handlers, build_handler

            async with asyncio.TaskGroup() as taskgroup:
                for client_name, value in config.items():
                    if isinstance(value, dict):
                        handlers = load_handlers(value["handlers"])
                        taskgroup.create_task(loop(client_name, value, handlers))

        self.app.add_background_task(mechanical_bull_loop, config_toml_obj)


async def handle(
    client: bovine.BovineClient,
    data: dict,
    # config.toml arguments
    signals: SCITTSignals = None,
    following: dict[str, Follow] = None,
    raise_on_follow_failure: bool = False,
    # handler arguments
    handler_event: HandlerEvent = None,
    handler_api_version: HandlerAPIVersion = HandlerAPIVersion.unstable,
):
    try:
        logger.info(f"{__file__}:handle(handler_event={handler_event})")
        match handler_event:
            case HandlerEvent.OPENED:
                # Listen for events from SCITT
                # TODO Do this without using a client, server side
                async def federate_created_entries_pass_client(
                    sender: SCITTServiceEmulator,
                    created_entry: SCITTSignalsFederationCreatedEntry = None,
                ):
                    nonlocal client
                    await federate_created_entries(client, sender, created_entry)

                client.federate_created_entries = types.MethodType(
                    signals.federation.created_entry.connect(
                        federate_created_entries_pass_client
                    ),
                    client,
                )
                # print(signals.federation.created_entry.connect(federate_created_entries))
                # Preform ActivityPub related init
                if following:
                    try:
                        async with asyncio.TaskGroup() as tg:
                            for key, value in following.items():
                                logger.info("Following... %r", value)
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

                    # Send signal to submit federated claim
                    # TODO Announce that this entry ID was created via
                    # federation to avoid an infinate loop
                    await signals.federation.submit_claim.send_async(
                        client, claim=claim
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
    sender: SCITTServiceEmulator,
    created_entry: SCITTSignalsFederationCreatedEntry = None,
):
    try:
        logger.info("federate_created_entry() created_entry: %r", created_entry)
        note = (
            client.object_factory.note(
                content=json.dumps(
                    {
                        "treeAlgorithm": created_entry.tree_alg,
                        "service_parameters": base64.b64encode(
                            created_entry.public_service_parameters
                        ).decode(),
                        "entry_id": created_entry.entry_id,
                        "receipt": base64.b64encode(created_entry.receipt).decode(),
                        "claim": base64.b64encode(created_entry.claim).decode(),
                    }
                )
            )
            .as_public()
            .build()
        )
        activity = client.activity_factory.create(note).build()
        logger.info("Sending... %r", activity)
        await client.send_to_outbox(activity)

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
