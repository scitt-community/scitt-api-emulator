import os
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


class SCITTFederationActivityPubBovine(SCITTFederation):
    def __init__(self, app, signals, config_path):
        super().__init__(app, signals, config_path)

        self.handle_name = self.config["handle_name"]
        self.fqdn = self.config.get("fqdn", None)
        # This is the federation middleware workspace, not the same as the
        # tree_alg class's workspace
        self.workspace = Path(self.config["workspace"]).expanduser()

        self.bovine_db_url = self.config.get("bovine_db_url",
                                             os.environ.get("BOVINE_DB_URL",
                                                            None))
        if self.bovine_db_url and self.bovine_db_url.startswith("~"):
            self.bovine_db_url = str(Path(self.bovine_db_url).expanduser())
        # TODO Pass this as variable
        if not "BOVINE_DB_URL" in os.environ and self.bovine_db_url:
            os.environ["BOVINE_DB_URL"] = self.bovine_db_url
            logging.debug(f"Set BOVINE_DB_URL to {self.bovine_db_url}")

        BovinePubSub(app)
        BovineHerd(app, db_url=self.bovine_db_url)

        app.while_serving(self.initialize_service)

    async def make_client_session(self):
        return aiohttp.ClientSession(trust_env=True)

    async def initialize_service(self):
        # TODO Better domain / fqdn building
        if self.fqdn:
            self.domain = self.fqdn
            # TODO netloc remove scheme (http, https) before set to domain
            # Use schem to build endpoint_path
        else:
            self.domain = f'http://localhost:{self.app.config["port"]}'

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
            bovine_name = await bovine_store.register(
                self.handle_name,
            )
            logger.info("Created actor with database name %s", bovine_name)
            await bovine_store.add_identity_string_to_actor(
                bovine_name,
                "key0",
                did_key,
            )
            _account, actor_url = await self.app.config["bovine_store"].get_account_url_for_identity(did_key)
            logger.info("Actor key added in database. actor_url is %s", actor_url)

        # Run client handlers
        async def mechanical_bull_loop(config):
            try:
                # from mechanical_bull.event_loop import loop
                from mechanical_bull.handlers import load_handlers, build_handler

                for client_name, value in config.items():
                    if isinstance(value, dict):
                        handlers = load_handlers(value["handlers"])
                        # taskgroup.create_task(loop(client_name, value, handlers))
                        # await asyncio.sleep(10)
                        client_config = value
                        # TODO DEBUG TESTING XXX NOTE REMOVE
                        os.environ["BUTCHER_ALLOW_HTTP"] = "1"
                        client_config["domain"] = client_config["host"]
                        # self.app.add_background_task(loop, client_name,
                        #                                   client_config,
                        #                                   handlers)
                        await loop(client_name,
                                                          client_config,
                                                          handlers)
                        continue
                        i = 1
                        while True:
                            try:
                                pprint.pprint(client_config)
                                # client = await self.app.config["bovine_async_exit_stack"].enter_async_context(bovine.BovineClient(**client_config))
                                client = bovine.BovineClient(**client_config)
                                print("client:", client)
                                session = await self.make_client_session()
                                # client = await self.app.config["bovine_async_exit_stack"].enter_async_context(client)
                                print("session:", session)
                                print("session._request_class:", session._request_class)
                                print("Client init success!!!")
                                # await handle_connection_with_reconnect(
                                #     client, handlers, client_name=client_name,
                                # )
                            except aiohttp.client_exceptions.ClientConnectorError as e:
                                logger.info("Something went wrong connection: %s: attempt %i: %s", client_name, i, e)
                            except Exception as e:
                                logger.exception(e)
                                await asyncio.sleep(1)
                                # await asyncio.sleep(2 ** i)
                                i += 1
                                continue
                            self.app.add_background_task(handle_connection_with_reconnect, client, handlers, client_name=client_name)
                            break
            except Exception as e:
                logger.exception(e)


        # async with aiohttp.ClientSession(trust_env=True) as client_session:
        async with contextlib.AsyncExitStack() as async_exit_stack:
            self.app.config["bovine_async_exit_stack"] = async_exit_stack
            yield

        # await mechanical_bull_loop(config_toml_obj)
        self.app.add_background_task(mechanical_bull_loop, config_toml_obj)


async def handle(
    client: bovine.BovineClient,
    data: dict,
    # config.toml arguments
    signals: SCITTSignals = None,
    following: dict[str, dict] = None,
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
                    service = clazz(
                        signals=SCITTSignals(),
                        service_parameters_path=service_parameters_path,
                    )
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
    activity = client.activity_factory.follow(
        url,
    ).build()
    logger.info("Sending follow to %s: %r", actor_id, activity)
    await client.send_to_outbox(activity)


async def init_follow(client, retry: int = 5, **kwargs):
    for i in range(0, retry):
        try:
            return await _init_follow(client, retry=retry, **kwargs)
        except Exception as error:
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

import asyncio

import bovine
import json

import logging

from mechanical_bull.handlers import HandlerEvent, call_handler_compat


async def handle_connection(client: bovine.BovineClient, handlers: list):
    print("handle_connection")
    event_source = await client.event_source()
    print(event_source )
    logger.info("Connected")
    for handler in handlers:
        await call_handler_compat(
            handler,
            client,
            None,
            handler_event=HandlerEvent.OPENED,
        )
    async for event in event_source:
        if not event:
            return
        if event and event.data:
            data = json.loads(event.data)

            for handler in handlers:
                await call_handler_compat(
                    handler,
                    client,
                    data,
                    handler_event=HandlerEvent.DATA,
                )
    for handler in handlers:
        await call_handler_compat(
            handler,
            client,
            None,
            handler_event=HandlerEvent.CLOSED,
        )


async def handle_connection_with_reconnect(
    client: bovine.BovineClient,
    handlers: list,
    client_name: str = "BovineClient",
    wait_time: int = 10,
):
    while True:
        await handle_connection(client, handlers)
        logger.info(
            "Disconnected from server for %s, reconnecting in %d seconds",
            client_name,
            wait_time,
        )
        await asyncio.sleep(wait_time)


async def loop(client_name, client_config, handlers):
    # TODO DEBUG TESTING XXX NOTE REMOVE
    os.environ["BUTCHER_ALLOW_HTTP"] = "1"
    # client_config["domain"] = "http://" + client_config["host"]
    i = 1
    while True:
        try:
            async with bovine.BovineClient(**client_config) as client:
                print("client:", client)
                await handle_connection_with_reconnect(
                    client, handlers, client_name=client_name
                )
        except Exception as e:
            logger.exception("Something went wrong for %s", client_name)
            logger.exception(e)
            await asyncio.sleep(1)
            # await asyncio.sleep(10)
            # await asyncio.sleep(2 ** i)
            i += 1
