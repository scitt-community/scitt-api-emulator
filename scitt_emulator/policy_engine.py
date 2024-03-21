#!/usr/bin/env python
"""
Implement GitHub Actions workflow evaluation as step towards workflow based
policy engine. TODO Receipts with attestations for SLSA L4.

Testing with token auth (fine grained tokens required for status checks):

NO_CELERY=1 GITHUB_TOKEN=$(gh auth token) nodemon -e py --exec 'clear; python -m pytest -s -vv scitt_emulator/policy_engine.py; test 1'

Testing with GitHub App auth:

LIFESPAN_CONFIG_1=github_app.yaml LIFESPAN_CALLBACK_1=scitt_emulator.policy_engine:lifespan_github_app_gidgethub nodemon -e py --exec 'clear; pytest -s -vv scitt_emulator/policy_engine.py; test 1'

**github_app.yaml**

```yaml
app_id: 1234567
private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  -----END RSA PRIVATE KEY-----
```

Usage with Celery:

Terminal 1:

```bash
nodemon --signal SIGKILL -e py --exec 'clear; ./scitt_emulator/policy_engine.py --lifespan scitt_emulator.policy_engine:lifespan_github_app_gidgethub github_app.yaml api --workers 1 --bind 0.0.0.0:8080; test 1'
```

Terminal 2:

nodemon -e py --exec 'clear; ./scitt_emulator/policy_engine.py --lifespan scitt_emulator.policy_engine:lifespan_github_app_gidgethub github_app.yaml worker; test 1'

Usage without Celery:

Terminal 1:

```bash
GITHUB_TOKEN=$(gh auth token) NO_CELERY=1 ./scitt_emulator/policy_engine.py --workers 1
```

**request.yml**

```yaml
context:
  config:
    env:
      GITHUB_REPOSITORY: "scitt-community/scitt-api-emulator"
      GITHUB_API: "https://api.github.com/"
      GITHUB_ACTOR: "aliceoa"
      GITHUB_ACTOR_ID: "1234567"
  secrets:
    MY_SECRET: "test-secret"
workflow: |
  on:
    push:
      branches:
      - main

  jobs:
    lint:
      runs-on: ubuntu-latest
      steps:
      - uses: actions/checkout@v4
```

In another terminal request exec via curl:

```bash
jsonschema -i <(cat request.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') <(python -c 'import json, scitt_emulator.policy_engine; print(json.dumps(scitt_emulator.policy_engine.PolicyEngineRequest.model_json_schema(), indent=4, sort_keys=True))')

TASK_ID=$(curl -X POST -H "Content-Type: application/json" -d @<(cat request.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost:8080/request/create  | jq -r .detail.id)
curl http://localhost:8080/request/status/$TASK_ID | jq

TASK_ID=$(curl -X POST http://localhost:8080/webhook/github -d '{"after": "a1b70ee3b0343adc24e3b75314262e43f5c79cc2", "repository": {"full_name": "pdxjohnny/scitt-api-emulator"}, "sender": {"login": "pdxjohnny"}}' -H "X-GitHub-Event: push" -H "X-GitHub-Delivery: 42" -H "Content-Type: application/json"  | jq -r .detail.id)
curl http://localhost:8080/request/status/$TASK_ID | jq
```

Or you can use the builtin client (workflow.yml is 'requests.yml'.workflow):

**workflow.yml**

```yaml
on:
  push:
    branches:
    - main
  workflow_dispatch:
    file_paths:
      description: 'File paths to download'
      default: '[]'
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
    - env:
        FILE_PATHS: ${{ github.event.inputs.file_paths }}
        GITHUB_TOKEN: ${{ github.token }}
      shell: python -u {0}
      run: |
        import os
        import json
        import pathlib

        from github import Github

        file_paths = json.loads(os.environ["FILE_PATHS"])

        g = Github(os.environ["GITHUB_TOKEN"])
        upstream = g.get_repo(os.environ["GITHUB_REPOSITORY"])

        for file_path in file_paths:
            file_path = pathlib.Path("./" + file_path)
            pygithub_fileobj = upstream.get_contents(
                str(file_path),
            )
            content = pygithub_fileobj.decoded_content
            file_path.write_bytes(content)
```

Pass inputs or more context with `--input` and `--context`.

```bash
TASK_ID=$(python -u ./scitt_emulator/policy_engine.py client --endpoint http://localhost:8080 create --repository pdxjohnny/scitt-api-emulator --workflow workflow.yml --input file_paths '["/README.md"]' | tee >(jq 1>/dev/stderr) | jq -r .detail.id)
python -u ./scitt_emulator/policy_engine.py client --endpoint http://localhost:8080 status --task-id "${TASK_ID}" | tee >(jq -r .detail.annotations.error[] 1>&2) | jq
```
"""
import os
import io
import sys
import json
import time
import enum
import uuid
import copy
import shlex
import types
import atexit
import asyncio
import pathlib
import zipfile
import tarfile
import inspect
import logging
import argparse
import tempfile
import textwrap
import datetime
import importlib
import traceback
import itertools
import subprocess
import contextlib
import contextvars
import urllib.request
import multiprocessing
import concurrent.futures
from typing import (
    Union,
    Callable,
    Optional,
    Tuple,
    List,
    Dict,
    Any,
    Annotated,
    Self,
    Iterator,
)


import yaml
import snoop
import pytest
import aiohttp
import gidgethub.apps
import gidgethub.aiohttp
import gunicorn.app.base
from celery import Celery, current_app as celery_current_app
from celery.result import AsyncResult
from fastapi import FastAPI, Request
from pydantic import (
    BaseModel,
    PlainSerializer,
    Field,
    model_validator,
    field_validator,
)
from fastapi.testclient import TestClient


logger = logging.getLogger(__name__)


def entrypoint_style_load(
    *args: str, relative: Optional[Union[str, pathlib.Path]] = None
) -> Iterator[Any]:
    """
    Load objects given the entrypoint formatted path to the object. Roughly how
    the python stdlib docs say entrypoint loading works.
    """
    # Push current directory into front of path so we can run things
    # relative to where we are in the shell
    if relative is not None:
        if relative == True:
            relative = os.getcwd()
        # str() in case of Path object
        sys.path.insert(0, str(relative))
    try:
        for entry in args:
            modname, qualname_separator, qualname = entry.partition(":")
            obj = importlib.import_module(modname)
            for attr in qualname.split("."):
                if hasattr(obj, "__getitem__"):
                    obj = obj[attr]
                else:
                    obj = getattr(obj, attr)
            yield obj
    finally:
        if relative is not None:
            sys.path.pop(0)


class PolicyEngineCompleteExitStatuses(enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class PolicyEngineComplete(BaseModel, extra="forbid"):
    id: str
    exit_status: PolicyEngineCompleteExitStatuses
    outputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})
    annotations: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})


class PolicyEngineStatuses(enum.Enum):
    SUBMITTED = "submitted"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    UNKNOWN = "unknown"
    INPUT_VALIDATION_ERROR = "input_validation_error"


class PolicyEngineStatusUpdateJobStep(BaseModel, extra="forbid"):
    status: PolicyEngineStatuses
    metadata: Dict[str, str]
    outputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})


class PolicyEngineStatusUpdateJob(BaseModel, extra="forbid"):
    steps: Dict[str, PolicyEngineStatusUpdateJobStep]


class PolicyEngineInProgress(BaseModel, extra="forbid"):
    id: str
    status_updates: Dict[str, PolicyEngineStatusUpdateJob]


class PolicyEngineSubmitted(BaseModel, extra="forbid"):
    id: str


class PolicyEngineUnknown(BaseModel, extra="forbid"):
    id: str


class PolicyEngineInputValidationError(BaseModel):
    msg: str
    loc: List[str]
    type: str
    url: Optional[str] = None
    input: Optional[str] = None


class PolicyEngineStatus(BaseModel, extra="forbid"):
    status: PolicyEngineStatuses
    detail: Union[
        PolicyEngineSubmitted,
        PolicyEngineInProgress,
        PolicyEngineComplete,
        PolicyEngineUnknown,
        List[PolicyEngineInputValidationError],
    ]

    @model_validator(mode="before")
    @classmethod
    def model_validate_detail(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            if "status" not in data:
                data["status"] = PolicyEngineStatuses.INPUT_VALIDATION_ERROR.value
            if isinstance(data["status"], PolicyEngineStatuses):
                data["status"] = data["status"].value

            detail_class = DETAIL_CLASS_MAPPING[data["status"]]
            data["detail"] = detail_class.model_validate(data["detail"])
        return data


DETAIL_CLASS_MAPPING = {
    PolicyEngineStatuses.SUBMITTED.value: PolicyEngineSubmitted,
    PolicyEngineStatuses.IN_PROGRESS.value: PolicyEngineInProgress,
    PolicyEngineStatuses.COMPLETE.value: PolicyEngineComplete,
    PolicyEngineStatuses.UNKNOWN.value: PolicyEngineUnknown,
    PolicyEngineStatuses.INPUT_VALIDATION_ERROR.value: types.SimpleNamespace(
        model_validate=lambda detail: list(map(PolicyEngineInputValidationError.model_validate, detail)),
    ),
}


class PolicyEngineWorkflowJobStep(BaseModel, extra="forbid"):
    id: Optional[str] = None
    # TODO Alias doesn't seem to be working here
    # if_condition: Optional[str] = Field(default=None, alias="if")
    # TODO Implement step if conditionals, YAML load output of eval_js
    if_condition: Optional[Union[str, bool, int]] = Field(default=None)
    name: Optional[str] = None
    uses: Optional[str] = None
    shell: Optional[str] = None
    # TODO Alias doesn't seem to be working here
    # with_inputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {}, alias="with")
    with_inputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})
    env: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})
    run: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def fix_hyphen_keys(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for find, replace in [
                ("if", "if_condition"),
                ("with", "with_inputs"),
            ]:
                if find in data:
                    data[replace] = data[find]
                    del data[find]
        return data


class PolicyEngineWorkflowJob(BaseModel, extra="forbid"):
    runs_on: Union[str, List[str], Dict[str, Any]] = Field(
        default_factory=lambda: [],
    )
    steps: Optional[List[PolicyEngineWorkflowJobStep]] = Field(
        default_factory=lambda: [],
    )

    @model_validator(mode="before")
    @classmethod
    def fix_hyphen_keys(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for find, replace in [("runs-on", "runs_on")]:
                if find in data:
                    data[replace] = data[find]
                    del data[find]
        return data


class PolicyEngineWorkflow(BaseModel, extra="forbid"):
    name: Optional[str] = None
    on: Union[List[str], Dict[str, Any]] = Field(
        default_factory=lambda: [],
    )
    jobs: Optional[Dict[str, PolicyEngineWorkflowJob]] = Field(
        default_factory=lambda: {},
    )

    @model_validator(mode="before")
    @classmethod
    def fix_yaml_on_parsed_as_bool(cls, data: Any) -> Any:
        if data and isinstance(data, dict):
            for check in [1, True]:
                if check in data:
                    data["on"] = data[check]
                    del data[check]
        return data


class PolicyEngineRequest(BaseModel, extra="forbid"):
    # Inputs should come from json-ld @context instance
    inputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})
    workflow: Union[str, dict, PolicyEngineWorkflow] = Field(
        default_factory=lambda: PolicyEngineWorkflow()
    )
    context: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})
    stack: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})

    @field_validator("workflow")
    @classmethod
    def parse_workflow_github_actions(cls, workflow, _info):
        if isinstance(workflow, str):
            workflow = yaml.safe_load(workflow)
        if isinstance(workflow, dict):
            workflow = PolicyEngineWorkflow.model_validate(workflow)
        return workflow

    @field_validator("context")
    @classmethod
    def parse_context_set_secrets_if_not_set(cls, context, _info):
        context.setdefault("secrets", {})
        return context


celery_app = Celery(
    "tasks",
    backend=os.environ.get("CELERY_BACKEND", "redis://localhost"),
    broker=os.environ.get("CELERY_BROKER", "redis://localhost"),
    broker_connection_retry_on_startup=True,
)


def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1


def _no_celery_task(func, bind=False, no_celery_async=None):
    async def asyncio_delay(*args):
        nonlocal bind
        nonlocal no_celery_async
        if no_celery_async is None:
            raise Exception(
                "Must specify async def version of task via @celery_task decorator keyword argument no_celery_async"
            )
        task_id = str(uuid.uuid4())
        if bind:
            mock_celery_task_bind_self = types.SimpleNamespace(
                request=types.SimpleNamespace(
                    id=task_id,
                )
            )
            args = [mock_celery_task_bind_self] + list(args)
        task = asyncio.create_task(no_celery_async(*args))

        async def async_no_celery_try_set_state(task_id):
            request = fastapi_current_request.get()
            async with request.state.no_celery_async_results_lock:
                no_celery_try_set_state(
                    request.state.no_celery_async_results[task_id],
                )

        task.add_done_callback(
            lambda _task: asyncio.create_task(
                async_no_celery_try_set_state(task_id)
            ),
        )
        request = fastapi_current_request.get()
        async with request.state.no_celery_async_results_lock:
            results = request.state.no_celery_async_results
            results[task_id] = {
                "state": "PENDING",
                "result": None,
                "future": None,
                "task": task,
            }
            no_celery_try_set_state(results[task_id])
        return types.SimpleNamespace(id=task_id)

    func.asyncio_delay = asyncio_delay
    return func


def no_celery_task(*args, **kwargs):
    if kwargs:

        def wrap(func):
            return _no_celery_task(func, **kwargs)

        return wrap
    return _no_celery_task(*args)


def no_celery_try_set_state(state):
    task = state["task"]
    future = state["future"]
    if task is not None:
        if not task.done():
            state["state"] = "PENDING"
        else:
            exception = task.exception()
            if exception is not None:
                state["result"] = exception
                state["state"] = "FAILURE"
            else:
                state["state"] = "SUCCESS"
                state["result"] = task.result()
    elif future is not None:
        exception = future.exception(timeout=0)
        if exception is not None:
            state["result"] = exception
            state["state"] = "FAILURE"
        elif not future.done():
            state["state"] = "PENDING"
        else:
            state["state"] = "SUCCESS"
            state["result"] = future.result()


class NoCeleryAsyncResult:
    def __init__(self, task_id, *, app=None):
        self.task_id = task_id

    @property
    def state(self):
        request = fastapi_current_request.get()
        results = request.state.no_celery_async_results
        if self.task_id not in results:
            return "UNKNOWN"
        state = results[self.task_id]
        no_celery_try_set_state(state)
        return state["state"]

    def get(self):
        result = fastapi_current_request.get().state.no_celery_async_results[
            self.task_id
        ]["result"]
        if isinstance(result, Exception):
            raise result
        return result


def _make_celery_task_asyncio_delay(app, func, **kwargs):
    async def asyncio_delay(*args):
        nonlocal func
        return func.delay(*args)

    if kwargs:
        func = app.task(**kwargs)(func)
    else:
        func = app.task(func)
    func.asyncio_delay = asyncio_delay
    return func


def make_celery_task_asyncio_delay(app):
    def celery_task_asyncio_delay(*args, **kwargs):
        if kwargs:

            def wrap(func):
                return _make_celery_task_asyncio_delay(app, func, **kwargs)

            return wrap
        return _make_celery_task_asyncio_delay(app, *args, **kwargs)

    return celery_task_asyncio_delay


if int(os.environ.get("NO_CELERY", "0")):
    AsyncResult = NoCeleryAsyncResult
    celery_task = no_celery_task
else:
    celery_task = make_celery_task_asyncio_delay(celery_app)


def download_step_uses_from_url(
    context,
    request,
    step,
    step_uses_org_repo,
    step_uses_version,
    step_download_url,
):
    stack = request.context["stack"][-1]

    exit_stack = stack["exit_stack"]
    if "cachedir" in stack:
        downloads_path = stack["cachedir"]
    else:
        downloads_path = exit_stack.enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        )
    downloads_path = pathlib.Path(downloads_path)

    # TODO(security) MoM of hashes? stat as well? How to validate on disk?
    compressed_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "compressed.zip"
    )
    extracted_tmp_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "extracted_tmp"
    )
    extracted_path = pathlib.Path(
        downloads_path, step_uses_org_repo, "extracted"
    )
    compressed_path.parent.mkdir(parents=True, exist_ok=True)
    headers = {}
    github_token = stack["secrets"].get("GITHUB_TOKEN", "")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    request = urllib.request.Request(
        step_download_url,
        headers=headers,
    )
    if not compressed_path.is_file():
        request = exit_stack.enter_context(urllib.request.urlopen(request))
        compressed_path.write_bytes(request.read())
    if not extracted_path.is_dir():
        zipfileobj = exit_stack.enter_context(zipfile.ZipFile(compressed_path))
        zipfileobj.extractall(extracted_tmp_path)
        # Rename uplevel from repo-vYXZ name as archive into extracted/
        list(extracted_tmp_path.glob("*"))[0].rename(extracted_path)

    stack.setdefault("steps", {})
    stack["steps"].setdefault("extracted_path", {})
    stack["steps"]["extracted_path"][step.uses] = extracted_path
    # https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
    stack["env"]["GITHUB_ACTION_PATH"] = str(extracted_path.resolve())

    return extracted_path.resolve()


def download_step_uses(context, request, step):
    exception = None
    step_uses_org_repo, step_uses_version = step.uses.split("@")
    # TODO refs/heads/
    for step_download_url in [
        f"https://github.com/{step_uses_org_repo}/archive/refs/tags/{step_uses_version}.zip",
        f"https://github.com/{step_uses_org_repo}/archive/{step_uses_version}.zip",
        f"https://github.com/{step_uses_org_repo}/archive/refs/heads/{step_uses_version}.zip",
    ]:
        try:
            return download_step_uses_from_url(
                context,
                request,
                step,
                step_uses_org_repo,
                step_uses_version,
                step_download_url,
            )
        except Exception as error:
            exception = error
    raise exception


def transform_property_accessors(js_code):
    transformed_code = ""
    index = 0
    while index < len(js_code):
        if js_code[index] in ('"', "'"):
            # If within a string, find the closing quote
            quote = js_code[index]
            end_quote_index = js_code.find(quote, index + 1)
            if end_quote_index == -1:
                # If no closing quote is found, break the loop
                break
            else:
                # Append the string as is
                transformed_code += js_code[index : end_quote_index + 1]
                index = end_quote_index + 1
        elif js_code[index].isspace():
            # If whitespace, just append it
            transformed_code += js_code[index]
            index += 1
        elif js_code[index] == ".":
            # Replace dot with bracket notation if not within a string
            transformed_code += "['"
            prop_end_index = index + 1
            while (
                prop_end_index < len(js_code)
                and js_code[prop_end_index].isalnum()
                or js_code[prop_end_index] == "_"
                or js_code[prop_end_index] == "-"
            ):
                prop_end_index += 1
            transformed_code += js_code[index + 1 : prop_end_index]
            transformed_code += "']"
            index = prop_end_index
        else:
            # Just append characters as is
            transformed_code += js_code[index]
            index += 1
    return transformed_code


def _evaluate_using_javascript(context, request, code_block):
    stack = request.context["stack"][-1]

    exit_stack = stack["exit_stack"]
    tempdir = exit_stack.enter_context(
        tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
    )

    github_context = {
        **{
            input_key.lower().replace(
                "github_", "", 1
            ): evaluate_using_javascript(
                context,
                request,
                input_value,
            )
            for input_key, input_value in stack["env"].items()
            if input_key.startswith("GITHUB_")
        },
        **{
            "token": stack["secrets"].get("GITHUB_TOKEN", ""),
            "event": {
                "inputs": request.context["inputs"],
            },
        },
    }
    runner_context = {
        "debug": stack.get("debug", 1),
    }
    steps_context = stack["outputs"]
    # TODO secrets_context

    # Find property accessors in dot notation and replace dot notation
    # with bracket notation. Avoids replacements within strings.
    code_block = transform_property_accessors(code_block)

    javascript_path = pathlib.Path(tempdir, "check_output.js")
    # TODO vars and env contexts
    javascript_path.write_text(
        textwrap.dedent(
            r"""
            function always() { return "__GITHUB_ACTIONS_ALWAYS__"; }
            const github = """
            + json.dumps(github_context, sort_keys=True)
            + """;
            const runner = """
            + json.dumps(runner_context, sort_keys=True)
            + """;
            const steps = """
            + json.dumps(steps_context, sort_keys=True)
            + """;
            const result = ("""
            + code_block
            + """);
            console.log(result)
            """
        ).strip()
    )
    output = subprocess.check_output(
        [context.state.deno, "repl", "-q", f"--eval-file={javascript_path.resolve()}"],
        stdin=request.context["devnull"],
        cwd=stack["workspace"],
    ).decode()
    if output.startswith(
        f'Error in --eval-file file "{javascript_path.resolve()}"'
    ):
        raise Exception(
            output
            + ("-" * 100)
            + "\n"
            + javascript_path.read_text()
            + ("-" * 100)
            + "\n"
        )
    return output.strip()


def evaluate_using_javascript(context, request, code_block):
    if code_block is None:
        return ""

    # TODO Not startswith, search for each and run deno
    if not isinstance(code_block, str) or "${{" not in code_block:
        return str(code_block)

    result = ""
    start_idx = 0
    end_idx = 0
    while "${{" in code_block[start_idx:]:
        # Find the starting index of "${{"
        start_idx = code_block.index("${{", start_idx)
        result += code_block[end_idx:start_idx]
        # Find the ending index of "}}"
        end_idx = code_block.index("}}", start_idx) + 2
        # Extract the data between "${{" and "}}"
        data = code_block[start_idx + 3 : end_idx - 2]
        # Call evaluate_using_javascript() with the extracted data
        evaluated_data = _evaluate_using_javascript(context, request, data)
        # Append the evaluated data to the result
        result += code_block[start_idx + 3 : end_idx - 2].replace(
            data, str(evaluated_data)
        )
        # Move the start index to the next position after the match
        start_idx = end_idx

    result += code_block[start_idx:]

    return result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "template,should_be",
    [
        [
            "${{ github.actor }} <${{ github.actor_id }}+${{ github.actor }}@users.noreply.github.com>",
            "aliceoa <1234567+aliceoa@users.noreply.github.com>",
        ],
        [
            "${{ github.actor_id + \" \" + 'https://github.com' + '/' + github.actor }}",
            "1234567 https://github.com/aliceoa",
        ],
    ],
)
async def test_evaluate_using_javascript(template, should_be):
    context = PolicyEngineContext(
        lifespan=DEFAULT_LIFESPAN_CALLBACKS,
        extra_inits=[
            policy_engine_context_extra_init_secret_github_token_from_github_app,
            policy_engine_context_extra_init_secret_github_token_from_lifespan,
        ],
    )
    request = PolicyEngineRequest(
        context={
            "config": {
                "env": {
                    "GITHUB_ACTOR": "aliceoa",
                    "GITHUB_ACTOR_ID": "1234567",
                },
            },
        }
    )
    async with async_celery_setup_workflow(context, request) as (context, request):
        evaluated = evaluate_using_javascript(
            context,
            request,
            template,
        )
        assert evaluated == should_be


def step_parse_outputs_github_actions(context, step, step_outputs_string):
    outputs = {}
    current_output_key = None
    current_output_delimiter = None
    current_output_value = ""
    for line in step_outputs_string.split("\n"):
        if "=" in line:
            current_output_key, current_output_value = line.split(
                "=", maxsplit=1
            )
            outputs[current_output_key] = current_output_value
        elif "<<" in line:
            current_output_key, current_output_delimiter = line.split(
                "<<", maxsplit=1
            )
        elif current_output_delimiter:
            if line.startswith(current_output_delimiter):
                outputs[current_output_key] = current_output_value[:-1]
                current_output_key = None
                current_output_delimiter = None
                current_output_value = ""
            else:
                current_output_value += line + "\n"
    return outputs


def step_build_default_inputs(context, request, action_yaml_obj, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, request, input_value["default"]
        )
        for input_key, input_value in action_yaml_obj.get("inputs", {}).items()
        if "default" in input_value
    }


def step_build_env(context, request, step):
    return {
        input_key: evaluate_using_javascript(context, request, input_value)
        for input_key, input_value in step.env.items()
    }


def step_build_inputs(context, request, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, request, input_value
        )
        for input_key, input_value in step.with_inputs.items()
    }


def step_io_output_github_actions(context, request):
    stack = request.context["stack"][-1]
    step_tempdir = stack["exit_stack"].enter_context(
        tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
    )
    step_outputs_path = pathlib.Path(step_tempdir, "output.txt")
    step_env_path = pathlib.Path(step_tempdir, "env.txt")
    step_outputs_path.write_text("")
    step_env_path.write_text("")
    return {
        "GITHUB_OUTPUT": str(step_outputs_path.resolve()),
        "GITHUB_ENV": str(step_env_path.resolve()),
        "GITHUB_WORKSPACE": stack["workspace"],
    }


def step_io_update_stack_output_and_env_github_actions(context, request, step):
    stack = request.context["stack"][-1]
    outputs = step_parse_outputs_github_actions(
        context,
        step,
        pathlib.Path(stack["env"]["GITHUB_OUTPUT"]).read_text(),
    )
    context_env_updates = step_parse_outputs_github_actions(
        context,
        step,
        pathlib.Path(stack["env"]["GITHUB_ENV"]).read_text(),
    )

    if step.id:
        stack["outputs"].setdefault(step.id, {})
        stack["outputs"][step.id]["outputs"] = outputs
    stack["env"].update(context_env_updates)


def execute_step_uses(context, request, step):
    stack = request.context["stack"][-1]

    extracted_path = stack["steps"]["extracted_path"][step.uses]
    action_yaml_path = list(extracted_path.glob("action.*"))[0]
    action_yaml_obj = yaml.safe_load(action_yaml_path.read_text())

    stack["env"].update(
        {
            **step_io_output_github_actions(context, request),
            **step_build_default_inputs(
                context, request, action_yaml_obj, step
            ),
        }
    )

    if action_yaml_obj["runs"]["using"].startswith("node"):
        env = copy.deepcopy(os.environ)
        env.update(stack["env"])
        cmd = [
            context.state.nodejs,
            extracted_path.joinpath(action_yaml_obj["runs"]["main"]),
        ]
        tee_proc = subprocess.Popen(
            ["tee", stack["console_output"]],
            stdin=subprocess.PIPE,
        )
        try:
            completed_proc = subprocess.run(
                cmd,
                cwd=stack["workspace"],
                stdin=request.context["devnull"],
                stdout=tee_proc.stdin,
                stderr=tee_proc.stdin,
                env=env,
            )
            step_io_update_stack_output_and_env_github_actions(
                context,
                request,
                step,
            )
            try:
                completed_proc.check_returncode()
            except Exception as error:
                tee_proc.stdin.close()
                tee_proc.wait()
                raise Exception(f'Command ({shlex.join(map(str, cmd))}) exited with code {error.returncode}:\n{pathlib.Path(stack["console_output"]).read_text(errors="ignore")}') from error
        finally:
            tee_proc.stdin.close()
            tee_proc.wait()
    elif action_yaml_obj["runs"]["using"] == "composite":
        composite_steps = action_yaml_obj["runs"]["steps"]
        # TODO HACK Remove by fixing PyDantic Field.alias = True deserialization
        for composite_step in composite_steps:
            if "with" in composite_step:
                composite_step["with_inputs"] = composite_step["with"]
                del composite_step["with"]
        stack = celery_run_workflow_context_stack_make_new(context, request, step.uses)
        # TODO Reusable workflows, populate secrets
        # stack["secrets"] = request.context["secrets"]
        celery_run_workflow(
            context,
            PolicyEngineRequest(
                inputs=step.with_inputs,
                workflow={
                    "jobs": {
                        "composite": {
                            "steps": composite_steps,
                        },
                    },
                },
                context=request.context,
                stack=stack,
            ),
        )
    else:
        raise NotImplementedError("Only node and composite actions implemented")


def execute_step_uses_org_repo_at_version(context, request, step):
    download_step_uses(context, request, step)
    execute_step_uses(context, request, step)


def execute_step_run(context, request, step):
    stack = request.context["stack"][-1]
    stack["env"].update(step_io_output_github_actions(context, request))

    temp_script_path = pathlib.Path(
        stack["exit_stack"].enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        ),
        "run.sh",
    )

    step_run = evaluate_using_javascript(context, request, step.run)
    temp_script_path.write_text(step_run)

    shell = stack["shell"]
    if "{0}" not in shell:
        shell += " {0}"
    shell = shell.replace("{0}", str(temp_script_path.resolve()))
    cmd = shlex.split(shell)

    env = copy.deepcopy(os.environ)
    env.update(stack["env"])
    tee_proc = subprocess.Popen(
        ["tee", stack["console_output"]],
        stdin=subprocess.PIPE,
    )
    try:
        completed_proc = subprocess.run(
            cmd,
            cwd=stack["workspace"],
            stdin=request.context["devnull"],
            stdout=tee_proc.stdin,
            stderr=tee_proc.stdin,
            env=env,
        )

        step_io_update_stack_output_and_env_github_actions(
            context,
            request,
            step,
        )

        try:
            completed_proc.check_returncode()
        except Exception as error:
            tee_proc.stdin.close()
            tee_proc.wait()
            raise Exception(f'Command ({shlex.join(map(str, cmd))}) exited with code {error.returncode}:\n{pathlib.Path(stack["console_output"]).read_text(errors="ignore")}') from error
    finally:
        tee_proc.stdin.close()
        tee_proc.wait()


def execute_step(context, request, step):
    stack = request.context["stack"][-1]

    if_condition = step.if_condition
    if if_condition is not None:
        if not isinstance(if_condition, (bool, int)):
            if not "${{" in if_condition:
                if_condition = "${{ " + if_condition + " }}"
            if_condition = evaluate_using_javascript(context, request, if_condition)
            if_condition = yaml.safe_load(f"if_condition: {if_condition}")["if_condition"]
        if not if_condition:
            return
        if stack["error"] and if_condition != "__GITHUB_ACTIONS_ALWAYS__":
            return

    if step.uses:
        if "@" in step.uses:
            execute_step_uses_org_repo_at_version(context, request, step)
        else:
            raise NotImplementedError("Only uses: org/repo@vXYZ is implemented")
    elif step.run:
        execute_step_run(context, request, step)
    else:
        raise NotImplementedError(
            "Only uses: org/repo@vXYZ and run implemented"
        )


def celery_run_workflow_context_stack_make_new(context, request, stack_path_part):
    old_stack = request.context
    if request.context["stack"]:
        old_stack = request.context["stack"][-1]
    stack = {
        "stack_path": old_stack.get("stack_path", []) + [stack_path_part],
        "error": old_stack.get("error", None),
        # TODO shell from platform.system() selection done in lifecycle
        "shell": old_stack.get("shell", "bash -xe"),
        "outputs": {},
        "annotations": {},
        "secrets": {},
        "cachedir": old_stack["cachedir"],
        "tempdir": old_stack["tempdir"],
        "workspace": old_stack["workspace"],
        "env": copy.deepcopy(old_stack["env"]),
    }
    return stack


def celery_run_workflow_context_stack_push(context, request, stack):
    old_stack = request.context
    if request.context["stack"]:
        old_stack = request.context["stack"][-1]
    stack["exit_stack"] = contextlib.ExitStack().__enter__()
    console_output_path = pathlib.Path(
        stack["exit_stack"].enter_context(
            tempfile.TemporaryDirectory(dir=stack.get("tempdir", None)),
        ),
        "console_output.txt",
    )
    console_output_path.write_bytes(b"")
    stack["console_output"] = str(console_output_path)
    request.context["stack"].append(stack)


def celery_run_workflow_context_stack_pop(context, request):
    # TODO Deal with ordering of lines by time, logging module?
    popped_stack = request.context["stack"].pop()
    request.context["console_output"].append(
        [
            popped_stack["stack_path"],
            pathlib.Path(popped_stack["console_output"]).read_bytes(),
        ],
    )
    popped_stack["exit_stack"].__exit__(None, None, None)


async def celery_run_workflow_context_init(
    context,
    request,
    *,
    force_init: bool = False,
):
    request.context.setdefault("secrets", {})
    config = request.context.get("config", {})
    config_cwd = config.get("cwd", os.getcwd())
    config_env = config.get("env", {})
    if force_init or "env" not in request.context:
        request.context["env"] = copy.deepcopy(config_env)
    if force_init or "devnull" not in request.context:
        # Open /dev/null for empty stdin to subprocesses
        request.context["devnull"] = open(os.devnull)
    if force_init or "inputs" not in request.context:
        request.context["inputs"] = copy.deepcopy(request.inputs)
    if force_init or "cachedir" not in request.context:
        # Cache dir for caching actions
        cache_path = pathlib.Path(config_cwd, ".cache")
        cache_path.mkdir(exist_ok=True)
        request.context["cachedir"] = str(cache_path)
    if force_init or "tempdir" not in request.context:
        # Temp dir
        tempdir_path = pathlib.Path(config_cwd, ".tempdir")
        tempdir_path.mkdir(exist_ok=True)
        request.context["tempdir"] = str(tempdir_path)
        if "RUNNER_TEMP" not in request.context["env"]:
            request.context["env"]["RUNNER_TEMP"] = request.context["tempdir"]
        if "RUNNER_TOOL_CACHE" not in request.context["env"]:
            request.context["env"]["RUNNER_TOOL_CACHE"] = request.context[
                "tempdir"
            ]
    if force_init or "workspace" not in request.context:
        # Workspace dir
        request.context["workspace"] = request.context[
            "exit_stack"
        ].enter_context(
            tempfile.TemporaryDirectory(dir=config.get("tempdir", None)),
        )
    if force_init or "stack" not in request.context:
        request.context["stack"] = []
    if force_init or "console_output" not in request.context:
        request.context["console_output"] = []
    if force_init or "_init" not in request.context:
        request.context["_init"] = True
        for extra_init in context.extra_inits:
            if inspect.iscoroutinefunction(extra_init):
                await extra_init(context, request)
            else:
                extra_init(context, request)


@contextlib.contextmanager
def prepend_to_path(*args: str, env=None):
    """
    Prepend all given directories to the ``PATH`` environment variable.
    """
    if env is None:
        raise Exception("env kwarg must be given")
    old_path = env.get("PATH", "")
    # TODO Will this work on Windows?
    env["PATH"] = ":".join(list(map(str, args)) + old_path.split(":"))
    try:
        yield env
    finally:
        env["PATH"] = old_path


def which(binary):
    for dirname in os.environ.get("PATH", "").split(":"):
        check_path = pathlib.Path(dirname, binary)
        if check_path.exists():
            return check_path.resolve()


@contextlib.asynccontextmanager
async def lifespan_deno(
    config_string,
    _app,
    _context,
    state,
):
    deno_path = which("deno")
    if deno_path is not None:
        yield {"deno": deno_path}
        return
    with tempfile.TemporaryDirectory(prefix="deno-") as tempdir:
        downloads_path = pathlib.Path(tempdir)
        compressed_path = pathlib.Path(downloads_path, "compressed.zip")

        github_token = None
        if "github_app" in state:
            github_token = state["github_app"].danger_wide_permissions_token
        elif "github_token" in state:
            github_token = state["github_token"]

        headers = {}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        def do_download():
            request = urllib.request.Request(config_string, headers=headers)
            with urllib.request.urlopen(request) as response:
                compressed_path.write_bytes(response.read())
            with zipfile.ZipFile(compressed_path) as zipfileobj:
                zipfileobj.extractall(downloads_path)
            compressed_path.unlink()

        logger.warning("Downloading deno...")
        await asyncio.get_event_loop().run_in_executor(None, do_download)

        deno_path = downloads_path.joinpath("deno").resolve()
        deno_path.chmod(0o755)
        logger.warning("Finished downloading deno: %s", deno_path)

        yield {"deno": deno_path}


@contextlib.asynccontextmanager
async def lifespan_nodejs(
    config_string,
    _app,
    _context,
    _state,
):
    nodejs_path = which("node")
    if nodejs_path is not None:
        yield {"nodejs": nodejs_path}
        return
    with tempfile.TemporaryDirectory(prefix="nodejs-") as tempdir:
        downloads_path = pathlib.Path(tempdir)

        def do_download():
            with urllib.request.urlopen(config_string) as fileobj:
                with tarfile.open(fileobj=fileobj, mode='r|*') as tarfileobj:
                    tarfileobj.extractall(downloads_path)

        logger.warning("Downloading nodejs...")
        await asyncio.get_event_loop().run_in_executor(None, do_download)

        nodejs_path = list(
            [
                path
                for path in downloads_path.rglob("node")
                if path.parent.stem == "bin"
            ]
        )[0].resolve()
        nodejs_path.chmod(0o755)
        logger.warning("Finished downloading nodejs: %s", nodejs_path)

        yield {"nodejs": nodejs_path}


@contextlib.asynccontextmanager
async def lifespan_gidgethub(
    _config_string,
    _app,
    _context,
    _state,
):
    async with aiohttp.ClientSession(trust_env=True) as session:
        yield {
            "gidgethub": gidgethub.aiohttp.GitHubAPI(
                session,
                # TODO Change actor
                "pdxjohnny",
            ),
        }


class LifespanGitHubAppConfig(BaseModel):
    app_id: int
    private_key: str
    danger_wide_permissions_token: str


@contextlib.asynccontextmanager
async def lifespan_github_app(
    config_string,
    app,
    context,
    _state,
):
    config = yaml.safe_load(
        pathlib.Path(config_string).expanduser().read_text()
    )

    # NOTE SECURITY This token has permissions to all installations!!! Swap
    # it for a more finely scoped token next:
    config["danger_wide_permissions_token"] = gidgethub.apps.get_jwt(
        app_id=config["app_id"],
        private_key=config["private_key"],
    )

    yield {"github_app": LifespanGitHubAppConfig.model_validate(config)}


@contextlib.asynccontextmanager
async def lifespan_github_token(
    config_string,
    app,
    context,
    _state,
):
    if (
        config_string == "try_env"
        and not os.environ.get("GITHUB_TOKEN", "")
    ):
        yield
        return

    if config_string == "env" and not os.environ.get("GITHUB_TOKEN", ""):
        raise ValueError("GITHUB_TOKEN environment variable is not set")

    if config_string in ("try_env", "env"):
        config_string = os.environ["GITHUB_TOKEN"]

    yield {"github_token": config_string}


@contextlib.asynccontextmanager
def policy_engine_context_extra_init_secret_github_token_from_lifespan(
    context, request
):
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" not in secrets and hasattr(context.state, "github_token"):
        secrets["GITHUB_TOKEN"] = context.state.github_token


async def gidgethub_get_access_token(context, request):
    # If we have a fine grained personal access token try using that
    if hasattr(context.state, "github_token"):
        return {"token": context.state.github_token}
    # Find installation ID associated with requesting actor to generated
    # finer grained token
    installation_id = None
    async for data in context.state.gidgethub.getiter(
        "/app/installations",
        jwt=context.state.github_app.danger_wide_permissions_token,
    ):
        if (
            request.context["config"]["env"].get("GITHUB_ACTOR", None)
            == data["account"]["login"]
        ):
            installation_id = data["id"]
            break
        elif request.context["config"]["env"]["GITHUB_REPOSITORY"].startswith(
            data["account"]["login"] + "/"
        ):
            installation_id = data["id"]
            break
    if installation_id is None:
        raise Exception(
            f'App installation not found for GitHub Repository {request.context["config"]["env"]["GITHUB_REPOSITORY"]!r} or Actor {request.context["config"]["env"].get("GITHUB_ACTOR", None)!r}'
        )

    result = await gidgethub.apps.get_installation_access_token(
        context.state.gidgethub,
        installation_id=installation_id,
        app_id=context.state.github_app.app_id,
        private_key=context.state.ggithub_app.private_key,
    )
    result["installation"] = data
    return result


# TODO We need to async init lifespan callbacks and set context.state which
# will be not serializable on initial entry into async_celery_run_workflow
# @app.task(bind=True, base=MyTask)
# https://celery.school/sqlalchemy-session-celery-tasks
async def policy_engine_context_extra_init_secret_github_token_from_github_app(
    context, request
):
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" in secrets or not hasattr(context.state, "gidgethub") or not hasattr(context.state, "github_app"):
        return

    secrets["GITHUB_TOKEN"] = (
        await gidgethub_get_access_token(context, request)
    )["token"]


def make_entrypoint_style_string(obj):
    """
    Celery gets confused about import paths when os.exec()'d due to __main__.
    This fixes that by finding what package this file is within via path
    traversal of directories up the tree until no __init__.py file is found.
    """
    module_name = inspect.getmodule(obj).__name__
    file_path = pathlib.Path(__file__)
    module_path = [file_path.stem]
    if module_name == "__main__":
        module_in_dir_path = file_path.parent
        while module_in_dir_path.joinpath("__init__.py").exists():
            module_path.append(module_in_dir_path.stem)
            module_in_dir_path = module_in_dir_path.parent
        module_name = ".".join(module_path[::-1])
    return f"{module_name}:{obj.__name__}"


class LifespanCallbackWithConfig(BaseModel):
    entrypoint_string: Optional[str] = None
    config_string: Optional[str] = None
    callback: Optional[Callable] = Field(exclude=True, default=None)

    @model_validator(mode="after")
    def load_callback_or_set_entrypoint_string(self) -> Self:
        if self.callback is not None and self.config_string is not None:
            self.entrypoint_string = (
                f"{make_entrypoint_style_string(self.callback)}"
            )
        elif self.entrypoint_string is not None and self.config_string is not None:
            self.callback = list(entrypoint_style_load(self.entrypoint_string))[
                0
            ]
        else:
            raise ValueError(
                "Must specify either (entrypoint_string and config_string) or (callback and config_string) via kwargs"
            )

    def __call__(self, *args, **kwargs):
        return self.callback(self.config_string, *args, **kwargs)


AnnotatedEntrypoint = Annotated[
    Callable,
    PlainSerializer(
        lambda obj: make_entrypoint_style_string(obj)
        if obj is not None and inspect.getmodule(obj) is not None
        else obj,
        return_type=str,
    ),
]


AnnotatedLifespanCallbackWithConfig = Annotated[
    Callable,
    PlainSerializer(
        lambda obj: obj.model_dump() if obj is not None else obj,
        return_type=dict,
    ),
]


class PolicyEngineContext(BaseModel, extra="forbid"):
    app: Optional[Any] = Field(exclude=True, default=None)
    state: Optional[Any] = Field(exclude=True, default=None)
    lifespan: Union[
        List[Dict[str, Any]], List[AnnotatedLifespanCallbackWithConfig]
    ] = Field(
        default_factory=lambda: [],
    )
    extra_inits: Union[List[str], List[AnnotatedEntrypoint]] = Field(
        default_factory=lambda: [],
    )
    extra_inits_config: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {}
    )

    @field_validator("extra_inits")
    @classmethod
    def parse_extra_inits(cls, extra_inits, _info):
        return list(
            [
                extra_init
                if not isinstance(extra_init, str)
                else list(entrypoint_style_load(extra_init))[0]
                for extra_init in extra_inits
            ]
        )

    @field_validator("lifespan")
    @classmethod
    def parse_lifespan(cls, lifespan, _info):
        return list(
            [
                lifespan_callback
                if isinstance(lifespan_callback, LifespanCallbackWithConfig)
                else LifespanCallbackWithConfig(**lifespan_callback)
                for lifespan_callback in lifespan
            ]
        )


fastapi_current_app = contextvars.ContextVar("fastapi_current_app")
fastapi_current_request = contextvars.ContextVar("fastapi_current_request")


@contextlib.asynccontextmanager
async def async_celery_setup_workflow(context, request):
    if isinstance(context, str):
        context = PolicyEngineContext.model_validate_json(context)
    if isinstance(request, str):
        request = PolicyEngineRequest.model_validate_json(request)
    stack = request.stack

    workflow = request.workflow

    async with contextlib.AsyncExitStack() as async_exit_stack:
        with contextlib.ExitStack() as exit_stack:
            if "async_exit_stack" not in request.context:
                request.context["async_exit_stack"] = async_exit_stack
            if "exit_stack" not in request.context:
                request.context["exit_stack"] = exit_stack
            if context.app is None or context.state is None:
                await request.context["async_exit_stack"].enter_async_context(
                    startup_fastapi_app_policy_engine_context(
                        fastapi_current_app.get()
                        if int(os.environ.get("NO_CELERY", "0"))
                        else celery_current_app,
                        context,
                    )
                )
            await celery_run_workflow_context_init(
                context,
                request,
            )
            if stack is None or len(stack) == 0:
                stack = celery_run_workflow_context_stack_make_new(
                    context, request, workflow.name,
                )
                stack["secrets"] = copy.deepcopy(request.context["secrets"])
                celery_run_workflow_context_stack_push(context, request, stack)
            yield (context, request)


async def async_celery_run_workflow(context, request):
    async with async_celery_setup_workflow(context, request) as (
        context,
        request,
    ):
        # TODO Kick off jobs in parallel / dep matrix
        for job_name, job in request.workflow.jobs.items():
            old_stack = request.context["stack"][-1]
            stack = celery_run_workflow_context_stack_make_new(
                context, request, job_name,
            )
            celery_run_workflow_context_stack_push(context, request, stack)
            # Don't allow messing with outputs at workflow scope (copy.deepcopy)
            stack["outputs"] = copy.deepcopy(old_stack["outputs"])
            # Don't allow messing with secrets at workflow scope (copy.deepcopy)
            stack["secrets"] = copy.deepcopy(old_stack["secrets"])
            # Run steps
            for i, step in enumerate(job.steps):
                old_stack = request.context["stack"][-1]
                stack = celery_run_workflow_context_stack_make_new(context, request, f"{i + 1} / {len(job.steps)}")
                celery_run_workflow_context_stack_push(context, request, stack)
                if step.shell:
                    stack["shell"] = step.shell
                # Keep the weakref, outputs should mod via pointer with job
                stack["outputs"] = old_stack["outputs"]
                # Don't allow messing with secrets (copy.deepcopy)
                stack["secrets"] = copy.deepcopy(old_stack["secrets"])
                stack["env"].update(step_build_env(context, request, step))
                stack["env"].update(step_build_inputs(context, request, step))
                try:
                    # step_index is tuple of (current index, length of steps)
                    execute_step(context, request, step)
                except Exception as step_error:
                    # TODO error like app: and state: in PolicyEngineContext
                    if int(os.environ.get("DEBUG", "0")):
                        step_error = traceback.format_exc()
                        traceback.print_exc(file=sys.stderr)
                    request.context["stack"][-1]["error"] = step_error
                    if request.context["stack"][-2]["error"] is None:
                        request.context["stack"][-2]["error"] = step_error
                finally:
                    celery_run_workflow_context_stack_pop(context, request)
            job_error = request.context["stack"][-1]["error"]
            if job_error is not None:
                if not isinstance(job_error, Exception):
                    job_error = Exception(job_error)
                raise job_error


    detail = PolicyEngineComplete(
        id="",
        exit_status=PolicyEngineCompleteExitStatuses.SUCCESS,
        outputs={},
    )
    request_status = PolicyEngineStatus(
        status=PolicyEngineStatuses.COMPLETE,
        detail=detail,
    )
    return request_status


async def no_celery_async_celery_run_workflow(context, request):
    try:
        return (
            await async_celery_run_workflow(context, request)
        ).model_dump_json()
    except Exception as error:
        if int(os.environ.get("DEBUG", "0")):
            error = traceback.format_exc()
        detail = PolicyEngineComplete(
            id="",
            exit_status=PolicyEngineCompleteExitStatuses.FAILURE,
            annotations={"error": [str(error)]},
        )
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.COMPLETE,
            detail=detail,
        )
        return request_status.model_dump_json()


@celery_task(no_celery_async=no_celery_async_celery_run_workflow)
def celery_run_workflow(context, request):
    return asyncio.get_event_loop().run_until_complete(
        no_celery_async_celery_run_workflow(context, request),
    )


@contextlib.asynccontextmanager
async def startup_fastapi_app_policy_engine_context(
    app,
    context: Optional[Dict[str, Any]] = None,
):
    state = {}
    if context is None:
        context = {}
    if isinstance(context, str):
        context = PolicyEngineContext.model_validate_json(context)
    elif not isinstance(context, PolicyEngineContext):
        context = PolicyEngineContext.model_validate(context)
    context.app = app
    state["context"] = context
    async with contextlib.AsyncExitStack() as async_exit_stack:
        for lifespan_callback in context.lifespan:
            state_update = await async_exit_stack.enter_async_context(
                lifespan_callback(app, context, state),
            )
            if state_update:
                state.update(state_update)
        context.state = types.SimpleNamespace(**state)
        yield state


def make_fastapi_app(
    *,
    context: Optional[Dict[str, Any]] = None,
):
    app = FastAPI(
        lifespan=lambda app: startup_fastapi_app_policy_engine_context(
            app,
            context,
        ),
    )

    @app.get("/request/status/{request_id}")
    async def route_policy_engine_status(
        request_id: str,
        fastapi_request: Request,
    ) -> PolicyEngineStatus:
        global celery_app
        fastapi_current_app.set(fastapi_request.app)
        fastapi_current_request.set(fastapi_request)
        async with fastapi_request.state.no_celery_async_results_lock:
            request_task = AsyncResult(request_id, app=celery_app)
            request_task_state = request_task.state
        if request_task_state == "PENDING":
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.IN_PROGRESS,
                detail=PolicyEngineInProgress(
                    id=request_id,
                    # TODO Provide previous status updates?
                    status_updates={},
                ),
            )
        elif request_task_state in ("SUCCESS", "FAILURE"):
            async with fastapi_request.state.no_celery_async_results_lock:
                status_json_string = request_task.get()
            status = json.loads(status_json_string)
            detail_class = DETAIL_CLASS_MAPPING[status["status"]]
            status["detail"] = detail_class(**status["detail"])
            request_status = PolicyEngineStatus(**status)
            request_status.detail.id = request_id
        else:
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.UNKNOWN,
                detail=PolicyEngineUnknown(
                    id=request_id,
                ),
            )
        return request_status

    @app.post("/request/create")
    async def route_request(
        request: PolicyEngineRequest,
        fastapi_request: Request,
    ) -> PolicyEngineStatus:
        fastapi_current_app.set(fastapi_request.app)
        fastapi_current_request.set(fastapi_request)
        # TODO Handle when submitted.status cases
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.SUBMITTED,
            detail=PolicyEngineSubmitted(
                id=str(
                    (
                        await celery_run_workflow.asyncio_delay(
                            fastapi_request.state.context.model_dump_json(),
                            request.model_dump_json(),
                        )
                    ).id
                ),
            ),
        )
        return request_status


    @app.post("/webhook/github")
    async def github_webhook_endpoint(request: Request):
        fastapi_current_app.set(request.app)
        fastapi_current_request.set(request)
        # TODO(security) Set webhook secret as kwarg in from_http() call
        event = sansio.Event.from_http(request.headers, await request.body())
        # TODO Configurable events routed to workflows, issue ops
        if event.event not in ("push", "pull_request"):
            return
        # Copy context for this request
        context = PolicyEngineContext.model_validate_json(
            request.state.context.model_dump_json()
        )
        context.app = request.app
        context.state = request.state
        # Router does not return results of dispatched functions
        task_id = await check_suite_requested_triggers_run_workflows(
            event,
            context.state.gidgethub,
            context,
        )
        return PolicyEngineStatus(
            status=PolicyEngineStatuses.SUBMITTED,
            detail=PolicyEngineSubmitted(id=task_id),
        )

    return app


class NoLockNeeded:
    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_value, _exc_traceback):
        pass


@contextlib.asynccontextmanager
async def lifespan_no_celery(
    config_string,
    _app,
    _context,
    _state,
):
    lock = asyncio.Lock()
    if not int(config_string):
        lock = NoLockNeeded()
    yield {
        "no_celery_async_results_lock": lock,
        "no_celery_async_results": {},
    }


DEFAULT_LIFESPAN_CALLBACKS = [
    LifespanCallbackWithConfig(
        callback=lifespan_no_celery,
        config_string=os.environ.get("NO_CELERY", "0"),
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_gidgethub,
        config_string="",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_github_token,
        config_string="try_env",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_deno,
        config_string="https://github.com/denoland/deno/releases/download/v1.41.3/deno-x86_64-unknown-linux-gnu.zip",
    ),
    LifespanCallbackWithConfig(
        callback=lifespan_nodejs,
        config_string="https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz",
    ),
]
for callback_key, entrypoint_string in os.environ.items():
    if not callback_key.startswith("LIFESPAN_CALLBACK_"):
        continue
    config_key = callback_key.replace("CALLBACK", "CONFIG", 1)
    if not config_key in os.environ:
        raise Exception(
            f"{callback_key} set in environment. {config_key} required but not found."
        )
    DEFAULT_LIFESPAN_CALLBACKS.append(
        LifespanCallbackWithConfig(
            entrypoint_string=entrypoint_string,
            config_string=os.environ[config_key],
        )
    )


async def background_task_celery_worker():
    # celery_app.worker_main(argv=["worker", "--loglevel=INFO"])
    celery_app.tasks["tasks.celery_run_workflow"] = celery_run_workflow
    celery_app.tasks["tasks.workflow_run_github_app_gidgethub"] = (
        workflow_run_github_app_gidgethub
    )
    async with startup_fastapi_app_policy_engine_context(
        celery_app,
        context={
            "lifespan": DEFAULT_LIFESPAN_CALLBACKS,
            "extra_inits": [
                policy_engine_context_extra_init_secret_github_token_from_github_app,
                policy_engine_context_extra_init_secret_github_token_from_lifespan,
            ],
        },
    ) as state:
        # Ensure these are always in the path so they don't download on request
        with prepend_to_path(
            state["deno"].parent, state["nodejs"].parent, env=os.environ,
        ) as env:
            celery_app.Worker(app=celery_app).start()


def celery_worker_exec_with_python():
    import nest_asyncio

    nest_asyncio.apply()
    asyncio.run(background_task_celery_worker())


module_name, function_name = make_entrypoint_style_string(celery_worker_exec_with_python).split(":")
CELERY_WORKER_EXEC_WITH_PYTHON = f"import {module_name}; {module_name}.{function_name}()"


@contextlib.contextmanager
def subprocess_celery_worker(**kwargs):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            CELERY_WORKER_EXEC_WITH_PYTHON,
        ],
        **kwargs,
    )
    try:
        yield proc
    finally:
        proc.terminate()


@pytest.fixture
def pytest_fixture_background_task_celery_worker():
    if int(os.environ.get("NO_CELERY", "0")):
        yield
        return
    with subprocess_celery_worker() as proc:
        yield proc


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context,workflow",
    [
        [
            {
                "lifespan": DEFAULT_LIFESPAN_CALLBACKS,
                "extra_inits": [
                    policy_engine_context_extra_init_secret_github_token_from_github_app,
                    policy_engine_context_extra_init_secret_github_token_from_lifespan,
                ],
            },
            {
                "jobs": {
                    "TEST_JOB": {
                        "steps": [
                            {
                                "id": "greeting-step",
                                "env": {
                                    "REPO_NAME": "${{ github.event.inputs.repo_name }}",
                                },
                                "run": "echo hello=$REPO_NAME | tee -a $GITHUB_OUTPUT",
                            },
                            {
                                "uses": "actions/github-script@v7",
                                "env": {
                                    "GREETING": "${{ steps.greeting-step.outputs.hello }}",
                                },
                                "with": {
                                    "script": 'console.log(`Hello ${process.env["GREETING"]}`)',
                                },
                            },
                        ],
                    },
                },
            },
        ],
        [
            {
                "lifespan": DEFAULT_LIFESPAN_CALLBACKS,
                "extra_inits": [
                    policy_engine_context_extra_init_secret_github_token_from_github_app,
                    policy_engine_context_extra_init_secret_github_token_from_lifespan,
                ],
            },
            textwrap.dedent(
                """
                on:
                  push:
                    branches:
                    - main

                jobs:
                  test:
                    runs-on: self-hosted
                    steps:
                    - uses: actions/checkout@v4
                    - run: |
                        echo Hello World
                """
            ),
        ],
    ],
)
async def test_read_main(
    pytest_fixture_background_task_celery_worker,
    context,
    workflow,
):
    app = make_fastapi_app(context=context)

    policy_engine_request = PolicyEngineRequest(
        inputs={
            "repo_name": "scitt-community/scitt-api-emulator",
        },
        context={
            "config": {
                "env": {
                    "GITHUB_REPOSITORY": "scitt-community/scitt-api-emulator",
                    "GITHUB_API": "https://api.github.com/",
                    "GITHUB_ACTOR": "pdxjohnny",
                    "GITHUB_ACTOR_ID": "1234567",
                },
            },
        },
        # URN for receipt for policy / transparency-configuration
        workflow=workflow,
    )
    policy_engine_request_serialized = policy_engine_request.model_dump_json()

    with TestClient(app) as client:
        # Submit
        response = client.post(
            "/request/create", content=policy_engine_request_serialized
        )
        assert response.status_code == 200, json.dumps(
            response.json(), indent=4
        )
        policy_engine_request_status = response.json()
        assert (
            PolicyEngineStatuses.SUBMITTED.value
            == policy_engine_request_status["status"]
        )

        policy_engine_request_id = policy_engine_request_status["detail"]["id"]

        # Check complete
        for _ in range(0, 1000):
            response = client.get(f"/request/status/{policy_engine_request_id}")
            assert response.status_code == 200, json.dumps(
                response.json(), indent=4
            )
            policy_engine_request_status = response.json()
            policy_engine_request_id = policy_engine_request_status["detail"][
                "id"
            ]
            if (
                PolicyEngineStatuses.IN_PROGRESS.value
                != policy_engine_request_status["status"]
            ):
                break
            time.sleep(0.01)

        assert (
            PolicyEngineStatuses.COMPLETE.value
            == policy_engine_request_status["status"]
        )

        # Check completed results
        policy_engine_request_completed = policy_engine_request_status["detail"]


import asyncio
import importlib
import os
import sys
import traceback

import aiohttp
from aiohttp import web
import cachetools
from gidgethub import aiohttp as gh_aiohttp
from gidgethub import routing
from gidgethub import sansio


router = routing.Router()
cache = cachetools.LRUCache(maxsize=500)


# https://docs.github.com/en/enterprise-cloud@latest/rest/checks/runs?apiVersion=2022-11-28
# https://docs.github.com/en/enterprise-cloud@latest/webhooks/webhook-events-and-payloads?actionType=requested_action#check_run
# https://docs.github.com/en/enterprise-cloud@latest/rest/guides/using-the-rest-api-to-interact-with-checks?apiVersion=2022-11-28#check-runs-and-requested-actions
# @router.register("check_run", action="requested_action")
# @router.register("check_run", action="rerequested")


async def async_workflow_run_github_app_gidgethub(
    context,
    request,
    event,
    task_id,
):
    event = sansio.Event(
        event["data"],
        event=event["event"],
        delivery_id=event["delivery_id"],
    )
    async with async_celery_setup_workflow(context, request) as (
        context,
        request,
    ):
        access_token_response = await gidgethub_get_access_token(
            context, request
        )
        # access_token_response["installation"] contains installation info
        installation_jwt = access_token_response["token"]
        started_at = datetime.datetime.now()
        full_name = event.data["repository"]["full_name"]
        # NOTE BUG XXX https://support.github.com/ticket/personal/0/2686424
        # The REST check-run endpoint docs say those routes work with fine
        # grained personal access tokens, but they also say they only work with
        # GitHub Apps, I keep getting Resource not accessible by personal access
        # token when I make a request. Is this an inconsistency with the
        # documentation? Should it work with fine grained PAT's as listed? I've
        # enabled Read & Write on status checks for the fine grained PAT I'm
        # using.
        # https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#create-a-check-run
        check_run_id = None
        if hasattr(context.state, "github_app"):
            # GitHub App, use check-runs API
            url = f"https://api.github.com/repos/{full_name}/check-runs"
            data = {
                "name": request.workflow.name,
                "head_sha": event.data["after"],
                "status": "in_progress",
                "external_id": task_id,
                "started_at": started_at.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "output": {
                    "title": request.workflow.name,
                    "summary": "",
                    "text": "",
                },
            }
        else:
            # Personal Access Token, use commit status API
            url = f'https://api.github.com/repos/{full_name}/statuses/{event.data["after"]}'
            data = {
                "state": "pending",
                # TODO FQDN from lifespan config
                "target_url": f"https://example.com/build/status/{task_id}",
                "description": "TODO description TODO",
                "context": f"policy_engine/workflow/{request.workflow.name}",
            }
        check_run_result = await context.state.gidgethub.post(
            url, data=data, jwt=installation_jwt
        )
        check_run_id = check_run_result["id"]
        status = await async_celery_run_workflow(context, request)
        if hasattr(context.state, "github_app"):
            # GitHub App, use check-runs API
            url = f"https://api.github.com/repos/{full_name}/check-runs/{check_run_id}"
            data = {
                "name": request.workflow.name,
                "started_at": started_at.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "status": "completed",
                "conclusion": status.detail.exit_status.value,
                "completed_at": datetime.datetime.now()
                .astimezone(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "output": {
                    "title": "Mighty Readme report",
                    "summary": "There are 0 failures, 2 warnings, and 1 notices.",
                    "text": "You may have some misspelled words on lines 2 and 4. You also may want to add a section in your README about how to install your app.",
                    "annotations": [
                        {
                            "path": "README.md",
                            "annotation_level": "warning",
                            "title": "Spell Checker",
                            "message": "Check your spelling for '''banaas'''.",
                            "raw_details": "Do you mean '''bananas''' or '''banana'''?",
                            "start_line": 2,
                            "end_line": 2,
                        },
                        {
                            "path": "README.md",
                            "annotation_level": "warning",
                            "title": "Spell Checker",
                            "message": "Check your spelling for '''aples'''",
                            "raw_details": "Do you mean '''apples''' or '''Naples'''",
                            "start_line": 4,
                            "end_line": 4,
                        },
                    ],
                    "images": [
                        {
                            "alt": "Super bananas",
                            "image_url": "http://example.com/images/42",
                        }
                    ],
                },
            }
            await context.state.gidgethub.patch(
                url, data=data, jwt=installation_jwt
            )
        else:
            # Personal Access Token, use commit status API
            url = f'https://api.github.com/repos/{full_name}/statuses/{event.data["after"]}'
            data = {
                # TODO Handle failure
                "state": "success",
                "target_url": f"https://example.com/build/status/{task_id}",
                "description": "TODO description TODO",
                "context": f"policy_engine/workflow/{request.workflow.name}",
            }
            await context.state.gidgethub.post(
                url, data=data, jwt=installation_jwt
            )
            # TODO Create commit comment with same content as GitHub App would
            # https://docs.github.com/en/enterprise-cloud@latest/rest/commits/comments?apiVersion=2022-11-28#create-a-commit-comment

    detail = PolicyEngineComplete(
        id="",
        exit_status=PolicyEngineCompleteExitStatuses.SUCCESS,
        outputs={},
    )
    request_status = PolicyEngineStatus(
        status=PolicyEngineStatuses.COMPLETE,
        detail=detail,
    )
    return request_status


async def no_celery_async_workflow_run_github_app_gidgethub(
    self, context, request, event
):
    try:
        return (
            await async_workflow_run_github_app_gidgethub(
                context,
                request,
                event,
                self.request.id,
            )
        ).model_dump_json()
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        detail = PolicyEngineComplete(
            id="",
            exit_status=PolicyEngineCompleteExitStatuses.FAILURE,
            annotations={"error": [str(error)]},
        )
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.COMPLETE,
            detail=detail,
        )
        return request_status.model_dump_json()


@celery_task(
    bind=True, no_celery_async=no_celery_async_workflow_run_github_app_gidgethub
)
def workflow_run_github_app_gidgethub(self, context, request, event):
    return asyncio.get_event_loop().run_until_complete(
        no_celery_async_workflow_run_github_app_gidgethub(
            self,
            context,
            request,
            event,
        )
    )


# @router.register("check_suite", action="requested")
@router.register("push")
@router.register("pull_request", action="opened")
@router.register("pull_request", action="synchronize")
async def check_suite_requested_triggers_run_workflows(
    event,
    gh,
    context,
):
    return str(
        (
            await workflow_run_github_app_gidgethub.asyncio_delay(
                context.model_dump_json(),
                PolicyEngineRequest(
                    context={
                        "config": {
                            "env": {
                                "GITHUB_ACTOR": event.data["sender"]["login"],
                                "GITHUB_REPOSITORY": event.data["repository"][
                                    "full_name"
                                ],
                            },
                        },
                    },
                    # TODO workflow router to specify which webhook trigger which workflows
                    workflow=textwrap.dedent(
                        """
                        name: 'My Cool Status Check'
                        on:
                          push:
                            branches:
                            - main

                        jobs:
                          test:
                            runs-on: self-hosted
                            steps:
                            - uses: actions/checkout@v4
                            - run: |
                                echo Hello World
                        """
                    ),
                ).model_dump_json(),
                event.__dict__,
            )
        ).id
    )


@pytest.mark.asyncio
async def test_github_app_gidgethub_github_webhook(
    pytest_fixture_background_task_celery_worker,
):
    context = {
        "lifespan": DEFAULT_LIFESPAN_CALLBACKS,
        "extra_inits": [
            policy_engine_context_extra_init_secret_github_token_from_github_app,
            policy_engine_context_extra_init_secret_github_token_from_lifespan,
        ],
    }

    app = make_fastapi_app(context=context)

    data = {
        "after": "a1b70ee3b0343adc24e3b75314262e43f5c79cc2",
        "repository": {
            "full_name": "pdxjohnny/scitt-api-emulator",
        },
        "sender": {
            "login": "pdxjohnny",
        },
    }
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "42",
    }

    with TestClient(app) as client:
        # Submit
        response = client.post(
            "/webhook/github",
            headers=headers,
            json=data,
        )
        assert response.status_code == 200, json.dumps(
            response.json(), indent=4
        )
        policy_engine_request_status = response.json()
        assert (
            PolicyEngineStatuses.SUBMITTED.value
            == policy_engine_request_status["status"]
        )

        policy_engine_request_id = policy_engine_request_status["detail"]["id"]

        # Check complete
        for _ in range(0, 1000):
            response = client.get(f"/request/status/{policy_engine_request_id}")
            assert response.status_code == 200, json.dumps(
                response.json(), indent=4
            )
            policy_engine_request_status = response.json()
            policy_engine_request_id = policy_engine_request_status["detail"][
                "id"
            ]
            if (
                PolicyEngineStatuses.IN_PROGRESS.value
                != policy_engine_request_status["status"]
            ):
                break
            time.sleep(0.01)

        assert (
            PolicyEngineStatuses.COMPLETE.value
            == policy_engine_request_status["status"]
        )

        # Check completed results
        policy_engine_request_completed = policy_engine_request_status["detail"]


class StandaloneApplication(gunicorn.app.base.BaseApplication):
    # https://docs.gunicorn.org/en/stable/custom.html
    # https://www.uvicorn.org/deployment/#gunicorn

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def cli_worker(args):
    os.execvpe(
        sys.executable,
        [
            sys.executable,
            "-c",
            CELERY_WORKER_EXEC_WITH_PYTHON,
        ],
        env={
            **os.environ,
            **{
                f"LIFESPAN_CALLBACK_{i}": lifespan_callback.entrypoint_string
                for i, lifespan_callback in enumerate(args.lifespan)
            },
            **{
                f"LIFESPAN_CONFIG_{i}": lifespan_callback.config_string
                for i, lifespan_callback in enumerate(args.lifespan)
            },
        },
    )


def cli_api(args):
    app = make_fastapi_app(
        context={
            "extra_inits": args.request_context_extra_inits,
            "lifespan": args.lifespan,
        },
    )
    options = {
        "bind": args.bind,
        "workers": args.workers,
        "worker_class": "uvicorn.workers.UvicornWorker",
    }
    StandaloneApplication(app, options).run()


async def client_create(
    endpoint: str,
    repository: str,
    workflow: Union[str, dict, PolicyEngineWorkflow],
    input: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
    session: Optional[aiohttp.ClientSession] = None,
):
    if isinstance(workflow, str):
        if workflow.startswith("https://"):
            # TODO Download workflow, optionally supply auth token
            raise NotImplementedError("Workflows from URLs not implemented")
        elif workflow.endswith(".yml") or workflow.endswith(".yaml"):
            workflow = pathlib.Path(workflow).expanduser().read_text()
    request = PolicyEngineRequest(
        inputs=dict(input),
        context={
            "config": {
                "env": {
                    "GITHUB_REPOSITORY": repository,
                    "GITHUB_API": "https://api.github.com/",
                    # TODO Lookup from auth response?
                    # "GITHUB_ACTOR": actor,
                    # "GITHUB_ACTOR_ID": actor_id,
                },
            },
        },
        workflow=workflow,
    )
    if context is not None:
        request.context.update(context)

    async with contextlib.AsyncExitStack() as async_exit_stack:
        if session is None:
            session = await async_exit_stack.enter_async_context(
                aiohttp.ClientSession(trust_env=True),
            )
        url = f"{endpoint}/request/create"
        async with session.post(url, json=request.model_dump()) as response:
            try:
                status = PolicyEngineStatus.model_validate(await response.json())
            except:
                raise Exception(await response.text())

            if PolicyEngineStatuses.SUBMITTED != status.status:
                raise Exception(status)

    return status


async def client_status(
    endpoint: str,
    task_id: str,
    poll_interval_in_seconds: Union[int, float] = 0.01,
    timeout: Optional[int] = None,
    session: Optional[aiohttp.ClientSession] = None,
):
    async with contextlib.AsyncExitStack() as async_exit_stack:
        if session is None:
            session = await async_exit_stack.enter_async_context(
                aiohttp.ClientSession(trust_env=True),
            )
        # TODO Make this an argument or provide another command to poll + wss://
        # Check complete
        time_elapsed = 0.0
        while timeout == 0 or time_elapsed < timeout:
            url = f"{endpoint}/request/status/{task_id}"
            async with session.get(url) as response:
                try:
                    status = PolicyEngineStatus.model_validate(await response.json())
                except:
                    raise Exception(await response.text())
            if PolicyEngineStatuses.IN_PROGRESS != status.status:
                break
            await asyncio.sleep(poll_interval_in_seconds)
            time_elapsed += poll_interval_in_seconds

        if PolicyEngineStatuses.COMPLETE != status.status:
            raise Exception(f"Task timeout reached: {status!r}")

    return status


def cli_async_output(func, args):
    args = vars(args)
    output_args = {
        "output_format": "json",
        "output_file": sys.stdout,
    }
    del args["func"]
    for key in output_args:
        if key in args:
            output_args[key] = args[key]
            del args[key]
    output_args = types.SimpleNamespace(**output_args)
    coro = func(**args)
    result = asyncio.run(coro)
    if hasattr(result, "model_dump_json"):
        result = json.loads(result.model_dump_json())
    if output_args.output_format == "json":
        serialized = json.dumps(result, indent=4, sort_keys=True)
    elif output_args.output_format == "yaml":
        serialized = yaml.dump(result, default_flow_style=False)[:-1]
    else:
        raise NotImplementedError("Can only output JSON and YAML")
    print(serialized, file=output_args.output_file)


def parser_add_argument_lifespan(parser):
    parser.add_argument(
        "--lifespan",
        nargs=2,
        action="append",
        metavar=("entrypoint", "config"),
        default=DEFAULT_LIFESPAN_CALLBACKS,
        help=f"entrypoint.style:path ~/path/to/assocaited/config.json for startup and shutdown async context managers. Yield from to set fastapi|celery.app.state",
    )


def cli():
    # TODO Take sys.argv as args to parse as optional
    estimated_number_of_workers = number_of_workers()

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(help="sub-command help")
    parser.set_defaults(func=lambda _: None)

    parser_worker = subparsers.add_parser("worker", help="Run Celery worker")
    parser_worker.set_defaults(func=cli_worker)
    parser_add_argument_lifespan(parser_worker)

    parser_api = subparsers.add_parser("api", help="Run API server")
    parser_api.set_defaults(func=cli_api)
    parser_add_argument_lifespan(parser_api)
    parser_api.add_argument(
        "--bind",
        default="127.0.0.1:8080",
        help="Interface to bind on, default: 127.0.0.1:8080",
    )
    parser_api.add_argument(
        "--workers",
        type=int,
        default=estimated_number_of_workers,
        help=f"Number of workers, default: {estimated_number_of_workers}",
    )
    parser_api.add_argument(
        "--request-context-extra-inits",
        nargs="+",
        default=[
            policy_engine_context_extra_init_secret_github_token_from_github_app,
            policy_engine_context_extra_init_secret_github_token_from_lifespan,
        ],
        help=f"Entrypoint style paths for PolicyEngineContext.extra_inits",
    )

    parser_client = subparsers.add_parser("client", help="Interact with API")
    parser_client.set_defaults(func=lambda _args: None)
    client_subparsers = parser_client.add_subparsers(help="Client")
    parser_client.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout to wait for status to move to complete. 0 is don't wait just check status",
    )
    parser_client.add_argument(
        "--endpoint",
        "-e",
        required=True,
        help="Endpoint to connect to",
    )
    parser_client.add_argument(
        "--output-format",
        default="json",
        help="Output format (json, yaml)",
    )
    parser_client.add_argument(
        "--output-file",
        default=sys.stdout,
        type=argparse.FileType('w', encoding='UTF-8'),
        help="Output file",
    )

    parser_client_create = client_subparsers.add_parser("create", help="Create workflow execution request")
    parser_client_create.set_defaults(
        func=lambda args: cli_async_output(client_create, args),
    )
    parser_client_create.add_argument(
        "--input",
        "-i",
        nargs=2,
        action="append",
        metavar=("key", "value"),
        default=[],
        help="Inputs to workflow",
    )
    parser_client_create.add_argument(
        "--context",
        "-c",
        type=json.loads,
        default={},
        help="JSON string for updates to context",
    )
    parser_client_create.add_argument(
        "--workflow",
        "-w",
        required=True,
        help="Workflow to run",
    )
    parser_client_create.add_argument(
        "--repository",
        "-R",
        required=True,
        help="Repository to run as",
    )

    parser_client_status = client_subparsers.add_parser("status", help="Status of workflow execution request")
    parser_client_status.set_defaults(
        func=lambda args: cli_async_output(client_status, args),
    )
    parser_client_status.add_argument(
        "--task-id",
        "-t",
        default=None,
        help="Task ID to monitor status of",
    )
    parser_client_status.add_argument(
        "--poll-interval-in-seconds",
        "-p",
        type=float,
        default=0.01,
        help="Time between poll re-request of status route",
    )

    args = parser.parse_args()

    if hasattr(args, "lifespan"):
        args.lifespan = list(
            map(
                lambda arg: arg
                if isinstance(arg, LifespanCallbackWithConfig)
                else LifespanCallbackWithConfig(
                    entrypoint_string=arg[0],
                    config_string=arg[1],
                ),
                args.lifespan,
            )
        )

    args.func(args)


if __name__ == "__main__":
    cli()
