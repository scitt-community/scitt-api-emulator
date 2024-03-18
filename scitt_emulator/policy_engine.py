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
TASK_ID=$(curl -X PUT -H "Content-Type: application/json" -d @<(cat request.yml | sed -e "s/__GITHUB_TOKEN_FROM_ENV__/$(gh auth token)/g" | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost:8080/request/create  | jq -r .detail.id)
curl http://localhost:8080/request/status/$TASK_ID | jq
```
"""
import os
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
import inspect
import argparse
import tempfile
import textwrap
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


from scitt_emulator.plugin_helpers import entrypoint_style_load


class PolicyEngineCompleteExitStatuses(enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class PolicyEngineComplete(BaseModel, extra="forbid"):
    id: str
    exit_status: PolicyEngineCompleteExitStatuses
    outputs: Optional[Dict[str, Any]] = Field(default_factory=lambda: {})


class PolicyEngineStatuses(enum.Enum):
    SUBMITTED = "submitted"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    UNKNOWN = "unknown"


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


class PolicyEngineStatus(BaseModel, extra="forbid"):
    status: PolicyEngineStatuses
    detail: Union[
        PolicyEngineSubmitted,
        PolicyEngineInProgress,
        PolicyEngineComplete,
        PolicyEngineUnknown,
    ]


DETAIL_CLASS_MAPPING = {
    PolicyEngineStatuses.SUBMITTED.value: PolicyEngineSubmitted,
    PolicyEngineStatuses.IN_PROGRESS.value: PolicyEngineInProgress,
    PolicyEngineStatuses.COMPLETE.value: PolicyEngineComplete,
    PolicyEngineStatuses.UNKNOWN.value: PolicyEngineUnknown,
}


class PolicyEngineWorkflowJobStep(BaseModel, extra="forbid"):
    id: Optional[str] = None
    # TODO Alias doesn't seem to be working here
    # if_condition: Optional[str] = Field(default=None, alias="if")
    # TODO Implement step if conditionals, YAML load output of eval_js
    if_condition: Optional[str] = Field(default=None)
    name: Optional[str] = None
    uses: Optional[str] = None
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
    backend="redis://localhost",
    broker="redis://localhost",
    broker_connection_retry_on_startup=True,
)


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

    # Find property accessors in dot notation and replace dot notation
    # with bracket notation. Avoids replacements within strings.
    code_block = transform_property_accessors(code_block)

    javascript_path = pathlib.Path(tempdir, "check_output.js")
    # TODO vars and env contexts
    javascript_path.write_text(
        textwrap.dedent(
            r"""
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
        ["deno", "repl", "-q", f"--eval-file={javascript_path.resolve()}"],
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
    context = PolicyEngineContext()
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
    with contextlib.ExitStack() as exit_stack:
        if "exit_stack" not in request.context:
            request.context["exit_stack"] = exit_stack
        await celery_run_workflow_context_init(
            context,
            request,
        )
        stack = celery_run_workflow_context_stack_make_new(context, request)
        stack["secrets"] = copy.deepcopy(request.context["secrets"])
        celery_run_workflow_context_stack_push(
            context,
            request,
            stack,
        )

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
                outputs[current_output_key] = current_output_value
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
        tee_proc = subprocess.Popen(["tee", stack["console_output"]])
        try:
            completed_proc = subprocess.run(
                [
                    "node",
                    extracted_path.joinpath(action_yaml_obj["runs"]["main"]),
                ],
                cwd=stack["workspace"],
                stdin=request.context["devnull"],
                stdout=tee_proc.stdin,
                stderr=tee_proc.stdin,
                env=env,
            )
            completed_proc.check_returncode()
        finally:
            tee_proc.terminate()
    elif action_yaml_obj["runs"]["using"] == "composite":
        composite_steps = action_yaml_obj["runs"]["steps"]
        # TODO HACK Remove by fixing PyDantic Field.alias = True deserialization
        for composite_step in composite_steps:
            if "with" in composite_step:
                composite_step["with_inputs"] = composite_step["with"]
                del composite_step["with"]
        stack = celery_run_workflow_context_stack_make_new(context, request)
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

    step_io_update_stack_output_and_env_github_actions(context, request, step)


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

    temp_script_path.write_text(step.run)

    shell = stack.get("shell", "bash -xe")
    if "{0}" not in shell:
        shell += " {0}"
    shell = shell.replace("{0}", str(temp_script_path.resolve()))
    cmd = shlex.split(shell)

    env = copy.deepcopy(os.environ)
    env.update(stack["env"])
    tee_proc = subprocess.Popen(["tee", stack["console_output"]])
    try:
        completed_proc = subprocess.run(
            cmd,
            cwd=stack["workspace"],
            stdin=request.context["devnull"],
            stdout=tee_proc.stdin,
            stderr=tee_proc.stdin,
            env=env,
        )
        completed_proc.check_returncode()
    finally:
        tee_proc.terminate()

    step_io_update_stack_output_and_env_github_actions(
        context,
        request,
        step,
    )


def execute_step(context, request, step):
    old_stack = request.context["stack"][-1]
    stack = celery_run_workflow_context_stack_make_new(context, request)
    celery_run_workflow_context_stack_push(context, request, stack)
    # Keep the weakref, outputs should mod via pointer
    stack["outputs"] = old_stack["outputs"]
    # Don't allow messing with secrets (use copy.deepcopy)
    stack["secrets"] = copy.deepcopy(old_stack["secrets"])
    stack["env"].update(step_build_env(context, request, step))
    stack["env"].update(step_build_inputs(context, request, step))

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

    celery_run_workflow_context_stack_pop(context, request)


def celery_run_workflow_context_stack_make_new(context, request):
    old_stack = request.context
    if request.context["stack"]:
        old_stack = request.context["stack"][-1]
    stack = {
        "outputs": {},
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
    stack["exit_stack"] = old_stack["exit_stack"].enter_context(
        contextlib.ExitStack(),
    )
    stack["console_output"] = str(
        pathlib.Path(
            old_stack["exit_stack"].enter_context(
                tempfile.TemporaryDirectory(dir=old_stack.get("tempdir", None)),
            ),
            "console_output.txt",
        )
    )
    request.context["stack"].append(stack)


def celery_run_workflow_context_stack_pop(context, request):
    # TODO Deal with ordering of lines by time, logging module?
    request.context["console_output"].append(
        pathlib.Path(
            request.context["stack"][-1]["console_output"]
        ).read_bytes(),
    )
    request.context["stack"].pop()


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


def policy_engine_context_extra_init_secret_github_token_from_env(
    context, request
):
    # TODO Another function which overrides or clears secrets if set
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" not in secrets and "GITHUB_TOKEN" in os.environ:
        secrets["GITHUB_TOKEN"] = os.environ["GITHUB_TOKEN"]


@contextlib.asynccontextmanager
async def lifespan_github_app_gidgethub(
    config_string,
    app,
    _context,
):
    config = yaml.safe_load(
        pathlib.Path(config_string).expanduser().read_text()
    )

    if isinstance(app, FastAPI):

        @app.post("/webhook/github")
        async def github_webhook_endpoint(request: Request):
            # TODO(security) Set webhook secret as kwarg in from_http() call
            event = sansio.Event.from_http(
                request.headers, await request.body()
            )
            print("GH delivery ID", event.delivery_id, file=sys.stderr)
            await router.dispatch(event, request.app.state.gidgethub.gh)

    # NOTE SECURITY This token has permissions to all installations!!! Swap
    # it for a more finely scoped token next:
    config["danger_wide_permissions_token"] = gidgethub.apps.get_jwt(
        app_id=config["app_id"],
        private_key=config["private_key"],
    )

    async with aiohttp.ClientSession(trust_env=True) as session:
        yield {
            "gidgethub": types.SimpleNamespace(
                gh=gidgethub.aiohttp.GitHubAPI(
                    session,
                    # TODO Change actor
                    "pdxjohnny",
                ),
                **config,
            )
        }


# TODO We need to async init lifespan callbacks and set context.app.state which
# will be not serializable on initial entry into async_celery_run_workflow
# @app.task(bind=True, base=MyTask)
# https://celery.school/sqlalchemy-session-celery-tasks
async def policy_engine_context_extra_init_secret_github_token_from_github_app(
    context, request
):
    secrets = request.context["secrets"]
    if "GITHUB_TOKEN" in secrets or not hasattr(context.app.state, "gidgethub"):
        return

    # Find installation ID associated with requesting actor to generated
    # finer grained token
    installation_id = None
    async for data in context.app.state.gidgethub.gh.getiter(
        "/app/installations",
        jwt=context.app.state.gidgethub.danger_wide_permissions_token,
    ):
        if (
            request.context["config"]["env"]["GITHUB_ACTOR"]
            == data["account"]["login"]
        ):
            installation_id = data["id"]
        elif request.context["config"]["env"]["GITHUB_REPOSITORY"].startswith(
            data["account"]["login"] + "/"
        ):
            installation_id = data["id"]
    if installation_id is None:
        raise Exception(
            f'App installation not found for GitHub Repository {request.context["config"]["env"]["GITHUB_REPOSITORY"]!r} or Actor {request.context["config"]["env"]["GITHUB_ACTOR"]!r}'
        )

    access_token_response = await gidgethub.apps.get_installation_access_token(
        context.app.state.gidgethub.gh,
        installation_id=installation_id,
        app_id=context.app.state.gidgethub.app_id,
        private_key=context.app.state.gidgethub.private_key,
    )

    secrets["GITHUB_TOKEN"] = access_token_response["token"]


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
        if self.callback and self.config_string:
            self.entrypoint_string = f"{make_entrypoint_style_string(self.callback)}:{self.config_string}"
        elif self.entrypoint_string and self.config_string:
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


async def async_celery_run_workflow(context, request):
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
            if (
                context.app is None
                or not hasattr(context.app, "state")
                or not len(context.app.state)
            ):
                state = types.SimpleNamespace(
                    **await request.context[
                        "async_exit_stack"
                    ].enter_async_context(
                        startup_fastapi_app_policy_engine_context(
                            fastapi_current_app.get()
                            if int(os.environ.get("NO_CELERY", "0"))
                            else celery_current_app,
                            context,
                        )
                    )
                )
                context.app.state = state
            await celery_run_workflow_context_init(
                context,
                request,
            )
            if stack is None or len(stack) == 0:
                stack = celery_run_workflow_context_stack_make_new(
                    context, request
                )
                stack["secrets"] = copy.deepcopy(request.context["secrets"])
            celery_run_workflow_context_stack_push(context, request, stack)
            # Run steps
            for job in workflow.jobs.values():
                # TODO Kick off jobs in parallel / dep matrix
                for step in job.steps:
                    execute_step(context, request, step)

        detail = PolicyEngineComplete(
            id="",
            exit_status=PolicyEngineCompleteExitStatuses.SUCCESS,
            outputs={},
        )
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.COMPLETE,
            detail=detail,
        )
        return request_status.model_dump_json()


def celery_run_workflow(context, request):
    return asyncio.get_event_loop().run_until_complete(
        async_celery_run_workflow(context, request),
    )


task_celery_run_workflow = celery_app.task(celery_run_workflow)


def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1


NO_CELERY_ASYNC_RESULTS = {}
EXECUTOR = concurrent.futures.ProcessPoolExecutor(
    max_workers=number_of_workers()
).__enter__()
atexit.register(lambda: EXECUTOR.__exit__(None, None, None))


def no_celery_task(func):
    def delay(*args):
        nonlocal func
        global EXECUTOR
        task_id = str(uuid.uuid4())
        future = EXECUTOR.submit(func, *args)
        NO_CELERY_ASYNC_RESULTS[task_id] = {
            "state": "PENDING",
            "result": None,
            "future": future,
        }
        future.add_done_callback(
            lambda _future: no_celery_try_set_state(
                NO_CELERY_ASYNC_RESULTS[task_id],
            ),
        )
        return types.SimpleNamespace(id=task_id)

    func.delay = delay
    return func


def no_celery_try_set_state(state):
    future = state["future"]
    if not future.done():
        state["state"] = "PENDING"
    else:
        exception = future.exception(timeout=0)
        if exception is not None:
            state["result"] = exception
            state["state"] = "FAILURE"
        else:
            state["state"] = "SUCCESS"
            state["result"] = future.result()


class NoCeleryAsyncResult:
    def __init__(self, task_id, *, app=None):
        self.task_id = task_id

    @property
    def state(self):
        state = NO_CELERY_ASYNC_RESULTS[self.task_id]
        no_celery_try_set_state(state)
        return state["state"]

    def get(self):
        result = NO_CELERY_ASYNC_RESULTS[self.task_id]["result"]
        if isinstance(result, Exception):
            raise result
        return result


if "NO_CELERY" in os.environ:
    AsyncResult = NoCeleryAsyncResult
    task_celery_run_workflow = no_celery_task(celery_run_workflow)


@contextlib.asynccontextmanager
async def startup_fastapi_app_policy_engine_context(
    app,
    context: Optional[Dict[str, Any]] = None,
):
    state = {}
    if context is None:
        context = {}
    if not isinstance(context, PolicyEngineContext):
        context = PolicyEngineContext.model_validate(context)
    context.app = app
    state["context"] = context
    async with contextlib.AsyncExitStack() as async_exit_stack:
        for lifespan_callback in context.lifespan:
            state.update(
                await async_exit_stack.enter_async_context(
                    lifespan_callback(app, context)
                )
            )
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
    def route_policy_engine_status(
        request_id: str,
    ) -> PolicyEngineStatus:
        global celery_app
        request_task = AsyncResult(request_id, app=celery_app)
        if request_task.state == "PENDING":
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.IN_PROGRESS,
                detail=PolicyEngineInProgress(
                    id=request_id,
                    # TODO Provide previous status updates?
                    status_updates={},
                ),
            )
        elif request_task.state in ("SUCCESS", "FAILURE"):
            status_json_string = request_task.get()
            status = json.loads(status_json_string)
            detail_class = DETAIL_CLASS_MAPPING[status["status"]]
            status["detail"] = detail_class(**status["detail"])
            request_status = PolicyEngineStatus(**status)
        else:
            request_status = PolicyEngineStatus(
                status=PolicyEngineStatuses.UNKNOWN,
                detail=PolicyEngineUnknown(
                    id=request_id,
                ),
            )
        return request_status

    @app.put("/request/create")
    def route_request(
        request: PolicyEngineRequest,
        fastapi_request: Request,
    ) -> PolicyEngineStatus:
        fastapi_current_app.set(fastapi_request.app)
        # TODO Handle when submitted.status cases
        request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.SUBMITTED,
            detail=PolicyEngineSubmitted(
                id=str(
                    task_celery_run_workflow.delay(
                        fastapi_request.state.context.model_dump_json(),
                        request.model_dump_json(),
                    ).id
                ),
            ),
        )
        return request_status

    return app


DEFAULT_LIFESPAN_CALLBACKS = []
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
    celery_app.tasks["tasks.celery_run_workflow"] = task_celery_run_workflow
    celery_app.Worker(app=celery_app).start()


CELERY_WORKER_EXEC_WITH_PYTHON = r"import scitt_emulator.policy_engine; scitt_emulator.policy_engine.celery_worker_exec_with_python()"


def celery_worker_exec_with_python():
    import nest_asyncio

    nest_asyncio.apply()
    asyncio.run(background_task_celery_worker())


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
    if "NO_CELERY" in os.environ:
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
                    policy_engine_context_extra_init_secret_github_token_from_env,
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
                    policy_engine_context_extra_init_secret_github_token_from_env,
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
        response = client.put(
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
            time.sleep(5)

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


@router.register("check_suite", action="requested")
# @router.register("push")
# @router.register("pull_request", action="opened")
# @router.register("pull_request", action="synchronize")
async def check_suite_requested_triggers_run_workflows(
    event, gh, *arg, **kwargs
):
    snoop.pp(event)
    # pull_request = event.data["pull_request"]
    # push = event.data["push"]
    # await gh.post(pull_request["labels_url"], data=["needs review"])


event = {
    "action": "requested",
    "check_suite": {
        "id": 21807775404,
        "node_id": "CS_kwDOJQW3oM8AAAAFE9g-rA",
        "head_branch": "policy_engine",
        "head_sha": "fb43597076a07684c739d18277eec8d4828a3362",
        "status": "queued",
        "conclusion": None,
        "url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/check-suites/21807775404",
        "before": "cba79df088bf6cffa1c78d3b69ab279616b234fb",
        "after": "fb43597076a07684c739d18277eec8d4828a3362",
        "pull_requests": [],
        "app": {
            "id": 647627,
            "slug": "alice-oa",
            "node_id": "A_kwDOAFrL4c4ACeHL",
            "owner": {
                "login": "pdxjohnny",
                "id": 5950433,
                "node_id": "MDQ6VXNlcjU5NTA0MzM=",
                "avatar_url": "https://avatars.githubusercontent.com/u/5950433?v=4",
                "gravatar_id": "",
                "url": "https://api.github.com/users/pdxjohnny",
                "html_url": "https://github.com/pdxjohnny",
                "followers_url": "https://api.github.com/users/pdxjohnny/followers",
                "following_url": "https://api.github.com/users/pdxjohnny/following{/other_user}",
                "gists_url": "https://api.github.com/users/pdxjohnny/gists{/gist_id}",
                "starred_url": "https://api.github.com/users/pdxjohnny/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/pdxjohnny/subscriptions",
                "organizations_url": "https://api.github.com/users/pdxjohnny/orgs",
                "repos_url": "https://api.github.com/users/pdxjohnny/repos",
                "events_url": "https://api.github.com/users/pdxjohnny/events{/privacy}",
                "received_events_url": "https://api.github.com/users/pdxjohnny/received_events",
                "type": "User",
                "site_admin": False,
            },
            "name": "Alice OA",
            "description": "",
            "external_url": "https://alice.chadig.com",
            "html_url": "https://github.com/apps/alice-oa",
            "created_at": "2023-11-23T14:33:00Z",
            "updated_at": "2023-11-23T14:33:44Z",
            "permissions": {
                "actions": "write",
                "checks": "write",
                "contents": "write",
                "deployments": "write",
                "discussions": "write",
                "issues": "write",
                "metadata": "read",
                "organization_actions_variables": "write",
                "organization_custom_properties": "write",
                "organization_custom_roles": "read",
                "organization_events": "read",
                "organization_self_hosted_runners": "write",
                "pages": "write",
                "pull_requests": "write",
                "statuses": "write",
                "workflows": "write",
            },
            "events": [
                "check_run",
                "check_suite",
                "commit_comment",
                "create",
                "custom_property",
                "custom_property_values",
                "delete",
                "deployment",
                "deployment_protection_rule",
                "deployment_review",
                "deployment_status",
                "deploy_key",
                "discussion",
                "discussion_comment",
                "fork",
                "gollum",
                "issues",
                "issue_comment",
                "label",
                "merge_queue_entry",
                "milestone",
                "page_build",
                "public",
                "pull_request",
                "pull_request_review",
                "pull_request_review_comment",
                "pull_request_review_thread",
                "push",
                "release",
                "repository",
                "repository_dispatch",
                "star",
                "status",
                "watch",
                "workflow_dispatch",
                "workflow_job",
                "workflow_run",
            ],
        },
        "created_at": "2024-03-17T15:55:31Z",
        "updated_at": "2024-03-17T15:55:31Z",
        "rerequestable": True,
        "runs_rerequestable": True,
        "latest_check_runs_count": 0,
        "check_runs_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/check-suites/21807775404/check-runs",
        "head_commit": {
            "id": "fb43597076a07684c739d18277eec8d4828a3362",
            "tree_id": "d290beff5cd229ddff5c8e20ec26b478d6b82ab9",
            "message": "GitHub App style token issuance\n\nSigned-off-by: John Andersen <johnandersenpdx@gmail.com>",
            "timestamp": "2024-03-17T15:55:25Z",
            "author": {
                "name": "John Andersen",
                "email": "johnandersenpdx@gmail.com",
            },
            "committer": {
                "name": "John Andersen",
                "email": "johnandersenpdx@gmail.com",
            },
        },
    },
    "repository": {
        "id": 621131680,
        "node_id": "R_kgDOJQW3oA",
        "name": "scitt-api-emulator",
        "full_name": "pdxjohnny/scitt-api-emulator",
        "private": False,
        "owner": {
            "login": "pdxjohnny",
            "id": 5950433,
            "node_id": "MDQ6VXNlcjU5NTA0MzM=",
            "avatar_url": "https://avatars.githubusercontent.com/u/5950433?v=4",
            "gravatar_id": "",
            "url": "https://api.github.com/users/pdxjohnny",
            "html_url": "https://github.com/pdxjohnny",
            "followers_url": "https://api.github.com/users/pdxjohnny/followers",
            "following_url": "https://api.github.com/users/pdxjohnny/following{/other_user}",
            "gists_url": "https://api.github.com/users/pdxjohnny/gists{/gist_id}",
            "starred_url": "https://api.github.com/users/pdxjohnny/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/pdxjohnny/subscriptions",
            "organizations_url": "https://api.github.com/users/pdxjohnny/orgs",
            "repos_url": "https://api.github.com/users/pdxjohnny/repos",
            "events_url": "https://api.github.com/users/pdxjohnny/events{/privacy}",
            "received_events_url": "https://api.github.com/users/pdxjohnny/received_events",
            "type": "User",
            "site_admin": False,
        },
        "html_url": "https://github.com/pdxjohnny/scitt-api-emulator",
        "description": "SCITT API Emulator",
        "fork": True,
        "url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator",
        "forks_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/forks",
        "keys_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/keys{/key_id}",
        "collaborators_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/collaborators{/collaborator}",
        "teams_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/teams",
        "hooks_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/hooks",
        "issue_events_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/issues/events{/number}",
        "events_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/events",
        "assignees_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/assignees{/user}",
        "branches_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/branches{/branch}",
        "tags_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/tags",
        "blobs_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/git/blobs{/sha}",
        "git_tags_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/git/tags{/sha}",
        "git_refs_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/git/refs{/sha}",
        "trees_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/git/trees{/sha}",
        "statuses_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/statuses/{sha}",
        "languages_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/languages",
        "stargazers_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/stargazers",
        "contributors_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/contributors",
        "subscribers_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/subscribers",
        "subscription_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/subscription",
        "commits_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/commits{/sha}",
        "git_commits_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/git/commits{/sha}",
        "comments_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/comments{/number}",
        "issue_comment_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/issues/comments{/number}",
        "contents_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/contents/{+path}",
        "compare_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/compare/{base}...{head}",
        "merges_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/merges",
        "archive_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/{archive_format}{/ref}",
        "downloads_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/downloads",
        "issues_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/issues{/number}",
        "pulls_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/pulls{/number}",
        "milestones_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/milestones{/number}",
        "notifications_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/notifications{?since,all,participating}",
        "labels_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/labels{/name}",
        "releases_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/releases{/id}",
        "deployments_url": "https://api.github.com/repos/pdxjohnny/scitt-api-emulator/deployments",
        "created_at": "2023-03-30T03:43:27Z",
        "updated_at": "2023-09-12T21:02:36Z",
        "pushed_at": "2024-03-17T15:55:29Z",
        "git_url": "git://github.com/pdxjohnny/scitt-api-emulator.git",
        "ssh_url": "git@github.com:pdxjohnny/scitt-api-emulator.git",
        "clone_url": "https://github.com/pdxjohnny/scitt-api-emulator.git",
        "svn_url": "https://github.com/pdxjohnny/scitt-api-emulator",
        "homepage": "https://scitt-community.github.io/scitt-api-emulator",
        "size": 290,
        "stargazers_count": 0,
        "watchers_count": 0,
        "language": "Python",
        "has_issues": False,
        "has_projects": True,
        "has_downloads": True,
        "has_wiki": True,
        "has_pages": False,
        "has_discussions": False,
        "forks_count": 0,
        "mirror_url": None,
        "archived": False,
        "disabled": False,
        "open_issues_count": 1,
        "license": {
            "key": "mit",
            "name": "MIT License",
            "spdx_id": "MIT",
            "url": "https://api.github.com/licenses/mit",
            "node_id": "MDc6TGljZW5zZTEz",
        },
        "allow_forking": True,
        "is_template": False,
        "web_commit_signoff_required": True,
        "topics": [],
        "visibility": "public",
        "forks": 0,
        "open_issues": 1,
        "watchers": 0,
        "default_branch": "auth",
    },
    "sender": {
        "login": "pdxjohnny",
        "id": 5950433,
        "node_id": "MDQ6VXNlcjU5NTA0MzM=",
        "avatar_url": "https://avatars.githubusercontent.com/u/5950433?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/pdxjohnny",
        "html_url": "https://github.com/pdxjohnny",
        "followers_url": "https://api.github.com/users/pdxjohnny/followers",
        "following_url": "https://api.github.com/users/pdxjohnny/following{/other_user}",
        "gists_url": "https://api.github.com/users/pdxjohnny/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/pdxjohnny/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/pdxjohnny/subscriptions",
        "organizations_url": "https://api.github.com/users/pdxjohnny/orgs",
        "repos_url": "https://api.github.com/users/pdxjohnny/repos",
        "events_url": "https://api.github.com/users/pdxjohnny/events{/privacy}",
        "received_events_url": "https://api.github.com/users/pdxjohnny/received_events",
        "type": "User",
        "site_admin": False,
    },
    "installation": {
        "id": 44340847,
        "node_id": "MDIzOkludGVncmF0aW9uSW5zdGFsbGF0aW9uNDQzNDA4NDc=",
    },
}


@pytest.mark.asyncio
async def test_check_suite_requested_triggers_run_workflows():
    return
    await check_suite_requested_triggers_run_workflows(event, gh)


"""
curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/check-runs
{
    "name": "mighty_readme",
    "head_sha": "fb43597076a07684c739d18277eec8d4828a3362",
    "status": "in_progress",
    "external_id": task_id,
    "started_at": "2018-05-04T01:14:52Z",
    "output": {"title": "Mighty Readme report", "summary": "", "text": ""},
}

curl -L \
  -X PATCH \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/check-runs/CHECK_RUN_ID
{
    "name": "mighty_readme",
    "started_at": "2018-05-04T01:14:52Z",
    "status": "completed",
    "conclusion": "success",
    "completed_at": "2018-05-04T01:14:52Z",
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
"""


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


def cli():
    # TODO Take sys.argv as args to parse as optional
    estimated_number_of_workers = number_of_workers()

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(help="sub-command help")
    parser.set_defaults(func=lambda _: None)
    parser.add_argument(
        "--lifespan",
        nargs=2,
        action="append",
        metavar=("entrypoint", "config"),
        default=DEFAULT_LIFESPAN_CALLBACKS,
        help=f"entrypoint.style:path ~/path/to/assocaited/config.json for startup and shutdown async context managers. Yield from to set fastapi|celery.app.state",
    )

    parser_worker = subparsers.add_parser("worker", help="Run Celery worker")
    parser_worker.set_defaults(func=cli_worker)

    parser_api = subparsers.add_parser("api", help="Run API server")
    parser_api.set_defaults(func=cli_api)
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
            policy_engine_context_extra_init_secret_github_token_from_env,
        ],
        help=f"Entrypoint style paths for PolicyEngineContext.extra_inits",
    )

    args = parser.parse_args()

    args.lifespan = list(
        map(
            lambda arg: LifespanCallbackWithConfig(
                entrypoint_string=arg[0],
                config_string=arg[1],
            ),
            args.lifespan,
        )
    )

    args.func(args)


if __name__ == "__main__":
    cli()
