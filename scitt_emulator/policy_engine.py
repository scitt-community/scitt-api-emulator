"""
Implement GitHub Actions workflow evaluation as step towards workflow based
policy engine. TODO Receipts with attestations for SLSA L4.

Testing:

NO_CELERY=1 GITHUB_TOKEN=$(gh auth token) nodemon -e py --exec 'clear; python -m pytest -s -vv scitt_emulator/policy_engine.py; test 1'

Terminal 1:

```bash
NO_CELERY=1 python -m uvicorn --port 8080 scitt_emulator.policy_engine:app
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
    GITHUB_TOKEN: __GITHUB_TOKEN_FROM_ENV__
workflow: |
  on: push

  jobs:
    lint:
      runs-on: ubuntu-latest
      steps:
      - uses: actions/checkout@v4
```

Terminal 2:

```bash
jsonschema -i <(cat request.yml | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') <(python -c 'import json, scitt_emulator.policy_engine; print(json.dumps(scitt_emulator.policy_engine.PolicyEngineRequest.model_json_schema(), indent=4, sort_keys=True))')
curl -X PUT -H "Content-Type: application/json" -d @<(cat request.yml | sed -e "s/__GITHUB_TOKEN_FROM_ENV__/$(gh auth token)/g" | python -c 'import json, yaml, sys; print(json.dumps(yaml.safe_load(sys.stdin.read()), indent=4, sort_keys=True))') http://localhost:8080/request/create | jq
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
import pathlib
import zipfile
import tempfile
import textwrap
import subprocess
import traceback
import itertools
import subprocess
import contextlib
import urllib.request
import concurrent.futures
from typing import Union, Optional, List, Dict, Any


import yaml
import snoop
import pytest
from celery import Celery
from celery.result import AsyncResult
from fastapi import FastAPI
from pydantic import BaseModel, Field, model_validator, field_validator
from fastapi.testclient import TestClient


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


celery_app = Celery(
    "tasks", backend="redis://localhost", broker="redis://localhost"
)


def download_step_uses_from_url(
    context,
    policy_engine_request,
    step,
    step_uses_org_repo,
    step_uses_version,
    step_download_url,
):
    stack = context["stack"][-1]

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


def download_step_uses(context, policy_engine_request, step):
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
                policy_engine_request,
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


def _evaluate_using_javascript(context, code_block):
    stack = context["stack"][-1]

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
                input_value,
            )
            for input_key, input_value in stack["env"].items()
            if input_key.startswith("GITHUB_")
        },
        **{
            "token": stack["secrets"]["GITHUB_TOKEN"],
            "event": {
                "inputs": context["inputs"],
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
        stdin=context["devnull"],
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


def evaluate_using_javascript(context, code_block):
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
        evaluated_data = _evaluate_using_javascript(context, data)
        # Append the evaluated data to the result
        result += code_block[start_idx + 3 : end_idx - 2].replace(
            data, str(evaluated_data)
        )
        # Move the start index to the next position after the match
        start_idx = end_idx

    result += code_block[start_idx:]

    return result


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
def test_evaluate_using_javascript(template, should_be):
    context = {
        "config": {
            "env": {
                "GITHUB_ACTOR": "aliceoa",
                "GITHUB_ACTOR_ID": "1234567",
            },
        },
        "secrets": {
            "GITHUB_TOKEN": "",
        },
    }
    stack = {}
    with contextlib.ExitStack() as exit_stack:
        if "exit_stack" not in context:
            context["exit_stack"] = exit_stack
        celery_run_workflow_context_init(
            context,
            PolicyEngineRequest(),
        )
        if stack is None or len(stack) == 0:
            stack = celery_run_workflow_context_stack_make_new(context)
            stack["secrets"] = copy.deepcopy(context["secrets"])
        celery_run_workflow_context_stack_push(context, stack)

        evaluated = evaluate_using_javascript(
            context,
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


def step_build_default_inputs(context, action_yaml_obj, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, input_value["default"]
        )
        for input_key, input_value in action_yaml_obj.get("inputs", {}).items()
        if "default" in input_value
    }


def step_build_env(context, step):
    return {
        input_key: evaluate_using_javascript(context, input_value)
        for input_key, input_value in step.env.items()
    }


def step_build_inputs(context, step):
    return {
        f"INPUT_{input_key.upper()}": evaluate_using_javascript(
            context, input_value
        )
        for input_key, input_value in step.with_inputs.items()
    }


def step_io_output_github_actions(context):
    stack = context["stack"][-1]
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


@snoop
def step_io_update_stack_output_and_env_github_actions(
    context, policy_engine_request, step
):
    stack = context["stack"][-1]
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


@snoop
def execute_step_uses(context, policy_engine_request, step):
    stack = context["stack"][-1]

    extracted_path = stack["steps"]["extracted_path"][step.uses]
    action_yaml_path = list(extracted_path.glob("action.*"))[0]
    action_yaml_obj = yaml.safe_load(action_yaml_path.read_text())

    stack["env"].update(
        {
            **step_io_output_github_actions(context),
            **step_build_default_inputs(context, action_yaml_obj, step),
        }
    )

    if action_yaml_obj["runs"]["using"].startswith("node"):
        env = copy.deepcopy(os.environ)
        env.update(stack["env"])
        snoop.pp(stack["env"])
        tee_proc = subprocess.Popen(["tee", stack["console_output"]])
        try:
            completed_proc = subprocess.run(
                [
                    "node",
                    extracted_path.joinpath(action_yaml_obj["runs"]["main"]),
                ],
                cwd=stack["workspace"],
                stdin=context["devnull"],
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
        stack = celery_run_workflow_context_stack_make_new(context)
        # TODO Reusable workflows, populate secrets
        # stack["secrets"] = context["secrets"]
        celery_run_workflow(
            PolicyEngineRequest(
                inputs=step.with_inputs,
                workflow={
                    "jobs": {
                        "composite": {
                            "steps": composite_steps,
                        },
                    },
                },
                context=context,
                stack=stack,
            ),
        )
    else:
        raise NotImplementedError("Only node and composite actions implemented")

    step_io_update_stack_output_and_env_github_actions(
        context, policy_engine_request, step
    )


def execute_step_uses_org_repo_at_version(context, policy_engine_request, step):
    download_step_uses(context, policy_engine_request, step)
    execute_step_uses(context, policy_engine_request, step)


@snoop
def execute_step_run(context, policy_engine_request, step):
    stack = context["stack"][-1]
    stack["env"].update(step_io_output_github_actions(context))

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
    snoop.pp(stack["env"])
    tee_proc = subprocess.Popen(["tee", stack["console_output"]])
    try:
        completed_proc = subprocess.run(
            cmd,
            cwd=stack["workspace"],
            stdin=context["devnull"],
            stdout=tee_proc.stdin,
            stderr=tee_proc.stdin,
            env=env,
        )
        completed_proc.check_returncode()
    finally:
        tee_proc.terminate()

    step_io_update_stack_output_and_env_github_actions(
        context,
        policy_engine_request,
        step,
    )


@snoop
def execute_step(context, policy_engine_request, step):
    old_stack = context["stack"][-1]
    stack = celery_run_workflow_context_stack_make_new(context)
    celery_run_workflow_context_stack_push(context, stack)
    # Keep the weakref, outputs should mod via pointer
    stack["outputs"] = old_stack["outputs"]
    # Don't allow messing with secrets (use copy.deepcopy)
    stack["secrets"] = copy.deepcopy(old_stack["secrets"])
    stack["env"].update(step_build_env(context, step))
    stack["env"].update(step_build_inputs(context, step))

    if step.uses:
        if "@" in step.uses:
            execute_step_uses_org_repo_at_version(
                context, policy_engine_request, step
            )
        else:
            raise NotImplementedError("Only uses: org/repo@vXYZ is implemented")
    elif step.run:
        execute_step_run(context, policy_engine_request, step)
    else:
        raise NotImplementedError(
            "Only uses: org/repo@vXYZ and run implemented"
        )

    celery_run_workflow_context_stack_pop(context)


def celery_run_workflow_context_stack_make_new(context):
    old_stack = context
    if context["stack"]:
        old_stack = context["stack"][-1]
    stack = {
        "outputs": {},
        "secrets": {},
        "cachedir": old_stack["cachedir"],
        "tempdir": old_stack["tempdir"],
        "workspace": old_stack["workspace"],
        "env": copy.deepcopy(old_stack["env"]),
    }
    snoop.pp(stack["env"])
    return stack


def celery_run_workflow_context_stack_push(context, stack):
    old_stack = context
    if context["stack"]:
        old_stack = context["stack"][-1]
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
    context["stack"].append(stack)


def celery_run_workflow_context_stack_pop(context):
    # TODO Deal with ordering of lines by time, logging module?
    context["console_output"].append(
        pathlib.Path(context["stack"][-1]["console_output"]).read_bytes(),
    )
    context["stack"].pop()


def celery_run_workflow_context_init(
    context, request, *, force_init: bool = False
):
    config = context.get("config", {})
    config_cwd = config.get("cwd", os.getcwd())
    config_env = config.get("env", {})
    if force_init or "env" not in context:
        context["env"] = copy.deepcopy(config_env)
    if force_init or "devnull" not in context:
        # Open /dev/null for empty stdin to subprocesses
        context["devnull"] = open(os.devnull)
    if force_init or "inputs" not in context:
        context["inputs"] = copy.deepcopy(request.inputs)
    if force_init or "cachedir" not in context:
        # Cache dir for caching actions
        cache_path = pathlib.Path(config_cwd, ".cache")
        cache_path.mkdir(exist_ok=True)
        context["cachedir"] = str(cache_path)
    if force_init or "tempdir" not in context:
        # Temp dir
        tempdir_path = pathlib.Path(config_cwd, ".tempdir")
        tempdir_path.mkdir(exist_ok=True)
        context["tempdir"] = str(tempdir_path)
        if "RUNNER_TEMP" not in context["env"]:
            context["env"]["RUNNER_TEMP"] = context["tempdir"]
        if "RUNNER_TOOL_CACHE" not in context["env"]:
            context["env"]["RUNNER_TOOL_CACHE"] = context["tempdir"]
    if force_init or "workspace" not in context:
        # Workspace dir
        context["workspace"] = context["exit_stack"].enter_context(
            tempfile.TemporaryDirectory(dir=config.get("tempdir", None)),
        )
    if force_init or "stack" not in context:
        context["stack"] = []
    if force_init or "console_output" not in context:
        context["console_output"] = []


@snoop
def celery_run_workflow(request_json):
    snoop.pp(request_json)
    request = PolicyEngineRequest.model_validate_json(request_json)
    snoop.pp(request)
    context = request.context
    stack = request.stack

    workflow = request.workflow

    with contextlib.ExitStack() as exit_stack:
        if "exit_stack" not in context:
            context["exit_stack"] = exit_stack
        celery_run_workflow_context_init(
            context,
            request,
        )
        if stack is None or len(stack) == 0:
            stack = celery_run_workflow_context_stack_make_new(context)
            stack["secrets"] = copy.deepcopy(context["secrets"])
        celery_run_workflow_context_stack_push(context, stack)
        # Run steps
        for job in workflow.jobs.values():
            # TODO Kick off jobs in parallel / dep matrix
            for step in job.steps:
                execute_step(context, request, step)
        snoop.pp(stack)
        snoop.pp(context["stack"][-1]["outputs"])

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


task_celery_run_workflow = celery_app.task(celery_run_workflow)


NO_CELERY_ASYNC_RESULTS = {}
EXECUTOR = concurrent.futures.ProcessPoolExecutor().__enter__()
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


@snoop
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


app = FastAPI()


@app.get("/request/status/{policy_engine_request_id}")
def route_policy_engine_status(
    policy_engine_request_id: str,
) -> PolicyEngineStatus:
    global celery_app
    policy_engine_request_task = AsyncResult(
        policy_engine_request_id, app=celery_app
    )
    if policy_engine_request_task.state == "PENDING":
        policy_engine_request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.IN_PROGRESS,
            detail=PolicyEngineInProgress(
                id=policy_engine_request_id,
                # TODO Provide previous status updates?
                status_updates={},
            ),
        )
    elif policy_engine_request_task.state in ("SUCCESS", "FAILURE"):
        status_json_string = policy_engine_request_task.get()
        snoop.pp(status_json_string)
        status = json.loads(status_json_string)
        detail_class = DETAIL_CLASS_MAPPING[status["status"]]
        status["detail"] = detail_class(**status["detail"])
        policy_engine_request_status = PolicyEngineStatus(**status)
    else:
        policy_engine_request_status = PolicyEngineStatus(
            status=PolicyEngineStatuses.UNKNOWN,
            detail=PolicyEngineUnknown(
                id=policy_engine_request_id,
            ),
        )
    snoop.pp(policy_engine_request_task.__dict__)
    snoop.pp(policy_engine_request_status)
    return policy_engine_request_status


@app.put("/request/create")
def route_policy_engine_request(
    request: PolicyEngineRequest,
) -> PolicyEngineStatus:
    # TODO Handle when submitted.status cases
    policy_engine_request_status = PolicyEngineStatus(
        status=PolicyEngineStatuses.SUBMITTED,
        detail=PolicyEngineSubmitted(
            id=str(
                task_celery_run_workflow.delay(
                    request.model_dump_json(),
                ).id
            ),
        ),
    )
    snoop.pp(policy_engine_request_status)
    return policy_engine_request_status


def background_task_celery_worker():
    # celery_app.worker_main(argv=["worker", "--loglevel=INFO"])
    celery_app.Worker().start()


@pytest.fixture
def pytest_fixture_background_task_celery_worker():
    if "NO_CELERY" in os.environ:
        yield
        return
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            r"import scitt_emulator.policy_engine; scitt_emulator.policy_engine.background_task_celery_worker()",
        ],
    )
    try:
        yield proc
    finally:
        proc.terminate()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "workflow",
    [
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
)
async def test_read_main(
    pytest_fixture_background_task_celery_worker,
    workflow,
):
    client = TestClient(app)

    policy_engine_request = PolicyEngineRequest(
        inputs={
            "repo_name": "scitt-community/scitt-api-emulator",
        },
        context={
            "config": {
                "env": {
                    "GITHUB_REPOSITORY": "scitt-community/scitt-api-emulator",
                    "GITHUB_API": "https://api.github.com/",
                    "GITHUB_ACTOR": "aliceoa",
                    "GITHUB_ACTOR_ID": "1234567",
                },
            },
            "secrets": {"GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", "")},
        },
        # URN for receipt for policy / transparency-configuration
        workflow=workflow,
    )
    policy_engine_request_serialized = policy_engine_request.model_dump_json()
    # Submit
    response = client.put(
        "/request/create", content=policy_engine_request_serialized
    )
    assert response.status_code == 200, json.dumps(response.json(), indent=4)
    policy_engine_request_status = response.json()
    assert (
        PolicyEngineStatuses.SUBMITTED.value
        == policy_engine_request_status["status"]
    )

    policy_engine_request_id = policy_engine_request_status["detail"]["id"]

    # Check complete
    for _ in range(0, 1000):
        response = client.get(f"/request/status/{policy_engine_request_id}")
        assert response.status_code == 200, json.dumps(response.json(), indent=4)
        policy_engine_request_status = response.json()
        policy_engine_request_id = policy_engine_request_status["detail"]["id"]
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
