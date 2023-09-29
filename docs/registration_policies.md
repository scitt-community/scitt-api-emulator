# Registration Policies

- References
  - [5.2.2. Registration Policies](https://www.ietf.org/archive/id/draft-birkholz-scitt-architecture-02.html#name-registration-policies)

## Simple decoupled file based policy engine

The SCITT API emulator can deny entry based on presence of
`operation.policy.{insert,denied,failed}` files. Currently only for use with
`use_lro=True`.

This is a simple way to enable evaluation of claims prior to submission by
arbitrary policy engines which watch the workspace (fanotify, inotify, etc.).

[![asciicast-of-simple-decoupled-file-based-policy-engine](https://asciinema.org/a/572766.svg)](https://asciinema.org/a/572766)

Start the server

```console
$ rm -rf workspace/
$ mkdir -p workspace/storage/operations
$ scitt-emulator server --workspace workspace/ --tree-alg CCF --use-lro
Service parameters: workspace/service_parameters.json
^C
```

Modification of config to non-`*` insert policy. Restart SCITT API emulator server after this.

```console
$ echo "$(cat workspace/service_parameters.json)" \
    | jq '.insertPolicy = "allowlist.schema.json"' \
    | tee workspace/service_parameters.json.new \
    && mv workspace/service_parameters.json.new workspace/service_parameters.json
{
  "serviceId": "emulator",
  "treeAlgorithm": "CCF",
  "signatureAlgorithm": "ES256",
  "serviceCertificate": "-----BEGIN CERTIFICATE-----",
  "insertPolicy": "allowlist.schema.json"
}
```

Basic policy engine in two files

**enforce_policy.py**

```python
import os
import sys
import pathlib

policy_reason = ""
if "POLICY_REASON_PATH" in os.environ:
    policy_reason = pathlib.Path(os.environ["POLICY_REASON_PATH"]).read_text()

cose_path = pathlib.Path(sys.argv[-1])
policy_action_path = cose_path.with_suffix(".policy." + os.environ["POLICY_ACTION"].lower())
policy_action_path.write_text(policy_reason)
```

Simple drop rule based on claim content allowlist.

**allowlist.schema.json**

```json
{
    "$id": "https://schema.example.com/scitt-allowlist.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "properties": {
        "issuer": {
            "type": "string",
            "enum": [
                "did:web:example.org"
            ]
        }
    }
}
```

**jsonschema_validator.py**

```python
import os
import sys
import json
import pathlib
import traceback

import cbor2
import pycose
from jsonschema import validate, ValidationError
from pycose.messages import CoseMessage, Sign1Message

from scitt_emulator.scitt import ClaimInvalidError, COSE_Headers_Issuer

claim = sys.stdin.buffer.read()

msg = CoseMessage.decode(claim)

if pycose.headers.ContentType not in msg.phdr:
    raise ClaimInvalidError("Claim does not have a content type header parameter")
if COSE_Headers_Issuer not in msg.phdr:
    raise ClaimInvalidError("Claim does not have an issuer header parameter")

if not msg.phdr[pycose.headers.ContentType].startswith("application/json"):
    raise TypeError(
        f"Claim content type does not start with application/json: {msg.phdr[pycose.headers.ContentType]!r}"
    )

SCHEMA = json.loads(pathlib.Path(os.environ["SCHEMA_PATH"]).read_text())

try:
    validate(
        instance={
            "$schema": "https://schema.example.com/scitt-policy-engine-jsonschema.schema.json",
            "issuer": msg.phdr[COSE_Headers_Issuer],
            "claim": json.loads(msg.payload.decode()),
        },
        schema=SCHEMA,
    )
except ValidationError as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
```

We'll create a small wrapper to serve in place of a more fully featured policy
engine.

**policy_engine.sh**

```bash
export SCHEMA_PATH="${1}"
CLAIM_PATH="${2}"

echo ${CLAIM_PATH}

(python3 jsonschema_validator.py < ${CLAIM_PATH} 2>error && POLICY_ACTION=insert python3 enforce_policy.py ${CLAIM_PATH}) || (python3 -c 'import sys, json; print(json.dumps({"type": "denied", "detail": sys.stdin.read()}))' < error > reason.json; POLICY_ACTION=denied POLICY_REASON_PATH=reason.json python3 enforce_policy.py ${CLAIM_PATH})
```

Example running allowlist check and enforcement.

```console
npm install -g nodemon
nodemon -e .cose --exec 'find workspace/storage/operations -name \*.cose -exec nohup sh -xe policy_engine.sh $(cat workspace/service_parameters.json | jq -r .insertPolicy) {} \;'
```

Also ensure you restart the server with the new config we edited.

```console
scitt-emulator server --workspace workspace/ --tree-alg CCF --use-lro
```

Create claim from allowed issuer (`.org`) and from non-allowed (`.com`).

```console
$ scitt-emulator client create-claim --issuer did:web:example.com --content-type application/json --payload '{"sun": "yellow"}' --out claim.cose
A COSE signed Claim was written to:  claim.cose
$ scitt-emulator client submit-claim --claim claim.cose --out claim.receipt.cbor
Traceback (most recent call last):
  File "/home/alice/.local/bin/scitt-emulator", line 33, in <module>
    sys.exit(load_entry_point('scitt-emulator', 'console_scripts', 'scitt-emulator')())
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/cli.py", line 22, in main
    args.func(args)
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 196, in <lambda>
    func=lambda args: submit_claim(
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 107, in submit_claim
    raise_for_operation_status(operation)
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 43, in raise_for_operation_status
    raise ClaimOperationError(operation)
scitt_emulator.client.ClaimOperationError: Operation error denied: 'did:web:example.com' is not one of ['did:web:example.org']

Failed validating 'enum' in schema['properties']['issuer']:
    {'enum': ['did:web:example.org'], 'type': 'string'}

On instance['issuer']:
    'did:web:example.com'

$ scitt-emulator client create-claim --issuer did:web:example.org --content-type application/json --payload '{"sun": "yellow"}' --out claim.cose
A COSE signed Claim was written to:  claim.cose
$ scitt-emulator client submit-claim --claim claim.cose --out claim.receipt.cbor
Claim registered with entry ID 1
Receipt written to claim.receipt.cbor
```
