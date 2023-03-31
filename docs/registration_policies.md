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
    | jq '.insertPolicy = "external"' \
    | tee workspace/service_parameters.json.new \
    && mv workspace/service_parameters.json.new workspace/service_parameters.json
{
  "serviceId": "emulator",
  "treeAlgorithm": "CCF",
  "signatureAlgorithm": "ES256",
  "serviceCertificate": "-----BEGIN CERTIFICATE-----",
  "insertPolicy": "external"
}
```

Basic policy engine in two files

**enforce_policy.py**

```python
import os
import sys
import pathlib

cose_path = pathlib.Path(sys.argv[-1])
policy_action_path = cose_path.with_suffix(".policy." + os.environ["POLICY_ACTION"].lower())
policy_action_path.write_text("")
```

Simple drop rule based on claim content blocklist.

**is_on_blocklist.py**

```python
import os
import sys
import json

import cbor2
import pycose
from pycose.messages import CoseMessage, Sign1Message

from scitt_emulator.scitt import ClaimInvalidError, COSE_Headers_Issuer

BLOCKLIST_DEFAULT = [
    "did:web:example.com",
]
BLOCKLIST_DEFAULT_JSON = json.dumps(BLOCKLIST_DEFAULT)
BLOCKLIST = json.loads(os.environ.get("BLOCKLIST", BLOCKLIST_DEFAULT_JSON))

claim = sys.stdin.buffer.read()

msg = CoseMessage.decode(claim)

if pycose.headers.ContentType not in msg.phdr:
    raise ClaimInvalidError(
        "Claim does not have a content type header parameter"
    )
if COSE_Headers_Issuer not in msg.phdr:
    raise ClaimInvalidError("Claim does not have an issuer header parameter")

if msg.phdr[COSE_Headers_Issuer] not in BLOCKLIST:
    sys.exit(1)

# EXIT_SUCCESS == MUST block. In case of thrown errors/exceptions.
```

Example running blocklist check and enforcement to disable issuer (example:
`did:web:example.com`).

```console
$ npm install -g nodemon
$ nodemon -e .cose --exec 'find workspace/storage/operations -name \*.cose -exec nohup sh -xc "echo {} && (python3 is_on_blocklist.py < {} && POLICY_ACTION=denied python3 enforce_policy.py {}) || POLICY_ACTION=insert python3 enforce_policy.py {}" \;'
```

Create claim from blocked issuer (`.com`) and from non-blocked (`.org`).

```console
$ scitt-emulator client create-claim --issuer did:web:example.com --content-type application/json --payload '{"sun": "yellow"}' --out claim.cose
Claim written to claim.cose
$ scitt-emulator client submit-claim --claim claim.cose --out claim.receipt.cbor
Traceback (most recent call last):
  File "/home/alice/.local/bin/scitt-emulator", line 33, in <module>
    sys.exit(load_entry_point('scitt-emulator', 'console_scripts', 'scitt-emulator')())
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/cli.py", line 22, in main
    args.func(args)
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 182, in <lambda>
    func=lambda args: submit_claim(
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 93, in submit_claim
    raise_for_operation_status(operation)
  File "/home/alice/Documents/python/scitt-api-emulator/scitt_emulator/client.py", line 29, in raise_for_operation_status
    raise RuntimeError(f"Operation error: {operation['error']}")
RuntimeError: Operation error: {'status': 'denied'}
$ scitt-emulator client create-claim --issuer did:web:example.org --content-type application/json --payload '{"sun": "yellow"}' --out claim.cose
Claim written to claim.cose
$ scitt-emulator client submit-claim --claim claim.cose --out claim.receipt.cbor
Claim registered with entry ID 1
Receipt written to claim.receipt.cbor
```
