# Registration Policies

- References
  - [5.2.2. Registration Policies](https://www.ietf.org/archive/id/draft-birkholz-scitt-architecture-02.html#name-registration-policies)

## Simple decoupled file based policy engine

The SCITT API emulator can deny entry based on presence of
`operation.policy.{insert,denied,failed}` files. Currently only for use with
`use_lro=True`.

This is a simple way to enable evaluation of claims prior to submission by
arbitrary policy engines which watch the workspace (fanotify, inotify, etc.).

[![asciicast-of-simple-decoupled-file-based-policy-engine](https://asciinema.org/a/620587.svg)](https://asciinema.org/a/620587)

Start the server

```console
$ rm -rf workspace/
$ mkdir -p workspace/storage/operations
$ timeout 1s scitt-emulator server --workspace workspace/ --tree-alg CCF --use-lro
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
import unittest
import traceback
import contextlib
import urllib.parse
import urllib.request

import jwt
import cbor2
import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2
from pycose.messages import Sign1Message
from jsonschema import validate, ValidationError
import cryptography.hazmat.primitives.serialization

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.scitt import ClaimInvalidError, CWTClaims


def did_web_to_url(
    did_web_string, scheme=os.environ.get("DID_WEB_ASSUME_SCHEME", "https")
):
    return "/".join(
        [
            f"{scheme}:/",
            *[urllib.parse.unquote(i) for i in did_web_string.split(":")[2:]],
        ]
    )


def verify_signature(msg: Sign1Message) -> bool:
    """
    - TODOs
        - Should we use audiance? I think no, just want to make sure we've
          documented why thought if not. No usage makes sense to me becasue we
          don't know the intended audiance, it could be federated into
          multiple TS
        - Can you just pass a whole public key as an issuer?
        - Resolve DID keys (since that is what the arch says...)
    """

    # Figure out what the issuer is
    cwt_cose_loads = cwt.cose.COSE()._loads
    cwt_unverified_protected = cwt_cose_loads(
        cwt_cose_loads(msg.phdr[CWTClaims]).value[2]
    )
    unverified_issuer = cwt_unverified_protected[1]

    if unverified_issuer.startswith("did:web:"):
        unverified_issuer = did_web_to_url(unverified_issuer)

    # Load keys from issuer
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []

    from cryptography.hazmat.primitives import serialization

    cryptography_ssh_keys = []
    if "://" in unverified_issuer and not unverified_issuer.startswith("file://"):
        # TODO Logging for URLErrors
        # Check if OIDC issuer
        unverified_issuer_parsed_url = urllib.parse.urlparse(unverified_issuer)
        openid_configuration_url = unverified_issuer_parsed_url._replace(
            path="/.well-known/openid-configuration",
        ).geturl()
        with contextlib.suppress(urllib.request.URLError):
            with urllib.request.urlopen(openid_configuration_url) as response:
                if response.status == 200:
                    openid_configuration = json.loads(response.read())
                    jwks_uri = openid_configuration["jwks_uri"]
                    with urllib.request.urlopen(jwks_uri) as response:
                        if response.status == 200:
                            jwks = json.loads(response.read())
                            for jwk_key_as_dict in jwks["keys"]:
                                jwk_key_as_string = json.dumps(jwk_key_as_dict)
                                jwk_keys.append(
                                    jwcrypto.jwk.JWK.from_json(jwk_key_as_string),
                                )

        # Try loading ssh keys. Example: https://github.com/username.keys
        with contextlib.suppress(urllib.request.URLError):
            with urllib.request.urlopen(unverified_issuer) as response:
                while line := response.readline():
                    with contextlib.suppress(
                        (ValueError, cryptography.exceptions.UnsupportedAlgorithm)
                    ):
                        cryptography_ssh_keys.append(
                            cryptography.hazmat.primitives.serialization.load_ssh_public_key(
                                line
                            )
                        )

    for cryptography_ssh_key in cryptography_ssh_keys:
        jwk_keys.append(
            jwcrypto.jwk.JWK.from_pem(
                cryptography_ssh_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        )

    for jwk_key in jwk_keys:
        cwt_cose_key = cwt.COSEKey.from_pem(
            jwk_key.export_to_pem(),
            kid=jwk_key.thumbprint(),
        )
        cwt_cose_keys.append(cwt_cose_key)
        cwt_ec2_key_as_dict = cwt_cose_key.to_dict()
        pycose_cose_key = pycose.keys.ec2.EC2Key.from_dict(cwt_ec2_key_as_dict)
        pycose_cose_keys.append((cwt_cose_key, pycose_cose_key))

    for cwt_cose_key, pycose_cose_key in pycose_cose_keys:
        with contextlib.suppress(Exception):
            msg.key = pycose_cose_key
            verify_signature = msg.verify_signature()
            if verify_signature:
                return cwt_cose_key, pycose_cose_key


def main():
    claim = sys.stdin.buffer.read()

    msg = Sign1Message.decode(claim, tag=True)

    if pycose.headers.ContentType not in msg.phdr:
        raise ClaimInvalidError("Claim does not have a content type header parameter")
    if not msg.phdr[pycose.headers.ContentType].startswith("application/json"):
        raise TypeError(
            f"Claim content type does not start with application/json: {msg.phdr[pycose.headers.ContentType]!r}"
        )

    cwt_cose_key, _pycose_cose_key = verify_signature(msg)
    unittest.TestCase().assertTrue(
        cwt_cose_key,
        "Failed to verify signature on statement",
    )

    cwt_protected = cwt.decode(msg.phdr[CWTClaims], cwt_cose_key)
    issuer = cwt_protected[1]
    subject = cwt_protected[2]

    SCHEMA = json.loads(pathlib.Path(os.environ["SCHEMA_PATH"]).read_text())

    try:
        validate(
            instance={
                "$schema": "https://schema.example.com/scitt-policy-engine-jsonschema.schema.json",
                "issuer": issuer,
                "subject": subject,
                "claim": json.loads(msg.payload.decode()),
            },
            schema=SCHEMA,
        )
    except ValidationError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
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
$ npm install nodemon && \
  node_modules/.bin/nodemon -e .cose --exec 'find workspace/storage/operations -name \*.cose -exec nohup sh -xe policy_engine.sh $(cat workspace/service_parameters.json | jq -r .insertPolicy) {} \;'
```

Also ensure you restart the server with the new config we edited.

```console
$ scitt-emulator server --workspace workspace/ --tree-alg CCF --use-lro
```

The current emulator notary (create-statement) implementation will sign
statements using a generated ephemeral key or a key we provide via the
`--private-key-pem` argument.

Since we need to export the key for verification by the policy engine, we will
first generate it using `ssh-keygen`.

```console
$ export ISSUER_PORT="9000" \
  && export ISSUER_URL="http://localhost:${ISSUER_PORT}" \
  && ssh-keygen -q -f /dev/stdout -t ecdsa -b 384 -N '' -I $RANDOM <<<y 2>/dev/null | python -c 'import sys; from cryptography.hazmat.primitives import serialization; print(serialization.load_ssh_private_key(sys.stdin.buffer.read(), password=None).private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode().rstrip())' > private-key.pem \
  && scitt-emulator client create-claim \
    --private-key-pem private-key.pem \
    --issuer "${ISSUER_URL}" \
    --subject "solar" \
    --content-type application/json \
    --payload '{"sun": "yellow"}' \
    --out claim.cose
```

The core of policy engine we implemented in `jsonschema_validator.py` will
verify the COSE message generated using the public portion of the notary's key.
We've implemented two possible styles of key resolution. Both of them require
resolution of public keys via an HTTP server.

Let's start the HTTP server now, we'll populate the needed files in the
sections corresponding to each resolution style.

```console
$ python -m http.server "${ISSUER_PORT}" &
$ python_http_server_pid=$!
```

### SSH `authorized_keys` style notary public key resolution

Keys are discovered via making an HTTP GET request to the URL given by the
`issuer` parameter via the `web` DID method and de-serializing the SSH
public keys found within the response body.

GitHub exports a users authentication keys at https://github.com/username.keys
Leveraging this URL as an issuer `did:web:github.com:username.keys` with the
following pattern would enable a GitHub user to act as a SCITT notary.

Start an HTTP server with an SSH public key served at the root.

```console
$ cat private-key.pem | ssh-keygen -f /dev/stdin -y | tee index.html
```

### OpenID Connect token style notary public key resolution

Keys are discovered two part resolution of HTTP paths relative to the issuer

`/.well-known/openid-configuration` path is requested via HTTP GET. The
response body is parsed as JSON and the value of the `jwks_uri` key is
requested via HTTP GET.

`/.well-known/jwks` (is typically the value of `jwks_uri`) path is requested
via HTTP GET. The response body is parsed as JSON. Public keys are loaded
from the value of the `keys` key which stores an array of JSON Web Key (JWK)
style serializations.

```console
$ mkdir -p .well-known/
$ cat > .well-known/openid-configuration <<EOF
{
    "issuer": "${ISSUER_URL}",
    "jwks_uri": "${ISSUER_URL}/.well-known/jwks",
    "response_types_supported": ["id_token"],
    "claims_supported": ["sub", "aud", "exp", "iat", "iss"],
    "id_token_signing_alg_values_supported": ["ES384"],
    "scopes_supported": ["openid"]
}
EOF
$ cat private-key.pem | python -c 'import sys, json, jwcrypto.jwt; key = jwcrypto.jwt.JWK(); key.import_from_pem(sys.stdin.buffer.read()); print(json.dumps({"keys":[{**key.export_public(as_dict=True),"use": "sig","kid": key.thumbprint()}]}, indent=4, sort_keys=True))' | tee .well-known/jwks
{
    "keys": [
        {
            "crv": "P-384",
            "kid": "y96luxaBaw6FeWVEMti_iqLWPSYk8cKLzZG8X45PA2k",
            "kty": "EC",
            "use": "sig",
            "x": "ZQazDzYmcMHF5Dstkbw7SwWvR_oXQHFS-TLppri-0xDby8TmCpzHyr6TH03CLBxj",
            "y": "lsIbRskEv06Rf0vttkB3vpXdZ-a50ck74MVyRwOvN55P4s8usQAm3PY1KnAgWtHF"
        }
    ]
}
```

Attempt to submit the statement we created. You should see that due to our
current `allowlist.schema.json` the Transparency Service denied the insertion
of the statement into the log.

```console
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
```

Modify the allowlist to ensure that our issuer, aka our local HTTP server with
our keys, is set to be the allowed issuer.

```console
$ export allowlist="$(cat allowlist.schema.json)" && \
    jq '.properties.issuer.enum[0] = env.ISSUER_URL' <(echo "${allowlist}") \
    | tee allowlist.schema.json
```

Submit the statement from the issuer we just added to the allowlist.

```console
$ scitt-emulator client submit-claim --claim claim.cose --out claim.receipt.cbor
Claim registered with entry ID 1
Receipt written to claim.receipt.cbor
```

Stop the server that serves the public keys

```console
$ kill $python_http_server_pid
```
