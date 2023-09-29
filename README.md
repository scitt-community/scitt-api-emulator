# SCITT API Interoperability Client

This repository contains the source code for the SCITT API interoperability client and sample emulator.

It is meant to allow experimenting with [SCITT](https://datatracker.ietf.org/wg/scitt/about/) APIs and formats and proving interoperability of implementations.

Note the SCITT standards are not yet fully published and are subject to change.
This repository aims to keep up with changes to the WG output as faithfully as possible but in the event of inconsistencies between this and the IETF WG documents, the IETF documents are primary.

## Prerequisites

The emulator assumes a Linux environment with Python 3.10 or higher.
On Ubuntu, run the following to install Python:

```sh
sudo apt install python3.10-venv
```

### Optional Dependencies

If you want to use conda, first install it:

- [Install Conda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html)

You can get things setup with the following:

```sh
conda env create -f environment.yml
conda activate scitt
```

## Clone the Emulator

1. Clone the scitt-api-emulator repository and change into the scitt-api-emulator folder:

    ```sh
    git clone https://github.com/scitt-community/scitt-api-emulator.git
    ```

1. Move into the emulator director to utilize the local commands

    ```sh
    cd scitt-api-emulator
    ```

## Start the Proxy Server

The proxy server supports 2 options currently:

- 'CCF' uses the emulator server to create and verify receipts using the CCF tree algorithm
- 'RKVST' uses the RKVST production SaaS server to create and verify  receipts using native Merkle trees

**Note:** _the emulator is for experimentation only and not recommended for production use._

### Start a Fake Emulated SCITT Service

1. Start the service, under the `/workspace` directory, using CCF

    ```sh
    ./scitt-emulator.sh server --workspace workspace/ --tree-alg CCF
    ```

1. The server is running at http://localhost:8000/ and uses the `/workspace` folder to store the service parameters and service state  
  **Note:** _The default port is `8000` but can be changed with the `--port` argument._
1. Start another shell to run the test scripts, leaving the above shell for diagnostic output
1. Skip to [Create Claims](#create-claims)


### Start an RKVST SCITT Proxy Service

1. Start the service, under the `/workspace` directory, using RKVST  
  The default port is `8000` but can be changed with the `--port` argument.

    ```sh
    ./scitt-emulator.sh server --workspace workspace/ --tree-alg RKVST
    ```

### Executing Commands

The service has the following REST API:

- `POST /entries` submit a COSE_Sign1 claim as HTTP body, with a JSON response containing `"entry_id"`
- `GET /entries/<entry_id>` - retrieve the COSE_Sign1 claim for the corresponding entry id
- `GET /entries/<entry_id>/receipt` to retrieve the SCITT receipt.

The following steps should be done from a different terminal, leaving the service running in the background.

### Create Claims

1. Create a signed `json` claim with the payload: `{"sun": "yellow"}`, saving the formatted output to `claim.cose`

    ```sh
    ./scitt-emulator.sh client create-claim \
        --issuer did:web:example.com \
        --content-type application/json \
        --payload '{"sun": "yellow"}' \
        --out claim.cose
    ```

    _**Note:** The emulator generates an ad-hoc key pair to sign the claim and does not verify claim signatures upon submission._

2. View the signed claim by uploading `claim.cose` to one of the [CBOR or COSE Debugging Tools](#cose-and-cbor-debugging)

### Submit Claims and Retrieve Receipts

1. Submit the Signed Claim

    ```sh
    ./scitt-emulator.sh client submit-claim \
        --claim claim.cose \
        --out claim.receipt.cbor
    ```

1. View the response, noting the `Entry ID` value

    ```output
    Claim Registered:
        json:     {'entryId': '1'}
        Entry ID: 1
        Receipt:  ./claim.receipt.cbor
    ```

**Note:** The `submit-claim` command uses the default service URL `http://127.0.0.1:8000` which can be changed with the `--url` argument.
It can be used with the built-in server or an external service implementation.

### Retrieve Claims

1. Replace the `<entryId>` with the value from the `submit-claim` command above

```sh
./scitt-emulator.sh client retrieve-claim --entry-id <entryId> --out claim.cose
```

**Note:** The `retrieve-claim` command uses the default service URL `http://127.0.0.1:8000` which can be changed with the `--url` argument.
It can be used with the built-in server or an external service implementation.

This command sends the following request:

- `GET /entries/<entry_id>` to retrieve the claim.

### Retrieve Receipts

```sh
./scitt-emulator.sh client retrieve-receipt --entry-id 123 --out receipt.cbor
```

The `retrieve-receipt` command uses the default service URL `http://127.0.0.1:8000` which can be changed with the `--url` argument.
It can be used with the built-in server or an external service implementation.

This command sends the following request:

- `GET /entries/<entry_id>/receipt` to retrieve the receipt.

### Validate Receipts

```sh
./scitt-emulator.sh client verify-receipt \
    --claim claim.cose \
    --receipt claim.receipt.cbor \
    --service-parameters workspace/service_parameters.json
```

The `verify-receipt` command verifies a SCITT receipt given a SCITT claim and a service parameters file.
This command can be used to verify receipts generated by other implementations.

The `workspace/service_parameters.json` file gets created when starting a service using `./scitt-emulator.sh server`.
The format of this file is not standardized and is currently:

```json
{
    "serviceId": "emulator",
    "treeAlgorithm": "CCF",
    "signatureAlgorithm": "ES256",
    "insertPolicy": "*",
    "serviceCertificate": "-----BEGIN CERTIFICATE-----..."
}
```

`"signatureAlgorithm"` and `"serviceCertificate"` are additional parameters specific to the [`CCF` tree algorithm](https://ietf-scitt.github.io/draft-birkholz-scitt-receipts/draft-birkholz-scitt-receipts.html#name-additional-parameters).

To view the file:

```sh
cat workspace/service_parameters.json | jq
```

### COSE and CBOR Debugging

The following websites can be used to inspect COSE and CBOR files:

- [gluecose.github.io/cose-viewer](https://gluecose.github.io/cose-viewer/)
- [cbor.me](https://cbor.me/)

## Code Structure

`scitt_emulator/scitt.py` contains the core SCITT algorithms that are agnostic of a specific tree algorithm.

`scitt_emulator/ccf.py` is the implementation of the [CCF tree algorithm](https://ietf-scitt.github.io/draft-birkholz-scitt-receipts/draft-birkholz-scitt-receipts.html#name-ccf-tree-algorithm).
For each claim, a receipt is generated using a fake but valid Merkle tree that is independent of other submitted claims.
A real CCF service would maintain a single Merkle tree covering all submitted claims and auxiliary entries.

`scitt_emulator/rkvst.py` is a simple REST proxy that takes SCITT standard API calls and routes them through to the [RKVST production SaaS service](https://app.rkvst.io). 
Each claim is stored in a Merkle tree underpinning a Quorum blockchain and  receipts contain valid, verifiable inclusion proofs for the claim in that Merkle proof.
[More docs on receipts here](https://docs.rkvst.com/platform/overview/scitt-receipts/).

`scitt_emulator/server.py` is a simple Flask server that acts as a SCITT transparency service.

`scitt_emulator/client.py` is a CLI that supports creating claims, submitting claims to and retrieving receipts from the server, and verifying receipts.

In order to add a new tree algorithm, a file like `scitt_emulator/ccf.py` must be created and the containing class be added in `scitt_emulator/tree_algs.py`.

## Run Tests

```bash
./run-tests.sh
```

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
