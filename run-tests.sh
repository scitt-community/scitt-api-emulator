#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if [ ! -f "venv/bin/activate" ]; then
    echo "Setting up Python virtual environment."
    python3 -m venv "venv"
    . ./venv/bin/activate
    pip install -q -U pip setuptools wheel
    pip install -q -r dev-requirements.txt
    pip install -q -e .[oidc,federation-activitypub-bovine]
else
    . ./venv/bin/activate 
fi

pytest "$@"
