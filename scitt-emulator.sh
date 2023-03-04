#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

if [ ! -f "venv/bin/activate" ]; then
    echo "Setting up Python virtual environment."
    python -m venv "venv"
    . ./venv/bin/activate
    pip install -q -e .
else
    . ./venv/bin/activate 
fi

scitt-emulator "$@"
