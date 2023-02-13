# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import setup, find_packages

setup(
    name="scitt-emulator",
    version="0.0.1",
    packages=find_packages(),
    entry_points = {
        'console_scripts': [
            'scitt-emulator=scitt_emulator.cli:main'
        ]
    },
    python_requires=">=3.8",
    install_requires=[
        "cryptography",
        "cbor2",
        "pycose",
        "httpx",
        "flask"
    ],
)
