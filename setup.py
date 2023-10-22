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
        ],
        'scitt_emulator.verify_signature.key_loaders': [
            'did_key=scitt_emulator.key_loader_format_did_key:key_loader_format_did_key',
            'url_referencing_oidc_issuer=scitt_emulator.key_loader_format_url_referencing_oidc_issuer:key_loader_format_url_referencing_oidc_issuer',
            'url_referencing_ssh_authorized_keys=scitt_emulator.key_loader_format_url_referencing_ssh_authorized_keys:key_loader_format_url_referencing_ssh_authorized_keys',
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "cryptography",
        "cbor2",
        "cwt",
        "py-multicodec",
        "py-multibase",
        "jwcrypto",
        "pycose",
        "httpx",
        "flask",
        "quart",
        "rkvst-archivist"
    ],
    extras_require={
        "oidc": [
            "PyJWT",
            "jwcrypto",
            "jsonschema",
        ],
        "federation-activitypub-bovine": [
            "tomli",
            "tomli-w",
            "aiohttp",
            "bovine",
            "bovine-tool",
            "mechanical-bull",
        ],
    },
)
