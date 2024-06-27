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
            'did_jwk=scitt_emulator.key_loader_format_did_jwk:key_loader_format_did_jwk',
            'url_referencing_scitt_scrapi=scitt_emulator.key_loader_format_url_referencing_scitt_scrapi:key_loader_format_url_referencing_scitt_scrapi',
            'url_referencing_oidc_issuer=scitt_emulator.key_loader_format_url_referencing_oidc_issuer:key_loader_format_url_referencing_oidc_issuer',
            'url_referencing_ssh_authorized_keys=scitt_emulator.key_loader_format_url_referencing_ssh_authorized_keys:key_loader_format_url_referencing_ssh_authorized_keys',
        ],
        'scitt_emulator.key_helpers.transforms_key_instances': [
            'transform_key_instance_cwt_cose_ec2_to_pycose_ec2=scitt_emulator.key_transforms:transform_key_instance_cwt_cose_ec2_to_pycose_ec2',
            'transform_key_instance_jwcrypto_jwk_to_cwt_cose=scitt_emulator.key_loader_format_url_referencing_scitt_scrapi:transform_key_instance_jwcrypto_jwk_to_cwt_cose',
            'transform_key_instance_cryptography_ecc_public_to_jwcrypto_jwk=scitt_emulator:key_loader_format_url_referencing_ssh_authorized_keys.transform_key_instance_cryptography_ecc_public_to_jwcrypto_jwk',
        ],
        'scitt_emulator.key_helpers.verification_key_to_object': [
            'to_object_jwk=scitt_emulator.key_loader_format_did_jwk:to_object_jwk',
            'to_object_ssh_public=scitt_emulator.key_loader_format_url_referencing_ssh_authorized_keys:to_object_ssh_public',
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "cryptography",
        "cbor2",
        "cwt",
        "jwcrypto",
        "pycose",
        # TODO TODO NOTE XXX NOTE Convert aiohttp into httpx NOTE XXX TODO TODO
        "httpx",
        "flask",
        "rkvst-archivist"
    ],
    extras_require={
        "oidc": [
            "PyJWT",
            "jwcrypto",
            "jsonschema",
        ]
    },
)
