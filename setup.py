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
        'scitt_emulator.key_helpers.transforms_key_instances': [
            'transform_key_instance_cwt_cose_ec2_to_pycose_ec2=scitt_emulator.key_transforms:transform_key_instance_cwt_cose_ec2_to_pycose_ec2',
            'transform_key_instance_cryptography_ecc_public_to_jwcrypto_jwk=scitt_emulator:key_loader_format_did_key.transform_key_instance_cryptography_ecc_public_to_jwcrypto_jwk',
            'transform_key_instance_jwcrypto_jwk_to_cwt_cose=scitt_emulator.key_loader_format_url_referencing_oidc_issuer:transform_key_instance_jwcrypto_jwk_to_cwt_cose',
        ],
        'scitt_emulator.key_helpers.verification_key_to_object': [
            'to_object_oidc_issuer=scitt_emulator.key_loader_format_url_referencing_oidc_issuer:to_object_oidc_issuer',
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
