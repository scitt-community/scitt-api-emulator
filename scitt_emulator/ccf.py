# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import Optional
from pathlib import Path
from hashlib import sha256
import datetime
import json

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
    NoEncryption,
    PrivateFormat,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from scitt_emulator.scitt import SCITTServiceEmulator


class CCFSCITTServiceEmulator(SCITTServiceEmulator):
    tree_alg = "CCF"

    def __init__(
        self, service_parameters_path: Path, storage_path: Optional[Path] = None
    ):
        super().__init__(service_parameters_path, storage_path)
        if storage_path is not None:
            self._service_private_key_path = (
                self.storage_path / "service_private_key.pem"
            )

    def initialize_service(self):
        if self.service_parameters_path.exists():
            return

        # Create service private key
        service_private_key = ec.generate_private_key(ec.SECP256R1())
        service_private_key_pem = service_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        with open(self._service_private_key_path, "wb") as f:
            f.write(service_private_key_pem)
        print(f"Service private key written to {self._service_private_key_path}")

        # Create service certificate
        issuer = subject = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "service")]
        )
        service_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(service_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(service_private_key, hashes.SHA256())
        )
        service_cert_pem = service_cert.public_bytes(Encoding.PEM)

        self.service_parameters = {
            "serviceId": "emulator",
            "treeAlgorithm": self.tree_alg,
            "signatureAlgorithm": "ES256",
            "serviceCertificate": service_cert_pem.decode("utf-8"),
        }

        with open(self.service_parameters_path, "w") as f:
            json.dump(self.service_parameters, f)
        print(f"Service parameters written to {self.service_parameters_path}")

    def create_receipt_contents(self, countersign_tbi: bytes, entry_id: str):
        # Load service private key and certificate
        with open(self._service_private_key_path, "rb") as f:
            priv_key_service = load_pem_private_key(f.read(), None)

        service_cert = x509.load_pem_x509_certificate(
            self.service_parameters["serviceCertificate"].encode("utf-8")
        )

        # Create ad-hoc node key pair
        node_priv_key = ec.generate_private_key(ec.SECP256R1())
        node_pub_key = node_priv_key.public_key()

        # Create ad-hoc node certificate endorsed by service key
        node_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "node")])
            )
            .issuer_name(service_cert.subject)
            .public_key(node_pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(service_cert.not_valid_before)
            .not_valid_after(service_cert.not_valid_after)
            .sign(priv_key_service, hashes.SHA256())
        )
        node_cert_der = node_cert.public_bytes(Encoding.DER)

        # Compute Merkle tree leaf hash
        countersign_tbi_hash = sha256(countersign_tbi).digest()
        internal_hash = sha256(b"dummy").digest()
        internal_data = f"{entry_id}"
        internal_data_hash = sha256(internal_data.encode("ascii")).digest()
        leaf = sha256(
            internal_hash + internal_data_hash + countersign_tbi_hash
        ).digest()
        print("Leaf hash: " + leaf.hex())

        # Compute Merkle tree root
        fake_tree = CCFMerkleTree()
        for i in range(63):
            fake_tree.add_leaf(f"dummy-envelope-{i}".encode())
        fake_tree.add_leaf(leaf, do_hash=False)
        root = fake_tree.get_merkle_root()
        print("Root: " + root.hex())

        # Sign root
        signature = node_priv_key.sign(root, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        # Compute Merkle tree proof
        # Simplification, since the tree has an even number of leaves
        # and the leaf of interest is the last one.
        proof = [[True, level[-2]] for level in fake_tree.levels[::-1][:-1]]

        # Create receipt contents for CCF tree algorithm
        leaf_info = [internal_hash, internal_data]
        receipt_contents = [signature, node_cert_der, proof, leaf_info]

        return receipt_contents

    def verify_receipt_contents(self, receipt_contents: list, countersign_tbi: bytes):
        [signature, node_cert_der, proof, leaf_info] = receipt_contents

        [internal_hash, internal_data] = leaf_info

        # Compute Merkle tree leaf hash
        countersign_tbi_hash = sha256(countersign_tbi).digest()
        internal_data_hash = sha256(internal_data.encode("ascii")).digest()
        leaf = sha256(
            internal_hash + internal_data_hash + countersign_tbi_hash
        ).digest()
        print("Leaf hash: " + leaf.hex())

        # Compute Merkle tree root
        current = leaf
        for [left, hash] in proof:
            if left:
                current = sha256(hash + current).digest()
            else:
                current = sha256(current + hash).digest()
        root = current
        print("Root: " + root.hex())

        # Verify Merkle tree root signature
        node_cert = x509.load_der_x509_certificate(node_cert_der)
        node_cert.public_key().verify(
            signature, root, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        # Verify node certificate
        service_cert = x509.load_pem_x509_certificate(
            self.service_parameters["serviceCertificate"].encode("utf-8")
        )
        verify_certificate_is_issued_by(node_cert, service_cert)


def verify_certificate_is_issued_by(
    certificate: x509.Certificate, other: x509.Certificate
):
    if other.subject != certificate.issuer:
        raise RuntimeError(
            "Certificate issuer does not match subject of issuer certificate"
        )
    public_key = other.public_key()
    signature = certificate.signature
    data = certificate.tbs_certificate_bytes
    if isinstance(public_key, ec.EllipticCurvePublicKeyWithSerialization):
        public_key.verify(
            signature,
            data,
            signature_algorithm=ec.ECDSA(certificate.signature_hash_algorithm),
        )
    else:
        raise NotImplementedError("Unsupported public key type")


class CCFMerkleTree(object):
    """
    CCF-style Merkle Tree implementation.
    """

    def __init__(self):
        self.levels = []
        self.reset_tree()

    def reset_tree(self):
        self.leaves = []
        self.levels = []

    def add_leaf(self, values: bytes, do_hash=True):
        digest = values
        if do_hash:
            digest = sha256(values).digest()
        self.leaves.append(digest)

    def get_leaf(self, index: int) -> bytes:
        return self.leaves[index]

    def get_leaf_count(self) -> int:
        return len(self.leaves)

    def get_merkle_root(self) -> bytes:
        # Always make tree before getting root
        self._make_tree()
        if self.levels is None:
            raise Exception(
                "Unexpected error while getting root. CCFMerkleTree has no levels."
            )

        return self.levels[0][0]

    def _calculate_next_level(self):
        solo_leaf = None
        # number of leaves on the level
        number_of_leaves_on_current_level = len(self.levels[0])

        if number_of_leaves_on_current_level == 1:
            raise Exception("Merkle Tree should have more than one leaf at every level")

        if (
            number_of_leaves_on_current_level % 2 == 1
        ):  # if odd number of leaves on the level
            # Get the solo leaf (last leaf in-case the leaves are odd numbered)
            solo_leaf = self.levels[0][-1]
            number_of_leaves_on_current_level -= 1

        new_level = []
        for left_node, right_node in zip(
            self.levels[0][0:number_of_leaves_on_current_level:2],
            self.levels[0][1:number_of_leaves_on_current_level:2],
        ):
            new_level.append(sha256(left_node + right_node).digest())
        if solo_leaf is not None:
            new_level.append(solo_leaf)
        self.levels = [
            new_level,
        ] + self.levels  # prepend new level

    def _make_tree(self):
        if self.get_leaf_count() > 0:
            self.levels = [
                self.leaves,
            ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
