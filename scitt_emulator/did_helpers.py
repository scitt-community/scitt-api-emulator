import os
import ast
import sys
import base64
import inspect
import urllib.parse
from typing import Optional, Callable, Dict, Tuple, Union

import multibase
import multicodec
import cryptography.hazmat.primitives.asymmetric.ec


def did_web_to_url(
    did_web_string: str,
    *,
    scheme: Optional[str] = None,
):
    if scheme is None:
        scheme = os.environ.get("DID_WEB_ASSUME_SCHEME", "https")
    return "/".join(
        [
            f"{scheme}:/",
            *[urllib.parse.unquote(i) for i in did_web_string.split(":")[2:]],
        ]
    )


class DIDKeyInvalidPublicKeyLengthError(ValueError):
    """
    If the byte length of rawPublicKeyBytes does not match the expected public
    key length for the associated multicodecValue, an invalidPublicKeyLength
    error MUST be raised.
    """


class DIDKeyDecoderNotFoundError(NotImplementedError):
    """
    Raised when we don't have a function implemented to decode the given key
    """


class DIDKeyDecoderError(Exception):
    """
    Raised when we failed to decode a key from a did:key DID method
    """


class DIDKeyInvalidPublicKeyError(DIDKeyDecoderError):
    """
    Raised when the raw bytes of a key are invalid during decode
    """


DID_KEY_METHOD = "did:key:"


def did_key_decode_public_key(multibase_value: str) -> Tuple[bytes, bytes]:
    # 3.1.2.3
    # Decode multibaseValue using the base58-btc multibase alphabet and set
    # multicodecValue to the multicodec header for the decoded value.
    multibase_value_decoded = multibase.decode(multibase_value)
    # Implementers are cautioned to ensure that the multicodecValue is set to
    # the result after performing varint decoding.
    multicodec_value = multicodec.extract_prefix(multibase_value_decoded)
    # Set the rawPublicKeyBytes to the bytes remaining after the multicodec
    # header.
    raw_public_key_bytes = multicodec.remove_prefix(multibase_value_decoded)
    # Return multicodecValue and rawPublicKeyBytes as the decodedPublicKey.
    return multicodec_value, raw_public_key_bytes


class _MULTICODEC_VALUE_NOT_FOUND_IN_TABLE:
    pass


MULTICODEC_VALUE_NOT_FOUND_IN_TABLE = _MULTICODEC_VALUE_NOT_FOUND_IN_TABLE()

# Multicodec hexadecimal value, public key, byte length,	Description
MULTICODEC_HEX_SECP256K1_PUBLIC_KEY = 0xE7
MULTICODEC_HEX_X25519_PUBLIC_KEY = 0xEC
MULTICODEC_HEX_ED25519_PUBLIC_KEY = 0xED
MULTICODEC_HEX_P256_PUBLIC_KEY = 0x1200
MULTICODEC_HEX_P384_PUBLIC_KEY = 0x1201
MULTICODEC_HEX_P521_PUBLIC_KEY = 0x1202
MULTICODEC_HEX_RSA_PUBLIC_KEY = 0x1205

MULTICODEC_VALUE_TABLE = {
    MULTICODEC_HEX_SECP256K1_PUBLIC_KEY: 33,  # secp256k1-pub - Secp256k1 public key (compressed)
    MULTICODEC_HEX_X25519_PUBLIC_KEY: 32,  # x25519-pub - Curve25519 public key
    MULTICODEC_HEX_ED25519_PUBLIC_KEY: 32,  # ed25519-pub - Ed25519 public key
    MULTICODEC_HEX_P256_PUBLIC_KEY: 33,  # p256-pub - P-256 public key (compressed)
    MULTICODEC_HEX_P384_PUBLIC_KEY: 49,  # p384-pub - P-384 public key (compressed)
    MULTICODEC_HEX_P521_PUBLIC_KEY: None,  # 	p521-pub - P-521 public key (compressed)
    MULTICODEC_HEX_RSA_PUBLIC_KEY: None,  # 	rsa-pub - RSA public key. DER-encoded ASN.1 type RSAPublicKey according to IETF RFC 8017 (PKCS #1)
}


def did_key_signature_method_creation(
    multibase_value: hex,
    raw_public_key_bytes: bytes,
) -> Union[cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey]:
    # 3.1.2 https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm
    # Initialize verificationMethod to an empty object.
    verification_method = {}

    # Set multicodecValue and rawPublicKeyBytes to the result of passing
    # multibaseValue and options to § 3.1.3 Decode Public Key Algorithm.
    # Ensure the proper key length of rawPublicKeyBytes based on the
    # multicodecValue table
    public_key_length_MUST_be = MULTICODEC_VALUE_TABLE.get(
        multibase_value, MULTICODEC_VALUE_NOT_FOUND_IN_TABLE
    )
    if public_key_length_MUST_be is MULTICODEC_VALUE_NOT_FOUND_IN_TABLE:
        raise DIDKeyDecoderNotFoundError(
            f"multibase_value {multibase_value!r} not in MULTICODEC_VALUE_NOT_FOUND_IN_TABLE {MULTICODEC_VALUE_NOT_FOUND_IN_TABLE!r}"
        )

    # If the byte length of rawPublicKeyBytes does not match the expected public
    # key length for the associated multicodecValue, an invalidPublicKeyLength
    # error MUST be raised.
    if public_key_length_MUST_be is not None and public_key_length_MUST_be != len(
        raw_public_key_bytes
    ):
        raise DIDKeyInvalidPublicKeyLengthError(
            f"public_key_length_MUST_be: {public_key_length_MUST_be } != len(raw_public_key_bytes): {len(raw_public_key_bytes)}"
        )

    # Ensure the rawPublicKeyBytes are a proper encoding of the public key type
    # as specified by the multicodecValue. This validation is often done by a
    # cryptographic library when importing the public key by, for example,
    # ensuring that an Elliptic Curve public key is a specific coordinate that
    # exists on the elliptic curve. If an invalid public key value is detected,
    # an invalidPublicKey error MUST be raised.
    #
    # SPEC ISSUE: Request for feedback on implementability:  It is not clear if
    # this particular check is implementable across all public key types. The
    # group is accepting feedback on the implementability of this particular
    # feature.
    try:
        if multibase_value in (
            MULTICODEC_HEX_P256_PUBLIC_KEY,
            MULTICODEC_HEX_P384_PUBLIC_KEY,
            MULTICODEC_HEX_P521_PUBLIC_KEY,
        ):
            public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
                raw_public_key_bytes,
            )
        else:
            raise DIDKeyDecoderNotFoundError(
                f"No importer for multibase_value {multibase_value!r}"
            )
    except Exception as e:
        raise DIDKeyInvalidPublicKeyError(
            f"invalid raw_public_key_bytes: {raw_public_key_bytes!r}"
        ) from e

    return public_key


def did_key_to_cryptography_key(
    did_key: str,
) -> Union[cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey]:
    """
    References

    - https://w3c-ccg.github.io/did-method-key/#p-384
    - RFC7515: JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
    - RFC8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE): https://www.rfc-editor.org/rfc/rfc8037

    Examples

    - P-384: https://github.com/w3c-ccg/did-method-key/blob/f5abee840c31e92cd1ac11737e0b62103ab99d21/test-vectors/nist-curves.json#L112-L166

    >>> did_key_to_cryptography_key("did:key:invalid")
    Traceback (most recent call last):
    DIDKeyDecoderNotFoundError: ...
    >>> public_key = did_key_to_cryptography_key("did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9")
    >>> public_key.__class__
    <class 'cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey'>
    """
    try:
        multibase_value, raw_public_key_bytes = did_key_decode_public_key(
            did_key.replace(DID_KEY_METHOD, "", 1)
        )
    except Exception as e:
        raise DIDKeyDecoderNotFoundError(did_key) from e

    try:
        return did_key_signature_method_creation(multibase_value, raw_public_key_bytes)
    except Exception as e:
        raise DIDKeyDecoderError(did_key) from e

    raise DIDKeyDecoderNotFoundError(did_key)
