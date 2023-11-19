import json
import contextlib
import urllib.parse
import urllib.request
from typing import List, Tuple

import cwt
import cwt.algs.ec2
import pycose
import pycose.keys.ec2

# TODO Remove this once we have a example flow for proper key verification
import jwcrypto.jwk

from scitt_emulator.did_helpers import did_web_to_url


def key_loader_format_url_referencing_activitypub_actor(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []

    # TODO Support for lookup by did:key, also, is that just bonvie that does
    # that via webfinger? Need to check
    if (
        not unverified_issuer.startswith("did:web:")
        or urllib.parse.quote("webfinger?resource=") not in unverified_issuer
    ):
        return pycose_cose_keys

    # export DOMAIN="scitt.unstable.chadig.com"; curl -s $(curl -s "https://${DOMAIN}/.well-known/webfinger?resource=acct:bovine@${DOMAIN}" | jq -r .links[0].href) | jq -r .publicKey.publicKeyPem
    raise NotImplementedError()
