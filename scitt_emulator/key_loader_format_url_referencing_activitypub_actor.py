import os
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



def key_loader_format_url_referencing_activitypub_actor(
    unverified_issuer: str,
) -> List[Tuple[cwt.COSEKey, pycose.keys.ec2.EC2Key]]:
    """
    >>> import jwcrypto
    >>> import httptest
    >>>
    >>> class TestHTTPServer(httptest.Handler):
    ...
    ...     def do_GET(self):
    ...         status_code = 200
    ...         response = {"status": "failure"}
    ...         if self.path.startswith("/.well-known/webfinger?resource="):
    ...             # TODO Add server url as prefix
    ...             response = {"links": [{"href": f"http://localhost:{self.server.server_port}/endpoint/alice"}]}
    ...         elif self.path.startswith("/endpoint/"):
    ...             response = {"publicKey": {"publicKeyPem": jwcrypto.jwk.JWK.generate(kty="EC", crv="P-384").export_to_pem().decode()}}
    ...         else:
    ...             status_code = 400
    ...         contents = json.dumps(response).encode()
    ...         self.send_response(status_code)
    ...         self.send_header("Content-type", "application/json")
    ...         self.send_header("Content-length", len(contents))
    ...         self.end_headers()
    ...         self.wfile.write(contents)
    >>>
    >>> with httptest.Server(TestHTTPServer) as ts:
    ...     len(key_loader_format_url_referencing_activitypub_actor(f"alice@{ts.url()[:-1]}"))
    1
    """
    jwk_keys = []
    cwt_cose_keys = []
    pycose_cose_keys = []

    # TODO Support for lookup by did:key, also, is that just bonvie that does
    # that via webfinger? Need to check
    # if (
    #     not unverified_issuer.startswith("did:web:")
    #     or urllib.parse.quote("webfinger?resource=") not in unverified_issuer
    # ):
    #     return pycose_cose_keys
    if "@" not in unverified_issuer:
        return pycose_cose_keys

    handle_name, domain = unverified_issuer.split("@", maxsplit=1)
    scheme = os.environ.get("DID_WEB_ASSUME_SCHEME", "https")
    if "://" in domain:
        scheme = domain.split("://")[0]
    if not domain.startswith(scheme):
        domain = f"{scheme}://{domain}"
    domain_no_scheme = domain.replace(f"{scheme}://", "", 1)

    # Webfinger the account
    with urllib.request.urlopen(f"{domain}/.well-known/webfinger?resource=acct:{handle_name}@{domain_no_scheme}") as response:
        for link in json.load(response)["links"]:
            with urllib.request.urlopen(link["href"]) as response:
                public_key_pem = json.load(response)["publicKey"]["publicKeyPem"]
                jwk_keys.append(jwcrypto.jwk.JWK.from_pem(public_key_pem.encode()))

    for jwk_key in jwk_keys:
        cwt_cose_key = cwt.COSEKey.from_pem(
            jwk_key.export_to_pem(),
            kid=jwk_key.thumbprint(),
        )
        cwt_cose_keys.append(cwt_cose_key)
        cwt_ec2_key_as_dict = cwt_cose_key.to_dict()
        pycose_cose_key = pycose.keys.ec2.EC2Key.from_dict(cwt_ec2_key_as_dict)
        pycose_cose_keys.append((cwt_cose_key, pycose_cose_key))

    return pycose_cose_keys
