import os
import urllib.parse
from typing import Optional


DID_JWK_METHOD = "did:jwk:"


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


def url_to_did_web(url_string):
    url = urllib.parse.urlparse(url_string)
    return ":".join(
        [
            urllib.parse.quote(i)
            for i in ["did", "web", url.netloc, *filter(bool, url.path.split("/"))]
        ]
    )
