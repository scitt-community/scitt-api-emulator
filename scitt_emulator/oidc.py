# Copyright (c) SCITT Authors.
# Licensed under the MIT License.
import jwt
import json
import jsonschema
from werkzeug.wrappers import Request
from scitt_emulator.client import HttpClient


class OIDCAuthMiddleware:
    def __init__(self, app, config_path):
        self.app = app
        self.asgi_app = app.asgi_app
        self.config = {}
        if config_path and config_path.exists():
            self.config = json.loads(config_path.read_text())

        # Initialize JSON Web Key client for given issuer
        self.client = HttpClient()
        self.oidc_configs = {}
        self.jwks_clients = {}
        for issuer in self.config['issuers']:
            self.oidc_configs[issuer] = self.client.get(
                f"{issuer}/.well-known/openid-configuration"
            ).json()
            self.jwks_clients[issuer] = jwt.PyJWKClient(self.oidc_configs[issuer]["jwks_uri"])

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers", []))
        token = headers.get(b"authorization", "").replace(b"Bearer ", b"").decode()
        claims = self.validate_token(token)
        if "claim_schema" in self.config and claims["iss"] in self.config["claim_schema"]:
            jsonschema.validate(claims, schema=self.config["claim_schema"][claims["iss"]])
        return await self.asgi_app(scope, receive, send)

    def validate_token(self, token):
        validation_error = Exception(f"Failed to validate against all issuers: {self.jwks_clients.keys()!s}")
        for issuer, jwk_client in self.jwks_clients.items():
            try:
                return jwt.decode(
                    token,
                    key=jwk_client.get_signing_key_from_jwt(token).key,
                    algorithms=self.oidc_configs[issuer]["id_token_signing_alg_values_supported"],
                    audience=self.config.get("audience", None),
                    issuer=self.oidc_configs[issuer]["issuer"],
                    options={"strict_aud": self.config.get("strict_aud", True),},
                    leeway=self.config.get("leeway", 0),
                )
            except jwt.PyJWTError as error:
                validation_error = error
        raise validation_error
