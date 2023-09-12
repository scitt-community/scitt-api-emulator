# OIDC Support

- References
  - [5.1.1.1.1.](https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/blob/main/draft-ietf-scitt-architecture.md#comment-on-oidc)

[![asciicast-of-oidc-auth-issued-by-github-actions](https://asciinema.org/a/607600.svg)](https://asciinema.org/a/607600)

## Dependencies

Install the SCITT API Emulator with the `oidc` extra.

```console
$ pip install -e .[oidc]
```

## Usage example with GitHub Actions

See [`notarize.yml`](../.github/workflows/notarize.yml)

References:

- https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/using-openid-connect-with-reusable-workflows
- https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
