# Elegant JWT

[![EO principles respected here](https://www.elegantobjects.org/badge.svg)](https://www.elegantobjects.org)

JSON Web Tokens in the [Elegant Objects](https://www.elegantobjects.org/) style.
The library hides `pyjwt` behind small immutable objects: a `Token`, its
`Claims`, and a `Signature` that owns the algorithm and the key.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tokens That Expire](#tokens-that-expire)
- [Refusing Expired Tokens](#refusing-expired-tokens)
- [Stamping the Issuer](#stamping-the-issuer)
- [Asymmetric Algorithms](#asymmetric-algorithms)
- [Testing Without Waiting](#testing-without-waiting)
- [Your Own Signature](#your-own-signature)
- [Errors](#errors)
- [Design](#design)
- [Development](#development)

## Installation

```bash
uv add elegant-jwt
```

or

```bash
pip install elegant-jwt
```

## Quick Start

Create a token and read it back:

```python
from elegant_jwt import Hs256, JwtClaims, JwtToken

signature = Hs256("a-secret-of-at-least-thirty-two-bytes!")

raw = JwtClaims({"sub": "42"}).token(signature).value()
print(raw)  # => "eyJhbGciOiJIUzI1NiIs..."

claims = JwtToken(raw, signature).claims()
print(claims.json())  # => {"sub": "42"}
```

The algorithm is an object, never a hardcoded string. Pick `Hs256`, `Rs256`,
or `Es256`, or implement the `Signature` interface yourself.

## Tokens That Expire

Wrap your claims in `ExpiringClaims` to add an `exp` claim. The lifetime is
in seconds:

```python
from elegant_jwt import ExpiringClaims, Hs256, JwtClaims

signature = Hs256("a-secret-of-at-least-thirty-two-bytes!")

token = ExpiringClaims(
    JwtClaims({"sub": "42"}),
    3600,
).token(signature)

print(token.expired())   # => False
print(token.validity())  # => 3600 (seconds left until expiration)
```

## Refusing Expired Tokens

`StrictToken` is a decorator that refuses to give claims from an expired
token. Use it wherever an expired token must be treated as an error:

```python
from elegant_jwt import ExpiringClaims, Hs256, JwtClaims, JwtToken, StrictToken

signature = Hs256("a-secret-of-at-least-thirty-two-bytes!")
raw = ExpiringClaims(JwtClaims({"sub": "42"}), 3600).token(signature).value()

token = StrictToken(JwtToken(raw, signature))
token.claims()  # raises Exception once the token has expired
```

A strict token needs an `exp` claim to judge freshness, so create it with
`ExpiringClaims`.

## Stamping the Issuer

`IssuedClaims` adds `iat` (issued at) and `iss` (issuer) claims. Decorators
stack, each one adding its own claims on top:

```python
from elegant_jwt import ExpiringClaims, Hs256, IssuedClaims, JwtClaims

token = IssuedClaims(
    ExpiringClaims(
        JwtClaims({"sub": "42"}),
        3600,
    ),
    "my-service",
).token(Hs256("a-secret-of-at-least-thirty-two-bytes!"))

print(token.claims().json())
# => {"sub": "42", "exp": 1788094023, "iat": 1788090423, "iss": "my-service"}
```

## Asymmetric Algorithms

`Rs256` and `Es256` sign with a private key and verify with a public key,
both in PEM format:

```python
from elegant_jwt import JwtClaims, JwtToken, Rs256

signature = Rs256(private_pem, public_pem)

raw = JwtClaims({"sub": "42"}).token(signature).value()
claims = JwtToken(raw, signature).claims()
```

A service that only verifies tokens holds just the public key and never
calls `encoded`.

## Testing Without Waiting

Time is an input, not a hidden call. Every object that needs the current
time accepts a `Clock`, so tests never sleep and never patch:

```python
from elegant_jwt import Clock, ExpiringClaims, JwtClaims


class FrozenClock(Clock):
    def __init__(self, instant: int):
        self.instant = instant

    def moment(self) -> int:
        return self.instant


claims = ExpiringClaims(JwtClaims({"sub": "42"}), 60, FrozenClock(1000))
print(claims.json())  # => {"sub": "42", "exp": 1060}
```

## Your Own Signature

Need a key from a JWKS endpoint, a vault, or a database? Implement the
`Signature` interface and keep the policy (cache, retry, timeout) on your
side; the library stays free of I/O:

```python
from elegant_jwt import Signature


class VaultSignature(Signature):
    def __init__(self, vault: Vault):
        self.vault = vault

    def encoded(self, payload: dict) -> str:
        return Hs256(self.vault.secret()).encoded(payload)

    def decoded(self, raw: str, options: dict) -> dict:
        return Hs256(self.vault.secret()).decoded(raw, options)
```

## Errors

Every failure raises a plain `Exception` with a human message, chained to
the original cause:

```python
try:
    JwtToken("not-a-token", signature).claims()
except Exception as trouble:
    print(trouble)  # => "The access token is not valid."
```

## Design

- Every class is immutable; a change produces a new object.
- New behavior comes from decorators (`StrictToken`, `ExpiringClaims`,
  `IssuedClaims`), not from modification of existing classes.
- The library performs no network and no filesystem access.

## Development

```bash
make unit     # tests with coverage
make black    # formatting
make flake8   # style
make ruff     # lint
```
