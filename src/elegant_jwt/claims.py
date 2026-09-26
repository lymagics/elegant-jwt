from abc import ABC, abstractmethod
from copy import deepcopy
from typing import TYPE_CHECKING
from uuid import uuid4

from plum import dispatch

from elegant_jwt.clock import Clock, SystemClock
from elegant_jwt.signature import Signature

if TYPE_CHECKING:
    from elegant_jwt.token import Token


class Claims(ABC):
    @abstractmethod
    def token(self, signature: Signature) -> "Token":
        pass

    @abstractmethod
    def json(self) -> dict:
        pass


class JwtClaims(Claims):
    def __init__(self, payload: dict):
        self.payload = payload

    def token(self, signature: Signature) -> "Token":
        from elegant_jwt.token import JwtToken

        try:
            return JwtToken(signature.encoded(self.json()), signature)
        except Exception as cause:
            raise Exception("The claims could not be signed.") from cause

    def json(self) -> dict:
        return deepcopy(self.payload)


class ExpiringClaims(Claims):
    @dispatch
    def __init__(self, origin: Claims, lifetime: int):
        self.__init__(origin, lifetime, SystemClock())

    @dispatch
    def __init__(self, origin: Claims, lifetime: int, clock: Clock):
        self.origin = origin
        self.lifetime = lifetime
        self.clock = clock

    def token(self, signature: Signature) -> "Token":
        return JwtClaims(self.json()).token(signature)

    def json(self) -> dict:
        return {**self.origin.json(), "exp": self.clock.moment() + self.lifetime}


class NotBeforeClaims(Claims):
    @dispatch
    def __init__(self, origin: Claims, delay: int):
        self.__init__(origin, delay, SystemClock())

    @dispatch
    def __init__(self, origin: Claims, delay: int, clock: Clock):
        self.origin = origin
        self.delay = delay
        self.clock = clock

    def token(self, signature: Signature) -> "Token":
        return JwtClaims(self.json()).token(signature)

    def json(self) -> dict:
        return {**self.origin.json(), "nbf": self.clock.moment() + self.delay}


class IssuedClaims(Claims):
    @dispatch
    def __init__(self, origin: Claims, issuer: str):
        self.__init__(origin, issuer, SystemClock())

    @dispatch
    def __init__(self, origin: Claims, issuer: str, clock: Clock):
        self.origin = origin
        self.issuer = issuer
        self.clock = clock

    def token(self, signature: Signature) -> "Token":
        return JwtClaims(self.json()).token(signature)

    def json(self) -> dict:
        return {
            **self.origin.json(),
            "iat": self.clock.moment(),
            "iss": self.issuer,
        }


class JtiClaims(Claims):
    @dispatch
    def __init__(self, origin: Claims):
        self.__init__(origin, str(uuid4()))

    @dispatch
    def __init__(self, origin: Claims, identity: str):
        self.origin = origin
        self.identity = identity

    def token(self, signature: Signature) -> "Token":
        return JwtClaims(self.json()).token(signature)

    def json(self) -> dict:
        return {**self.origin.json(), "jti": self.identity}
