from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

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

        return JwtToken(signature.encoded(self.json()), signature)

    def json(self) -> dict:
        return dict(self.payload)


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
