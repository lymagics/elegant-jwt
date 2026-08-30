from abc import ABC, abstractmethod

from plum import dispatch

from elegant_jwt.claims import Claims, JwtClaims
from elegant_jwt.clock import Clock, SystemClock
from elegant_jwt.signature import Signature


class Token(ABC):
    @abstractmethod
    def claims(self) -> Claims:
        pass

    @abstractmethod
    def expired(self) -> bool:
        pass

    @abstractmethod
    def validity(self) -> int:
        pass

    @abstractmethod
    def value(self) -> str:
        pass


class JwtToken(Token):
    @dispatch
    def __init__(self, raw: str, signature: Signature):
        self.__init__(raw, signature, SystemClock())

    @dispatch
    def __init__(self, raw: str, signature: Signature, clock: Clock):
        self.raw = raw
        self.signature = signature
        self.clock = clock

    def claims(self) -> Claims:
        try:
            return JwtClaims(self.signature.decoded(self.raw, {}))
        except Exception as cause:
            raise Exception("The access token is not valid.") from cause

    def expired(self) -> bool:
        return self.validity() == 0

    def validity(self) -> int:
        payload = self.signature.decoded(self.raw, {"verify_exp": False})
        try:
            expiration = int(payload["exp"])
        except KeyError as cause:
            raise Exception("The token has no expiration claim.") from cause
        return max(0, expiration - self.clock.moment())

    def value(self) -> str:
        return self.raw


class StrictToken(Token):
    def __init__(self, origin: Token):
        self.origin = origin

    def claims(self) -> Claims:
        if self.origin.expired():
            raise Exception("The access token has expired.")
        return self.origin.claims()

    def expired(self) -> bool:
        return self.origin.expired()

    def validity(self) -> int:
        return self.origin.validity()

    def value(self) -> str:
        return self.origin.value()
