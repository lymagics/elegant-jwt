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
        payload = self._payload()
        if "exp" in payload and self._validity(payload) == 0:
            raise Exception("The access token has expired.")
        return JwtClaims(payload)

    def expired(self) -> bool:
        return self.validity() == 0

    def validity(self) -> int:
        return self._validity(self._payload())

    def value(self) -> str:
        return self.raw

    def _payload(self) -> dict:
        try:
            return self.signature.decoded(self.raw, {"verify_exp": False})
        except Exception as cause:
            raise Exception("The access token is not valid.") from cause

    def _validity(self, payload: dict) -> int:
        try:
            expiration = int(payload["exp"])
        except KeyError as cause:
            raise Exception("The token has no expiration claim.") from cause
        except (TypeError, ValueError) as cause:
            raise Exception("The expiration claim is not a number.") from cause
        return max(0, expiration - self.clock.moment())


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
