from abc import ABC, abstractmethod

import jwt


class Signature(ABC):
    @abstractmethod
    def encoded(self, payload: dict) -> str:
        pass

    @abstractmethod
    def decoded(self, raw: str, options: dict) -> dict:
        pass


class Hs256(Signature):
    def __init__(self, secret: str):
        self.secret = secret

    def encoded(self, payload: dict) -> str:
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def decoded(self, raw: str, options: dict) -> dict:
        return jwt.decode(raw, self.secret, algorithms=["HS256"], options=options)


class Rs256(Signature):
    def __init__(self, private_key: str, public_key: str):
        self.private_key = private_key
        self.public_key = public_key

    def encoded(self, payload: dict) -> str:
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def decoded(self, raw: str, options: dict) -> dict:
        return jwt.decode(raw, self.public_key, algorithms=["RS256"], options=options)


class Es256(Signature):
    def __init__(self, private_key: str, public_key: str):
        self.private_key = private_key
        self.public_key = public_key

    def encoded(self, payload: dict) -> str:
        return jwt.encode(payload, self.private_key, algorithm="ES256")

    def decoded(self, raw: str, options: dict) -> dict:
        return jwt.decode(raw, self.public_key, algorithms=["ES256"], options=options)


class AudienceSignature(Signature):
    def __init__(self, origin: Signature, audience: str):
        self.origin = origin
        self.audience = audience

    def encoded(self, payload: dict) -> str:
        return self.origin.encoded(payload)

    def decoded(self, raw: str, options: dict) -> dict:
        payload = self.origin.decoded(raw, {**options, "verify_aud": False})
        jwt.decode(
            raw,
            options={"verify_signature": False, "verify_aud": True},
            audience=self.audience,
        )
        return payload
