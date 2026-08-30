from elegant_jwt import Clock, Signature


class FakeClock(Clock):
    def __init__(self, instant: int):
        self.instant = instant

    def moment(self) -> int:
        return self.instant


class FakeSignature(Signature):
    def __init__(self, raw: str, payload: dict):
        self.raw = raw
        self.payload = payload

    def encoded(self, payload: dict) -> str:
        return self.raw

    def decoded(self, raw: str, options: dict) -> dict:
        return dict(self.payload)


class BrokenSignature(Signature):
    def __init__(self, trouble: str):
        self.trouble = trouble

    def encoded(self, payload: dict) -> str:
        raise Exception(self.trouble)

    def decoded(self, raw: str, options: dict) -> dict:
        raise Exception(self.trouble)
