import time
from abc import ABC, abstractmethod


class Clock(ABC):
    @abstractmethod
    def moment(self) -> int:
        pass


class SystemClock(Clock):
    def moment(self) -> int:
        return int(time.time())
