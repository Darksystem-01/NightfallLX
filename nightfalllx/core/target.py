from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TargetSpec:
    url: str
    method: str = "GET"
    params: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    authorized: bool = False

    def __post_init__(self) -> None:
        self.method = self.method.upper()

    @property
    def request_params(self) -> dict[str, Any]:
        return self.data if self.method == "POST" else self.params

    @property
    def parameters(self) -> list[str]:
        return list(self.request_params)
