from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Protocol

from nightfalllx.core.finding import Finding


class TargetProtocol(Protocol):
    url: str
    method: str
    params: dict[str, Any]
    request_params: dict[str, Any]
    parameters: list[str]
    authorized: bool


class BaseModule(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    requires_parameters: ClassVar[bool] = False

    def applicable(self, target: TargetProtocol) -> bool:
        if self.requires_parameters and not target.params:
            return False
        return True

    @abstractmethod
    def run(self, target: TargetProtocol) -> list[Finding]:
        """Run detection-only checks and return evidence-backed findings."""
        raise NotImplementedError
