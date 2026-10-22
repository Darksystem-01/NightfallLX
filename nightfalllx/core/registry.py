from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from nightfalllx.core.module import BaseModule

MODULE_REGISTRY: dict[str, type[BaseModule]] = {}

ModuleType = TypeVar("ModuleType", bound=type[BaseModule])


def register(cls: ModuleType) -> ModuleType:
    name = getattr(cls, "name", "")
    if not name or name == "base":
        raise ValueError("module must define a unique non-base name")
    if name in MODULE_REGISTRY:
        raise ValueError(f"duplicate module name: {name}")
    MODULE_REGISTRY[name] = cls
    return cls


def get_module(name: str) -> type[BaseModule]:
    return MODULE_REGISTRY[name]


def iter_modules() -> Iterable[type[BaseModule]]:
    return MODULE_REGISTRY.values()
