from __future__ import annotations

import pytest

from nightfalllx.core.finding import Finding
from nightfalllx.core.module import BaseModule
from nightfalllx.core.registry import MODULE_REGISTRY, get_module, register


class DemoModule(BaseModule):
    name = "demo"
    description = "test module"

    def run(self, target) -> list[Finding]:
        return []


def test_register_and_lookup_module() -> None:
    MODULE_REGISTRY.pop("demo", None)
    assert register(DemoModule) is DemoModule
    assert get_module("demo") is DemoModule
    with pytest.raises(ValueError):
        register(DemoModule)
    MODULE_REGISTRY.pop("demo", None)
