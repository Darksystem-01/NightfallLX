from __future__ import annotations

import re

from nightfalllx.core.blind import BlindExtractor


def test_blind_extractor_recovers_version_with_binary_search() -> None:
    version = "8.0.32"

    def oracle(condition: str) -> bool:
        match = re.search(
            r"ASCII\(SUBSTRING\(\(@@version\),([0-9]+),1\)\)>([0-9]+)",
            condition,
        )
        assert match
        position = int(match.group(1))
        threshold = int(match.group(2))
        code = ord(version[position - 1]) if position <= len(version) else 0
        return code > threshold

    extractor = BlindExtractor(oracle, rate_limit=0, max_length=16)
    result = extractor.extract_version()
    assert result.value == version
    assert result.requests > 0
