from __future__ import annotations

import random

from nightfalllx.core.mutator import PayloadMutator


def test_sqli_mutations_include_comment_spaces_and_encoding() -> None:
    mutator = PayloadMutator(random.Random(7))
    mutations = mutator.for_sqli("' UNION SELECT 1")
    payloads = [mutation.payload for mutation in mutations]
    techniques = {mutation.technique for mutation in mutations}

    assert "'/**/UNION/**/SELECT/**/1" in payloads
    assert any(payload.startswith("%27") for payload in payloads)
    assert "space-to-comment" in techniques
    assert "urlencode" in techniques
    assert "dual" not in techniques


def test_xss_mutations_include_unicode_and_case_variants() -> None:
    mutator = PayloadMutator(random.Random(3))
    mutations = mutator.for_xss("<script>alert(1)</script>")
    payloads = [mutation.payload for mutation in mutations]
    techniques = {mutation.technique for mutation in mutations}

    assert any("\\u003c" in payload for payload in payloads)
    assert any("%3C" in payload for payload in payloads)
    assert "tag-case" in techniques
    assert len(mutations) == len({(m.payload, m.technique) for m in mutations})


def test_generic_mutations_are_capped_and_deduplicated() -> None:
    mutator = PayloadMutator(random.Random(1))
    mutations = mutator.for_payload("abc def", context="generic", limit=3)
    assert len(mutations) <= 3
    assert mutations[0].technique == "identity"
