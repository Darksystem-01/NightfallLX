from __future__ import annotations

from nightfalllx.core.agent import AgentBrain
from nightfalllx.core.console import Console
from nightfalllx.core.http import Resp


def response(
    status: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> Resp:
    return Resp(
        url="http://127.0.0.1/",
        status=status,
        text=text,
        headers=headers or {},
    )


def brain() -> AgentBrain:
    return AgentBrain(console=Console(verbose=False, quiet=True))


def test_cloudflare_baseline_triggers_aggressive_plan() -> None:
    baseline = response(
        status=403,
        text="Attention Required! Just a moment...",
        headers={"Server": "cloudflare", "cf-ray": "test-ray"},
    )
    assessment = brain().analyze_response(baseline)
    assert assessment.detected
    assert assessment.name == "Cloudflare"
    assert assessment.confidence >= 80
    assert assessment.blocked

    plan = brain().think("' OR 1=1--", baseline, context="sqli")
    assert plan.aggressive
    assert plan.use_hpp
    assert plan.tls_profile == "random"
    assert any(mutation.technique == "urlencode" for mutation in plan.mutations)
    assert any("/**/" in mutation.payload for mutation in plan.mutations)


def test_modsecurity_body_signature_is_detected() -> None:
    baseline = response(status=406, text="ModSecurity: Request blocked")
    assessment = brain().analyze_response(baseline)
    assert assessment.detected
    assert assessment.name == "ModSecurity"
    assert assessment.blocked


def test_clean_baseline_keeps_plan_conservative() -> None:
    baseline = response(status=200, text="normal page")
    plan = brain().think("<script>alert(1)</script>", baseline, context="xss")
    assert not plan.aggressive
    assert not plan.use_hpp
    assert plan.tls_profile == "auto"
    assert len(plan.mutations) <= 4


def test_observed_block_escalates_the_next_plan() -> None:
    agent = brain()
    clean = response(status=200, text="normal page")
    first = agent.think("1 OR 1=1", clean, context="sqli")
    assert not first.aggressive

    blocked = response(status=403, text="request blocked by security policy")
    assessment = agent.observe(blocked)
    assert assessment.blocked
    assert agent.blocked_streak == 1

    second = agent.think("1 OR 1=1", clean, context="sqli")
    assert second.aggressive
    assert second.use_hpp
    assert second.tls_profile == "random"
