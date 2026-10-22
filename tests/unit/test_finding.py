from __future__ import annotations

from nightfalllx.core.finding import (
    ConfidenceCalculator,
    ConfidenceSignal,
    Evidence,
    Finding,
    Severity,
)


def test_evidence_redacts_and_truncates() -> None:
    evidence = Evidence.capture(
        "GET /?token=supersecret HTTP/1.1",
        "Set-Cookie: session=abc123\nAuthorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        secrets=("supersecret",),
        limit=40,
    )
    assert "supersecret" not in evidence.request
    assert "abc123" not in evidence.response
    assert "eyJhbGci" not in evidence.response
    assert evidence.redacted
    assert evidence.truncated


def test_finding_serialises_integer_confidence() -> None:
    finding = Finding(
        module="sqli",
        severity=Severity.HIGH,
        confidence=100,
        url="http://127.0.0.1/item?id=1",
        title="Boolean-based SQL injection",
        cwe_id=89,
        parameter="id",
        evidence=Evidence.capture("GET /item?id=1'", "different response"),
    )
    payload = finding.to_dict()
    assert payload["severity"] == "HIGH"
    assert payload["confidence"] == 100
    assert payload["confidence_label"] == "confirmed"
    assert payload["cwe_id"] == 89
    assert payload["fingerprint"] == finding.fingerprint


def test_high_and_critical_are_downgraded_below_90() -> None:
    high = Finding("xss", Severity.HIGH, 89, "http://127.0.0.1/")
    low = Finding("xss", Severity.CRITICAL, 69, "http://127.0.0.1/")
    confirmed = Finding("xss", Severity.HIGH, 90, "http://127.0.0.1/")
    assert high.severity is Severity.MEDIUM
    assert low.severity is Severity.INFO
    assert confirmed.severity is Severity.HIGH


def test_confidence_calculator_uses_independent_signals() -> None:
    signals = (
        ConfidenceSignal("first", 40, True),
        ConfidenceSignal("second", 40, True),
        ConfidenceSignal("control", 20, False),
    )
    assert ConfidenceCalculator.score(signals) == 80
    assert ConfidenceCalculator.label(80) == "probable"
    assert ConfidenceCalculator.adjust_severity(Severity.CRITICAL, 80) is Severity.MEDIUM
