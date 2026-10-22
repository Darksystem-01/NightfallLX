from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True, slots=True)
class ConfidenceSignal:
    name: str
    weight: int
    passed: bool
    detail: str = ""


class ConfidenceCalculator:
    HIGH_THRESHOLD = 90
    MEDIUM_THRESHOLD = 70

    @classmethod
    def score(cls, signals: Iterable[ConfidenceSignal]) -> int:
        total = sum(max(0, min(100, signal.weight)) for signal in signals if signal.passed)
        return max(0, min(100, total))

    @classmethod
    def adjust_severity(cls, severity: Severity, confidence: int) -> Severity:
        if severity in (Severity.CRITICAL, Severity.HIGH) and confidence < cls.HIGH_THRESHOLD:
            if confidence >= cls.MEDIUM_THRESHOLD:
                return Severity.MEDIUM
            return Severity.INFO
        return severity

    @classmethod
    def label(cls, confidence: int) -> str:
        if confidence >= cls.HIGH_THRESHOLD:
            return "confirmed"
        if confidence >= cls.MEDIUM_THRESHOLD:
            return "probable"
        if confidence >= 40:
            return "possible"
        return "unverified"


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|"
    r"set-cookie|session(?:id)?)\b(\s*[:=]\s*)([^\s&;,'\"]+)"
)


def redact_text(text: str, secrets: Iterable[str] = ()) -> tuple[str, bool]:
    redacted = False
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "<redacted>")
            redacted = True
    if _JWT_RE.search(text):
        text = _JWT_RE.sub("<redacted-jwt>", text)
        redacted = True
    new_text, count = _SECRET_RE.subn(r"\1\2<redacted>", text)
    if count:
        redacted = True
        text = new_text
    return text, redacted


@dataclass(frozen=True, slots=True)
class Evidence:
    request: str = ""
    response: str = ""
    summary: str = ""
    truncated: bool = False
    redacted: bool = False

    @classmethod
    def capture(
        cls,
        request: str,
        response: str,
        *,
        secrets: Iterable[str] = (),
        limit: int = 2048,
        summary: str = "",
    ) -> Evidence:
        values = tuple(secrets)
        request, request_redacted = redact_text(request or "", values)
        response, response_redacted = redact_text(response or "", values)
        summary, summary_redacted = redact_text(summary or "", values)
        truncated = any(len(value) > limit for value in (request, response, summary))
        return cls(
            request=request[:limit],
            response=response[:limit],
            summary=summary[:limit],
            truncated=truncated,
            redacted=request_redacted or response_redacted or summary_redacted,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "response": self.response,
            "summary": self.summary,
            "truncated": self.truncated,
            "redacted": self.redacted,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    module: str
    severity: Severity
    confidence: int
    url: str
    title: str = ""
    cwe_id: int | None = None
    parameter: str = ""
    payload: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    remediation: str = ""
    detail: str = ""
    references: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        score = max(0, min(100, int(self.confidence)))
        severity = ConfidenceCalculator.adjust_severity(self.severity, score)
        object.__setattr__(self, "confidence", score)
        object.__setattr__(self, "severity", severity)

    @property
    def confidence_label(self) -> str:
        return ConfidenceCalculator.label(self.confidence)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.module, self.url, self.parameter, self.title)

    @property
    def endpoint(self) -> str:
        return self.url

    @property
    def fingerprint(self) -> str:
        material = "\x00".join(
            (
                self.module,
                self.url,
                self.parameter,
                self.title,
                str(self.cwe_id or ""),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "cwe_id": self.cwe_id,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "detail": self.detail,
            "references": list(self.references),
            "next_steps": list(self.next_steps),
            "fingerprint": self.fingerprint,
        }
