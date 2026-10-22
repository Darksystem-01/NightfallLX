from __future__ import annotations

from dataclasses import dataclass

from nightfalllx.core.console import Console
from nightfalllx.core.http import Resp
from nightfalllx.core.mutator import Mutation, PayloadMutator


@dataclass(frozen=True, slots=True)
class WAFAssessment:
    name: str | None
    confidence: int
    blocked: bool
    challenge: bool
    evidence: tuple[str, ...] = ()

    @property
    def detected(self) -> bool:
        return self.name is not None


@dataclass(frozen=True, slots=True)
class EvasionPlan:
    waf: str | None
    confidence: int
    aggressive: bool
    use_hpp: bool
    tls_profile: str
    mutations: tuple[Mutation, ...]
    reason: str


class AgentBrain:
    WAF_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
        (
            "Cloudflare",
            ("cf-ray", "cf-mitigated", "cf-cache-status", "cf-chl"),
            ("cloudflare",),
            ("just a moment", "attention required", "checking your browser", "cf-chl"),
        ),
        (
            "ModSecurity",
            ("x-modsecurity", "mod_security"),
            ("modsecurity", "mod_security"),
            ("modsecurity", "request blocked", "not acceptable", "access denied"),
        ),
        (
            "AWS WAF",
            ("x-amzn-waf-action", "x-amzn-requestid"),
            ("awselb", "aws"),
            ("request blocked", "aws waf"),
        ),
        (
            "Akamai",
            ("akamai-x-cache", "akamai-x-get-cache-key", "x-akamai-transformed"),
            ("akamaighost", "akamai"),
            ("access denied", "reference #"),
        ),
        (
            "Imperva",
            ("x-iinfo", "incap_ses", "visid_incap"),
            ("incapsula", "imperva"),
            ("incapsula", "request unsuccessful"),
        ),
        (
            "Sucuri",
            ("x-sucuri-id", "x-sucuri-cache"),
            ("sucuri",),
            ("sucuri website firewall", "access denied"),
        ),
        (
            "F5 BIG-IP",
            ("x-wa-info", "x-cnection"),
            ("bigip", "f5"),
            ("the requested url was rejected", "support id"),
        ),
    )
    BLOCK_STATUSES = {403, 406, 429}
    BLOCK_MARKERS = (
        "access denied",
        "request blocked",
        "security policy",
        "not acceptable",
        "blocked by",
        "web application firewall",
    )
    CHALLENGE_MARKERS = (
        "captcha",
        "just a moment",
        "checking your browser",
        "cf-chl",
        "turnstile",
        "challenge-platform",
    )

    def __init__(self, console: Console | None = None, mutator: PayloadMutator | None = None):
        self.console = console or Console(verbose=False, quiet=True)
        self.mutator = mutator or PayloadMutator()
        self._blocked_streak = 0
        self._last_assessment: WAFAssessment | None = None

    def analyze_response(self, response: Resp) -> WAFAssessment:
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = (response.text or "")[:65536].lower()
        evidence: list[str] = []
        name: str | None = None
        confidence = 0
        challenge = any(marker in body for marker in self.CHALLENGE_MARKERS)

        for candidate, header_keys, server_tokens, body_markers in self.WAF_RULES:
            header_hits = [key for key in header_keys if key in headers]
            server = headers.get("server", "").lower()
            server_hit = any(token in server for token in server_tokens)
            body_hit = any(marker in body for marker in body_markers)
            if not (header_hits or server_hit or body_hit):
                continue
            name = candidate
            confidence = 60
            if header_hits:
                confidence += 20
                evidence.extend(f"header:{key}" for key in header_hits)
            if body_hit:
                confidence += 20
                evidence.append("body:block-marker")
            if server_hit:
                evidence.append("header:server")
            confidence = min(confidence, 98)
            break

        blocked_status = response.status in self.BLOCK_STATUSES
        blocked_marker = any(marker in body for marker in self.BLOCK_MARKERS)
        if name is None and (blocked_status or blocked_marker):
            name = "Generic WAF/block"
            confidence = 55 if blocked_status else 45
            if blocked_status:
                evidence.append(f"status:{response.status}")

        if blocked_status:
            evidence.append(f"status:{response.status}")
        if challenge:
            evidence.append("body:challenge")
        blocked = blocked_status or blocked_marker or challenge
        if name is not None:
            blocked = True
        if name is None and not blocked:
            confidence = 0

        return WAFAssessment(
            name=name,
            confidence=confidence,
            blocked=blocked,
            challenge=challenge,
            evidence=tuple(dict.fromkeys(evidence)),
        )

    def think(
        self,
        payload: str,
        baseline: Resp,
        context: str = "generic",
    ) -> EvasionPlan:
        assessment = self.analyze_response(baseline)
        self._last_assessment = assessment
        aggressive = assessment.blocked or self._blocked_streak > 0
        mutations = self.mutator.for_payload(payload, context=context)
        if not aggressive:
            mutations = mutations[:4]
        use_hpp = aggressive and context == "sqli"
        tls_profile = "random" if aggressive else "auto"
        reason = (
            f"WAF={assessment.name or 'none'} confidence={assessment.confidence}%"
            if assessment.detected
            else "no WAF signature in baseline"
        )
        if self._blocked_streak:
            reason += f"; previous blocks={self._blocked_streak}"
        self.console.debug(
            f"agent: {reason}; aggressive={aggressive}; mutations={len(mutations)}"
        )
        return EvasionPlan(
            waf=assessment.name,
            confidence=assessment.confidence,
            aggressive=aggressive,
            use_hpp=use_hpp,
            tls_profile=tls_profile,
            mutations=tuple(mutations),
            reason=reason,
        )

    def observe(self, response: Resp) -> WAFAssessment:
        assessment = self.analyze_response(response)
        if assessment.blocked:
            self._blocked_streak += 1
        else:
            self._blocked_streak = 0
        self._last_assessment = assessment
        return assessment

    @property
    def blocked_streak(self) -> int:
        return self._blocked_streak

    @property
    def last_assessment(self) -> WAFAssessment | None:
        return self._last_assessment
