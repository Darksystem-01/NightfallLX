from __future__ import annotations

from nightfalllx.core.finding import Finding, Severity
from nightfalllx.core.http import HttpClient
from nightfalllx.core.module import BaseModule, TargetProtocol
from nightfalllx.core.verifier import VulnerabilityVerifier


class XSSModule(BaseModule):
    name = "xss"
    description = "Context-aware reflected XSS verification with DOM parsing"

    def __init__(self, client: HttpClient):
        self.client = client

    def run(self, target: TargetProtocol) -> list[Finding]:
        if not target.authorized:
            raise PermissionError("XSSModule requires TargetSpec.authorized=True")

        verifier = VulnerabilityVerifier(self.client, authorized=True)
        findings: list[Finding] = []
        for parameter in target.parameters:
            result = verifier.verify_xss(
                target.url,
                parameter,
                params=dict(target.request_params),
                method=target.method,
            )
            if not result.vulnerable:
                continue
            findings.append(
                Finding(
                    module=self.name,
                    severity=Severity.HIGH,
                    confidence=result.confidence,
                    url=target.url,
                    title="Reflected Cross-Site Scripting (XSS)",
                    cwe_id=79,
                    parameter=parameter,
                    payload="HTML, attribute, and script-context break-out probes",
                    evidence=result.evidence,
                    detail=result.detail,
                    remediation=(
                        "Apply context-aware output encoding at render time and enforce a "
                        "Content-Security-Policy that forbids inline script."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ),
                    next_steps=(
                        "Confirm execution in a browser with a benign canary under the rules of engagement.",
                    ),
                )
            )
        return findings
