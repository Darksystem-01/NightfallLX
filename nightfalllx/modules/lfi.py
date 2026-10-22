from __future__ import annotations

from nightfalllx.core.finding import Finding, Severity
from nightfalllx.core.http import HttpClient
from nightfalllx.core.module import BaseModule, TargetProtocol
from nightfalllx.core.verifier import VulnerabilityVerifier


class LFIModule(BaseModule):
    name = "lfi"
    description = "Read-only PHP filter source disclosure verification"

    def __init__(self, client: HttpClient, *, resource: str = "index.php"):
        self.client = client
        self.resource = resource

    def run(self, target: TargetProtocol) -> list[Finding]:
        if not target.authorized:
            raise PermissionError("LFIModule requires TargetSpec.authorized=True")

        verifier = VulnerabilityVerifier(self.client, authorized=True)
        findings: list[Finding] = []
        for parameter in target.parameters:
            result = verifier.verify_lfi(
                target.url,
                parameter,
                resource=self.resource,
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
                    title="Local File Inclusion (PHP filter source disclosure)",
                    cwe_id=98,
                    parameter=parameter,
                    payload=f"php://filter/convert.base64-encode/resource={self.resource}",
                    evidence=result.evidence,
                    detail=result.detail,
                    remediation=(
                        "Never derive include paths from request data. Map identifiers to a "
                        "fixed allow-list and verify resolved paths stay inside the intended directory."
                    ),
                    references=(
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                    ),
                )
            )
        return findings
