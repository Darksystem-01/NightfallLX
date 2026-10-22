from __future__ import annotations

from nightfalllx.core.finding import Finding, Severity
from nightfalllx.core.http import HttpClient
from nightfalllx.core.module import BaseModule, TargetProtocol
from nightfalllx.core.verifier import VulnerabilityVerifier


class RCEModule(BaseModule):
    name = "rce"
    description = "Harmless-command RCE verification using fixed id, whoami, and sleep probes"

    def __init__(self, client: HttpClient, *, sleep_delay: float = 5.0):
        self.client = client
        self.sleep_delay = sleep_delay

    def run(self, target: TargetProtocol) -> list[Finding]:
        if not target.authorized:
            raise PermissionError("RCEModule requires TargetSpec.authorized=True")

        verifier = VulnerabilityVerifier(self.client, authorized=True)
        findings: list[Finding] = []
        for parameter in target.parameters:
            result = verifier.verify_rce(
                target.url,
                parameter,
                params=dict(target.request_params),
                method=target.method,
                sleep_delay=self.sleep_delay,
            )
            if not result.vulnerable:
                continue
            findings.append(
                Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    confidence=result.confidence,
                    url=target.url,
                    title="Remote Code Execution (safe PoC)",
                    cwe_id=78,
                    parameter=parameter,
                    payload="; id / | whoami / ; sleep N",
                    evidence=result.evidence,
                    detail=(
                        "RCE confirmed via harmless command execution (e.g., id). "
                        "Only fixed id, whoami, and sleep probes were used; no destructive "
                        "command, reverse shell, or data exfiltration was performed."
                    ),
                    remediation=(
                        "Avoid shell invocation with request-controlled data. Use fixed command "
                        "allow-lists and argument arrays, and run services with least privilege."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                    ),
                    next_steps=(
                        "Review the affected endpoint's command construction under the rules of engagement.",
                    ),
                )
            )
        return findings
