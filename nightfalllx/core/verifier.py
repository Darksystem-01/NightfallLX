from __future__ import annotations

import base64
import binascii
import difflib
import re
import statistics
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from bs4 import BeautifulSoup

from nightfalllx.core.console import Console
from nightfalllx.core.finding import (
    ConfidenceCalculator,
    ConfidenceSignal,
    Evidence,
    Finding,
    Severity,
)
from nightfalllx.core.http import HttpClient, Resp


@dataclass(frozen=True, slots=True)
class VerificationResult:
    vulnerable: bool
    confidence: int
    signals: tuple[ConfidenceSignal, ...]
    evidence: Evidence
    detail: str = ""

    @property
    def confidence_label(self) -> str:
        return ConfidenceCalculator.label(self.confidence)

    def to_finding(
        self,
        *,
        module: str,
        severity: Severity,
        url: str,
        title: str,
        cwe_id: int | None = None,
        parameter: str = "",
        payload: str = "",
        remediation: str = "",
        references: tuple[str, ...] = (),
    ) -> Finding:
        return Finding(
            module=module,
            severity=severity,
            confidence=self.confidence,
            url=url,
            title=title,
            cwe_id=cwe_id,
            parameter=parameter,
            payload=payload,
            evidence=self.evidence,
            remediation=remediation,
            detail=self.detail,
            references=references,
        )


class VulnerabilityVerifier:
    SSTI_ENGINES = (
        ("jinja2", "{{7*7}}", "{{7*8}}", "49", "56"),
        ("freemarker", "${7*7}", "${7*8}", "49", "56"),
        ("erb", "<%= 7*7 %>", "<%= 7*8 %>", "49", "56"),
        ("ruby", "#{7*7}", "#{7*8}", "49", "56"),
        ("twig", "{{7*'7'}}", "{{7*'8'}}", "49", "56"),
        ("smarty", "{7*7}", "{7*8}", "49", "56"),
        ("spring_el", "*{7*7}", "*{7*8}", "49", "56"),
    )
    LFI_PAYLOAD = "php://filter/convert.base64-encode/resource={resource}"
    LFI_TRAVERSALS = (
        ("../../../../etc/passwd", re.compile(r"root:.*?:0:0:")),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", re.compile(r"root:.*?:0:0:")),
        ("..%252f..%252f..%252f..%252fetc%252fpasswd", re.compile(r"root:.*?:0:0:")),
        ("....//....//....//etc/passwd", re.compile(r"root:.*?:0:0:")),
        ("/etc/passwd", re.compile(r"root:.*?:0:0:")),
        ("../../../../windows/win.ini", re.compile(r"(?i)\[(?:fonts|extensions)\]")),
        ("..\\..\\..\\..\\windows\\win.ini", re.compile(r"(?i)\[(?:fonts|extensions)\]")),
    )
    BOOLEAN_SQLI_PAIRS = (
        ("{original} AND 1=1", "{original} AND 1=2"),
        ("{original}' AND '1'='1", "{original}' AND '1'='2"),
        ("{original}' AND 1=1-- -", "{original}' AND 1=2-- -"),
        ("{original}\" AND \"1\"=\"1", "{original}\" AND \"1\"=\"2"),
        ("{original}\" AND 1=1-- -", "{original}\" AND 1=2-- -"),
        ("{original}') AND ('1'='1", "{original}') AND ('1'='2"),
        ("{original}') AND 1=1-- -", "{original}') AND 1=2-- -"),
    )
    PHP_MARKERS = ("<?php", "<?=")
    BLOCK_STATUSES = {403, 406, 429}
    RCE_ID_PATTERN = re.compile(r"uid=\d+\([^)]+\)")
    RCE_WHOAMI_PATTERN = re.compile(
        r"(?m)^(?:root|www-data|nginx|apache|nobody|vapf|ubuntu|daemon)$"
    )
    RCE_COMMAND_PROBES = (
        ("id", "; id", RCE_ID_PATTERN),
        ("whoami", "| whoami", RCE_WHOAMI_PATTERN),
        ("id", "&& id", RCE_ID_PATTERN),
        ("whoami", "&& whoami", RCE_WHOAMI_PATTERN),
        ("id", "| id", RCE_ID_PATTERN),
        ("whoami", "; whoami", RCE_WHOAMI_PATTERN),
        ("id", "$(id)", RCE_ID_PATTERN),
        ("whoami", "$(whoami)", RCE_WHOAMI_PATTERN),
        ("id", "`id`", RCE_ID_PATTERN),
        ("whoami", "`whoami`", RCE_WHOAMI_PATTERN),
        ("id", "\nid\n", RCE_ID_PATTERN),
        ("whoami", "\nwhoami\n", RCE_WHOAMI_PATTERN),
    )
    RCE_SLEEP_TEMPLATES = (
        "; sleep {delay}",
        "| sleep {delay}",
        "& sleep {delay}",
        "&& sleep {delay}",
        "$(sleep {delay})",
        "`sleep {delay}`",
        "\nsleep {delay}\n",
    )

    def __init__(
        self,
        client: HttpClient,
        console: Console | None = None,
        *,
        authorized: bool = False,
    ):
        self.client = client
        self.console = console or client.console
        self.authorized = authorized

    def _require_authorized(self) -> None:
        if not self.authorized:
            raise PermissionError(
                "Active vulnerability verification requires authorized=True and a scoped target."
            )

    def _request(
        self,
        method: str,
        url: str,
        params: dict[str, Any],
    ) -> Resp:
        method = method.upper()
        if method == "GET":
            return self.client.get(url, params=params)
        if method == "POST":
            return self.client.post(url, data=params)
        return self.client.request(method, url, params=params)

    @staticmethod
    def _query_string(params: dict[str, Any]) -> str:
        return urlencode(params, doseq=True)

    @staticmethod
    def similarity(left: str, right: str) -> float:
        left = (left or "")[:10000]
        right = (right or "")[:10000]
        if not left and not right:
            return 1.0
        return difflib.SequenceMatcher(None, left, right).ratio()

    @staticmethod
    def _is_blocked(response: Resp) -> bool:
        return response.error != "" or response.status in VulnerabilityVerifier.BLOCK_STATUSES

    def _evidence(
        self,
        method: str,
        url: str,
        params: dict[str, Any],
        response: Resp,
        summary: str = "",
    ) -> Evidence:
        return Evidence.capture(
            f"{method.upper()} {url}?{self._query_string(params)}",
            response.snippet(limit=600),
            summary=summary,
        )

    def _result(
        self,
        signals: tuple[ConfidenceSignal, ...],
        evidence: Evidence,
        detail: str,
    ) -> VerificationResult:
        confidence = ConfidenceCalculator.score(signals)
        return VerificationResult(
            vulnerable=confidence >= ConfidenceCalculator.HIGH_THRESHOLD,
            confidence=confidence,
            signals=signals,
            evidence=evidence,
            detail=detail,
        )

    def _failure(self, detail: str, evidence: Evidence | None = None) -> VerificationResult:
        return VerificationResult(
            vulnerable=False,
            confidence=0,
            signals=(ConfidenceSignal("request", 100, False, detail),),
            evidence=evidence or Evidence(),
            detail=detail,
        )

    def verify_ssti(
        self,
        url: str,
        parameter: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        engines: tuple[tuple[str, str, str, str, str], ...] | None = None,
    ) -> VerificationResult:
        self._require_authorized()
        base_params = dict(params or {})
        base_params.setdefault(parameter, "1")
        baseline = self._request(method, url, base_params)
        if baseline.error:
            return self._failure(f"SSTI baseline request failed: {baseline.error}")

        best_partial: VerificationResult | None = None
        for engine, first, second, expected_first, expected_second in engines or self.SSTI_ENGINES:
            if expected_first in baseline.text or expected_second in baseline.text:
                continue
            first_params = dict(base_params)
            first_params[parameter] = first
            first_response = self._request(method, url, first_params)
            if first_response.error or expected_first not in first_response.text:
                continue

            second_params = dict(base_params)
            second_params[parameter] = second
            second_response = self._request(method, url, second_params)
            if second_response.error:
                continue

            signals = (
                ConfidenceSignal("math_first", 40, True, f"{first} -> {expected_first}"),
                ConfidenceSignal(
                    "math_second",
                    40,
                    expected_second in second_response.text,
                    f"{second} -> {expected_second}",
                ),
                ConfidenceSignal("baseline_clean", 20, True, "canaries absent from baseline"),
            )
            evidence = self._evidence(
                method,
                url,
                second_params,
                second_response,
                summary=f"SSTI {engine}: {first}={expected_first}, {second}={expected_second}",
            )
            result = self._result(
                signals,
                evidence,
                f"SSTI engine={engine}; first={expected_first in first_response.text}; "
                f"second={expected_second in second_response.text}",
            )
            if result.vulnerable:
                return result
            best_partial = best_partial or result

        if best_partial is not None:
            return best_partial
        return self._failure("No SSTI engine returned two independent arithmetic results")

    def verify_xss(
        self,
        url: str,
        parameter: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        marker: str = "vapfXssCanary",
    ) -> VerificationResult:
        self._require_authorized()
        base_params = dict(params or {})
        base_params.setdefault(parameter, "1")
        baseline = self._request(method, url, base_params)
        if baseline.error:
            return self._failure(f"XSS baseline request failed: {baseline.error}")
        if marker in baseline.text:
            return self._failure("XSS marker already present in baseline")

        payloads = (
            ("attribute_breakout", f'"><script>{marker}()</script>'),
            ("tag_injection", f"<script>{marker}()</script>"),
            ("script_breakout", f"</script><script>{marker}()</script>"),
        )
        best_partial: VerificationResult | None = None
        for context, payload in payloads:
            query = dict(base_params)
            query[parameter] = payload
            response = self._request(method, url, query)
            if response.error:
                continue
            raw_hit = payload in response.text
            soup = BeautifulSoup(response.text or "", "html.parser")
            dom_hit = soup.find("script", string=re.compile(re.escape(marker))) is not None
            signals = (
                ConfidenceSignal("raw_dom", 50, raw_hit, "payload present unencoded"),
                ConfidenceSignal("parsed_script", 30, dom_hit, "script element parsed from DOM"),
                ConfidenceSignal(
                    "context_breakout",
                    20,
                    context in ("attribute_breakout", "script_breakout") and raw_hit,
                    "context-breaking payload present",
                ),
            )
            evidence = self._evidence(
                method,
                url,
                query,
                response,
                summary=f"XSS context={context}; raw={raw_hit}; parsed={dom_hit}",
            )
            result = self._result(
                signals,
                evidence,
                f"XSS context={context}; raw_dom={raw_hit}; parsed_script={dom_hit}",
            )
            if result.vulnerable:
                return result
            best_partial = best_partial or result

        if best_partial is not None:
            return best_partial
        return self._failure("XSS payload was not reflected into an executable DOM context")

    def verify_lfi(
        self,
        url: str,
        parameter: str,
        *,
        resource: str = "index.php",
        params: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> VerificationResult:
        self._require_authorized()
        query = dict(params or {})
        payload = self.LFI_PAYLOAD.format(resource=resource)
        query[parameter] = payload
        response = self._request(method, url, query)
        if not response.error and response.text:
            blobs = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", response.text or "")
            valid_base64 = False
            php_source = False
            for blob in blobs:
                try:
                    padded = blob + "=" * (-len(blob) % 4)
                    decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    continue
                valid_base64 = True
                if any(marker in decoded for marker in self.PHP_MARKERS):
                    php_source = True
                    break

            if valid_base64 and php_source:
                signals = (
                    ConfidenceSignal("base64_output", 50, valid_base64, "valid base64 blob decoded"),
                    ConfidenceSignal("php_source", 50, php_source, "decoded content contains PHP markers"),
                )
                evidence = self._evidence(
                    method,
                    url,
                    query,
                    response,
                    summary=f"LFI base64={valid_base64}; php={php_source}; source not stored",
                )
                return self._result(
                    signals,
                    evidence,
                    f"LFI filter output base64={valid_base64}; PHP source markers={php_source}",
                )

        for trav_payload, pattern in self.LFI_TRAVERSALS:
            t_query = dict(params or {})
            t_query[parameter] = trav_payload
            t_resp = self._request(method, url, t_query)
            if t_resp.error or not t_resp.text:
                continue
            if pattern.search(t_resp.text):
                signals = (
                    ConfidenceSignal("file_disclosure", 70, True, f"disclosed system file via {trav_payload}"),
                    ConfidenceSignal("pattern_match", 30, True, "regex pattern confirmed"),
                )
                evidence = self._evidence(
                    method,
                    url,
                    t_query,
                    t_resp,
                    summary=f"LFI path traversal confirmed ({trav_payload})",
                )
                return self._result(
                    signals,
                    evidence,
                    f"LFI path traversal verified with payload: {trav_payload}",
                )

        signals = (
            ConfidenceSignal("base64_output", 50, False, "no valid base64 stream decoded"),
            ConfidenceSignal("php_source", 50, False, "no PHP markers found"),
        )
        evidence = self._evidence(
            method,
            url,
            query,
            response if not response.error else Resp(url=url),
            summary="LFI verification failed",
        )
        return self._result(
            signals,
            evidence,
            "LFI verification failed: no file disclosure or base64 stream detected",
        )

    def verify_boolean_sqli(
        self,
        url: str,
        parameter: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> VerificationResult:
        self._require_authorized()
        base_params = dict(params or {})
        original = base_params.get(parameter, "1")
        baseline = self._request(method, url, base_params)
        if baseline.error or not baseline.text:
            return self._failure("Boolean SQLi baseline request failed or was empty")

        best_result: VerificationResult | None = None
        for true_tmpl, false_tmpl in self.BOOLEAN_SQLI_PAIRS:
            true_params = dict(base_params)
            true_params[parameter] = true_tmpl.format(original=original)
            false_params = dict(base_params)
            false_params[parameter] = false_tmpl.format(original=original)

            true_first = self._request(method, url, true_params)
            false_first = self._request(method, url, false_params)
            true_second = self._request(method, url, true_params)
            false_second = self._request(method, url, false_params)
            if any(response.error for response in (true_first, false_first, true_second, false_second)):
                continue

            true_similarity = (
                self.similarity(baseline.text, true_first.text)
                + self.similarity(baseline.text, true_second.text)
            ) / 2
            false_similarity = (
                self.similarity(baseline.text, false_first.text)
                + self.similarity(baseline.text, false_second.text)
            ) / 2
            separation = true_similarity - false_similarity
            repeatable = (
                abs(self.similarity(true_first.text, true_second.text) - 1.0) <= 0.05
                and abs(self.similarity(false_first.text, false_second.text) - 1.0) <= 0.05
            )
            signals = (
                ConfidenceSignal(
                    "true_branch_matches",
                    30,
                    true_similarity >= 0.95,
                    f"true similarity={true_similarity:.3f}",
                ),
                ConfidenceSignal(
                    "false_branch_diverges",
                    30,
                    false_similarity <= 0.85,
                    f"false similarity={false_similarity:.3f}",
                ),
                ConfidenceSignal(
                    "branch_separation",
                    20,
                    separation >= 0.10,
                    f"separation={separation:.3f}",
                ),
                ConfidenceSignal(
                    "repeatable",
                    20,
                    repeatable,
                    "both branches repeat consistently",
                ),
            )
            evidence = self._evidence(
                method,
                url,
                false_params,
                false_second,
                summary=(
                    f"boolean true similarity={true_similarity:.3f}; "
                    f"false similarity={false_similarity:.3f}"
                ),
            )
            result = self._result(
                signals,
                evidence,
                f"boolean true_similarity={true_similarity:.3f} "
                f"false_similarity={false_similarity:.3f} separation={separation:.3f}",
            )
            if result.vulnerable:
                return result
            best_result = best_result or result

        return best_result or self._failure("Boolean SQLi differential test did not diverge")

    def verify_rce(
        self,
        url: str,
        parameter: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        sleep_delay: float = 5.0,
    ) -> VerificationResult:
        self._require_authorized()
        if not 0 < sleep_delay <= 5.0:
            raise ValueError("sleep_delay must be between 0 and 5 seconds")

        base_params = dict(params or {})
        base_params.setdefault(parameter, "1")
        baseline = self._request(method, url, base_params)
        if baseline.error:
            return self._failure(f"RCE baseline request failed: {baseline.error}")

        for label, payload, pattern in self.RCE_COMMAND_PROBES:
            query = dict(base_params)
            query[parameter] = payload
            first = self._request(method, url, query)
            second = self._request(method, url, query)
            if first.error or second.error:
                continue
            first_match = pattern.search(first.text or "") is not None
            second_match = pattern.search(second.text or "") is not None
            baseline_clean = pattern.search(baseline.text or "") is None
            signals = (
                ConfidenceSignal(
                    "output_match",
                    60,
                    first_match,
                    f"{label} output matched ({payload})",
                ),
                ConfidenceSignal(
                    "repeatable",
                    20,
                    second_match,
                    f"{label} output matched twice",
                ),
                ConfidenceSignal(
                    "baseline_clean",
                    20,
                    baseline_clean,
                    "marker absent from baseline",
                ),
            )
            evidence = self._evidence(
                method,
                url,
                query,
                second,
                summary=f"RCE confirmed via harmless command execution ({label}: {payload})",
            )
            result = self._result(
                signals,
                evidence,
                f"RCE output-based {label}: first={first_match} second={second_match}",
            )
            if result.vulnerable:
                return result

        baseline_times: list[float] = []
        for _ in range(3):
            started = time.monotonic()
            response = self._request(method, url, base_params)
            if response.error:
                return self._failure(f"RCE timing baseline failed: {response.error}")
            baseline_times.append(time.monotonic() - started)

        baseline_mean = statistics.mean(baseline_times)
        baseline_stdev = statistics.pstdev(baseline_times)

        for sleep_tmpl in self.RCE_SLEEP_TEMPLATES:
            sleep_params = dict(base_params)
            sleep_params[parameter] = sleep_tmpl.format(delay=sleep_delay)
            injection_times: list[float] = []
            last_response: Resp | None = None
            timing_failed = False
            for _ in range(3):
                started = time.monotonic()
                last_response = self._request(method, url, sleep_params)
                if last_response.error:
                    timing_failed = True
                    break
                injection_times.append(time.monotonic() - started)

            if timing_failed or len(injection_times) < 3:
                continue

            injection_mean = statistics.mean(injection_times)
            injection_stdev = statistics.pstdev(injection_times)
            delta = injection_mean - baseline_mean
            all_delayed = all(
                sample >= baseline_mean + sleep_delay * 0.75
                for sample in injection_times
            )
            timing_signals = (
                ConfidenceSignal(
                    "baseline_stable",
                    15,
                    baseline_stdev <= max(0.15, sleep_delay * 0.15),
                    f"baseline stdev={baseline_stdev:.3f}s",
                ),
                ConfidenceSignal(
                    "all_samples_delayed",
                    40,
                    all_delayed,
                    f"injection times={[round(value, 3) for value in injection_times]}",
                ),
                ConfidenceSignal(
                    "mean_delta",
                    25,
                    delta >= sleep_delay * 0.8,
                    f"delta={delta:.3f}s",
                ),
                ConfidenceSignal(
                    "injection_stable",
                    20,
                    injection_stdev <= max(0.2, sleep_delay * 0.35),
                    f"injection stdev={injection_stdev:.3f}s",
                ),
            )
            evidence = self._evidence(
                method,
                url,
                sleep_params,
                last_response or Resp(url=url),
                summary=f"RCE confirmed via sleep-based timing verification ({sleep_tmpl})",
            )
            result = self._result(
                timing_signals,
                evidence,
                f"RCE time-based baseline_mean={baseline_mean:.3f}s "
                f"baseline_stdev={baseline_stdev:.3f}s injection_mean={injection_mean:.3f}s "
                f"injection_stdev={injection_stdev:.3f}s",
            )
            if result.vulnerable:
                return result

        return self._failure("RCE verification failed across all command probes and timing templates")

    def verify_time_based_sqli(
        self,
        url: str,
        parameter: str,
        payload_template: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        delay: float = 2.0,
        samples: int = 3,
    ) -> VerificationResult:
        self._require_authorized()
        if samples < 3:
            raise ValueError("time-based SQLi verification requires at least 3 samples")
        if delay <= 0:
            raise ValueError("delay must be positive")

        base_params = dict(params or {})
        base_params.setdefault(parameter, "1")
        baseline_times: list[float] = []
        for _ in range(samples):
            started = time.monotonic()
            response = self._request(method, url, base_params)
            elapsed = time.monotonic() - started
            if response.error:
                return self._failure(f"SQLi baseline request failed: {response.error}")
            baseline_times.append(elapsed)

        payload = payload_template.replace("{delay}", str(delay))
        injection_params = dict(base_params)
        injection_params[parameter] = payload
        injection_times: list[float] = []
        last_response: Resp | None = None
        for _ in range(samples):
            started = time.monotonic()
            last_response = self._request(method, url, injection_params)
            elapsed = time.monotonic() - started
            if last_response.error:
                return self._failure(f"SQLi injection request failed: {last_response.error}")
            injection_times.append(elapsed)

        baseline_mean = statistics.mean(baseline_times)
        baseline_stdev = statistics.pstdev(baseline_times)
        injection_mean = statistics.mean(injection_times)
        injection_stdev = statistics.pstdev(injection_times)
        delta = injection_mean - baseline_mean
        minimum_delay = delay * 0.75
        all_delayed = all(sample >= baseline_mean + minimum_delay for sample in injection_times)

        timing_signals = (
            ConfidenceSignal(
                "baseline_stable",
                15,
                baseline_stdev <= max(0.15, delay * 0.15),
                f"baseline stdev={baseline_stdev:.3f}s",
            ),
            ConfidenceSignal(
                "all_samples_delayed",
                40,
                all_delayed,
                f"injection times={[round(value, 3) for value in injection_times]}",
            ),
            ConfidenceSignal(
                "mean_delta",
                25,
                delta >= delay * 0.8,
                f"delta={delta:.3f}s",
            ),
            ConfidenceSignal(
                "injection_stable",
                20,
                injection_stdev <= max(0.2, delay * 0.35),
                f"injection stdev={injection_stdev:.3f}s",
            ),
        )
        evidence = self._evidence(
            method,
            url,
            injection_params,
            last_response or Resp(url=url),
            summary=(
                f"baseline mean={baseline_mean:.3f}s stdev={baseline_stdev:.3f}s; "
                f"injection mean={injection_mean:.3f}s stdev={injection_stdev:.3f}s"
            ),
        )
        return self._result(
            timing_signals,
            evidence,
            f"baseline_mean={baseline_mean:.3f}s baseline_stdev={baseline_stdev:.3f}s "
            f"injection_mean={injection_mean:.3f}s injection_stdev={injection_stdev:.3f}s",
        )

    def hpp_probe(
        self,
        url: str,
        parameter: str,
        values: tuple[Any, ...],
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> Resp:
        self._require_authorized()
        query = dict(params or {})
        query[parameter] = list(values)
        return self._request(method, url, query)

    def verify_hpp_bypass(
        self,
        url: str,
        parameter: str,
        blocked_value: Any,
        *,
        benign_value: Any = "1",
        params: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> VerificationResult:
        self._require_authorized()
        base_params = dict(params or {})
        blocked_params = dict(base_params)
        blocked_params[parameter] = blocked_value
        blocked = self._request(method, url, blocked_params)
        if not self._is_blocked(blocked):
            return self._failure("Original parameter was not blocked; HPP bypass not applicable")

        hpp_params = dict(base_params)
        hpp_params[parameter] = [blocked_value, benign_value]
        hpp_response = self._request(method, url, hpp_params)
        bypassed = not self._is_blocked(hpp_response)
        signals = (
            ConfidenceSignal("original_blocked", 40, True, f"status={blocked.status}"),
            ConfidenceSignal(
                "hpp_allowed",
                60,
                bypassed,
                f"HPP status={hpp_response.status}",
            ),
        )
        evidence = self._evidence(
            method,
            url,
            hpp_params,
            hpp_response,
            summary=f"HPP bypass={bypassed}; original status={blocked.status}",
        )
        return self._result(
            signals,
            evidence,
            f"HPP bypass={bypassed}; original={blocked.status}; polluted={hpp_response.status}",
        )
