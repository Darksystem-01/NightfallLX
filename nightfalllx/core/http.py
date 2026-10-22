from __future__ import annotations

import hashlib
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from nightfalllx.core.console import Console
from nightfalllx.core.mutator import Mutation

if TYPE_CHECKING:
    from nightfalllx.core.agent import EvasionPlan

curl_requests: Any = None
try:
    from curl_cffi import requests as _curl_requests

    curl_requests = _curl_requests
    _HAS_CURL_CFFI = True
except ImportError:
    _HAS_CURL_CFFI = False


CURL_IMPERSONATIONS = ("chrome", "safari", "firefox", "edge")


@dataclass(frozen=True, slots=True)
class TLSProfile:
    name: str
    minimum: ssl.TLSVersion
    maximum: ssl.TLSVersion


TLS_PROFILES = {
    "TLSv1_2": TLSProfile("TLSv1_2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
    "TLSv1_1": TLSProfile("TLSv1_1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    "TLSv1_0": TLSProfile("TLSv1_0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
}


def build_ssl_context(profile: str, verify: bool) -> ssl.SSLContext:
    selected = TLS_PROFILES.get(profile, TLS_PROFILES["TLSv1_2"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = selected.minimum
        context.maximum_version = selected.maximum
    except (ValueError, ssl.SSLError):
        pass
    if selected.name in ("TLSv1_1", "TLSv1_0"):
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return context


def choose_impersonation(rng: random.Random | None = None) -> str:
    return (rng or random).choice(CURL_IMPERSONATIONS)


class _SSLAdapter(HTTPAdapter):
    def __init__(self, context: ssl.SSLContext, *args: Any, **kwargs: Any):
        self._ssl_context = context
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["ssl_context"] = self._ssl_context
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(*args, **kwargs)


@dataclass(slots=True)
class Resp:
    url: str
    status: int = 0
    elapsed: float = 0.0
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 400

    @property
    def length(self) -> int:
        return len((self.text or "").encode("utf-8", errors="replace"))

    @property
    def digest(self) -> str:
        return hashlib.sha256((self.text or "").encode("utf-8", errors="replace")).hexdigest()

    def header(self, name: str, default: str = "") -> str:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return default

    def snippet(self, needle: str | None = None, limit: int = 240) -> str:
        text = self.text or ""
        if needle:
            index = text.lower().find(needle.lower())
            if index >= 0:
                start = max(0, index - limit // 3)
                return text[start:start + limit]
        return text[:limit]


def _is_tls_error(exc: requests.RequestException) -> bool:
    if isinstance(exc, requests.exceptions.SSLError):
        return True
    message = str(exc).lower()
    return any(token in message for token in ("ssl", "tls", "certificate", "handshake"))


def _parse_cookie_string(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            cookies[name] = value
    return cookies


class HttpClient:
    def __init__(
        self,
        console: Console | None = None,
        timeout: float = 10.0,
        delay: float = 0.0,
        proxy: str | None = None,
        verify: bool = True,
        follow: bool = False,
        headers: dict[str, str] | None = None,
        cookie: str | None = None,
        tls_profile: str = "auto",
        impersonate: str | None = None,
        impersonation_rng: random.Random | None = None,
    ):
        self.console = console or Console(verbose=False, quiet=True)
        self.timeout = timeout
        self.delay = delay
        self.proxy = proxy
        self.verify = verify
        self.follow = follow
        self.headers = dict(headers or {})
        self.cookie = cookie or ""
        self.request_count = 0
        self._tls_names = self._profiles_for(tls_profile)
        self._tls_index = 0
        self._session = requests.Session()
        self._session.verify = self.verify
        if not self.verify:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
        self._configure_session()
        if self.headers:
            self._session.headers.update(self.headers)
        for name, value in _parse_cookie_string(self.cookie).items():
            self._session.cookies.set(name, value)

        self._curl_session: Any = None
        self._impersonate = impersonate
        if self._impersonate is None and tls_profile == "random" and _HAS_CURL_CFFI:
            self._impersonate = choose_impersonation(impersonation_rng)
        self._backend = "curl_cffi" if self._impersonate and _HAS_CURL_CFFI else "requests"
        if self._impersonate and not _HAS_CURL_CFFI:
            self.console.warn("curl_cffi is not installed; falling back to requests TLS")

    @staticmethod
    def _profiles_for(tls_profile: str) -> list[str]:
        if tls_profile == "modern":
            return ["TLSv1_2"]
        if tls_profile == "legacy":
            return ["TLSv1_0"]
        return ["TLSv1_2", "TLSv1_0"]

    @property
    def tls_profile(self) -> str:
        return self._tls_names[self._tls_index]

    def _configure_session(self) -> None:
        context = build_ssl_context(self.tls_profile, self.verify)
        adapter = _SSLAdapter(context, pool_maxsize=16)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        if self.proxy:
            self._session.proxies.update({"http": self.proxy, "https": self.proxy})

    def _advance_tls(self) -> bool:
        if self._tls_index + 1 >= len(self._tls_names):
            return False
        self._tls_index += 1
        self.console.debug(f"TLS handshake failed; retrying with {self.tls_profile}")
        self._configure_session()
        return True

    def _request_requests(self, method: str, url: str, kwargs: dict[str, Any]) -> Resp:
        while True:
            try:
                raw = self._session.request(method, url, timeout=self.timeout, **kwargs)
                return Resp(
                    url=raw.url,
                    status=raw.status_code,
                    elapsed=raw.elapsed.total_seconds(),
                    text=raw.text or "",
                    headers=dict(raw.headers),
                )
            except requests.RequestException as exc:
                if _is_tls_error(exc) and self._advance_tls():
                    continue
                return Resp(url=url, error=f"{type(exc).__name__}: {exc}")

    def _request_curl(self, method: str, url: str, kwargs: dict[str, Any]) -> Resp:
        try:
            if self._curl_session is None:
                self._curl_session = curl_requests.Session(
                    impersonate=self._impersonate,
                    verify=self.verify,
                    proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
                )
                if self.headers:
                    self._curl_session.headers.update(self.headers)
            allow_redirects = kwargs.pop("allow_redirects", self.follow)
            raw = self._curl_session.request(
                cast(Any, method),
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
            elapsed = getattr(getattr(raw, "elapsed", None), "total_seconds", lambda: 0.0)()
            return Resp(
                url=str(raw.url),
                status=int(raw.status_code),
                elapsed=elapsed,
                text=raw.text or "",
                headers=dict(raw.headers),
            )
        except Exception as exc:
            return Resp(url=url, error=f"{type(exc).__name__}: {exc}")

    def request(self, method: str, url: str, **kwargs: Any) -> Resp:
        kwargs.setdefault("allow_redirects", self.follow)
        if self.delay:
            time.sleep(self.delay)
        preview = ""
        if kwargs.get("params"):
            preview = urlencode(kwargs["params"])
        elif kwargs.get("data") and isinstance(kwargs["data"], dict):
            preview = urlencode(kwargs["data"])
        elif kwargs.get("json"):
            preview = str(kwargs["json"])[:200]
        self.console.debug(f"-> {method} {url} {preview}"[:400])
        started = time.time()
        if self._backend == "curl_cffi":
            response = self._request_curl(method, url, kwargs)
        else:
            response = self._request_requests(method, url, kwargs)
        self.request_count += 1
        if not response.error:
            self.console.debug(f"<- {response.status} {response.length}B {time.time() - started:.2f}s")
        return response

    def request_evasive(
        self,
        method: str,
        url: str,
        parameter: str,
        payload: str,
        plan: EvasionPlan,
        *,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Resp:
        self._activate_plan_tls(plan)
        mutations = plan.mutations or (Mutation(payload, "identity"),)
        original = (params or {}).get(parameter, "1")
        base_values = list(original) if isinstance(original, (list, tuple)) else [original]
        last = Resp(url=url, error="no evasion attempts")
        for mutation in mutations:
            query = dict(params or {})
            if plan.use_hpp:
                query[parameter] = base_values + [mutation.payload]
            else:
                query[parameter] = mutation.payload
            last = self.request(method, url, params=query, **kwargs)
            if not self._is_blocked(last):
                return last
        return last

    def _activate_plan_tls(self, plan: EvasionPlan) -> None:
        if plan.tls_profile == "random" and _HAS_CURL_CFFI and not self._impersonate:
            self._impersonate = choose_impersonation()
            self._backend = "curl_cffi"
        elif plan.tls_profile == "legacy" and self.tls_profile != "TLSv1_0":
            self._tls_names = ["TLSv1_0"]
            self._tls_index = 0
            self._configure_session()

    @staticmethod
    def _is_blocked(response: Resp) -> bool:
        return response.error != "" or response.status in {403, 406, 429}

    def get(self, url: str, **kwargs: Any) -> Resp:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Resp:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self._session.close()
        if self._curl_session is not None:
            self._curl_session.close()
