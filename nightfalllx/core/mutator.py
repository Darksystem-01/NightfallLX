from __future__ import annotations

import random
import re
from dataclasses import dataclass
from urllib.parse import quote

SQL_KEYWORDS = re.compile(
    r"\b(SELECT|UNION|AND|OR|WHERE|FROM|SLEEP|BENCHMARK|ORDER|BY|NULL|"
    r"WAITFOR|DELAY|INSERT|UPDATE|DELETE|DROP|EXEC)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Mutation:
    payload: str
    technique: str
    encoding: str = "none"


class PayloadMutator:
    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random()

    def for_payload(
        self,
        payload: str,
        context: str = "generic",
        limit: int = 32,
    ) -> list[Mutation]:
        if context == "sqli":
            mutations = self.for_sqli(payload)
        elif context == "xss":
            mutations = self.for_xss(payload)
        else:
            mutations = self.for_generic(payload)
        return self._dedupe(mutations, limit)

    def for_sqli(self, payload: str) -> list[Mutation]:
        mutations = [Mutation(payload, "identity")]
        if " " in payload:
            mutations.append(Mutation(payload.replace(" ", "/**/"), "space-to-comment"))
            mutations.append(Mutation(payload.replace(" ", "+"), "space-to-plus"))
            mutations.append(Mutation(payload.replace(" ", "%20"), "space-to-percent20"))
        mixed = SQL_KEYWORDS.sub(lambda match: self._mixed_case(match.group(0)), payload)
        if mixed != payload:
            mutations.append(Mutation(mixed, "keyword-case"))
        encoded = quote(payload, safe="")
        mutations.append(Mutation(encoded, "urlencode", "url"))
        mutations.append(Mutation(quote(encoded, safe=""), "double-urlencode", "url"))
        return mutations

    def for_xss(self, payload: str) -> list[Mutation]:
        mutations = [Mutation(payload, "identity")]
        if "<" in payload:
            mutations.append(Mutation(payload.replace("<", "\\u003c"), "unicode-less-than"))
            mutations.append(Mutation(payload.replace("<", "%3C"), "percent-less-than"))
            mutations.append(Mutation(payload.replace("<", "&#60;"), "entity-less-than"))
        if ">" in payload:
            mutations.append(Mutation(payload.replace(">", "\\u003e"), "unicode-greater-than"))
        cased = re.sub(
            r"<(/?)([a-zA-Z][a-zA-Z0-9]*)",
            lambda match: f"<{match.group(1)}{self._mixed_case(match.group(2))}",
            payload,
        )
        if cased != payload:
            mutations.append(Mutation(cased, "tag-case"))
        encoded = quote(payload, safe="")
        mutations.append(Mutation(encoded, "urlencode", "url"))
        mutations.append(Mutation(quote(encoded, safe=""), "double-urlencode", "url"))
        return mutations

    def for_generic(self, payload: str) -> list[Mutation]:
        mutations = [Mutation(payload, "identity")]
        mixed = SQL_KEYWORDS.sub(lambda match: self._mixed_case(match.group(0)), payload)
        if mixed != payload:
            mutations.append(Mutation(mixed, "keyword-case"))
        encoded = quote(payload, safe="")
        mutations.append(Mutation(encoded, "urlencode", "url"))
        mutations.append(Mutation(quote(encoded, safe=""), "double-urlencode", "url"))
        return mutations

    def _mixed_case(self, value: str) -> str:
        return "".join(
            char.upper() if self.rng.random() < 0.5 else char.lower()
            for char in value
        )

    @staticmethod
    def _dedupe(mutations: list[Mutation], limit: int) -> list[Mutation]:
        seen: set[tuple[str, str]] = set()
        unique: list[Mutation] = []
        for mutation in mutations:
            key = (mutation.payload, mutation.technique)
            if key in seen:
                continue
            seen.add(key)
            unique.append(mutation)
            if len(unique) >= limit:
                break
        return unique
