"""Privacy Lint: checks Case Summary narrative for accusatory language and identities (FR-5).

Applies the Privacy and Fairness Standard's neutral-language rule: describe activity,
never intent, guilt, character or personal circumstances, and never real identities.
Control-mapping fields are not linted: ATT&CK technique names are quoted reference labels.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Word stems and phrases that assert intent or guilt, or speculate about a person's life.
_BANNED = [
    r"malicious\w*", r"criminal\w*", r"crimes?", r"guilt\w*", r"theft", r"thie(f|ves)", r"steal\w*", r"stole\w*",
    r"fraud\w*", r"traitor\w*", r"suspects?", r"perpetrators?", r"culprits?", r"wrongdoing", r"bad actors?",
    r"threat actors?", r"insider threats?", r"exfiltrat\w*", r"espionage", r"sabotag\w*", r"disgruntled",
    r"dishonest\w*", r"liars?", r"financial (difficult\w*|problems?|trouble)", r"debts?", r"mental health",
    r"depress\w*", r"divorc\w*",
]
_BANNED_RE = re.compile(r"\b(" + "|".join(_BANNED) + r")\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


@dataclass(frozen=True)
class Violation:
    field: str
    kind: str  # accusatory_or_speculative | real_name | email_address
    term: str


def _items(fields: dict[str, str | list[str]]) -> Iterable[tuple[str, str]]:
    for name, value in fields.items():
        if isinstance(value, str):
            yield name, value
        else:
            for i, item in enumerate(value):
                yield f"{name}[{i}]", item


def lint_fields(fields: dict[str, str | list[str]], real_names: Iterable[str] = ()) -> list[Violation]:
    names = [n for n in real_names if n and len(n) > 3]
    violations: list[Violation] = []
    for field, text in _items(fields):
        for m in _BANNED_RE.finditer(text):
            violations.append(Violation(field, "accusatory_or_speculative", m.group(0)))
        for name in names:
            if name.lower() in text.lower():
                violations.append(Violation(field, "real_name", name))
        for m in _EMAIL_RE.finditer(text):
            violations.append(Violation(field, "email_address", m.group(0)))
    return violations
