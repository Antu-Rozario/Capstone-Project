"""Control Mapping: Finding type -> MITRE ATT&CK techniques and NIST SP 800-53 controls (FR-11).

The mapping lives in `mappings/controls.json` so the Evaluation/Security Lead can review
and verify it without touching code. Every lookup carries the file's verification status.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_MAPPING = Path(__file__).resolve().parents[2] / "mappings" / "controls.json"


@dataclass(frozen=True)
class ControlMapping:
    rules: dict[str, dict[str, list[dict[str, str]]]]
    verified: bool
    note: str
    attack_version: str | None

    def lookup(self, finding_type: str) -> dict[str, Any]:
        entry = self.rules[finding_type]
        return {
            "finding_type": finding_type,
            "attack": list(entry["attack"]),
            "nist": list(entry["nist"]),
            "verified": self.verified,
            "note": self.note,
        }


def load_control_mapping(path: Path = DEFAULT_MAPPING) -> ControlMapping:
    raw = json.loads(Path(path).read_text())
    return ControlMapping(
        rules=raw["mappings"],
        verified=bool(raw["verified"]),
        note=str(raw.get("note", "")),
        attack_version=raw.get("attack_version"),
    )
