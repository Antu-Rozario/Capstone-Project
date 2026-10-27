"""Human-in-the-loop checkpoint: Review Decisions on Case Summaries (FR-6).

Sensitive Recommendations (`requires_approval: true`) are never authorised until the
latest Review Decision on the case is `approved`. Every decision is kept, so rejected
cases can be counted as false positives.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DECISIONS = ("approved", "rejected", "needs_more_info")


@dataclass(frozen=True)
class ReviewDecision:
    case_id: str
    decision: str
    reviewer: str
    notes: str
    timestamp: str  # ISO 8601, UTC


class ReviewStore:
    """Append-only JSON store of Review Decisions, keyed by case ID."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._data: dict[str, list[dict[str, str]]] = json.loads(self.path.read_text()) if self.path.exists() else {}

    def record(self, case_id: str, decision: str, reviewer: str, notes: str = "") -> ReviewDecision:
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        if not reviewer.strip():
            raise ValueError("a Review Decision needs the reviewer's name")
        entry = ReviewDecision(case_id, decision, reviewer.strip(), notes.strip(), datetime.now(timezone.utc).isoformat())
        self._data.setdefault(case_id, []).append(asdict(entry))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))
        return entry

    def history(self, case_id: str) -> list[ReviewDecision]:
        return [ReviewDecision(**d) for d in self._data.get(case_id, [])]

    def latest(self, case_id: str) -> ReviewDecision | None:
        history = self.history(case_id)
        return history[-1] if history else None

    def status(self, case_id: str) -> str:
        latest = self.latest(case_id)
        return latest.decision if latest else "pending_review"


def authorised_actions(case: dict[str, Any], decision: ReviewDecision | None) -> list[dict[str, Any]]:
    """Actions that may be carried out now: unrestricted ones always, sensitive ones only after approval."""
    approved = decision is not None and decision.decision == "approved"
    return [a for a in case["recommended_actions"] if approved or not a["requires_approval"]]
