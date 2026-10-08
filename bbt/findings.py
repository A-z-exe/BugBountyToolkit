"""Finding model and aggregation.

A *finding* is a single, human-reviewable observation with a severity and
enough context to reproduce it. Modules return findings; the reporting module
renders them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    title: str
    severity: str = "info"
    category: str = "general"
    target: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = "medium"  # low | medium | high
    metadata: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITY_ORDER:
            self.severity = "info"
        if self.confidence not in ("low", "medium", "high"):
            self.confidence = "medium"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self.severity]

    def to_dict(self) -> Dict[str, object]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "target": self.target,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
            "metadata": self.metadata,
        }


class FindingsStore:
    """Collects findings, de-duplicates them and produces summaries."""

    def __init__(self) -> None:
        self._items: List[Finding] = []
        self._seen: set = set()

    def add(self, finding: Finding) -> bool:
        key = (finding.title.strip().lower(), finding.target.strip().lower())
        if key in self._seen:
            return False
        self._seen.add(key)
        self._items.append(finding)
        return True

    def extend(self, findings: Iterable[Finding]) -> int:
        added = 0
        for finding in findings:
            if self.add(finding):
                added += 1
        return added

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def sorted(self) -> List[Finding]:
        return sorted(self._items, key=lambda f: (f.rank, f.title.lower()))

    def counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self._items:
            counts[finding.severity] += 1
        return counts

    def to_list(self) -> List[Dict[str, object]]:
        return [f.to_dict() for f in self.sorted()]

    def highest(self) -> Optional[Finding]:
        ordered = self.sorted()
        return ordered[0] if ordered else None
