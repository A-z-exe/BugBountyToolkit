"""The object every module receives: config, output paths, HTTP client, findings."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

from .config import Config
from .findings import Finding, FindingsStore
from .http_client import HttpClient
from .ui import UI

if TYPE_CHECKING:  # pragma: no cover
    from .target import Target


@dataclass
class ScanContext:
    config: Config
    target: "Target"
    output_dir: Path
    logger: logging.Logger
    ui: UI
    http: HttpClient
    findings: FindingsStore
    artifacts: Dict[str, str] = field(default_factory=dict)
    #: Shared per-target state (resolved web base URL, crawl results, ...).
    state: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def remember(self, key: str, value: Any) -> Any:
        """Store a value that later modules for the same target can reuse."""
        self.state[key] = value
        return value

    def recall(self, key: str, default: Any = None) -> Any:
        return self.state.get(key, default)

    # ------------------------------------------------------------------
    def artifact(self, name: str) -> Path:
        path = self.output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def register_artifact(self, key: str, path: Path | str) -> str:
        value = str(path)
        self.artifacts[key] = value
        return value

    def write_text(self, name: str, text: str, key: str | None = None) -> Path:
        path = self.artifact(name)
        path.write_text(text, encoding="utf-8", errors="replace")
        self.register_artifact(key or name, path)
        return path

    def write_json(self, name: str, data: Any, key: str | None = None) -> Path:
        path = self.artifact(name)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        self.register_artifact(key or name, path)
        return path

    def add_finding(self, finding: Finding) -> bool:
        added = self.findings.add(finding)
        if added:
            self.ui.found(finding.severity, finding.title, finding.target)
        return added
