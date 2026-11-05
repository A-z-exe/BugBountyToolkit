"""Tests for report/summary artifact registration (no network)."""
import json
import logging
import tempfile
import unittest
from pathlib import Path

from bbt.config import Config
from bbt.context import ScanContext
from bbt.findings import Finding, FindingsStore
from bbt.reporting import write_reports
from bbt.target import parse_target
from bbt.ui import UI


class ReportArtifactTests(unittest.TestCase):
    def test_reports_are_registered_as_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = ScanContext(
                config=Config(rate=0),
                target=parse_target("https://example.com"),
                output_dir=Path(tmp),
                logger=logging.getLogger("bbt.tests"),
                ui=UI(color=False),
                http=None,  # type: ignore[arg-type]
                findings=FindingsStore(),
            )
            ctx.findings.add(
                Finding(
                    title="Missing security headers (2)",
                    severity="low",
                    category="headers",
                    target="https://example.com/",
                )
            )
            md_path, json_path = write_reports(ctx, "web", 1.0)
            self.assertTrue(md_path.exists())
            self.assertTrue(json_path.exists())
            self.assertEqual(ctx.artifacts["report"], str(md_path))
            self.assertEqual(ctx.artifacts["scan_summary"], str(json_path))
            summary = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["artifacts"]["report"], "SECURITY_REPORT.md")
            self.assertEqual(summary["artifacts"]["scan_summary"], "scan_summary.json")


if __name__ == "__main__":
    unittest.main()
