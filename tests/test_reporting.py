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

    def test_hunt_scope_and_tool_runs_are_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir = Path(tmp) / "tools"
            tools_dir.mkdir()
            artifact = tools_dir / "nuclei.jsonl"
            artifact.write_text("", encoding="utf-8")
            ctx = ScanContext(
                config=Config(rate=0),
                target=parse_target("https://example.com"),
                output_dir=Path(tmp),
                logger=logging.getLogger("bbt.tests"),
                ui=UI(color=False),
                http=None,  # type: ignore[arg-type]
                findings=FindingsStore(),
            )
            ctx.remember("hunt_scope", ["example.com", "*.example.com"])
            ctx.remember("hunt_plan", ["httpx", "nuclei"])
            ctx.remember(
                "tool_runs",
                [
                    {
                        "name": "nuclei",
                        "status": "ran",
                        "duration_seconds": 2.5,
                        "findings": 1,
                        "artifacts": [str(artifact)],
                        "note": "",
                    }
                ],
            )
            md_path, _ = write_reports(ctx, "auto", 3.0)
            report = md_path.read_text(encoding="utf-8")
            self.assertIn("Authorized scope", report)
            self.assertIn("External Tool Runs", report)
            self.assertIn("tools/nuclei.jsonl", report)


if __name__ == "__main__":
    unittest.main()
