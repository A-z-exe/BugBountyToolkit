"""Tests for the auto-mode orchestrator (no binaries or network)."""
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bbt import hunt as hunt_module
from bbt.adapters import ToolRun
from bbt.config import Config
from bbt.hunt import HuntOrchestrator
from bbt.scope import ScopePolicy
from bbt.target import parse_target
from tests.fakes import FakeResponse, FakeUI


class HuntReportingTests(unittest.TestCase):
    def test_tool_runs_are_remembered_for_the_report(self):
        scope = ScopePolicy.from_entries(["app.example.com"])
        orchestrator = HuntOrchestrator(
            Config(rate=0), FakeUI(), logging.getLogger("bbt.tests"), scope
        )
        tool_run = ToolRun(
            name="httpx",
            description="fingerprint",
            status="ran",
            duration=1.2,
            artifacts=["tools/httpx.jsonl"],
        )
        captured = {}

        def fake_reports(ctx, mode, duration):
            captured["tool_runs"] = ctx.recall("tool_runs")
            return Path("report.md"), Path("summary.json")

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                hunt_module,
                "resolve_web_entry",
                return_value=(
                    "http://app.example.com/",
                    FakeResponse(status_code=200, text=""),
                ),
            ), mock.patch.object(
                hunt_module, "modules_for_mode", return_value=[]
            ), mock.patch.object(
                orchestrator, "_run_tools", return_value=[tool_run]
            ), mock.patch.object(
                hunt_module, "write_reports", side_effect=fake_reports
            ):
                summary = orchestrator._run_target(
                    parse_target("http://app.example.com"), Path(tmp)
                )

        self.assertEqual(captured["tool_runs"][0]["name"], "httpx")
        self.assertEqual(summary["tool_runs"][0]["status"], "ran")


if __name__ == "__main__":
    unittest.main()
