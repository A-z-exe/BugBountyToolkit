"""Tests for bounty report/PoC generation (no network)."""
import logging
import tempfile
import unittest
from pathlib import Path

from bbt.bounty import build_report, write_bounty_reports
from bbt.config import Config
from bbt.context import ScanContext
from bbt.findings import Finding, FindingsStore
from bbt.target import parse_target
from bbt.ui import UI


def _context(tmp: Path, **config_kwargs):
    config = Config(rate=0, **config_kwargs)
    return ScanContext(
        config=config,
        target=parse_target("https://example.com"),
        output_dir=tmp,
        logger=logging.getLogger("bbt.tests"),
        ui=UI(color=False),
        http=None,  # type: ignore[arg-type]
        findings=FindingsStore(),
    )


class BountyReportTests(unittest.TestCase):
    def test_report_contains_evidence_and_redacts_secrets(self):
        finding = Finding(
            title="Exposed environment file (.env)",
            severity="critical",
            category="exposure",
            target="https://example.com/.env",
            description="The file is accessible.",
            evidence="HTTP 200\nDB_PASSWORD=supersecret\nAPI_KEY=deadbeef",
            remediation="Remove the file.",
            confidence="high",
        )
        report = build_report(finding, 1)
        self.assertIn("Exposed environment file", report)
        self.assertIn("https://example.com/.env", report)
        self.assertIn("<REDACTED>", report)
        self.assertNotIn("supersecret", report)
        self.assertIn("Submission checklist", report)

    def test_scope_warning_for_often_rejected_classes(self):
        finding = Finding(
            title="Legacy TLS protocol support enabled",
            severity="medium",
            category="tls",
            target="https://example.com:443",
        )
        report = build_report(finding, 1)
        self.assertIn("Scope warning", report)
        self.assertIn("TLS best practices", report)

    def test_write_reports_and_poc_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _context(
                Path(tmp), write_pocs=True, authorized_pocs=True, bounty_reports=True
            )
            ctx.findings.add(
                Finding(
                    title="Potential BOLA/IDOR: object accessible to both accounts",
                    severity="high",
                    category="authz",
                    target="https://example.com/api/users/42",
                    evidence="A: 200; B: 200",
                    description="B can read A's object.",
                )
            )
            written = write_bounty_reports(ctx, "web", 1.5, 40, [])
            names = {path.name for path in written}
            self.assertIn("index.md", names)
            self.assertTrue(any(name.startswith("01-") and name.endswith(".md") for name in names))
            poc = next(path for path in written if path.name.startswith("poc-"))
            text = poc.read_text(encoding="utf-8")
            self.assertIn("curl", text)
            self.assertIn("<ACCOUNT_A_TOKEN>", text)
            self.assertNotIn("--dump", text)
            self.assertIn("bounty_reports", ctx.artifacts)

    def test_pocs_are_not_written_without_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _context(Path(tmp), write_pocs=True, authorized_pocs=False)
            ctx.findings.add(Finding(title="XSS", severity="medium", category="xss", target="https://x"))
            written = write_bounty_reports(ctx, "web", 1.0, 5, [])
            self.assertFalse(any(path.name.startswith("poc-") for path in written))
            index = next(path for path in written if path.name == "index.md")
            self.assertIn("--write-pocs", index.read_text(encoding="utf-8"))

    def test_index_lists_attack_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _context(Path(tmp))
            ctx.findings.add(
                Finding(title="Potential SSRF", severity="high", category="ssrf", target="https://x")
            )
            written = write_bounty_reports(
                ctx, "web", 1.0, 30, [{"severity": "high", "title": "Possible SSRF"}]
            )
            index = next(path for path in written if path.name == "index.md")
            text = index.read_text(encoding="utf-8")
            self.assertIn("Attack paths", text)
            self.assertIn("Possible SSRF", text)


if __name__ == "__main__":
    unittest.main()
