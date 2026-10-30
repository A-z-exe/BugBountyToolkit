"""Tests for attack-path correlation and risk scoring."""
import unittest

from bbt.attack import build_attack_paths, risk_score
from bbt.findings import Finding


def _finding(title, severity, target="http://target", description=""):
    return Finding(title=title, severity=severity, target=target, description=description)


class AttackPathTests(unittest.TestCase):
    def test_credential_disclosure_is_a_critical_chain(self):
        chains = build_attack_paths(
            [_finding("Exposed environment file (.env)", "critical")]
        )
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["id"], "credential-disclosure")
        self.assertEqual(chains[0]["severity"], "critical")
        self.assertIn("Exposed environment file (.env)", chains[0]["findings"])

    def test_xss_chain_requires_missing_headers(self):
        xss = _finding("Possible reflected XSS in parameter 'q'", "medium")
        headers = _finding("Missing security headers (6)", "medium")
        without_headers = build_attack_paths([xss])
        self.assertNotIn("xss-without-csp", {chain["id"] for chain in without_headers})
        with_headers = build_attack_paths([xss, headers])
        self.assertIn("xss-without-csp", {chain["id"] for chain in with_headers})

    def test_chains_are_sorted_by_severity(self):
        chains = build_attack_paths(
            [
                _finding("Possible SQL injection in parameter 'id'", "high"),
                _finding("Exposed environment file (.env)", "critical"),
                _finding("Open redirect via parameter 'next'", "medium"),
            ]
        )
        severities = [chain["severity"] for chain in chains]
        self.assertEqual(severities[0], "critical")
        self.assertLess(severities.index("high"), severities.index("medium"))

    def test_risk_score_is_bounded(self):
        findings = [
            _finding("Exposed environment file (.env)", "critical"),
            _finding("Possible SQL injection in parameter 'id'", "high"),
            _finding("Missing security headers (6)", "medium"),
        ]
        chains = build_attack_paths(findings)
        score = risk_score(findings, chains)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

    def test_no_findings_means_no_chains(self):
        self.assertEqual(build_attack_paths([]), [])
        self.assertEqual(risk_score([]), 0)


if __name__ == "__main__":
    unittest.main()
