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

    def test_protected_low_findings_do_not_become_a_critical_chain(self):
        # Regression: /.env returning 403 must not be reported as credential
        # disclosure, let alone a critical attack path.
        chains = build_attack_paths(
            [_finding("Exposed environment file (.env) (access protected)", "low")]
        )
        self.assertEqual(chains, [])

    def test_chain_severity_is_clamped_to_the_evidence(self):
        chains = build_attack_paths(
            [_finding("Exposed environment file (.env)", "high")]
        )
        credential = [c for c in chains if c["id"] == "credential-disclosure"][0]
        self.assertEqual(credential["severity"], "high")

    def test_https_findings_join_the_transport_chain(self):
        chains = build_attack_paths(
            [
                _finding("HTTPS is available but not enforced", "high"),
                _finding("Insecure cookie: SESSION", "high"),
            ]
        )
        transport = [c for c in chains if c["id"] == "weak-transport"][0]
        self.assertEqual(transport["severity"], "high")
        self.assertEqual(len(transport["findings"]), 2)

    def test_ssrf_bola_and_wordpress_chains(self):
        chains = build_attack_paths(
            [
                _finding("Potential SSRF via parameter 'url' (localhost)", "high"),
                _finding(
                    "Potential BOLA/IDOR: object accessible to both accounts", "high"
                ),
                _finding("Outdated WordPress plugin: foo (1.0 < 2.0)", "medium"),
            ]
        )
        ids = {chain["id"] for chain in chains}
        self.assertIn("ssrf", ids)
        self.assertIn("bola", ids)
        self.assertIn("wordpress", ids)

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
