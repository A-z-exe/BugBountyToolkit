"""Tests for external tool adapters and the hunt planner (no binaries run)."""
import unittest

from bbt.adapters import (
    findings_from_ffuf,
    findings_from_httpx,
    findings_from_katana,
    findings_from_nikto,
    findings_from_nuclei,
    findings_from_sqlmap_output,
    findings_from_wpscan,
    parse_httpx_jsonl,
    parse_katana_jsonl,
    plan_tool_names,
    _nikto_severity,
)
from bbt.scope import ScopePolicy


SCOPE = ScopePolicy.from_entries(["example.com"])


class PlannerTests(unittest.TestCase):
    def test_default_plan_is_fast(self):
        self.assertEqual(plan_tool_names(), ["httpx", "nuclei"])

    def test_deep_adds_discovery_and_subdomains(self):
        names = plan_tool_names(deep=True, subdomains_allowed=True)
        self.assertIn("katana", names)
        self.assertIn("ffuf", names)
        self.assertIn("nikto", names)
        self.assertIn("subfinder", names)

    def test_wordpress_adds_wpscan(self):
        self.assertIn("wpscan", plan_tool_names(wordpress=True))

    def test_aggressive_sqlmap_needs_a_query(self):
        self.assertNotIn("sqlmap", plan_tool_names(aggressive=True, has_query=False))
        self.assertIn("sqlmap", plan_tool_names(aggressive=True, has_query=True))

    def test_screenshots_are_opt_in(self):
        self.assertNotIn("gowitness", plan_tool_names())
        self.assertIn("gowitness", plan_tool_names(screenshots=True))


class HttpxParsingTests(unittest.TestCase):
    def test_jsonl_and_scope_filtering(self):
        text = (
            '{"url":"https://app.example.com/","status_code":200,'
            '"title":"App","webserver":"nginx","tech":["WordPress"]}\n'
            '{"url":"https://evil.test/","status_code":200,"tech":["nginx"]}\n'
            "not json\n"
        )
        rows = parse_httpx_jsonl(text)
        self.assertEqual(len(rows), 2)
        findings = findings_from_httpx(rows, SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].target, "https://app.example.com/")
        self.assertIn("WordPress", findings[0].metadata["tech"])


class KatanaParsingTests(unittest.TestCase):
    def test_jsonl_is_parsed_and_scoped(self):
        text = (
            '{"request":{"method":"GET","endpoint":"https://app.example.com/admin",'
            '"tag":"a"},"response":{"status_code":403}}\n'
            '{"request":{"method":"POST","endpoint":"https://app.example.com/api/users?id=1"},'
            '"response":{"status_code":200}}\n'
            '{"request":{"method":"GET","endpoint":"https://evil.test/secret"},'
            '"response":{"status_code":200}}\n'
            "not json\n"
        )
        rows = parse_katana_jsonl(text)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["status"], 403)
        self.assertEqual(rows[1]["method"], "POST")

        findings = findings_from_katana(rows, SCOPE, "https://app.example.com/")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")
        self.assertIn("/admin", findings[0].evidence)
        self.assertIn("/api/users?id=1", findings[0].evidence)
        self.assertNotIn("evil.test", findings[0].evidence)

    def test_boring_endpoints_do_not_create_a_finding(self):
        rows = parse_katana_jsonl(
            '{"request":{"endpoint":"https://app.example.com/about"},'
            '"response":{"status_code":200}}'
        )
        self.assertEqual(findings_from_katana(rows, SCOPE, "https://app.example.com/"), [])


class NucleiParsingTests(unittest.TestCase):
    def _row(self, **overrides):
        row = {
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed admin panel",
                "severity": "medium",
                "tags": ["panel"],
                "description": "An admin panel is exposed.",
                "reference": ["https://example.org/ref"],
            },
            "matched-at": "https://app.example.com/admin/",
        }
        row.update(overrides)
        return row

    def test_finding_is_mapped(self):
        findings = findings_from_nuclei([self._row()], SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].target, "https://app.example.com/admin/")
        self.assertEqual(findings[0].metadata["template"], "exposed-panel")

    def test_blocked_tags_are_dropped(self):
        row = self._row()
        row["info"]["tags"] = ["intrusive", "fuzz"]
        self.assertEqual(findings_from_nuclei([row], SCOPE), [])

    def test_tech_info_noise_is_dropped(self):
        row = self._row()
        row["info"]["severity"] = "info"
        row["info"]["tags"] = ["tech"]
        self.assertEqual(findings_from_nuclei([row], SCOPE), [])

    def test_out_of_scope_match_is_dropped(self):
        row = self._row(**{"matched-at": "https://evil.test/admin/"})
        self.assertEqual(findings_from_nuclei([row], SCOPE), [])


class FfufParsingTests(unittest.TestCase):
    def test_sensitive_paths_are_severity_scored(self):
        data = {
            "results": [
                {"url": "https://app.example.com/.env", "status": 200, "length": 120},
                {"url": "https://app.example.com/admin/", "status": 200, "length": 900},
                {"url": "https://app.example.com/images/", "status": 200, "length": 10},
                {"url": "https://evil.test/.env", "status": 200, "length": 120},
            ]
        }
        findings = findings_from_ffuf(data, SCOPE)
        by_path = {finding.target: finding.severity for finding in findings}
        self.assertEqual(by_path["https://app.example.com/.env"], "critical")
        self.assertEqual(by_path["https://app.example.com/admin/"], "medium")
        self.assertNotIn("https://app.example.com/images/", by_path)
        self.assertFalse(any("evil.test" in target for target in by_path))

    def test_forbidden_sensitive_path_is_downgraded(self):
        data = {
            "results": [
                {"url": "https://app.example.com/.env", "status": 403, "length": 0}
            ]
        }
        findings = findings_from_ffuf(data, SCOPE)
        self.assertEqual(findings[0].severity, "low")


class NiktoParsingTests(unittest.TestCase):
    def test_messages_are_classified(self):
        self.assertEqual(_nikto_severity("Remote command execution"), "high")
        self.assertEqual(_nikto_severity("Cross-site scripting"), "medium")
        self.assertEqual(_nikto_severity("Information disclosure"), "low")

    def test_findings_are_scoped(self):
        data = {
            "vulnerabilities": [
                {"url": "/admin/", "msg": "Admin panel exposed", "method": "GET"},
                {"url": "https://evil.test/", "msg": "XSS", "method": "GET"},
            ]
        }
        findings = findings_from_nikto(data, "https://app.example.com/", SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].target, "https://app.example.com/admin/")

    def test_real_host_list_format_is_flattened(self):
        data = [
            {
                "host": "app.example.com",
                "port": 443,
                "vulnerabilities": [
                    {"url": "/", "msg": "Admin panel exposed", "method": "GET"},
                    {"url": "/", "msg": "Suggested security header missing: x-frame-options."},
                ],
            }
        ]
        findings = findings_from_nikto(data, "https://app.example.com/", SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].target, "https://app.example.com/")


class WpscanParsingTests(unittest.TestCase):
    def test_outdated_core_and_users(self):
        data = {
            "version": {"number": "6.2", "status": "insecure"},
            "users": [{"id": 1, "slug": "admin"}],
            "plugins": {"akismet": {}},
        }
        findings = findings_from_wpscan(data, "https://app.example.com/", SCOPE)
        titles = [finding.title for finding in findings]
        self.assertTrue(any("Outdated WordPress core" in title for title in titles))
        self.assertTrue(any("user enumeration" in title for title in titles))
        self.assertTrue(any("plugins detected" in title for title in titles))

    def test_out_of_scope_url_returns_nothing(self):
        data = {"version": {"number": "6.2", "status": "insecure"}}
        self.assertEqual(findings_from_wpscan(data, "https://evil.test/", SCOPE), [])


class SqlmapParsingTests(unittest.TestCase):
    def test_confirmation_lines_become_one_finding(self):
        text = (
            "[INFO] testing 'AND boolean-based blind'\n"
            "[INFO] GET parameter 'id' is vulnerable\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
        )
        findings = findings_from_sqlmap_output(text, "https://app.example.com/item?id=1", SCOPE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertTrue(findings[0].metadata["verification_only"])

    def test_no_confirmation_means_no_finding(self):
        findings = findings_from_sqlmap_output(
            "[INFO] all tested parameters do not appear to be injectable",
            "https://app.example.com/item?id=1",
            SCOPE,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
