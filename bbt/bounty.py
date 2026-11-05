"""Bug-bounty report drafts and safe verification PoCs.

This module turns scanner findings into a structured report a human can review
and submit. It deliberately generates *verification* PoCs, not weaponised
exploits: no data dumping, no RCE payloads, no state-changing requests.

PoC files are written only with ``--write-pocs --i-have-authorization``.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Dict, List, Sequence

from . import __version__
from .context import ScanContext
from .findings import Finding

_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}"), r"\1<REDACTED>"),
    (
        re.compile(
            r"(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)"
            r"\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1<REDACTED>",
    ),
)


def _redact(text: str) -> str:
    value = text or ""
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def cvss_estimate(finding: Finding) -> float:
    return _CVSS.get(finding.severity, 0.0)


def _impact(finding: Finding) -> str:
    category = (finding.category or "").lower()
    text = f"{finding.title} {finding.description}".lower()
    if category in ("exposure",) or "exposed" in text:
        return (
            "The exposed resource can disclose credentials, source code, database "
            "content or internal configuration, enabling account takeover or further "
            "access. Confirm the file contains real data (not a soft-404 page)."
        )
    if "sql" in category or "sql injection" in text:
        return (
            "A confirmed SQL injection can expose or modify database records and may "
            "lead to authentication bypass or remote code execution depending on the "
            "database privileges."
        )
    if "xss" in category or "cross-site scripting" in text:
        return (
            "Script execution in a victim's browser can steal session data, perform "
            "actions as the victim or bypass CSRF protections. Demonstrate execution "
            "in a browser you control; do not target real users."
        )
    if category in ("authz",) or "bola" in text or "idor" in text:
        return (
            "A second account can reach an object it does not own. This is a direct "
            "confidentiality/integrity issue (PII, orders, exports, wallets) and is "
            "usually high impact in bug bounty programs."
        )
    if "ssrf" in category or "ssrf" in text:
        return (
            "Server-side requests can reach internal services, cloud metadata or "
            "localhost-only admin panels. Prove the request with a callback and stop "
            "before accessing sensitive data."
        )
    if "cors" in category:
        return (
            "If an arbitrary origin is trusted with credentials, any website can read "
            "authenticated API responses from a victim's browser."
        )
    if category in ("cookies", "transport", "tls"):
        return (
            "Weak transport or cookie flags make session interception and hijacking "
            "practical on shared networks. Pair this with a concrete attack path "
            "(e.g. HTTP login, missing Secure/HttpOnly) when reporting."
        )
    if "wordpress" in category:
        return (
            "Outdated WordPress components, XML-RPC or user enumeration can lead to "
            "account takeover or RCE through known plugin/core vulnerabilities. Map "
            "the exact version to a public advisory before reporting."
        )
    return "Verify the concrete security impact manually before submitting this draft."


def _steps(finding: Finding) -> List[str]:
    category = (finding.category or "").lower()
    if category == "authz":
        return [
            "Create/use two accounts you control: A owns the object, B is a second account.",
            "Request the object URL as A and save the response (status, length, key fields).",
            "Request the same URL as B with B's token/cookie.",
            "If B receives the same object data, capture both requests and the impact.",
        ]
    if "ssrf" in category:
        return [
            "Replace <CALLBACK_URL> in the PoC with a URL you control (Collaborator/webhook).",
            "Send the request and observe whether the target fetches your callback.",
            "If confirmed, test only benign internal targets allowed by the program.",
            "Capture the request, callback log and response difference.",
        ]
    if "sql" in category:
        return [
            "Send the baseline request and record the response.",
            "Send the quote payload from the PoC and compare the response.",
            "Confirm a database error/behaviour change; do not dump data.",
            "Capture the exact request/response and the vulnerable parameter.",
        ]
    if "xss" in category:
        return [
            "Open the PoC URL in a browser profile you control.",
            "Confirm the payload executes (a benign marker/alert is enough).",
            "Capture the request/response and a screenshot of execution.",
            "Do not target real users or leave persistent content on production.",
        ]
    if category == "exposure":
        return [
            "Request the reported URL with your authorized session.",
            "Confirm the response contains real content (not a soft-404 or WAF page).",
            "Capture status, content type and a redacted excerpt as evidence.",
            "Do not download more data than needed to prove the issue.",
        ]
    return [
        "Replay the request/URL from the evidence with your authorized account.",
        "Confirm the behaviour manually and capture a screenshot or HTTP transcript.",
        "Document the exact impact before submitting.",
    ]


def _poc_script(finding: Finding) -> str:
    # Quotes and newlines in a target must never be able to escape the
    # assignment and add extra shell commands to the generated script.
    raw_target = "".join(
        char if char.isprintable() else " " for char in (finding.target or "")
    ).strip()
    target = shlex.quote(raw_target)
    category = (finding.category or "").lower()
    title = finding.title.lower()
    header = (
        "#!/usr/bin/env bash\n"
        "# BBT verification PoC — non-destructive.\n"
        "# Only run this against systems you own or are explicitly authorized to test.\n"
        "# It does not dump data, change state or exploit a real user.\n"
        "set -euo pipefail\n\n"
    )
    if category == "authz" or "bola" in title or "idor" in title:
        body = (
            "URL=%s\n\n"
            "# Account A owns the object; account B must not be able to read it.\n"
            "curl -sS -o /dev/null -w 'A status: %%{http_code}\\n' \\\n"
            "  -H 'Authorization: Bearer <ACCOUNT_A_TOKEN>' \"$URL\"\n\n"
            "curl -sS -o /dev/null -w 'B status: %%{http_code}\\n' \\\n"
            "  -H 'Authorization: Bearer <ACCOUNT_B_TOKEN>' \"$URL\"\n\n"
            "# Compare the two responses manually. A 200 for B is the finding.\n"
        ) % target
    elif "ssrf" in category:
        body = (
            "URL=%s\n"
            "CALLBACK='<CALLBACK_URL>'\n\n"
            "# Replace CALLBACK with a URL you control, then check your callback log.\n"
            "curl -sS -D - -o /dev/null --max-time 15 \"$URL\"\n\n"
            "echo 'Now check the callback for an incoming request.'\n"
        ) % target
    elif "sql" in category:
        body = (
            "URL=%s\n\n"
            "# Baseline and quote payload; compare for a database error.\n"
            "curl -sS -D - -o /dev/null --max-time 15 \"$URL\"\n\n"
            "echo 'Send the quoted variant from the report evidence and compare.'\n"
        ) % target
    elif "xss" in category or "cross-site scripting" in title:
        body = (
            "URL=%s\n\n"
            "# Open this URL in a browser profile you control and check execution.\n"
            "echo \"$URL\"\n"
        ) % target
    elif "redirect" in category or "redirect" in title:
        body = (
            "URL=%s\n\n"
            "curl -sS -I --max-time 15 \"$URL\"\n"
            "# Check the Location header; it should point off-site for the PoC.\n"
        ) % target
    elif "cors" in category:
        body = (
            "URL=%s\n\n"
            "curl -sS -I --max-time 15 -H 'Origin: https://example.com' \"$URL\"\n"
        ) % target
    else:
        body = (
            "URL=%s\n\n"
            "curl -sS -o /dev/null -w 'status: %%{http_code} bytes: %%{size_download}\\n' \\\n"
            "  --max-time 15 \"$URL\"\n"
        ) % target
    return header + body


def _scope_warning(finding: Finding) -> str:
    category = (finding.category or "").lower()
    text = f"{finding.title} {finding.description}".lower()
    warnings = []
    if category in ("headers", "tls") or "technology disclosure" in text:
        warnings.append(
            "Many programs reject missing security headers, TLS best practices and "
            "server/version disclosure as non-exploitable. Confirm the program rules."
        )
    if category == "content-discovery":
        warnings.append(
            "Path/directory discovery is usually informational unless it exposes "
            "sensitive data or a concrete attack path."
        )
    if category == "wordpress":
        warnings.append(
            "Some programs explicitly exclude WordPress vulnerabilities; check the "
            "program's out-of-scope list before submitting."
        )
    if category == "cookies":
        warnings.append(
            "Missing cookie flags alone is often out of scope; pair it with a concrete "
            "session-interception scenario."
        )
    return " ".join(warnings)


def build_report(finding: Finding, index: int) -> str:
    evidence = _redact(finding.evidence)
    description = _redact(finding.description)
    references = finding.references or []
    lines = [
        "# %s" % finding.title,
        "",
        "> **Draft generated by BBT.** Verify manually and submit only inside the",
        "> program's declared scope. Automated output is not proof by itself.",
        "",
        "- **Target:** `%s`" % finding.target,
        "- **Category:** %s" % finding.category,
        "- **Severity:** %s (CVSS estimate %.1f)" % (finding.severity, cvss_estimate(finding)),
        "- **Confidence:** %s" % finding.confidence,
        "- **Generated by:** BBT v%s" % __version__,
        "",
        "## Summary",
        "",
        description or finding.title,
        "",
        "## Affected asset",
        "",
        "`%s`" % finding.target,
        "",
        "## Steps to reproduce",
        "",
    ]
    for number, step in enumerate(_steps(finding), 1):
        lines.append("%d. %s" % (number, step))
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    if evidence:
        lines.append("```text")
        lines.append(evidence)
        lines.append("```")
    else:
        lines.append("_No automated evidence was captured; attach your manual request/response._")
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(_impact(finding))
    lines.append("")
    if finding.remediation:
        lines.append("## Remediation")
        lines.append("")
        lines.append(_redact(finding.remediation))
        lines.append("")
    if references:
        lines.append("## References")
        lines.append("")
        for ref in references:
            lines.append("- %s" % ref)
        lines.append("")
    if finding.metadata:
        lines.append("## Metadata")
        lines.append("")
        lines.append("```json")
        lines.append(_redact(str(finding.metadata)))
        lines.append("```")
        lines.append("")
    warning = _scope_warning(finding)
    if warning:
        lines.append("## Scope warning")
        lines.append("")
        lines.append(warning)
        lines.append("")
    lines.append("## Submission checklist")
    lines.append("")
    lines.append("- [ ] Target is in the program's declared scope.")
    lines.append("- [ ] Reproduction was verified manually.")
    lines.append("- [ ] No user data was accessed or retained.")
    lines.append("- [ ] Tester IP / account details are included as required by the program.")
    lines.append("- [ ] Evidence is redacted where needed.")
    lines.append("")
    return "\n".join(lines)


def write_bounty_reports(
    ctx: ScanContext,
    mode: str,
    duration: float,
    risk: int,
    chains: Sequence[Dict[str, object]],
) -> List[Path]:
    """Write per-finding report drafts (and optional safe PoCs)."""
    if not getattr(ctx.config, "bounty_reports", True):
        return []
    findings = list(ctx.findings.sorted())
    if not findings:
        return []

    out_dir = ctx.output_dir / "bounty_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    rows = []

    for index, finding in enumerate(findings, 1):
        slug = re.sub(r"[^A-Za-z0-9]+", "-", finding.title).strip("-").lower()[:50] or "finding"
        stem = "%02d-%s" % (index, slug)
        report_path = out_dir / (stem + ".md")
        report_path.write_text(build_report(finding, index), encoding="utf-8")
        written.append(report_path)

        poc_name = ""
        if (
            getattr(ctx.config, "write_pocs", False)
            and getattr(ctx.config, "authorized_pocs", False)
        ):
            poc_path = out_dir / ("poc-" + stem + ".sh")
            poc_path.write_text(_poc_script(finding), encoding="utf-8")
            written.append(poc_path)
            poc_name = poc_path.name

        rows.append(
            {
                "index": index,
                "finding": finding,
                "report": report_path.name,
                "poc": poc_name,
            }
        )

    lines = [
        "# Bounty report drafts — `%s`" % ctx.target.display,
        "",
        "- **Mode:** `%s`" % mode,
        "- **Duration:** %.1fs" % duration,
        "- **Risk score:** **%d/100**" % risk,
        "- **Findings:** %d" % len(findings),
        "",
        "> These are drafts. Verify each issue manually, keep the target inside the",
        "> program scope, and redact secrets before submitting.",
        "",
        "> Scope warning: headers/TLS/version/server-disclosure and WordPress drafts",
        "> are commonly rejected — check the program rules before submitting.",
        "",
    ]
    if chains:
        lines.append("## Attack paths")
        lines.append("")
        for chain in chains:
            lines.append(
                "- **%s** — %s" % (str(chain.get("severity", "")).upper(), chain.get("title", ""))
            )
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| # | Severity | Title | Report | PoC |")
    lines.append("|---|----------|-------|--------|-----|")
    for row in rows:
        finding: Finding = row["finding"]  # type: ignore[assignment]
        report_link = "[%s](%s)" % (row["report"], row["report"])
        poc_link = "[%s](%s)" % (row["poc"], row["poc"]) if row["poc"] else "—"
        lines.append(
            "| %d | %s | %s | %s | %s |"
            % (
                row["index"],
                finding.severity.upper(),
                finding.title.replace("|", "\\|"),
                report_link,
                poc_link,
            )
        )
    lines.append("")
    if not any(row["poc"] for row in rows):
        lines.append(
            "_PoC scripts were not generated. Re-run with "
            "`--write-pocs --i-have-authorization` after reviewing scope._"
        )
        lines.append("")

    index_path = out_dir / "index.md"
    index_path.write_text("\n".join(lines), encoding="utf-8")
    written.append(index_path)
    ctx.register_artifact("bounty_reports", index_path)
    return written
