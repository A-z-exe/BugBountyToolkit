"""Attack-path correlation.

An automated scanner produces a list of observations. Bug bounty reports are
judged on *impact*, so this module groups findings into short attack chains
(what an attacker would do with them) and computes a simple risk score.

The rules are deliberately conservative: every chain points at real findings
and tells the tester what to verify manually before reporting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from .findings import SEVERITIES, Finding

_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_WEIGHTS = {"critical": 40, "high": 20, "medium": 7, "low": 2, "info": 0}


@dataclass(frozen=True)
class _Rule:
    id: str
    title: str
    severity: str
    any_terms: Tuple[str, ...] = ()
    all_terms: Tuple[str, ...] = ()
    impact: str = ""
    next_steps: Tuple[str, ...] = ()
    max_items: int = 6


_RULES: Sequence[_Rule] = (
    _Rule(
        id="credential-disclosure",
        title="Exposed secrets/source may lead to account takeover",
        severity="critical",
        any_terms=(
            "exposed environment file",
            "exposed git",
            "git configuration",
            "database dump",
            "backup archive",
            "exposed .htpasswd",
            "exposed web.config",
            "actuator env",
        ),
        impact=(
            "Configuration files, database dumps or source code are often enough to "
            "recover credentials, API keys or session secrets and pivot to authenticated "
            "areas of the application."
        ),
        next_steps=(
            "Download the file and confirm it contains real data (soft-404 pages are common).",
            "Search it for database, API, SMTP, cloud and admin credentials.",
            "Test recovered credentials only inside the program's declared scope.",
            "Report with a redacted excerpt and the exact URL.",
        ),
    ),
    _Rule(
        id="unauthenticated-service",
        title="Unauthenticated data service exposed",
        severity="critical",
        any_terms=(
            "exposed service: redis",
            "exposed service: mongodb",
            "exposed service: elasticsearch",
            "exposed service: memcached",
            "exposed service: docker",
            "exposed service: vnc",
            "exposed service: rdp",
            "exposed service: smb",
        ),
        impact=(
            "Databases, caches and container APIs frequently ship without authentication. "
            "Direct access can mean full data disclosure or remote code execution."
        ),
        next_steps=(
            "Confirm the service is reachable and unauthenticated with a single safe command.",
            "Do not modify or delete data; capture read-only proof.",
            "Check the program scope: shared hosting infrastructure may be out of scope.",
            "Report the endpoint, service banner and proof of unauthenticated access.",
        ),
    ),
    _Rule(
        id="sql-injection",
        title="Possible SQL injection could expose the database",
        severity="high",
        any_terms=("sql injection",),
        impact=(
            "A confirmed SQL injection can leak credentials and customer data, and in some "
            "setups allows file read/write or command execution."
        ),
        next_steps=(
            "Reproduce manually in a proxy (Burp/ffuf) and capture the database error.",
            "Prove impact with a read-only query (version(), current_user) — never dump data.",
            "Check for WAF behaviour and note the exact payload.",
            "Report the vulnerable parameter, request and evidence.",
        ),
    ),
    _Rule(
        id="xss-without-csp",
        title="Reflected XSS with no Content-Security-Policy mitigation",
        severity="medium",
        any_terms=("cross-site scripting", "reflected xss", "stored xss"),
        all_terms=("missing security headers",),
        impact=(
            "A reflected payload with no CSP can run script in a victim's session, steal "
            "tokens or perform actions as the victim."
        ),
        next_steps=(
            "Confirm execution in a real browser and check the response Content-Type.",
            "Try a context-appropriate payload; document any encoding/filtering.",
            "Build a minimal proof-of-concept page for the report.",
            "Suggest output encoding plus a strict CSP.",
        ),
    ),
    _Rule(
        id="cors-data-theft",
        title="CORS misconfiguration may allow cross-origin data theft",
        severity="high",
        any_terms=("cors:",),
        impact=(
            "If an arbitrary origin is trusted together with credentials, any website can "
            "read authenticated API responses from a victim's browser."
        ),
        next_steps=(
            "Re-test the endpoint with an Origin you control and with credentials.",
            "Confirm the response actually contains sensitive data.",
            "Capture the request/response pair showing ACAO and ACAC headers.",
        ),
    ),
    _Rule(
        id="jwt-weakness",
        title="Weak JWT configuration may allow token forgery or replay",
        severity="high",
        any_terms=(
            "jwt uses 'none'",
            "sensitive data inside jwt",
            "jwt has no expiration",
        ),
        impact=(
            "Unsigned tokens, secrets in claims or tokens that never expire turn a single "
            "leak into long-lived account access."
        ),
        next_steps=(
            "Decode the token and map which endpoints accept it.",
            "If alg=none is accepted, forge a token for a test account only.",
            "Never attack production accounts; use accounts you created.",
        ),
    ),
    _Rule(
        id="admin-surface",
        title="Administrative or debugging interface exposed",
        severity="medium",
        any_terms=(
            "phpmyadmin",
            "adminer",
            "wordpress admin",
            "spring boot actuator",
            "swagger ui",
            "graphql endpoint",
        ),
        impact=(
            "Admin panels, actuator endpoints and API consoles are high-value targets for "
            "credential attacks, information leaks and configuration changes."
        ),
        next_steps=(
            "Check for default credentials and missing authentication (within scope).",
            "Review exposed configuration/health data for secrets.",
            "Verify whether access is intentional and restricted by network policy.",
        ),
    ),
    _Rule(
        id="open-redirect",
        title="Open redirect can be chained for phishing or token theft",
        severity="medium",
        any_terms=("open redirect",),
        impact=(
            "A trusted-domain redirect can be used in phishing, OAuth token theft or to "
            "bypass allowlists that trust the target domain."
        ),
        next_steps=(
            "Confirm the Location header points off-site with a benign domain.",
            "Check whether it can be chained with an OAuth redirect_uri allowlist.",
            "Report the parameter and the exact redirect behaviour.",
        ),
    ),
    _Rule(
        id="weak-transport",
        title="Transport/cookie weaknesses lower the cost of session attacks",
        severity="medium",
        any_terms=(
            "login form served over plain http",
            "expired tls certificate",
            "outdated tls protocol negotiated",
            "self-signed tls certificate",
            "insecure cookie",
        ),
        impact=(
            "Plain HTTP, weak TLS or cookies without Secure/HttpOnly/SameSite make session "
            "hijacking and credential interception practical on shared networks."
        ),
        next_steps=(
            "Check whether the login flow is reachable over HTTP without a redirect.",
            "Verify cookie flags on the actual session cookie, not a tracking cookie.",
            "Report the exact URL and the affected cookie/TLS endpoint.",
        ),
    ),
    _Rule(
        id="information-leak",
        title="Information disclosure helps the next stage of an attack",
        severity="low",
        any_terms=(
            "server technology disclosure",
            "sensitive information in html comment",
            "email address(es) disclosed",
        ),
        impact=(
            "Version banners, developer comments and harvested emails feed phishing and "
            "targeted vulnerability research; on their own the impact is limited."
        ),
        next_steps=(
            "Map the disclosed software/version to known CVEs (patch level matters).",
            "Check whether comments reveal internal hosts, keys or debug endpoints.",
            "Report only if it meaningfully helps exploitation; low-severity noise is often rejected.",
        ),
    ),
    _Rule(
        id="api-exposure",
        title="Exposed API documentation widens the attack surface",
        severity="low",
        any_terms=(
            "api specification",
            "graphql introspection",
            "api documentation",
        ),
        impact=(
            "A full API schema exposes endpoints, parameters and roles that are easy to "
            "test for authorization flaws."
        ),
        next_steps=(
            "Download the specification and list endpoints not covered by the UI.",
            "Test object-level authorization (IDOR/BOLA) on a few representative endpoints.",
            "Report undocumented/admin endpoints with proof of missing authorization.",
        ),
    ),
)


def _finding_text(finding: Finding) -> str:
    return f"{finding.title} {finding.description}".lower()


def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    unique: List[Finding] = []
    for finding in findings:
        key = (finding.title.strip().lower(), finding.target.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def build_attack_paths(findings: Iterable[Finding]) -> List[Dict[str, object]]:
    """Group findings into human-readable attack chains."""
    items = _dedupe(findings)
    if not items:
        return []
    texts = [_finding_text(item) for item in items]
    chains: List[Dict[str, object]] = []

    for rule in _RULES:
        if rule.any_terms and not any(
            any(term in text for term in rule.any_terms) for text in texts
        ):
            continue
        if rule.all_terms and not all(
            any(term in text for text in texts) for term in rule.all_terms
        ):
            continue

        terms = rule.any_terms + rule.all_terms
        matched = [
            item
            for item, text in zip(items, texts)
            if any(term in text for term in terms)
        ]
        if not matched:
            continue

        severity = rule.severity
        for item in matched:
            if _SEVERITY_RANK.get(item.severity, 4) < _SEVERITY_RANK.get(severity, 4):
                severity = item.severity

        chains.append(
            {
                "id": rule.id,
                "title": rule.title,
                "severity": severity,
                "findings": [item.title for item in matched[: rule.max_items]],
                "count": len(matched),
                "impact": rule.impact,
                "next_steps": list(rule.next_steps),
            }
        )

    chains.sort(key=lambda chain: _SEVERITY_RANK.get(str(chain["severity"]), 4))
    return chains


def risk_score(
    findings: Iterable[Finding],
    chains: Iterable[Dict[str, object]] = (),
) -> int:
    """Return a 0-100 score for prioritisation (not a CVSS replacement)."""
    score = 0
    for finding in findings:
        score += _WEIGHTS.get(finding.severity, 0)
    for chain in chains:
        if chain.get("severity") in ("critical", "high"):
            score += 5
    return max(0, min(100, score))
