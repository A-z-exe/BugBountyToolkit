"""External-tool adapters used by the autonomous hunt orchestrator.

Every adapter:

* runs a binary with an argument list (never a shell),
* writes raw output under the target's ``tools/`` directory,
* parses the result into :class:`~bbt.findings.Finding` objects, and
* drops any parsed result whose URL/host is outside the authorized scope.

None of the adapters exploit anything: nuclei runs with intrusive/fuzzing/
brute-force/DoS/default-login tags excluded, nikto runs a conservative tuning
set, ffuf only discovers paths, and sqlmap (aggressive mode only) stops after
confirming an injection instead of dumping data.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .config import Config
from .findings import Finding
from .scope import ScopePolicy
from .target import Target
from .utils import DEFAULT_DIR_WORDS, have_tool, run_command

#: Tags that are never run, even if a template slips through another filter.
_BLOCKED_TAGS = {
    "intrusive",
    "fuzz",
    "fuzzing",
    "bruteforce",
    "brute-force",
    "dos",
    "headless",
    "default-login",
    "default-logins",
}
#: Technology-fingerprint results duplicate the httpx adapter.
_NOISE_TAGS = {"tech", "tech-detect", "wappalyzer", "fingerprint", "detect"}

_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class ToolRun:
    name: str
    description: str
    status: str  # ran | skipped | failed | timeout
    duration: float = 0.0
    command: List[str] = field(default_factory=list)
    returncode: int = 0
    artifacts: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    note: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "duration_seconds": round(self.duration, 2),
            "command": list(self.command),
            "returncode": self.returncode,
            "artifacts": list(self.artifacts),
            "findings": len(self.findings),
            "note": self.note,
            "data": self.data,
        }


def _tool_env(config: Config) -> Dict[str, str]:
    env = dict(os.environ)
    proxy = config.proxy or env.get("https_proxy") or env.get("HTTPS_PROXY")
    if proxy:
        env["http_proxy"] = proxy
        env["https_proxy"] = proxy
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
    return env


def _write(out_dir: Path, name: str, content: str) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    path.write_text(content, encoding="utf-8", errors="replace")
    return str(path)


def _json_lines(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _loads_tolerant(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _clean(text: Any, limit: int = 1200) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value[:limit]


def _severity(value: Any) -> str:
    severity = str(value or "info").strip().lower()
    return severity if severity in _SEVERITIES else "info"


def _tags(info: Dict[str, Any]) -> List[str]:
    raw = info.get("tags")
    if isinstance(raw, str):
        return [part.strip().lower() for part in raw.split(",") if part.strip()]
    if isinstance(raw, list):
        return [str(part).strip().lower() for part in raw if str(part).strip()]
    return []


class BaseAdapter:
    name = "base"
    description = ""
    binaries: Tuple[str, ...] = ()

    def binary(self) -> Optional[str]:
        for candidate in self.binaries:
            if have_tool(candidate):
                return candidate
        return None

    def _skipped(self, reason: str) -> ToolRun:
        return ToolRun(
            name=self.name,
            description=self.description,
            status="skipped",
            note=reason,
        )

    def run(
        self,
        target: Target,
        base_url: str,
        out_dir: Path,
        config: Config,
        scope: ScopePolicy,
    ) -> ToolRun:  # pragma: no cover - abstract
        raise NotImplementedError


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


def parse_httpx_jsonl(text: str) -> List[Dict[str, Any]]:
    return _json_lines(text)


def findings_from_httpx(
    rows: Sequence[Dict[str, Any]], scope: ScopePolicy
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for row in rows:
        url = str(row.get("url") or "")
        if not url or url in seen or not scope.allows_url(url):
            continue
        seen.add(url)
        tech = row.get("tech") or []
        if isinstance(tech, str):
            tech = [tech]
        server = row.get("webserver") or row.get("server") or ""
        cdn = row.get("cdn_name") or ""
        title = row.get("title") or ""
        status = row.get("status_code")
        if not (tech or server or cdn):
            continue
        details = []
        if tech:
            details.append("technology: " + ", ".join(str(item) for item in tech))
        if server:
            details.append(f"server: {server}")
        if cdn:
            details.append(f"cdn/waf: {cdn}")
        findings.append(
            Finding(
                title="Web technology fingerprint",
                severity="info",
                category="fingerprint",
                target=url,
                description=(
                    "HTTP fingerprinting identified the following components. "
                    "Version banners make targeted vulnerability research easier."
                ),
                evidence="\n".join(
                    [f"URL: {url}", f"HTTP: {status}", f"Title: {_clean(title, 200)}"]
                    + details
                ),
                remediation=(
                    "Remove unnecessary version banners and keep the identified "
                    "components patched; this is informational, not a vulnerability by itself."
                ),
                metadata={"tech": [str(item) for item in tech], "source": "httpx"},
                confidence="high",
            )
        )
    return findings


class HttpxAdapter(BaseAdapter):
    name = "httpx"
    description = "HTTP status, title, server, technology and TLS fingerprinting"
    binaries = ("httpx-toolkit", "httpx")

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("httpx-toolkit/httpx not installed")
        rate = int(config.rate) if config.rate and config.rate > 0 else 150
        cmd = [
            binary,
            "-u",
            base_url,
            "-j",
            "-silent",
            "-nc",
            "-title",
            "-td",
            "-sc",
            "-server",
            "-cdn",
            "-tls-grab",
            "-timeout",
            str(max(1, int(config.timeout))),
            "-rl",
            str(rate),
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=min(config.command_timeout, 180), env=_tool_env(config))
        duration = time.monotonic() - started
        stdout = str(result.get("stdout") or "")
        artifacts = [_write(out_dir, "httpx.jsonl", stdout)]
        rows = parse_httpx_jsonl(stdout)
        tech: List[str] = []
        for row in rows:
            value = row.get("tech") or []
            if isinstance(value, list):
                tech.extend(str(item) for item in value)
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if result.get("returncode") == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings_from_httpx(rows, scope),
            note=_clean(result.get("stderr"), 400),
            data={"results": rows, "tech": sorted(set(tech))},
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


def parse_nuclei_jsonl(text: str) -> List[Dict[str, Any]]:
    return _json_lines(text)


def findings_from_nuclei(
    rows: Sequence[Dict[str, Any]], scope: ScopePolicy
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for row in rows:
        info = row.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        tags = _tags(info)
        blocked = _BLOCKED_TAGS.intersection(tags)
        if blocked:
            continue
        severity = _severity(info.get("severity"))
        if severity == "info" and _NOISE_TAGS.intersection(tags):
            continue
        template = str(row.get("template-id") or row.get("templateID") or "nuclei")
        target = str(row.get("matched-at") or row.get("host") or "")
        if not target:
            continue
        url = target if "://" in target else f"https://{target.lstrip('/')}"
        if not scope.allows_url(url):
            continue
        title = str(info.get("name") or template)
        key = (template, target.lower())
        if key in seen:
            continue
        seen.add(key)
        matcher = str(row.get("matcher-name") or "")
        extracted = row.get("extracted-results") or []
        if isinstance(extracted, str):
            extracted = [extracted]
        evidence_lines = [f"template: {template}", f"matched: {target}"]
        if matcher:
            evidence_lines.append(f"matcher: {matcher}")
        if extracted:
            evidence_lines.append("extracted: " + ", ".join(str(item) for item in extracted[:10]))
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        classification = info.get("classification") or {}
        cve = ""
        if isinstance(classification, dict):
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            if cve_ids:
                cve = "CVE: " + ", ".join(str(item).upper() for item in cve_ids)
                evidence_lines.append(cve)
        findings.append(
            Finding(
                title=title,
                severity=severity,
                category="nuclei",
                target=url,
                description=_clean(info.get("description"), 1500),
                evidence="\n".join(evidence_lines),
                remediation=_clean(
                    info.get("remediation")
                    or "Apply the vendor fix for this template and re-test manually."
                ),
                references=[str(item) for item in references][:6],
                metadata={"template": template, "tags": tags, "source": "nuclei"},
                confidence="high" if severity in ("critical", "high", "medium") else "medium",
            )
        )
    return findings


class NucleiAdapter(BaseAdapter):
    name = "nuclei"
    description = "Template-based checks (intrusive/fuzzing/brute-force templates excluded)"
    binaries = ("nuclei",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("nuclei not installed")
        rate = int(config.rate) if config.rate and config.rate > 0 else 50
        cmd = [
            binary,
            "-u",
            base_url,
            "-j",
            "-silent",
            "-nc",
            "-dr",
            "-ni",
            "-etags",
            ",".join(sorted(_BLOCKED_TAGS)),
            "-rl",
            str(rate),
            "-timeout",
            str(max(5, int(config.timeout))),
            "-retries",
            "1",
            "-max-time",
            f"{max(30, int(config.command_timeout) - 15)}s",
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        stdout = str(result.get("stdout") or "")
        artifacts = [_write(out_dir, "nuclei.jsonl", stdout)]
        rows = parse_nuclei_jsonl(stdout)
        returncode = int(result.get("returncode") or 0)
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if returncode == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=returncode,
            artifacts=artifacts,
            findings=findings_from_nuclei(rows, scope),
            note=_clean(result.get("stderr"), 400),
            data={"matches": len(rows)},
        )
        budget = max(30, int(config.command_timeout) - 15)
        if returncode == -1:
            run.status = "timeout"
        elif returncode != 0 and duration >= max(10, budget - 5):
            run.status = "partial"
            run.note = (run.note + " stopped at max-time; partial results kept").strip()
        return run


# ---------------------------------------------------------------------------
# katana
# ---------------------------------------------------------------------------


def parse_katana_jsonl(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        request = value.get("request") if isinstance(value.get("request"), dict) else {}
        response = value.get("response") if isinstance(value.get("response"), dict) else {}
        url = str(request.get("endpoint") or request.get("url") or value.get("url") or "")
        if not url:
            continue
        try:
            status = int(response.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        rows.append(
            {
                "url": url,
                "method": str(request.get("method") or "GET").upper(),
                "status": status,
                "source": str(request.get("source") or ""),
                "tag": str(request.get("tag") or ""),
            }
        )
    return rows


_INTERESTING_PATH_WORDS = (
    "admin",
    "api",
    "upload",
    "debug",
    "token",
    "password",
    "secret",
    "internal",
    "backup",
    "config",
    "graphql",
    "swagger",
    "openapi",
    "actuator",
)


def findings_from_katana(
    rows: Sequence[Dict[str, Any]], scope: ScopePolicy, base_url: str
) -> List[Finding]:
    seen = set()
    endpoints: List[Dict[str, Any]] = []
    for row in rows:
        url = str(row.get("url") or "")
        if not url or url in seen:
            continue
        if not scope.allows_url(url):
            continue
        seen.add(url)
        endpoints.append(row)
    notable: List[Dict[str, Any]] = []
    for row in endpoints:
        parsed = urlparse(str(row.get("url") or ""))
        path = (parsed.path or "/").lower()
        interesting = (
            bool(parsed.query)
            or any(word in path for word in _INTERESTING_PATH_WORDS)
            or row.get("status") in (401, 403)
        )
        if interesting:
            notable.append(row)
    if not notable:
        return []
    evidence_lines = [
        f"{row.get('method', 'GET')} {row.get('status', 0)} {row.get('url', '')}"
        for row in notable[:40]
    ]
    if len(notable) > 40:
        evidence_lines.append(f"... and {len(notable) - 40} more")
    return [
        Finding(
            title=f"Katana discovered {len(notable)} notable endpoint(s)",
            severity="info",
            category="recon",
            target=base_url,
            description=(
                "The JavaScript-aware crawler found endpoints that are worth reviewing "
                "manually (parameterised, access-controlled or sensitive paths)."
            ),
            evidence="\n".join(evidence_lines),
            remediation="Review the endpoints and test them manually within scope.",
            metadata={
                "source": "katana",
                "endpoints": len(endpoints),
                "notable": len(notable),
            },
            confidence="medium",
        )
    ]


class KatanaAdapter(BaseAdapter):
    name = "katana"
    description = "JavaScript-aware crawl for additional in-scope endpoints"
    binaries = ("katana",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("katana not installed")
        rate = int(config.rate) if config.rate and config.rate > 0 else 50
        budget = max(30, int(config.command_timeout) - 15)
        cmd = [
            binary,
            "-u",
            base_url,
            "-j",
            "-silent",
            "-nc",
            "-jc",
            "-d",
            "2",
            "-fs",
            "fqdn",
            "-ct",
            f"{budget}s",
            "-mdp",
            "150",
            "-mrs",
            "524288",
            "-c",
            "5",
            "-rl",
            str(rate),
            "-timeout",
            str(max(5, int(config.timeout))),
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        stdout = str(result.get("stdout") or "")
        artifacts = [_write(out_dir, "katana.jsonl", stdout)]
        rows = parse_katana_jsonl(stdout)
        returncode = int(result.get("returncode") or 0)
        endpoints = [row["url"] for row in rows][:500]
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if returncode == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=returncode,
            artifacts=artifacts,
            findings=findings_from_katana(rows, scope, base_url),
            note=_clean(result.get("stderr"), 400),
            data={"count": len(rows), "endpoints": endpoints},
        )
        if returncode == -1:
            run.status = "timeout"
        elif returncode != 0 and duration >= max(10, budget - 5):
            run.status = "partial"
            run.note = (run.note + " stopped at crawl-duration; partial results kept").strip()
        return run


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------


def _wordlist(config: Config, out_dir: Path) -> Optional[str]:
    candidates = []
    if config.wordlist:
        candidates.append(config.wordlist)
    candidates.extend(
        [
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ]
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    fallback = out_dir / "bbt-dir-words.txt"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    fallback.write_text("\n".join(DEFAULT_DIR_WORDS) + "\n", encoding="utf-8")
    return str(fallback)


_SENSITIVE_WORDS = {
    "critical": (".env", ".git", ".svn", ".htpasswd", "wp-config", "dump.sql", "db.sql",
                 "backup.zip", "backup.tar", "id_rsa", "credentials"),
    "high": ("config", "secret", "token", "private", "debug", "phpinfo", "server-status",
             "actuator/env", "web.config", "backup"),
    "medium": ("admin", "dashboard", "login", "swagger", "openapi", "graphql", "api-docs",
               "actuator", "phpmyadmin", "adminer", "console"),
}


def _classify_path(path: str) -> Optional[str]:
    value = path.lower()
    for severity, words in _SENSITIVE_WORDS.items():
        if any(word in value for word in words):
            return severity
    return None


def findings_from_ffuf(
    data: Any, scope: ScopePolicy
) -> List[Finding]:
    if not isinstance(data, dict):
        return []
    results = data.get("results") or []
    findings: List[Finding] = []
    seen = set()
    for row in results:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        if not url or url in seen or not scope.allows_url(url):
            continue
        status = int(row.get("status") or 0)
        if status not in (200, 201, 204, 301, 302, 307, 401, 403):
            continue
        path = urlparse(url).path or "/"
        severity = _classify_path(path)
        if not severity:
            continue
        seen.add(url)
        if status in (401, 403) and severity in ("critical", "high"):
            severity = "low"
        evidence_lines = [
            f"URL: {url}",
            f"HTTP: {status}",
            f"length: {row.get('length')} words: {row.get('words')} lines: {row.get('lines')}",
        ]
        redirect = row.get("redirectlocation")
        if redirect:
            evidence_lines.append(f"redirect: {redirect}")
        findings.append(
            Finding(
                title=f"Sensitive path discovered: {path}",
                severity=severity,
                category="discovery",
                target=url,
                description=(
                    "Content discovery found a path whose name suggests sensitive "
                    "functionality or data. Verify the response manually; do not "
                    "download or modify any data."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Remove or protect the resource, require authentication, and "
                    "ensure backups/configuration files are not served by the web server."
                ),
                metadata={"status": status, "source": "ffuf"},
                confidence="medium" if status == 200 else "low",
            )
        )
    return findings


class FfufAdapter(BaseAdapter):
    name = "ffuf"
    description = "Content discovery against a curated wordlist (safe status codes)"
    binaries = ("ffuf",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("ffuf not installed")
        wordlist = _wordlist(config, out_dir)
        if not wordlist:
            return self._skipped("no wordlist available")
        out_file = out_dir / "ffuf.json"
        cmd = [
            binary,
            "-u",
            base_url.rstrip("/") + "/FUZZ",
            "-w",
            wordlist,
            "-mc",
            "200,204,301,302,307,401,403",
            "-ac",
            "-s",
            "-noninteractive",
            "-t",
            "20",
            "-timeout",
            str(max(3, int(config.timeout))),
            "-maxtime",
            str(max(15, int(config.command_timeout) - 15)),
            "-of",
            "json",
            "-o",
            str(out_file),
        ]
        if config.rate and config.rate > 0:
            cmd.extend(["-rate", str(int(config.rate))])
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        data = _loads_tolerant(out_file) if out_file.exists() else None
        artifacts: List[str] = []
        if out_file.exists():
            artifacts.append(str(out_file))
        stdout = str(result.get("stdout") or "")
        if stdout:
            artifacts.append(_write(out_dir, "ffuf.out", stdout))
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if data is not None else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings_from_ffuf(data, scope),
            note=_clean(result.get("stderr"), 400),
            data={"results": len((data or {}).get("results", [])) if isinstance(data, dict) else 0},
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------


def _nikto_severity(message: str) -> str:
    text = (message or "").lower()
    if any(word in text for word in ("remote code", "command execution", "authentication bypass",
                                     "default password", "sql injection", "shell")):
        return "high"
    if any(
        word in text
        for word in ("xss", "cross site", "cross-site", "traversal", "inclusion", "vulnerable")
    ):
        return "medium"
    if any(word in text for word in ("disclosure", "leak", "exposed", "information")):
        return "low"
    return "info"


def findings_from_nikto(
    data: Any, base_url: str, scope: ScopePolicy
) -> List[Finding]:
    vulnerabilities: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        hosts = [data]
    elif isinstance(data, list):
        hosts = [entry for entry in data if isinstance(entry, dict)]
    else:
        return []
    for host in hosts:
        items = host.get("vulnerabilities")
        if isinstance(items, list):
            vulnerabilities.extend(item for item in items if isinstance(item, dict))
        elif "msg" in host or "message" in host:
            vulnerabilities.append(host)
    origin = base_url.rstrip("/")
    if "://" in origin:
        parsed = urlparse(origin)
        origin = f"{parsed.scheme}://{parsed.netloc}"
    findings: List[Finding] = []
    seen = set()
    for item in vulnerabilities:
        message = _clean(item.get("msg") or item.get("message"), 600)
        if not message:
            continue
        if message.lower().startswith("suggested security header missing"):
            continue
        path = str(item.get("url") or "/")
        url = path if "://" in path else origin + (path if path.startswith("/") else "/" + path)
        if not scope.allows_url(url):
            continue
        key = (message, url)
        if key in seen:
            continue
        seen.add(key)
        references = item.get("references") or []
        if isinstance(references, str):
            references = [references]
        findings.append(
            Finding(
                title="Nikto finding: " + message[:120],
                severity=_nikto_severity(message),
                category="nikto",
                target=url,
                description=message,
                evidence=_clean(
                    f"{item.get('method', 'GET')} {url}\n"
                    f"OSVDB: {item.get('OSVDB', '')} id: {item.get('id', '')}"
                ),
                remediation="Verify manually and apply the server/framework vendor update.",
                references=[str(ref) for ref in references][:5],
                metadata={"source": "nikto"},
                confidence="low",
            )
        )
    return findings


class NiktoAdapter(BaseAdapter):
    name = "nikto"
    description = "Web server misconfiguration checks (conservative tuning set)"
    binaries = ("nikto",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("nikto not installed")
        out_file = out_dir / "nikto.json"
        cmd = [
            binary,
            "-h",
            base_url,
            "-maxtime",
            "5m",
            "-nointeractive",
            "-ask",
            "no",
            "-Tuning",
            "123b",
            "-Format",
            "json",
            "-output",
            str(out_file),
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        data = _loads_tolerant(out_file) if out_file.exists() else None
        if data is None:
            data = _loads_tolerant_text(str(result.get("stdout") or ""))
        artifacts: List[str] = []
        if out_file.exists():
            artifacts.append(str(out_file))
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if data is not None else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings_from_nikto(data, base_url, scope),
            note=_clean(result.get("stderr"), 400),
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# wpscan
# ---------------------------------------------------------------------------


def _loads_tolerant_text(text: str) -> Any:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def findings_from_wpscan(
    data: Any, base_url: str, scope: ScopePolicy
) -> List[Finding]:
    if not isinstance(data, dict) or not scope.allows_url(base_url):
        return []
    findings: List[Finding] = []
    version = data.get("version") or {}
    if isinstance(version, dict):
        number = str(version.get("number") or "")
        status = str(version.get("status") or "").lower()
        if number and status in ("insecure", "outdated"):
            findings.append(
                Finding(
                    title=f"Outdated WordPress core ({number})",
                    severity="medium",
                    category="wordpress",
                    target=base_url,
                    description=(
                        "WPScan reports that the WordPress core version is not current. "
                        "Outdated releases are commonly targeted with known exploits."
                    ),
                    evidence=f"version: {number}\nstatus: {status}",
                    remediation="Update WordPress core to the latest release and enable auto-updates.",
                    metadata={"source": "wpscan"},
                    confidence="medium",
                )
            )
    users = data.get("users") or []
    if isinstance(users, dict):
        users = list(users.values())
    if users:
        names = []
        for user in users[:20]:
            if isinstance(user, dict):
                names.append(str(user.get("slug") or user.get("name") or user.get("id") or "?"))
        findings.append(
            Finding(
                title="WordPress user enumeration",
                severity="low",
                category="wordpress",
                target=base_url,
                description=(
                    "WPScan enumerated WordPress users. Usernames help credential "
                    "attacks and should not be exposed when avoidable."
                ),
                evidence="users: " + ", ".join(names),
                remediation="Disable REST/author enumeration, use strong unique passwords and MFA.",
                metadata={"source": "wpscan"},
                confidence="medium",
            )
        )
    plugins = data.get("plugins") or {}
    themes = data.get("themes") or {}
    if isinstance(plugins, dict) and plugins:
        names = list(plugins.keys())[:30]
        findings.append(
            Finding(
                title=f"WordPress plugins detected ({len(plugins)})",
                severity="info",
                category="wordpress",
                target=base_url,
                description="Installed plugins enlarge the attack surface. Keep only needed plugins updated.",
                evidence="plugins: " + ", ".join(str(name) for name in names),
                remediation="Remove unused plugins and keep the rest on the latest release.",
                metadata={"source": "wpscan"},
                confidence="high",
            )
        )
    if isinstance(themes, dict) and themes:
        findings.append(
            Finding(
                title=f"WordPress themes detected ({len(themes)})",
                severity="info",
                category="wordpress",
                target=base_url,
                description="Detected themes should be kept updated and unused themes removed.",
                evidence="themes: " + ", ".join(str(name) for name in list(themes.keys())[:20]),
                remediation="Remove unused themes and update the active one.",
                metadata={"source": "wpscan"},
                confidence="high",
            )
        )
    return findings


class WpscanAdapter(BaseAdapter):
    name = "wpscan"
    description = "WordPress core/plugin/theme and user enumeration (passive)"
    binaries = ("wpscan",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("wpscan not installed")
        out_file = out_dir / "wpscan.json"
        cmd = [
            binary,
            "--url",
            base_url,
            "--no-banner",
            "--stealthy",
            "--format",
            "json",
            "--output",
            str(out_file),
            "--enumerate",
            "u",
            "--plugins-detection",
            "passive",
            "--themes-detection",
            "passive",
        ]
        if not config.verify_tls:
            cmd.append("--disable-tls-checks")
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        data = _loads_tolerant(out_file) if out_file.exists() else None
        artifacts: List[str] = []
        if out_file.exists():
            artifacts.append(str(out_file))
        stdout = str(result.get("stdout") or "")
        if stdout:
            artifacts.append(_write(out_dir, "wpscan.out", stdout))
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if data is not None else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings_from_wpscan(data, base_url, scope),
            note=_clean(result.get("stderr"), 400)
            or "WPScan vulnerability data needs --api-token; this run is fingerprinting only.",
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


class SubfinderAdapter(BaseAdapter):
    name = "subfinder"
    description = "Passive subdomain discovery (results are listed, not scanned)"
    binaries = ("subfinder",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("subfinder not installed")
        domain = target.host
        cmd = [binary, "-d", domain, "-silent", "-timeout", "5"]
        started = time.monotonic()
        result = run_command(cmd, timeout=min(config.command_timeout, 240), env=_tool_env(config))
        duration = time.monotonic() - started
        stdout = str(result.get("stdout") or "")
        names = []
        for line in stdout.splitlines():
            name = line.strip().lower().rstrip(".")
            if not name or name in names:
                continue
            if scope.allows_host(name):
                names.append(name)
        names = names[:500]
        artifacts = [_write(out_dir, "subdomains.txt", "\n".join(names) + ("\n" if names else ""))]
        findings: List[Finding] = []
        if names:
            findings.append(
                Finding(
                    title=f"Passive subdomains discovered ({len(names)})",
                    severity="info",
                    category="recon",
                    target=base_url,
                    description=(
                        "Subfinder collected subdomains from public sources. Only names "
                        "inside the declared scope are listed; they were not scanned."
                    ),
                    evidence="\n".join(names[:50]),
                    remediation="Review the list, then scan each name only if the program allows it.",
                    metadata={"source": "subfinder", "count": len(names)},
                    confidence="medium",
                )
            )
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if result.get("returncode") == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings,
            note=_clean(result.get("stderr"), 400),
            data={"subdomains": names[:100], "count": len(names)},
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# gowitness
# ---------------------------------------------------------------------------


class GowitnessAdapter(BaseAdapter):
    name = "gowitness"
    description = "Visual screenshot of the target page"
    binaries = ("gowitness",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("gowitness not installed")
        shots = out_dir / "screenshots"
        shots.mkdir(parents=True, exist_ok=True)
        cmd = [
            binary,
            "scan",
            "single",
            "--url",
            base_url,
            "--screenshot-path",
            str(shots),
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=min(config.command_timeout, 120), env=_tool_env(config))
        duration = time.monotonic() - started
        produced = sorted(str(path) for path in shots.glob("*") if path.is_file())
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if result.get("returncode") == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=produced[:10] or [str(shots)],
            note=_clean(result.get("stderr"), 400),
            data={"screenshots": produced[:10]},
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# sqlmap (aggressive only)
# ---------------------------------------------------------------------------


def findings_from_sqlmap_output(text: str, base_url: str, scope: ScopePolicy) -> List[Finding]:
    if not scope.allows_url(base_url):
        return []
    interesting = [
        line.strip()
        for line in (text or "").splitlines()
        if any(marker in line for marker in ("Parameter:", "Type:", "Title:", "Payload:", "is vulnerable"))
    ]
    if not any("is vulnerable" in line or "Parameter:" in line for line in interesting):
        return []
    return [
        Finding(
            title="SQL injection confirmed by sqlmap (verification only)",
            severity="high",
            category="injection",
            target=base_url,
            description=(
                "sqlmap confirmed an injectable parameter in boolean/error mode. "
                "No data was dumped and no state was changed. Re-verify manually and "
                "capture only the minimum proof required by the program."
            ),
            evidence="\n".join(interesting[:20]),
            remediation=(
                "Use parameterized queries/ORM bindings, validate input server-side and "
                "restrict database privileges. Rotate any credentials reachable from the DB."
            ),
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            metadata={"source": "sqlmap", "verification_only": True},
            confidence="high",
        )
    ]


class SqlmapAdapter(BaseAdapter):
    name = "sqlmap"
    description = "Boolean/error SQL injection confirmation (aggressive mode only)"
    binaries = ("sqlmap",)

    def run(self, target, base_url, out_dir, config, scope) -> ToolRun:
        binary = self.binary()
        if not binary:
            return self._skipped("sqlmap not installed")
        if "?" not in base_url:
            return self._skipped("target URL has no query parameters")
        out_path = out_dir / "sqlmap"
        out_path.mkdir(parents=True, exist_ok=True)
        cmd = [
            binary,
            "-u",
            base_url,
            "--batch",
            "--smart",
            "--level",
            "1",
            "--risk",
            "1",
            "--technique=BE",
            "--timeout",
            "10",
            "--retries",
            "1",
            "--threads",
            "1",
            "--random-agent",
            "--flush-session",
            "--disable-coloring",
            "--output-dir",
            str(out_path),
        ]
        started = time.monotonic()
        result = run_command(cmd, timeout=config.command_timeout, env=_tool_env(config))
        duration = time.monotonic() - started
        stdout = str(result.get("stdout") or "")
        artifacts = [_write(out_dir, "sqlmap.out", stdout + "\n" + str(result.get("stderr") or ""))]
        run = ToolRun(
            name=self.name,
            description=self.description,
            status="ran" if result.get("returncode") == 0 else "failed",
            duration=duration,
            command=cmd,
            returncode=int(result.get("returncode") or 0),
            artifacts=artifacts,
            findings=findings_from_sqlmap_output(stdout, base_url, scope),
            note=_clean(result.get("stderr"), 400),
            data={"verification_only": True},
        )
        if result.get("returncode") == -1:
            run.status = "timeout"
        return run


# ---------------------------------------------------------------------------
# Registry / planner
# ---------------------------------------------------------------------------

ADAPTERS: Dict[str, type] = {
    "httpx": HttpxAdapter,
    "nuclei": NucleiAdapter,
    "katana": KatanaAdapter,
    "ffuf": FfufAdapter,
    "nikto": NiktoAdapter,
    "wpscan": WpscanAdapter,
    "subfinder": SubfinderAdapter,
    "gowitness": GowitnessAdapter,
    "sqlmap": SqlmapAdapter,
}


def plan_tool_names(
    *,
    deep: bool = False,
    wordpress: bool = False,
    screenshots: bool = False,
    aggressive: bool = False,
    has_query: bool = False,
    subdomains_allowed: bool = False,
) -> List[str]:
    """Choose tools from the target's characteristics (the 'planner')."""
    names = ["httpx", "nuclei"]
    if deep:
        names.extend(["katana", "ffuf", "nikto"])
    if wordpress:
        names.append("wpscan")
    if deep and subdomains_allowed:
        names.append("subfinder")
    if screenshots:
        names.append("gowitness")
    if aggressive and has_query:
        names.append("sqlmap")
    # Preserve order, drop duplicates.
    ordered: List[str] = []
    for name in names:
        if name not in ordered:
            ordered.append(name)
    return ordered
