"""Autonomous, scope-gated hunt orchestration ("HuntBrain").

The orchestrator takes a web target, proves it is inside an authorized scope,
runs the built-in BBT modules, selects external tools based on what it finds
(WordPress, parameters, depth) and produces one correlated report.

It is deliberately *not* an exploitation framework. External tools run with
conservative flags; sqlmap is opt-in via ``--aggressive`` and stops after
confirming an injection without dumping data.
"""
from __future__ import annotations

import datetime
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Sequence

from . import __version__
from .adapters import ADAPTERS, ToolRun, plan_tool_names
from .attack import build_attack_paths, risk_score
from .checks import resolve_web_entry
from .config import Config
from .context import ScanContext
from .core import modules_for_mode
from .findings import FindingsStore
from .http_client import HttpClient
from .reporting import write_reports, write_session_summary
from .scope import ScopePolicy, guard_addresses, guard_report_targets
from .target import Target
from .ui import UI
from .utils import now_stamp, safe_filename

_WORDPRESS_MARKERS = ("wp-content/", "wp-includes/", "/wp-json", "wp-login.php")


class HuntError(RuntimeError):
    """Raised when a target cannot be hunted safely."""


class HuntOrchestrator:
    def __init__(
        self,
        config: Config,
        ui: UI,
        logger: logging.Logger,
        scope: ScopePolicy,
    ) -> None:
        self.config = config
        self.ui = ui
        self.log = logger
        self.scope = scope

    # ------------------------------------------------------------------
    def run(self, targets: Sequence[Target]) -> Path:
        if not targets:
            raise HuntError("no targets supplied")
        session_dir = self.config.output_root / f"hunt_{now_stamp()}"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.ui.ok(f"Hunt session directory: {session_dir}")
        self.ui.info(f"Authorized scope: {self.scope.describe()}")
        if not self.config.verify_tls:
            self.ui.warn("TLS verification is disabled for this hunt (--insecure).")

        results: List[Dict[str, object]] = []
        for index, target in enumerate(targets, 1):
            if target.kind == "cidr":
                raise HuntError(
                    "auto mode expects a website URL or hostname, not a CIDR range"
                )
            self.ui.header(f"[{index}/{len(targets)}] Hunting {target.display}")
            self._guard(target)
            results.append(self._run_target(target, session_dir))
        summary_path = write_session_summary(session_dir, results)
        self.ui.ok(f"Session summary: {summary_path}")
        return session_dir

    # ------------------------------------------------------------------
    def _guard(self, target: Target) -> None:
        self.scope.assert_target(target)
        addresses = guard_addresses(target, allow_private=self.config.allow_private)
        self.log.info("target %s resolved to %s", target.display, ", ".join(addresses))

    def _run_target(self, target: Target, session_dir: Path) -> Dict[str, object]:
        target_dir = session_dir / safe_filename(target.display)
        target_dir.mkdir(parents=True, exist_ok=True)
        findings = FindingsStore()
        http = HttpClient(self.config, logger=self.log)
        ctx = ScanContext(
            config=self.config,
            target=target,
            output_dir=target_dir,
            logger=self.log,
            ui=self.ui,
            http=http,
            findings=findings,
        )
        ctx.remember("hunt_scope", self.scope.to_list())
        started = time.monotonic()

        try:
            base_url, response = resolve_web_entry(ctx, target)
            if not base_url or response is None:
                raise HuntError(
                    f"{target.display} did not answer over HTTP(S); nothing to hunt"
                )
            if not self.scope.allows_url(base_url):
                raise HuntError(
                    f"resolved URL {base_url!r} is outside the authorized scope"
                )
            self.ui.ok(f"Reachable web entry point: {base_url}")
            body = ""
            try:
                body = (getattr(response, "text", "") or "")[:300000]
            except Exception:  # noqa: BLE001 - response bodies are best effort
                body = ""
            wordpress = any(marker in body for marker in _WORDPRESS_MARKERS)

            modules, skipped_modules = self._run_modules(ctx, target)
            tool_runs = self._run_tools(ctx, target, base_url, wordpress)
            budget = self.config.max_tool_findings
            for run in tool_runs:
                if budget <= 0:
                    run.findings = []
                    run.note = (run.note + " findings dropped by --max-tool-findings").strip()
                    continue
                if len(run.findings) > budget:
                    run.findings = run.findings[:budget]
                    run.note = (run.note + f" truncated to {budget} findings").strip()
                budget -= len(run.findings)
                for finding in run.findings:
                    ctx.add_finding(finding)

            # Drop anything outside scope that a module may have followed.
            removed = ctx.findings.retain(
                lambda finding: bool(guard_report_targets([finding], self.scope))
            )
            if removed:
                self.log.warning("%d finding(s) dropped because they were outside scope", removed)

            ctx.remember("tool_runs", [run.to_dict() for run in tool_runs])
            duration = time.monotonic() - started
            md_path, json_path = write_reports(ctx, "auto", duration)
            chains = build_attack_paths(ctx.findings)
            score = risk_score(ctx.findings, chains)
            hunt_summary = ctx.artifact("hunt_summary.json")
            hunt_summary.write_text(
                json.dumps(
                    {
                        "tool": "BBT",
                        "version": __version__,
                        "generated_at": datetime.datetime.now().isoformat(),
                        "mode": "auto",
                        "authorized": True,
                        "target": target.to_dict(),
                        "scope": self.scope.to_list(),
                        "base_url": base_url,
                        "wordpress_detected": wordpress,
                        "modules": modules,
                        "skipped_modules": skipped_modules,
                        "tool_plan": ctx.recall("hunt_plan", []),
                        "tool_runs": [run.to_dict() for run in tool_runs],
                        "summary": ctx.findings.counts(),
                        "total_findings": len(ctx.findings),
                        "risk_score": score,
                        "attack_paths": chains,
                        "report": str(md_path),
                        "scan_summary": str(json_path),
                    },
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                ),
                encoding="utf-8",
            )
            ctx.register_artifact("hunt_summary", hunt_summary)
            self.ui.ok(
                f"Finished in {duration:.1f}s - {len(ctx.findings)} finding(s), "
                f"risk {score}/100. Report: {md_path}"
            )
            return {
                "target": target.to_dict(),
                "base_url": base_url,
                "scope": self.scope.to_list(),
                "wordpress": wordpress,
                "modules": modules,
                "tool_runs": [run.to_dict() for run in tool_runs],
                "duration_seconds": round(duration, 2),
                "counts": ctx.findings.counts(),
                "total_findings": len(ctx.findings),
                "risk_score": score,
                "report": str(md_path),
                "summary": str(hunt_summary),
            }
        finally:
            http.close()

    # ------------------------------------------------------------------
    def _run_modules(self, ctx: ScanContext, target: Target):
        if self.config.hunt_deep:
            self.config.scan_network = True
            if self.scope.supports_subdomains(target.host):
                self.config.subdomain_enum = True

        ran: List[str] = []
        skipped: List[Dict[str, str]] = []
        for module_cls in modules_for_mode("full"):
            name = module_cls.name
            if name == "network" and not self.config.scan_network:
                skipped.append({"module": name, "reason": "network scan disabled (use --deep)"})
                continue
            if name == "subdomain":
                if not self.config.subdomain_enum:
                    skipped.append({"module": name, "reason": "subdomain enumeration disabled (use --deep)"})
                    continue
                if not self.scope.supports_subdomains(target.host):
                    skipped.append({"module": name, "reason": "scope does not include subdomains"})
                    continue
            module = module_cls(ctx)
            if not module.applies(target):
                skipped.append({"module": name, "reason": "not applicable to this target"})
                continue
            if not module.enabled():
                skipped.append(
                    {"module": name, "reason": "missing tools: " + ", ".join(module.missing_tools())}
                )
                continue
            self.ui.info(f"Module: {name} - {module.description}")
            try:
                produced = module.run(target) or []
            except Exception as exc:  # noqa: BLE001 - isolate module failures
                self.log.exception("module %s crashed", name)
                self.ui.error(f"Module {name} failed: {exc}")
                skipped.append({"module": name, "reason": f"crashed: {exc}"})
                continue
            for finding in produced:
                ctx.add_finding(finding)
            ran.append(name)
        return ran, skipped

    # ------------------------------------------------------------------
    def _run_tools(
        self,
        ctx: ScanContext,
        target: Target,
        base_url: str,
        wordpress: bool,
    ) -> List[ToolRun]:
        if not self.config.use_optional_tools:
            self.ui.warn("External tools disabled (--no-optional-tools)")
            return []
        has_query = bool(target.query) or "?" in base_url
        names = plan_tool_names(
            deep=self.config.hunt_deep,
            wordpress=wordpress,
            screenshots=self.config.screenshots,
            aggressive=self.config.aggressive,
            has_query=has_query,
            subdomains_allowed=self.scope.supports_subdomains(target.host),
        )
        ctx.remember("hunt_plan", names)
        self.ui.info("Tool plan: " + ", ".join(names))
        tools_dir = ctx.output_dir / "tools"
        runs: List[ToolRun] = []
        for name in names:
            adapter_cls = ADAPTERS.get(name)
            if adapter_cls is None:
                continue
            adapter = adapter_cls()
            tool_url = base_url
            if name == "sqlmap" and target.query:
                tool_url = target.url_with_query
            self.ui.info(f"Tool: {name} - {adapter.description}")
            try:
                run = adapter.run(target, tool_url, tools_dir, self.config, self.scope)
            except Exception as exc:  # noqa: BLE001 - one tool must not kill the hunt
                self.log.exception("tool %s crashed", name)
                run = ToolRun(
                    name=name,
                    description=adapter.description,
                    status="failed",
                    note=f"adapter crashed: {exc}",
                )
            if run.status == "skipped":
                self.ui.warn(f"{name}: {run.note}")
            else:
                self.ui.ok(
                    f"{name}: {run.status} in {run.duration:.1f}s, "
                    f"{len(run.findings)} finding(s)"
                )
            for artifact in run.artifacts:
                ctx.register_artifact(f"tool_{name}", artifact)
            runs.append(run)
        return runs
