"""Scan orchestration: module registry, target ordering and per-target execution."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple, Type

from .attack import build_attack_paths, risk_score
from .config import Config
from .context import ScanContext
from .findings import Finding, FindingsStore
from .http_client import HttpClient
from .modules.api import ApiModule
from .modules.authz import AuthzModule
from .modules.base import BaseModule
from .modules.info import InfoModule
from .modules.injection import InjectionModule
from .modules.network import NetworkModule
from .modules.ssrf import SsrfModule
from .modules.subdomain import SubdomainModule
from .modules.web import WebModule
from .modules.wordpress import WordpressModule
from .reporting import write_reports, write_session_summary
from .target import Target
from .ui import UI
from .utils import RateLimiter, is_private_ip, now_stamp, resolve_host, safe_filename

MODULE_CLASSES: Dict[str, Type[BaseModule]] = {
    "info": InfoModule,
    "network": NetworkModule,
    "web": WebModule,
    "wordpress": WordpressModule,
    "api": ApiModule,
    "authz": AuthzModule,
    "ssrf": SsrfModule,
    "subdomain": SubdomainModule,
    "injection": InjectionModule,
}

#: Which modules run for each mode. New modules can be added without a new CLI
#: mode (e.g. WordPress, authz and SSRF run inside web/api/full).
MODE_MODULES: Dict[str, List[str]] = {
    "info": ["info", "subdomain"],
    "network": ["network"],
    "web": ["web", "wordpress", "ssrf", "authz"],
    "api": ["api", "authz", "ssrf"],
    "injection": ["injection"],
    "full": [
        "info",
        "subdomain",
        "network",
        "web",
        "wordpress",
        "api",
        "authz",
        "ssrf",
        "injection",
    ],
    # Auto mode is executed by bbt.hunt.HuntOrchestrator; the same module set is
    # registered here so direct Scanner users get sensible behaviour.
    "auto": [
        "info",
        "subdomain",
        "network",
        "web",
        "wordpress",
        "api",
        "authz",
        "ssrf",
        "injection",
    ],
}

FULL_ORDER = MODE_MODULES["full"]


def modules_for_mode(mode: str) -> List[Type[BaseModule]]:
    if mode not in MODE_MODULES:
        raise ValueError(f"unknown mode: {mode}")
    return [MODULE_CLASSES[name] for name in MODE_MODULES[mode]]


class Scanner:
    def __init__(self, config: Config, ui: UI, logger: logging.Logger) -> None:
        self.config = config
        self.ui = ui
        self.log = logger
        self.rate_limiter = RateLimiter(config.rate)
        self._class_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    def classify(self, target: Target) -> str:
        """Return 'local' or 'remote' for a target.

        Public IPs and ranges are *remote* even though they are literal
        addresses. Only RFC1918/loopback/link-local assets, or hostnames that
        resolve to them, are local.
        """
        cached = self._class_cache.get(target.raw)
        if cached is not None:
            return cached

        if target.kind == "cidr":
            kind = "local" if target.is_private else "remote"
        elif target.kind == "ip":
            kind = "local" if is_private_ip(target.host) else "remote"
        elif target.is_private:
            kind = "local"
        else:
            addresses = resolve_host(target.host)
            if addresses and any(is_private_ip(ip) for ip in addresses):
                kind = "local"
            else:
                kind = "remote"

        self._class_cache[target.raw] = kind
        return kind

    def order_targets(self, targets: Sequence[Target]) -> List[Target]:
        local: List[Target] = []
        remote: List[Target] = []
        scope = self.config.scope
        for target in targets:
            kind = self.classify(target)
            if scope == "local" and kind != "local":
                self.ui.warn(f"Skipping {target.display} (outside local scope)")
                continue
            if scope == "remote" and kind != "remote":
                self.ui.warn(f"Skipping {target.display} (outside remote scope)")
                continue
            (local if kind == "local" else remote).append(target)
        return local + remote

    # ------------------------------------------------------------------
    def scan(self, targets: Sequence[Target], mode: str) -> Path:
        ordered = self.order_targets(targets)
        if not ordered:
            raise ValueError(
                "no targets remain after applying the scope filter "
                f"(--scope {self.config.scope})"
            )

        session_dir = self.config.output_root / f"scan_{now_stamp()}"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.ui.ok(f"Session directory: {session_dir}")

        session_results: List[Dict[str, object]] = []
        for index, target in enumerate(ordered, 1):
            kind = self.classify(target)
            self.ui.header(
                f"[{index}/{len(ordered)}] {target.display}  ({kind}, mode={mode})"
            )
            summary = self._scan_target(target, mode, session_dir)
            session_results.append(summary)

        summary_path = write_session_summary(session_dir, session_results)
        self.ui.ok(f"Session summary: {summary_path}")
        return session_dir

    # ------------------------------------------------------------------
    def _scan_target(self, target: Target, mode: str, session_dir: Path) -> Dict[str, object]:
        target_dir = session_dir / safe_filename(target.display)
        target_dir.mkdir(parents=True, exist_ok=True)

        findings = FindingsStore()
        http = HttpClient(self.config, rate_limiter=self.rate_limiter, logger=self.log)
        ctx = ScanContext(
            config=self.config,
            target=target,
            output_dir=target_dir,
            logger=self.log,
            ui=self.ui,
            http=http,
            findings=findings,
        )

        started = time.monotonic()
        ran: List[str] = []
        skipped: List[Tuple[str, str]] = []
        try:
            for module_cls in modules_for_mode(mode):
                module = module_cls(ctx)
                if not module.applies(target):
                    skipped.append((module.name, "not applicable to this target type"))
                    self.log.debug("module %s does not apply to %s", module.name, target.display)
                    continue
                if not module.enabled():
                    skipped.append(
                        (module.name, "missing tools: " + ", ".join(module.missing_tools()))
                    )
                    self.ui.warn(
                        f"Skipping {module.name} (missing tools: {', '.join(module.missing_tools())})"
                    )
                    continue
                self.ui.info(f"Running module: {module.name} - {module.description}")
                try:
                    produced = module.run(target) or []
                except Exception as exc:  # noqa: BLE001 - isolate module failures
                    self.log.exception("module %s crashed: %s", module.name, exc)
                    self.ui.error(f"Module {module.name} failed: {exc}")
                    continue
                for finding in produced:
                    ctx.add_finding(finding)
                ran.append(module.name)

            if not ran:
                reason = "; ".join(f"{name}: {why}" for name, why in skipped) or "no module produced results"
                ctx.add_finding(
                    Finding(
                        title="No checks executed for this target",
                        severity="info",
                        category="scan",
                        target=target.display,
                        description=(
                            f"Mode '{mode}' did not run any check against {target.kind} "
                            f"target {target.display!r}. Reasons: {reason}."
                        ),
                        remediation=(
                            "Use a URL or host target for web/API/injection checks. "
                            "For a URL in network mode add --scan-network, and for a CIDR "
                            "use the network module."
                        ),
                        confidence="high",
                    )
                )
                self.ui.warn(
                    f"No checks ran for {target.display} in mode {mode}. "
                    "Check the target type and mode (see report)."
                )
        finally:
            duration = time.monotonic() - started
            try:
                md_path, json_path = write_reports(ctx, mode, duration)
            finally:
                http.close()

        chains = build_attack_paths(findings)
        score = risk_score(findings, chains)
        self.ui.ok(
            f"Finished in {duration:.1f}s - {len(findings)} finding(s), "
            f"risk score {score}/100. Report: {md_path}"
        )
        return {
            "target": target.to_dict(),
            "scope": self.classify(target),
            "mode": mode,
            "modules": ran,
            "skipped": [{"module": name, "reason": why} for name, why in skipped],
            "duration_seconds": round(duration, 2),
            "counts": findings.counts(),
            "total_findings": len(findings),
            "risk_score": score,
            "attack_paths": chains,
            "report": str(md_path),
            "summary": str(json_path),
        }
