"""Information gathering: DNS, optional WHOIS/subfinder and TLS certificates."""
from __future__ import annotations

from typing import List

from ..checks import check_tls
from ..crypto import get_certificate_info
from ..findings import Finding
from ..target import Target
from ..utils import have_tool, resolve_host, reverse_dns, run_command
from .base import BaseModule


class InfoModule(BaseModule):
    name = "info"
    description = "DNS resolution, WHOIS and TLS certificate information"
    modes = ("info", "full")
    required_tools = ()  # whois / dig / subfinder are optional

    def applies(self, target: Target) -> bool:
        return target.kind in ("url", "host", "ip")

    def run(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        host = target.host
        self.ui.info(f"Resolving {host} ...")

        dns_info: dict = {"host": host, "addresses": []}
        addresses = resolve_host(host)
        if addresses:
            dns_info["addresses"] = addresses
            reverse = {}
            for ip in addresses:
                name = reverse_dns(ip)
                if name:
                    reverse[ip] = name
            if reverse:
                dns_info["reverse"] = reverse
            self.ui.ok(f"{host} -> {', '.join(addresses)}")
        else:
            self.ui.warn(f"Could not resolve {host}")

        # Optional richer DNS via dig / nslookup when available.
        if self.config.use_optional_tools and have_tool("dig"):
            result = run_command(["dig", "+short", host], timeout=self.config.command_timeout)
            dns_info["dig"] = (result.get("stdout") or "").strip()
        elif have_tool("nslookup"):
            result = run_command(["nslookup", host], timeout=self.config.command_timeout)
            dns_info["nslookup"] = (result.get("stdout") or "").strip()

        self.ctx.write_json("dns_info.json", dns_info, key="dns_info")

        # WHOIS (external tool, optional).
        if self.config.use_optional_tools and have_tool("whois"):
            self.ui.info("Running WHOIS lookup ...")
            out_path = self.ctx.artifact("whois_output.txt")
            result = run_command(["whois", host], timeout=self.config.command_timeout,
                                  output_file=out_path)
            if result.get("returncode") == 0:
                self.ctx.register_artifact("whois", out_path)
                self.ui.ok(f"WHOIS saved to {out_path}")
            else:
                self.ui.warn(f"WHOIS failed: {result.get('stderr')}")
        else:
            self.ui.info("WHOIS tool not found; skipping (install 'whois' for more details)")

        # Subdomain discovery (optional external tool).
        if (
            self.config.use_optional_tools
            and target.kind in ("url", "host")
            and have_tool("subfinder")
        ):
            self.ui.info("Discovering subdomains with subfinder ...")
            out_path = self.ctx.artifact("subfinder_output.txt")
            result = run_command(
                ["subfinder", "-d", host, "-silent"],
                timeout=self.config.command_timeout,
                output_file=out_path,
            )
            if result.get("returncode") == 0:
                self.ctx.register_artifact("subdomains", out_path)

        # TLS certificate (pure Python). Only attempt when TLS is plausible.
        tls_port = target.port or 443
        is_tls = target.scheme == "https" or tls_port in (443, 8443, 9443)
        if not is_tls:
            self.ui.info("Target is not HTTPS; skipping TLS certificate inspection")
        else:
            self.ui.info(f"Inspecting TLS certificate on {host}:{tls_port} ...")
            cert = get_certificate_info(host, tls_port, timeout=self.config.connect_timeout + 2)
            self.ctx.write_json("tls_certificate.json", cert, key="tls")
            if cert.get("ok"):
                self.ui.ok(
                    f"Certificate expires: {cert.get('not_after')} "
                    f"({cert.get('days_remaining')} days)"
                )
                tls_findings, _ = check_tls(self.ctx, host, tls_port)
                findings.extend(tls_findings)
            else:
                self.ui.warn(f"TLS inspection failed: {cert.get('error')}")

        return findings
