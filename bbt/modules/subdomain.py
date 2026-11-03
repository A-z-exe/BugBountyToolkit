"""Passive subdomain-takeover review.

Subdomains are collected from public certificate logs and resolved with DNS.
Only names whose CNAME points at a well-known claimable service *and* whose HTTP
response matches that service's "unclaimed" page are reported. Nothing is claimed.
"""
from __future__ import annotations

from typing import List

from ..findings import Finding
from ..recon import detect_takeover_service, enumerate_subdomains, takeover_marker
from ..target import Target
from ..utils import is_ip
from .base import BaseModule


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Passive subdomain enumeration + takeover fingerprints"
    modes = ("info", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return (
            self.config.subdomain_enum
            and target.kind in ("url", "host")
            and bool(target.host)
            and not is_ip(target.host)
        )

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        domain = target.host
        self.ui.info(
            f"Enumerating subdomains for {domain} (crt.sh + DNS, max {self.config.max_subdomains}) ..."
        )
        rows = enumerate_subdomains(domain, max_names=self.config.max_subdomains)
        findings: List[Finding] = []

        for row in rows:
            name = str(row.get("name") or "")
            for cname in row.get("cnames") or []:
                service = detect_takeover_service(str(cname))
                if not service:
                    continue
                response = self.http.get(
                    f"https://{name}/",
                    allow_redirects=True,
                    timeout=min(self.config.timeout, 10.0),
                )
                if response is None:
                    response = self.http.get(
                        f"http://{name}/",
                        allow_redirects=True,
                        timeout=min(self.config.timeout, 10.0),
                    )
                body = response.text if response is not None else ""
                marker = takeover_marker(str(cname), body)
                if not marker:
                    continue
                findings.append(
                    Finding(
                        title=f"Potential subdomain takeover: {name} -> {cname}",
                        severity="high",
                        category="takeover",
                        target=f"https://{name}/",
                        description=(
                            f"{name} is a CNAME to {cname} ({service}) and the origin "
                            "returns that service's 'unclaimed' page. An attacker may be "
                            "able to register the name and serve content on the domain."
                        ),
                        evidence=(
                            f"CNAME: {cname}\nservice: {service}\n"
                            f"marker: {marker!r}\nHTTP: {getattr(response, 'status_code', 'n/a')}"
                        ),
                        remediation=(
                            "Remove the dangling CNAME or reclaim the service name. "
                            "Do not claim it yourself; report it and let the owner fix it."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Subdomain_takeover"
                        ],
                        confidence="high",
                    )
                )

        self.ctx.write_json(
            "subdomains.json",
            {"domain": domain, "count": len(rows), "subdomains": rows},
            key="subdomains",
        )
        if not findings:
            self.ui.ok(f"No subdomain-takeover fingerprint found for {domain}")
        return findings
