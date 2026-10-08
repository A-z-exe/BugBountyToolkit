"""Network assessment: host discovery and TCP port scanning (pure Python).

This is the module that makes the toolkit useful *inside* a local network,
where DNS names may not resolve and only raw connectivity matters.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from ..config import RISKY_PORTS
from ..findings import Finding
from ..target import Target
from ..utils import (
    DISCOVERY_PORTS,
    expand_cidr,
    have_tool,
    parse_ports,
    resolve_host,
    run_command,
    scan_tcp_port,
    service_name,
)
from .base import BaseModule

#: Default severity for an exposed risky port; individual overrides below.
_PORT_SEVERITY = {
    2375: "critical",  # Docker API, plaintext
    2376: "medium",
    6379: "high",      # Redis
    27017: "high",     # MongoDB
    11211: "high",     # Memcached
    9200: "high",      # Elasticsearch
    445: "high",       # SMB
    3389: "high",      # RDP
    5900: "high",      # VNC
    23: "high",        # Telnet
    21: "medium",      # FTP
    3306: "medium",
    5432: "medium",
    1433: "medium",
    1521: "medium",
    2049: "medium",
    111: "low",
    135: "medium",
    139: "medium",
}


class NetworkModule(BaseModule):
    name = "network"
    description = "Host discovery and TCP port scanning"
    modes = ("network", "full")
    required_tools = ()  # nmap is optional

    def applies(self, target: Target) -> bool:
        return target.is_network or self.config.scan_network

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        threads = max(1, self.config.threads)
        timeout = self.config.connect_timeout

        # Work out the host list.
        if target.kind == "cidr":
            hosts = expand_cidr(target.raw, max_hosts=self.config.max_hosts)
            self.ui.info(f"Range {target.raw} expands to {len(hosts)} hosts")
        else:
            resolved = resolve_host(target.host) if target.kind == "host" else []
            hosts = resolved or [target.host]

        ports = parse_ports(self.config.ports)
        if target.port and target.port not in ports:
            ports = sorted(set(ports) | {target.port})

        # Discovery phase for ranges keeps the port scan focused on live hosts.
        if target.kind == "cidr" and len(hosts) > 1:
            self.ui.info(f"Discovering live hosts across {len(hosts)} addresses ...")
            live = self._discover(hosts, threads, timeout)
            self.ui.info(f"Discovered {len(live)} live host(s)")
            if not live:
                return [
                    Finding(
                        title="No live hosts discovered in range",
                        severity="info",
                        category="network",
                        target=target.raw,
                        description=(
                            "No TCP ports responded on the discovery set. Hosts may be "
                            "firewalled or use ICMP-only filtering."
                        ),
                        confidence="low",
                    )
                ]
            hosts = live

        self.ui.info(
            f"Scanning {len(hosts)} host(s) on {len(ports)} port(s) "
            f"with {threads} threads ..."
        )
        results = self._scan_ports(hosts, ports, threads, timeout)

        artifacts: Dict[str, object] = {}
        findings: List[Finding] = []
        for host in hosts:
            open_ports = results.get(host, [])
            artifacts[host] = [
                {"port": port, "service": service_name(port), "banner": banner}
                for port, banner in open_ports
            ]
            if not open_ports:
                continue

            self.ui.ok(
                f"{host}: " + ", ".join(f"{p}/{service_name(p)}" for p, _ in open_ports)
            )
            risky = []
            for port, banner in open_ports:
                if port in RISKY_PORTS:
                    severity = _PORT_SEVERITY.get(port, "medium")
                    risky.append((port, severity))
                    findings.append(
                        Finding(
                            title=f"Exposed service: {service_name(port)} ({port}/tcp)",
                            severity=severity,
                            category="network",
                            target=f"{host}:{port}",
                            description=RISKY_PORTS[port],
                            evidence=(banner[:200] if banner else f"Port {port} is open"),
                            remediation=(
                                "Restrict this service with a firewall, bind it to a trusted "
                                "interface, and require authentication."
                            ),
                        )
                    )
            if risky:
                self.ui.warn(f"{host}: {len(risky)} risky service(s) exposed")

            findings.append(
                Finding(
                    title="Open TCP ports discovered",
                    severity="info",
                    category="network",
                    target=host,
                    description=f"{len(open_ports)} open TCP port(s) were found on the host.",
                    evidence=", ".join(
                        f"{port}/{service_name(port)}" for port, _ in open_ports
                    ),
                    remediation="Review each exposed service and close anything unnecessary.",
                    confidence="high",
                )
            )

        self.ctx.write_json("network_scan.json", artifacts, key="network_scan")

        flat_report = []
        for host, open_ports in results.items():
            for port, banner in open_ports:
                flat_report.append(f"{host}:{port} open ({service_name(port)}) {banner}".strip())
        self.ctx.write_text(
            "network_scan.txt",
            "\n".join(flat_report) if flat_report else "No open ports found.",
            key="network_scan_txt",
        )

        # Optional nmap enrichment.
        if self.config.use_optional_tools and have_tool("nmap") and target.kind != "cidr":
            findings.extend(self._run_nmap(target, hosts, ports))

        return findings

    # ------------------------------------------------------------------
    def _discover(self, hosts: List[str], threads: int, timeout: float) -> List[str]:
        live: List[str] = []

        def up(host: str) -> bool:
            for port in DISCOVERY_PORTS:
                ok, _ = scan_tcp_port(host, port, timeout=timeout, banner=False)
                if ok:
                    return True
            return False

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(up, host): host for host in hosts}
            for future in as_completed(futures):
                if future.result():
                    live.append(futures[future])
        return sorted(live, key=_ip_sort_key)

    def _scan_ports(
        self, hosts: List[str], ports: List[int], threads: int, timeout: float
    ) -> Dict[str, List[Tuple[int, str]]]:
        results: Dict[str, List[Tuple[int, str]]] = {host: [] for host in hosts}

        def work(host: str, port: int) -> Tuple[str, int, bool, str]:
            ok, banner = scan_tcp_port(host, port, timeout=timeout, banner=True)
            return host, port, ok, banner

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(work, host, port) for host in hosts for port in ports
            ]
            for future in as_completed(futures):
                host, port, ok, banner = future.result()
                if ok:
                    results[host].append((port, _clean_banner(banner)))
        for host in results:
            results[host].sort(key=lambda item: item[0])
        return results

    # ------------------------------------------------------------------
    def _run_nmap(self, target: Target, hosts: List[str], ports: List[int]) -> List[Finding]:
        findings: List[Finding] = []
        if len(hosts) != 1:
            return findings
        host = hosts[0]
        port_spec = ",".join(str(p) for p in ports) or "1-1024"
        out_path = self.ctx.artifact("nmap_output.txt")
        self.ui.info(f"Running nmap service detection on {host} (optional) ...")
        result = run_command(
            ["nmap", "-sV", "-Pn", "-p", port_spec, host],
            timeout=max(self.config.command_timeout, 300),
            output_file=out_path,
        )
        if result.get("returncode") == 0:
            self.ctx.register_artifact("nmap", out_path)
            self.ui.ok(f"nmap output saved to {out_path}")
        else:
            self.ui.warn(f"nmap failed: {result.get('stderr')}")
        return findings


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _clean_banner(banner: str) -> str:
    if not banner:
        return ""
    banner = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", banner)
    return banner.replace("\r", " ").replace("\n", " ").strip()[:200]


def _ip_sort_key(host: str):
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return tuple([999] * 4)
