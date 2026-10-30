"""API security review: documentation discovery, CORS and JWT analysis."""
from __future__ import annotations

import base64
import json
from typing import List, Optional, Tuple

from ..checks import check_cors, establish_baseline, probe_paths, resolve_web_entry
from ..findings import Finding
from ..target import Target
from .base import BaseModule

API_DOC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
]


class ApiModule(BaseModule):
    name = "api"
    description = "API documentation discovery, CORS and JWT analysis"
    modes = ("api", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return target.is_web

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        base_url, _resp = resolve_web_entry(self.ctx, target)
        if not base_url and target.kind == "url":
            base_url = target.base_url
        if not base_url:
            return [
                Finding(
                    title="API service unreachable",
                    severity="info",
                    category="api",
                    target=target.display,
                    description="No HTTP(S) service responded, so API checks were skipped.",
                    confidence="low",
                )
            ]

        findings.extend(self._discover_docs(base_url))
        findings.extend(self._graphql_check(base_url))

        cors_findings, cors_data = check_cors(self.ctx, base_url)
        findings.extend(cors_findings)
        # Keep the API CORS evidence separate from the web module's file.
        self.ctx.write_json("api_cors_analysis.json", cors_data, key="api_cors")

        for token in self.config.tokens:
            findings.extend(self._analyze_jwt(token))

        return findings

    # ------------------------------------------------------------------
    def _discover_docs(self, base_url: str) -> List[Finding]:
        self.ui.info("Searching for API documentation ...")
        baseline = establish_baseline(self.ctx, base_url)
        hits, findings = probe_paths(self.ctx, base_url, API_DOC_PATHS, baseline)
        self.ctx.write_json(
            "api_docs_discovery.json",
            {"baseline": baseline, "hits": hits},
            key="api_docs",
        )
        for hit in hits:
            if hit["path"].endswith((".json", ".yaml")) and hit["status"] == 200:
                findings.append(
                    Finding(
                        title="Machine-readable API specification exposed",
                        severity="low",
                        category="api",
                        target=hit["url"],
                        description=(
                            "An API specification is publicly reachable and can reveal all "
                            "endpoints and parameters."
                        ),
                        evidence=f"HTTP {hit['status']}, Content-Type: {hit['content_type']}",
                        remediation="Restrict API documentation to authenticated/internal users.",
                        confidence="high",
                    )
                )
        return findings

    # ------------------------------------------------------------------
    def _graphql_check(self, base_url: str) -> List[Finding]:
        url = base_url.rstrip("/") + "/graphql"
        query = {"query": "{__schema{queryType{name}}}"}
        resp = self.http.post(url, json=query)
        if resp is None or resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []
        if isinstance(data, dict) and "data" in data and "__schema" in (data.get("data") or {}):
            return [
                Finding(
                    title="GraphQL introspection enabled",
                    severity="low",
                    category="api",
                    target=url,
                    description="The GraphQL schema can be introspected by unauthenticated users.",
                    evidence=json.dumps(data)[:200],
                    remediation="Disable introspection in production or require authentication.",
                    confidence="high",
                )
            ]
        return []

    # ------------------------------------------------------------------
    def _analyze_jwt(self, token: str) -> List[Finding]:
        findings: List[Finding] = []
        decoded = _decode_jwt(token)
        if decoded is None:
            return findings
        header, payload, signature = decoded

        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            findings.append(
                Finding(
                    title="JWT uses 'none' algorithm",
                    severity="critical",
                    category="jwt",
                    target=self.ctx.target.display,
                    description="The token declares the 'none' algorithm and may be unsigned.",
                    evidence=f"header: {header}",
                    remediation="Reject tokens with alg=none and enforce a strong algorithm.",
                    confidence="high",
                )
            )
        elif alg in ("hs256", "hs384", "hs512"):
            findings.append(
                Finding(
                    title="JWT uses a symmetric algorithm (HMAC)",
                    severity="info",
                    category="jwt",
                    target=self.ctx.target.display,
                    description="HMAC-signed tokens are safe only if the secret is strong and never leaked.",
                    evidence=f"header: {header}",
                    remediation="Use a long random secret; consider RS256/ES256 with key rotation.",
                    confidence="medium",
                )
            )

        if "exp" not in payload:
            findings.append(
                Finding(
                    title="JWT has no expiration claim",
                    severity="low",
                    category="jwt",
                    target=self.ctx.target.display,
                    description="The token does not expire, widening the impact of theft.",
                    evidence=f"payload: {payload}",
                    remediation="Add a short 'exp' claim.",
                    confidence="high",
                )
            )

        sensitive_keys = {"password", "passwd", "secret", "api_key", "apikey", "private_key"}
        exposed = sorted(set(payload) & sensitive_keys)
        if exposed:
            findings.append(
                Finding(
                    title="Sensitive data inside JWT payload",
                    severity="high",
                    category="jwt",
                    target=self.ctx.target.display,
                    description="JWT payloads are only Base64-encoded, never encrypted.",
                    evidence=f"exposed claims: {exposed}",
                    remediation="Never place secrets in a JWT payload.",
                    confidence="high",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _decode_jwt(token: str) -> Optional[Tuple[dict, dict, str]]:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]) or b"{}")
        payload = json.loads(_b64url_decode(parts[1]) or b"{}") if parts[1] else {}
    except (ValueError, TypeError):
        return None
    signature = parts[2] if len(parts) > 2 else ""
    return header, payload, signature
