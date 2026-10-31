"""Minimal OpenAPI / Swagger discovery and parsing.

The API module uses this to list documented endpoints; the authz module uses
the same parsed paths to build BOLA/IDOR candidates. Only JSON specs are
parsed, and only same-origin documents are requested.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from .context import ScanContext

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-json",
)

_METHODS = ("get", "post", "put", "patch", "delete", "head")
_PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def _resolve_ref(ref: str, spec: Dict[str, object]) -> Dict[str, object]:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: object = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part)
    return node if isinstance(node, dict) else {}


def fetch_spec(ctx: ScanContext, base_url: str) -> Optional[Dict[str, object]]:
    """Fetch and cache the first JSON API spec found on the target."""
    cached = ctx.recall("openapi_spec")
    if cached is not None:
        return cached or None

    root = base_url.rstrip("/") + "/"
    for path in SPEC_PATHS:
        url = urljoin(root, path.lstrip("/"))
        resp = ctx.http.get(url, timeout=min(ctx.config.timeout, 10.0))
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        if not ("paths" in data or "openapi" in data or "swagger" in data):
            continue
        ctx.remember("openapi_spec", data)
        ctx.remember("openapi_url", url)
        if hasattr(ctx, "write_json"):
            ctx.write_json("api_spec.json", data, key="api_spec")
        return data

    ctx.remember("openapi_spec", {})
    return None


def endpoints(spec: Dict[str, object]) -> List[Dict[str, object]]:
    """Return method + path + parameters for every documented operation."""
    out: List[Dict[str, object]] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return out

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method in _METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            params: List[Dict[str, object]] = []
            raw_params = list(operation.get("parameters") or []) + list(shared)
            for param in raw_params:
                if not isinstance(param, dict):
                    continue
                if "$ref" in param:
                    param = _resolve_ref(str(param.get("$ref")), spec)
                location = param.get("in")
                name = param.get("name")
                if location in ("path", "query") and name:
                    params.append(
                        {
                            "name": name,
                            "in": location,
                            "required": bool(param.get("required")),
                        }
                    )
            # Some specs put path params only in the path template.
            known = {str(p["name"]) for p in params}
            for name in _PATH_PARAM_RE.findall(path):
                if name not in known:
                    params.append({"name": name, "in": "path", "required": True})
            out.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "params": params,
                    "security": operation.get("security", spec.get("security")),
                }
            )
    return out


def path_parameters(path: str) -> List[str]:
    return _PATH_PARAM_RE.findall(path or "")
