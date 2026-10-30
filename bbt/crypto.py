"""TLS certificate inspection using only the standard library."""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional


def _flatten_rdn(rdn) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for sequence in rdn or ():
        for key, value in sequence:
            if key in out:
                out[key] = f"{out[key]}, {value}"
            else:
                out[key] = value
    return out


def _days_remaining(not_after: Optional[str]) -> Optional[int]:
    if not not_after:
        return None
    try:
        expires = parsedate_to_datetime(not_after)
    except (TypeError, ValueError):
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return (expires - now).days


def _decode_certificate(der: bytes) -> Dict[str, object]:
    """Decode a DER certificate to a dict using CPython's private helper."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
        ssl_module = getattr(ssl, "_ssl", None)
        decoder = getattr(ssl_module, "_test_decode_cert", None)
        if decoder is None:
            return {}
        return dict(decoder(path))
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


#: TLS versions that are deprecated but sometimes still enabled.
_LEGACY_TLS = (
    ("TLSv1", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
)


def probe_legacy_tls(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """Return the legacy TLS versions the server still accepts."""
    supported: List[str] = []
    if not hasattr(ssl, "TLSVersion"):
        return supported
    for label, version_name in _LEGACY_TLS:
        version = getattr(ssl.TLSVersion, version_name, None)
        if version is None:
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            try:
                # OpenSSL 3 disables old protocols at the default security
                # level; lower it so the probe reflects the server, not the
                # client policy.
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported.append(label)
        except Exception:  # noqa: BLE001 - unsupported/failed handshake is normal
            continue
    return supported


def get_certificate_info(
    host: str, port: int = 443, timeout: float = 5.0
) -> Dict[str, object]:
    """Connect and return certificate + protocol details.

    The result always contains ``ok``; on failure ``error`` explains why.
    """
    info: Dict[str, object] = {"host": host, "port": port, "ok": False}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                info["protocol"] = tls_sock.version()
                cipher = tls_sock.cipher()
                info["cipher"] = cipher[0] if cipher else None
    except Exception as exc:  # noqa: BLE001 - report any TLS failure
        info["error"] = str(exc)
        return info

    if not der:
        info["error"] = "server did not present a certificate"
        return info

    info["legacy_protocols"] = probe_legacy_tls(host, port, timeout=timeout)

    decoded = _decode_certificate(der)
    if not decoded:
        info.update(
            {
                "ok": True,
                "decoded": False,
                "decode_error": "certificate decoder unavailable or failed",
                "protocol": info.get("protocol"),
                "cipher": info.get("cipher"),
            }
        )
        return info

    subject = _flatten_rdn(decoded.get("subject"))
    issuer = _flatten_rdn(decoded.get("issuer"))
    alt_names: List[str] = []
    for typ, value in decoded.get("subjectAltName", []) or []:
        alt_names.append(f"{typ}:{value}")

    info.update(
        {
            "ok": True,
            "decoded": True,
            "subject": subject,
            "issuer": issuer,
            "self_signed": bool(subject) and subject == issuer,
            "not_before": decoded.get("notBefore"),
            "not_after": decoded.get("notAfter"),
            "subject_alt_name": alt_names,
            "days_remaining": _days_remaining(decoded.get("notAfter")),
            "der_size": len(der),
        }
    )
    return info
