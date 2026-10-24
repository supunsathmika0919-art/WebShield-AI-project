"""Certificate and negotiated-protocol inspection for a DNS-pinned target."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from webshield.scanner import ScanTarget


def _format_name(name: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    return ", ".join(
        f"{key}={value}"
        for group in name
        for key, value in group
    )


def check_tls(target: ScanTarget) -> dict[str, Any]:
    """Validate a peer certificate with system trust roots and report TLS metadata."""
    raw_socket: socket.socket | None = None
    try:
        raw_socket = socket.socket(target.address_family, socket.SOCK_STREAM)
        raw_socket.settimeout(8)
        raw_socket.connect(target.sockaddr)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_socket, server_hostname=target.hostname) as tls:
            raw_socket = None
            certificate = tls.getpeercert()
            expires_at = certificate.get("notAfter")
            expires_in_days = None
            if expires_at:
                expires_epoch = ssl.cert_time_to_seconds(expires_at)
                expires_in_days = int(
                    (expires_epoch - datetime.now(timezone.utc).timestamp()) // 86400
                )
            return {
                "status": "Valid",
                "tls_version": tls.version(),
                "subject": _format_name(certificate.get("subject", ())),
                "issuer": _format_name(certificate.get("issuer", ())),
                "expires_at": expires_at,
                "expires_in_days": expires_in_days,
            }
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as error:
        return {
            "status": "Failed",
            "error_type": type(error).__name__,
            "error": str(error),
        }
    finally:
        if raw_socket is not None:
            raw_socket.close()
