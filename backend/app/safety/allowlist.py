"""Host-allowlist guard.

This is the single most important safety control in Sentinel: the agent can
only ever send traffic to a host the operator has explicitly authorized. Every
outbound request in the execution engine must pass through `assert_allowed`
first. There is intentionally no bypass flag in the request API — the allowlist
is configured out-of-band via the ALLOWED_HOSTS environment variable.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from ..config import get_settings


class TargetNotAllowed(Exception):
    """Raised when a target host is not on the operator's allowlist."""


def _host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if not host:
        raise TargetNotAllowed(f"Could not parse a host from {url!r}.")
    return host.lower()


def _is_private(host: str) -> bool:
    """True if the host resolves only to private / loopback / link-local IPs."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable — treat as private so we fail closed.
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_global:
            return False
    return True


def assert_allowed(url: str) -> str:
    """Validate a target URL against the allowlist. Returns the normalized host.

    Fails closed: anything not explicitly permitted raises TargetNotAllowed.
    """
    settings = get_settings()
    host = _host_of(url)

    if host not in {h.lower() for h in settings.allowed_hosts}:
        raise TargetNotAllowed(
            f"Host {host!r} is not on the allowlist. "
            f"Authorized hosts: {settings.allowed_hosts or '[none configured]'}. "
            "Add it to ALLOWED_HOSTS only if you are authorized to test it."
        )

    if _is_private(host) and not settings.allow_private_targets:
        raise TargetNotAllowed(
            f"Host {host!r} resolves to a private/loopback address and "
            "ALLOW_PRIVATE_TARGETS is disabled."
        )

    return host


def is_allowed(url: str) -> bool:
    try:
        assert_allowed(url)
        return True
    except TargetNotAllowed:
        return False
