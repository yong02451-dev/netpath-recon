from app.core.dns_resolver import resolve_dns
import ipaddress
import os
import re

MAX_HOSTNAME_LENGTH = 253

# A DNS label: 1-63 chars of a-z, 0-9, hyphen; no leading or trailing hyphen.
_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")

# Off by default. Set ALLOW_PRIVATE_TARGETS=true to trace your own LAN hosts.
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"


def normalize_target(raw: str) -> str:
    """
    Turn user input into a clean hostname or IPv4 address, or raise ValueError.

    Accepts:  example.com, https://example.com/path?x=1, 8.8.8.8
    Rejects:  flags (-h), spaces, shell characters, credentials, ports,
              single-label names (localhost), IPv6 (the trace uses tracert -4).
    """
    if not isinstance(raw, str):
        raise ValueError("Target must be text")

    value = raw.strip()
    if not value or len(value) > 2048:
        raise ValueError("Target is empty or too long")

    # Strip an http(s) scheme; reject any other scheme
    scheme, sep, rest = value.partition("://")
    if sep:
        if scheme.lower() not in ("http", "https"):
            raise ValueError("Only http/https URLs are accepted")
        value = rest

    # Keep only the host part: drop path, query, fragment
    value = re.split(r"[/?#]", value, maxsplit=1)[0]

    if "@" in value:
        raise ValueError("Credentials in the target are not allowed")

    # Literal IP address?
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported right now")
        return str(ip)

    # Otherwise it must be a well-formed hostname
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid characters in hostname")

    if len(host) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname is too long")
    if "." not in host:
        raise ValueError("Enter a full domain name like example.com")

    labels = host.split(".")
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Not a valid hostname or IP address")

    # Real TLDs are never all digits. This also blocks tricks like "127.1",
    # which some network stacks silently expand to 127.0.0.1.
    if labels[-1].isdigit():
        raise ValueError("Not a valid hostname or IP address")

    return host


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def ensure_public_destination(ips: list[str]) -> None:
    """
    Raise ValueError if ANY resolved address is private, loopback,
    link-local, carrier-grade NAT, or otherwise non-public.
    Check the RESOLVED addresses, not just the typed name: an attacker can
    register a normal-looking domain that points at 127.0.0.1.
    """
    if ALLOW_PRIVATE_TARGETS:
        return
    for ip in ips:
        if not is_public_ip(ip):
            raise ValueError(f"Target resolves to a non-public address ({ip}); blocked")
        
def prepare_target(raw: str) -> str:
    """Normalize, make sure it resolves, and make sure it is public. Raises ValueError."""
    host = normalize_target(raw)
    dns_result = resolve_dns(host)
    if dns_result["error"]:
        raise ValueError(dns_result["error"])
    ensure_public_destination(dns_result["all_ips"])
    return host

def parse_run_request(request) -> tuple[str, list[str] | None, bool]:
    """Validate the JSON a client sends over a WebSocket. Raises ValueError."""
    if not isinstance(request, dict) or not isinstance(request.get("target"), str):
        raise ValueError(
            'Send JSON like {"target": "example.com", "modules": ["dns"], "active": false}'
        )
    modules = request.get("modules")
    if modules is not None and not (
        isinstance(modules, list) and all(isinstance(m, str) for m in modules)
    ):
        raise ValueError("modules must be a list of module ids")
    # Active checks only turn on for a literal true, never a truthy value like "yes"
    return request["target"], modules, request.get("active") is True