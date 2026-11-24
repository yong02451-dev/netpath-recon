import ipaddress
import json
import re
from collections import Counter
from urllib.parse import quote

import requests

from app.core.base import ReconModule
from app.core.http_fetch import read_limited, safe_get
from app.core.registry import register

_HOSTNAME_RE = re.compile(r"(\*\.)?[a-z0-9.-]+")
TIMEOUT = 30
RETRIES = 2
MAX_BYTES = 25_000_000   # crt.sh answers for big domains are several MB


def split_names(names: list[str], domain: str) -> tuple[list[str], list[str]]:
    """
    Separate names that really belong to `domain` from log noise: email
    addresses, other domains, and crafted entries like the phreedom.org
    certificate that imitates a google.com name.
    """
    domain = domain.lower()
    related, other = [], []
    for raw in names:
        name = raw.strip().lower()
        belongs = name == domain or name.endswith("." + domain)
        if belongs and _HOSTNAME_RE.fullmatch(name):
            related.append(name)
        else:
            other.append(name[:120])
    return related, other


def fetch_ct_records(domain: str) -> list[dict]:
    """Query crt.sh, retrying when it is slow. Other failures propagate."""
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    problem = "timed out"
    for _ in range(RETRIES + 1):
        try:
            response, _chain = safe_get(url, timeout=TIMEOUT)
            try:
                if response.status_code != 200:
                    raise RuntimeError(f"crt.sh answered with status {response.status_code}")
                return json.loads(read_limited(response, MAX_BYTES))
            finally:
                response.close()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            problem = "timed out or dropped the connection"
    raise RuntimeError(f"crt.sh {problem} after {RETRIES + 1} attempts")


@register
class CertTransparencyModule(ReconModule):
    id = "certs"
    name = "Certificate Transparency"
    description = "Certificates and names recorded in public CT logs"
    tier = "passive"
    source = "crt.sh (Certificate Transparency logs)"
    accepts = ("domain",)

    def collect(self, target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            raise ValueError("Certificate Transparency needs a domain name, not an IP address")

        records = fetch_ct_records(target)

        names = set()
        for record in records:
            for name in record.get("name_value", "").split("\n"):
                if name.strip():
                    names.add(name.strip())
        related, other = split_names(sorted(names), target)
        wildcards = [n for n in related if n.startswith("*.")]

        issuers = Counter(r.get("issuer_name") or "unknown" for r in records)
        starts = sorted(r["not_before"] for r in records if r.get("not_before"))

        data = {
            "cert_count": len(records),
            "names": related,
            "unrelated_names": other,
            "issuers": dict(issuers.most_common(10)),
        }

        observations = [
            self.observe(f"{len(records):,} certificates logged for this name", "Certificates"),
            self.observe(
                f"{len(related)} unique names belong to this domain ({len(wildcards)} wildcards)",
                "Certificates",
            ),
        ]
        if issuers:
            observations.append(self.observe(
                f"{len(issuers)} issuing CA name(s) seen",
                "Certificates",
                "; ".join(f"{name[:60]} ({count})" for name, count in issuers.most_common(5)),
            ))
        if starts:
            observations.append(self.observe(
                f"Certificates logged with start dates from {starts[0][:10]} to {starts[-1][:10]}",
                "Certificates",
            ))
        if other:
            observations.append(self.observe(
                f"{len(other)} log entries do not belong to this domain and were set aside",
                "Certificates",
                "; ".join(other[:3])[:300],
            ))
        return data, observations