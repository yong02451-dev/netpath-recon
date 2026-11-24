from urllib.parse import urljoin, urlparse

import requests

from app.core.dns_resolver import resolve_dns
from app.core.validation import ensure_public_destination

USER_AGENT = "recon-console/1.0"
MAX_REDIRECTS = 5


def safe_get(url: str, timeout: float = 10, max_redirects: int = MAX_REDIRECTS, headers: dict | None = None):
    """
    GET `url`, following redirects by hand so every hop can be checked.
    Returns (final_response, chain), where chain is a list of (url, status).
    The body is not downloaded yet; use read_limited() and close the response.
    Raises ValueError for a blocked, malformed, or endless redirect.
    """
    chain = []
    current = url
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Redirect to an unsupported URL: {current[:100]}")

        dns_result = resolve_dns(parsed.hostname)
        if dns_result["error"]:
            raise ValueError(f"Redirect target does not resolve: {parsed.hostname}")
        ensure_public_destination(dns_result["all_ips"])

        response = requests.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": USER_AGENT, **(headers or {})},
        )
        chain.append((current, response.status_code))

        location = response.headers.get("Location")
        if response.is_redirect and location:
            response.close()
            current = urljoin(current, location)
            continue
        return response, chain

    raise ValueError(f"Too many redirects (more than {max_redirects})")


def read_limited(response, limit: int = 1_000_000) -> bytes:
    """Read a response body, refusing anything larger than `limit` bytes."""
    body = b""
    for chunk in response.iter_content(chunk_size=16384):
        body += chunk
        if len(body) > limit:
            raise ValueError("Response is larger than the allowed size")
    return body