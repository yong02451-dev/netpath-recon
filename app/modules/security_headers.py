import requests

from app.core.base import ReconModule
from app.core.http_fetch import USER_AGENT, safe_get
from app.core.registry import register

CATEGORY = "Web security"

_SIMPLE_HEADERS = [
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
]
_DISCLOSURE_HEADERS = [
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "X-AspNet-Version"),
    ("x-generator", "X-Generator"),
]
_HSTS_NAMES = {"includesubdomains": "includeSubDomains", "preload": "preload"}


def parse_hsts(value: str) -> str:
    parts = []
    for directive in (d.strip() for d in value.split(";") if d.strip()):
        key, _, val = directive.partition("=")
        key = key.strip().lower()
        if key == "max-age" and val.strip().isdigit():
            seconds = int(val.strip())
            parts.append(f"max-age={seconds} ({seconds // 86400} days)")
        elif key in _HSTS_NAMES:
            parts.append(_HSTS_NAMES[key])
    return ", ".join(parts) or value[:100]


def summarize_csp(value: str) -> list[str]:
    directives = [d.strip() for d in value.split(";") if d.strip()]
    names = [d.split()[0].lower() for d in directives]
    notes = [f"{len(directives)} directives"]
    script_src = next((d.lower() for d in directives if d.lower().startswith("script-src")), "")
    for keyword in ("'unsafe-inline'", "'unsafe-eval'"):
        if keyword in script_src:
            notes.append(f"script-src contains {keyword}")
    if "frame-ancestors" in names:
        notes.append("frame-ancestors is set")
    return notes


def parse_cookie(header: str) -> dict:
    """Keep only the cookie's name and flags. The value is never stored."""
    first, *attributes = [p.strip() for p in header.split(";")]
    cookie = {"name": first.split("=", 1)[0].strip(), "secure": False, "httponly": False, "samesite": None}
    for attribute in attributes:
        key, _, value = attribute.partition("=")
        key = key.strip().lower()
        if key == "secure":
            cookie["secure"] = True
        elif key == "httponly":
            cookie["httponly"] = True
        elif key == "samesite":
            cookie["samesite"] = value.strip() or None
    return cookie


@register
class SecurityHeadersModule(ReconModule):
    id = "headers"
    name = "Security headers"
    description = "HSTS, CSP, cookie flags, referrer and cross-origin policies, redirects"
    tier = "active"   # it sends requests straight to the target
    source = "Target HTTPS response"
    accepts = ("domain",)

    def _http_redirect(self, target: str) -> str:
        """One plain request to port 80. Redirects are reported, never followed."""
        try:
            response = requests.get(
                f"http://{target}", timeout=8, allow_redirects=False,
                stream=True, headers={"User-Agent": USER_AGENT},
            )
        except requests.exceptions.RequestException as exc:
            return f"Port 80 was not reachable ({type(exc).__name__})"
        try:
            status = response.status_code
            location = response.headers.get("Location", "")
        finally:
            response.close()

        if 300 <= status < 400 and location:
            if location.lower().startswith("https://"):
                return f"HTTP on port 80 redirects to HTTPS (status {status})"
            return f"HTTP on port 80 redirects to {location[:100]} (status {status})"
        return f"HTTP on port 80 answered with status {status} and no redirect to HTTPS"

    def _analyze(self, h, cookies, chain, redirect_text):
        observations = []

        def add(text, evidence=None):
            observations.append(self.observe(text, CATEGORY, evidence))

        if len(chain) > 1:
            add(f"HTTPS request followed {len(chain) - 1} redirect(s)",
                " -> ".join(url[:80] for url, _ in chain)[:300])

        hsts = h.get("strict-transport-security")
        add(f"Strict-Transport-Security: {parse_hsts(hsts)}" if hsts
            else "Strict-Transport-Security header not observed", hsts[:200] if hsts else None)

        csp = h.get("content-security-policy")
        report_only = h.get("content-security-policy-report-only")
        if csp:
            add("Content-Security-Policy present: " + "; ".join(summarize_csp(csp)), csp[:300])
        else:
            add("Content-Security-Policy header not observed"
                + (" (a Report-Only policy is present)" if report_only else ""))
        if csp and report_only:
            add("Content-Security-Policy-Report-Only is also present", report_only[:300])

        for key, label in _SIMPLE_HEADERS:
            value = h.get(key)
            add(f"{label}: {value[:100]}" if value else f"{label} header not observed")

        permissions = h.get("permissions-policy")
        add(f"Permissions-Policy present ({permissions.count(',') + 1} entries)" if permissions
            else "Permissions-Policy header not observed", permissions[:200] if permissions else None)

        cors = h.get("access-control-allow-origin")
        if cors:
            add(f"Access-Control-Allow-Origin: {cors[:100]}")

        for key, label in _DISCLOSURE_HEADERS:
            value = h.get(key)
            if value:
                add(f"{label} header reports: {value[:100]}")

        for cookie in cookies[:10]:
            add(
                f"Cookie {cookie['name']}: Secure={'yes' if cookie['secure'] else 'no'}, "
                f"HttpOnly={'yes' if cookie['httponly'] else 'no'}, "
                f"SameSite={cookie['samesite'] or 'not set'}"
            )
        if len(cookies) > 10:
            add(f"{len(cookies) - 10} more cookies were set and are not listed")

        add(redirect_text)
        return observations

    def collect(self, target):
        response, chain = safe_get(f"https://{target}")
        try:
            status = response.status_code
            headers = dict(response.headers)
            cookies = [parse_cookie(c) for c in response.raw.headers.getlist("Set-Cookie")]
        finally:
            response.close()

        lowered = {k.lower(): v for k, v in headers.items()}
        redirect_text = self._http_redirect(target)

        data = {
            "final_url": chain[-1][0],
            "status": status,
            "chain": [{"url": url, "status": code} for url, code in chain],
            # Set-Cookie is left out here on purpose: its values can be session tokens
            "headers": {k: v[:500] for k, v in headers.items() if k.lower() != "set-cookie"},
            "cookies": cookies,
            "http_redirect": redirect_text,
        }
        return data, self._analyze(lowered, cookies, chain, redirect_text)