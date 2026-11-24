import dns.resolver

from app.core.base import ReconModule
from app.core.registry import register

_ALL_MEANING = {
    "-": "hard fail",
    "~": "soft fail",
    "?": "neutral",
    "+": "pass, which allows any sender",
}


def txt_records(name: str) -> list[str]:
    """TXT strings at `name`, or [] if there are none. Other DNS errors propagate."""
    try:
        answer = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    # A TXT record can be split into several chunks; join them back together
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def parse_tags(record: str) -> dict[str, str]:
    """Parse 'v=DMARC1; p=reject; rua=mailto:x@y.com' into a dict of lowercase keys."""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def describe_spf(records: list[str]) -> tuple[str, str | None]:
    """Return (one-line description, evidence) for a domain's SPF records."""
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return "No SPF record found", None
    if len(spf) > 1:
        return f"{len(spf)} SPF records found (RFC 7208 allows only one)", " | ".join(spf)[:300]

    record = spf[0]
    tokens = record.lower().split()
    for token in reversed(tokens):
        if token.lstrip("+-~?") == "all":
            qualifier = token[0] if token[0] in "+-~?" else "+"
            return f"SPF ends with {token} ({_ALL_MEANING[qualifier]})", record[:300]

    redirect = next((t for t in tokens if t.startswith("redirect=")), None)
    if redirect:
        return f"SPF delegates to {redirect.split('=', 1)[1]} via redirect", record[:300]
    return "SPF record has no final all mechanism", record[:300]


def describe_dmarc(records: list[str]) -> tuple[list[str], str | None]:
    """Return (descriptions, evidence) for the DMARC record."""
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return ["No DMARC record found"], None
    if len(dmarc) > 1:
        return [f"{len(dmarc)} DMARC records found (only one is allowed)"], " | ".join(dmarc)[:300]

    tags = parse_tags(dmarc[0])
    texts = [f"DMARC policy is p={tags.get('p', 'missing')}"]
    if tags.get("sp"):
        texts.append(f"DMARC subdomain policy is sp={tags['sp']}")
    texts.append(
        "DMARC aggregate reports (rua) are configured"
        if "rua" in tags
        else "DMARC has no aggregate report address (rua)"
    )
    if tags.get("pct") not in (None, "100"):
        texts.append(f"DMARC applies to {tags['pct']}% of mail (pct)")
    return texts, dmarc[0][:300]


@register
class EmailSecurityModule(ReconModule):
    id = "email"
    name = "Email security"
    description = "SPF, DMARC, MTA-STS and TLS-RPT records"
    tier = "passive"
    source = "Public DNS (TXT records)"
    accepts = ("domain",)

    def collect(self, target):
        spf = [r for r in txt_records(target) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in txt_records(f"_dmarc.{target}") if r.lower().startswith("v=dmarc1")]
        mta_sts = [r for r in txt_records(f"_mta-sts.{target}") if r.lower().startswith("v=stsv1")]
        tls_rpt = [r for r in txt_records(f"_smtp._tls.{target}") if r.lower().startswith("v=tlsrptv1")]

        data = {
            "spf": spf,
            "dmarc": dmarc,
            "mta_sts": mta_sts,
            "tls_rpt": tls_rpt,
            "not_checked": ["DKIM (selector names cannot be discovered from DNS)"],
        }

        spf_text, spf_evidence = describe_spf(spf)
        dmarc_texts, dmarc_evidence = describe_dmarc(dmarc)

        observations = [self.observe(spf_text, "Email security", spf_evidence)]
        observations += [self.observe(t, "Email security", dmarc_evidence) for t in dmarc_texts]
        observations.append(self.observe(
            f"MTA-STS record present ({mta_sts[0][:80]})" if mta_sts else "No MTA-STS record found",
            "Email security",
        ))
        observations.append(self.observe(
            "TLS-RPT record present" if tls_rpt else "No TLS-RPT record found",
            "Email security",
        ))
        observations.append(self.observe(
            "DKIM was not checked: selector names cannot be discovered from DNS",
            "Email security",
        ))
        return data, observations