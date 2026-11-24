import dns.exception
import dns.resolver

from app.core.base import ReconModule
from app.core.registry import register

# TXT record prefixes that show which third-party services a domain has verified
_VERIFICATION_PREFIXES = {
    "google-site-verification": "Google",
    "facebook-domain-verification": "Facebook",
    "apple-domain-verification": "Apple",
    "docusign": "DocuSign",
    "onetrust-domain-verification": "OneTrust",
    "cisco-ci-domain-verification": "Cisco",
    "atlassian-domain-verification": "Atlassian",
    "ms": "Microsoft",
}


def lookup(name: str, rtype: str) -> list[str]:
    """Answers for one record type; [] when the name simply has none."""
    try:
        answer = dns.resolver.resolve(name, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    if rtype == "TXT":
        # A TXT record can be split into chunks; join them back together
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]
    return [r.to_text() for r in answer]


def group_caa(records: list[str]) -> dict[str, list[str]]:
    """Turn '0 issue "letsencrypt.org"' lines into {'issue': ['letsencrypt.org']}."""
    grouped = {}
    for record in records:
        parts = record.split(None, 2)
        if len(parts) == 3:
            grouped.setdefault(parts[1].lower(), []).append(parts[2].strip('"'))
    return grouped


@register
class DnsRecordsModule(ReconModule):
    id = "dns"
    name = "DNS records"
    description = "A, AAAA, CNAME, MX, TXT, NS, SOA, CAA and DNSSEC records"
    tier = "passive"
    source = "Public DNS"
    accepts = ("domain",)

    def _observe_all(self, target, zone, records, caa_name, dnssec, errors):
        observations = []

        def add(text, evidence=None):
            observations.append(self.observe(text, "DNS", evidence))

        if records["a"]:
            add(f"{len(records['a'])} A record(s) resolve this name", ", ".join(records["a"]))
        else:
            add("No A record found")
        add(f"{len(records['aaaa'])} AAAA record(s) (IPv6)" if records["aaaa"]
            else "No AAAA record found (no IPv6 address published)",
            ", ".join(records["aaaa"]) or None)
        if records["cname"]:
            add(f"Name is an alias (CNAME) for {records['cname'][0].rstrip('.')}")

        if records["ns"]:
            add(f"{len(records['ns'])} nameserver(s) for zone {zone}",
                ", ".join(n.rstrip(".") for n in records["ns"]))

        soa = records["soa"][0].split() if records["soa"] else []
        if len(soa) >= 7:
            add(f"SOA primary nameserver is {soa[0].rstrip('.')}, serial {soa[2]}",
                f"admin mailbox {soa[1].rstrip('.')}; refresh {soa[3]}s, retry {soa[4]}s, "
                f"expire {soa[5]}s, minimum TTL {soa[6]}s")

        if records["mx"]:
            add("Mail is handled by: " + ", ".join(records["mx"]))
        else:
            add("No MX record found")

        services = sorted({
            label
            for txt in records["txt"]
            for prefix, label in _VERIFICATION_PREFIXES.items()
            if txt.lower().startswith(prefix + "=")
        })
        if services:
            add("TXT records show domain verification for: " + ", ".join(services),
                f"{len(records['txt'])} TXT records")

        caa = group_caa(records["caa"])
        if caa:
            parts = [f"{tag}: {', '.join(values)}" for tag, values in sorted(caa.items())]
            add(f"CAA at {caa_name} restricts certificate issuance ({'; '.join(parts)})")
        else:
            add("No CAA record found (no CA restriction is published)")

        if dnssec["ds"] and dnssec["dnskey"]:
            add(f"DNSSEC: DS and DNSKEY records are published for {zone} "
                "(this tool does not validate the chain)")
        elif dnssec["dnskey"]:
            add(f"DNSKEY is published for {zone} but no DS record was found")
        elif dnssec["ds"]:
            add(f"A DS record exists for {zone} but no DNSKEY was returned")
        else:
            add(f"No DNSSEC records found for {zone}")

        if errors:
            add("Some lookups failed and are missing above", "; ".join(f"{k}: {v}" for k, v in errors.items()))
        return observations

    def collect(self, target):
        # A subdomain has no NS/SOA of its own, so find the zone it belongs to
        zone = str(dns.resolver.zone_for_name(target)).rstrip(".")
        errors = {}

        def get(name, rtype):
            try:
                return lookup(name, rtype)
            except dns.exception.DNSException as exc:
                errors[f"{rtype} {name}"] = type(exc).__name__
                return []

        records = {rtype.lower(): get(target, rtype) for rtype in ("A", "AAAA", "CNAME", "MX", "TXT")}
        records["ns"] = get(zone, "NS")
        records["soa"] = get(zone, "SOA")

        caa_name = target
        records["caa"] = get(target, "CAA")
        if not records["caa"] and zone != target:
            caa_name = zone
            records["caa"] = get(zone, "CAA")

        dnssec = {"ds": bool(get(zone, "DS")), "dnskey": bool(get(zone, "DNSKEY"))}

        if errors and not any(records.values()):
            raise RuntimeError("DNS lookups failed: " + "; ".join(f"{k}: {v}" for k, v in errors.items()))

        data = {"zone": zone, "caa_found_at": caa_name, "dnssec": dnssec, **records}
        if errors:
            data["errors"] = errors
        return data, self._observe_all(target, zone, records, caa_name, dnssec, errors)