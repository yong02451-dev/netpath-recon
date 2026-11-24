import dns.exception
import dns.query
import dns.resolver

from app.core.base import ReconModule
from app.core.registry import register
from app.core.validation import ensure_public_destination

MAX_NAMESERVERS = 6
MAX_RECORDS = 5000      # stop reading a huge zone instead of filling memory
SAMPLE_SIZE = 25        # names kept as a sample in the result
TRANSFER_TIMEOUT = 10   # seconds per nameserver


def nameserver_ips(zone: str) -> list[tuple[str, str]]:
    """(nameserver name, IPv4 address) pairs for a zone."""
    pairs = []
    for ns in dns.resolver.resolve(zone, "NS"):
        ns_name = str(ns.target).rstrip(".")
        try:
            for a in dns.resolver.resolve(ns_name, "A"):
                pairs.append((ns_name, a.address))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
    return pairs[:MAX_NAMESERVERS]


def attempt_transfer(ip: str, zone: str) -> dict:
    """Ask one nameserver for a full zone transfer (AXFR) and classify the answer."""
    names = set()
    records = 0
    truncated = False
    try:
        for message in dns.query.xfr(ip, zone, lifetime=TRANSFER_TIMEOUT):
            for rrset in message.answer:
                names.add(rrset.name.to_text())
                records += len(rrset)
            if records > MAX_RECORDS:
                truncated = True
                break
    except dns.query.TransferError as exc:
        return {"result": "refused", "detail": str(exc)}
    except (dns.exception.Timeout, TimeoutError):
        return {"result": "timeout", "detail": f"No answer within {TRANSFER_TIMEOUT}s"}
    except (OSError, EOFError, dns.exception.DNSException) as exc:
        return {"result": "error", "detail": f"{type(exc).__name__}: {exc}"}

    if records == 0:
        return {"result": "error", "detail": "Empty response"}
    return {
        "result": "allowed",
        "records": records,
        "name_count": len(names),
        "names": sorted(names)[:SAMPLE_SIZE],
        "truncated": truncated,
    }


@register
class ZoneTransferModule(ReconModule):
    id = "zonexfr"
    name = "Zone transfer test"
    description = "Asks each nameserver for a full copy of the DNS zone (AXFR)"
    tier = "active"   # it sends a request straight to the target's nameservers
    source = "Target nameservers"
    accepts = ("domain",)

    def _describe(self, ns_name, ip, outcome):
        result = outcome["result"]
        if result == "refused":
            return self.observe(f"{ns_name} refused the zone transfer", "DNS", ip)
        if result == "allowed":
            text = (f"{ns_name} allowed a zone transfer: {outcome['records']} records "
                    f"across {outcome['name_count']} names")
            if outcome["truncated"]:
                text += " (stopped at the read limit)"
            return self.observe(text, "DNS", ", ".join(outcome["names"][:10]))
        return self.observe(f"{ns_name} could not be tested ({outcome['detail']})", "DNS", ip)

    def collect(self, target):
        # A subdomain has no nameservers of its own, so find the zone it belongs to
        zone = str(dns.resolver.zone_for_name(target)).rstrip(".")
        pairs = nameserver_ips(zone)
        if not pairs:
            raise RuntimeError(f"No nameservers found for {zone}")

        results, per_server = [], []
        for ns_name, ip in pairs:
            try:
                # Same SSRF guard as everywhere else: never connect to private addresses
                ensure_public_destination([ip])
            except ValueError:
                results.append({"nameserver": ns_name, "ip": ip, "result": "skipped",
                                "detail": "Non-public address"})
                per_server.append(self.observe(
                    f"{ns_name} was not tested: it resolves to a non-public address", "DNS", ip))
                continue

            outcome = attempt_transfer(ip, zone)
            results.append({"nameserver": ns_name, "ip": ip, **outcome})
            per_server.append(self._describe(ns_name, ip, outcome))

        allowed = [r for r in results if r["result"] == "allowed"]
        summary = (
            f"{len(allowed)} of {len(results)} nameservers allowed a zone transfer"
            if allowed else "No tested nameserver allowed a zone transfer"
        )
        observations = [self.observe(summary, "DNS", f"Zone: {zone}")] + per_server
        return {"zone": zone, "results": results}, observations