import json
import time
from datetime import datetime, timezone

import requests

from app.core.base import ReconModule
from app.core.http_fetch import read_limited, safe_get
from app.core.registry import register

CATEGORY = "Registration"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600
RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}

_bootstrap = {"loaded_at": 0.0, "map": {}}


class RdapUnavailable(Exception):
    """RDAP could not answer; the module falls back to WHOIS."""


def _load_bootstrap() -> dict[str, str]:
    """Map of TLD -> RDAP server URL from IANA, cached for a day."""
    now = time.time()
    if _bootstrap["map"] and now - _bootstrap["loaded_at"] < BOOTSTRAP_TTL:
        return _bootstrap["map"]
    try:
        response, _ = safe_get(BOOTSTRAP_URL, timeout=10)
        try:
            payload = json.loads(read_limited(response))
        finally:
            response.close()
    except (ValueError, requests.exceptions.RequestException) as exc:
        raise RdapUnavailable(f"RDAP bootstrap list unavailable ({type(exc).__name__})")

    mapping = {}
    for tlds, urls in payload.get("services", []):
        if urls:
            for tld in tlds:
                mapping[tld.lower()] = urls[0]
    _bootstrap.update(loaded_at=now, map=mapping)
    return mapping


def rdap_lookup(domain: str) -> tuple[dict, str]:
    tld = domain.rsplit(".", 1)[-1].lower()
    base = _load_bootstrap().get(tld)
    if not base:
        raise RdapUnavailable(f"No RDAP server is listed for .{tld}")

    try:
        response, _ = safe_get(f"{base.rstrip('/')}/domain/{domain}", timeout=10, headers=RDAP_HEADERS)
        try:
            if response.status_code != 200:
                raise RdapUnavailable(f"RDAP server answered with status {response.status_code}")
            return json.loads(read_limited(response)), base
        finally:
            response.close()
    except (ValueError, requests.exceptions.RequestException) as exc:
        raise RdapUnavailable(f"RDAP query failed ({type(exc).__name__})")


def _vcard_value(entity, field):
    vcard = (entity or {}).get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if item and item[0] == field and len(item) >= 4 and isinstance(item[3], str):
            return item[3]
    return None


def _find_entity(entities, role):
    for entity in entities or []:
        if role in entity.get("roles", []):
            return entity
        found = _find_entity(entity.get("entities"), role)
        if found:
            return found
    return None


def _event(events, action):
    for event in events or []:
        if event.get("eventAction") == action and event.get("eventDate"):
            return event["eventDate"]
    return None


def parse_rdap(payload: dict) -> dict:
    registrar_entity = _find_entity(payload.get("entities"), "registrar")
    iana_id = None
    for public_id in (registrar_entity or {}).get("publicIds", []):
        if "iana" in public_id.get("type", "").lower():
            iana_id = public_id.get("identifier")

    abuse = _find_entity((registrar_entity or {}).get("entities"), "abuse")
    events = payload.get("events")
    nameservers = sorted(
        n["ldhName"].lower() for n in payload.get("nameservers", []) if n.get("ldhName")
    )
    return {
        "registrar": _vcard_value(registrar_entity, "fn"),
        "iana_id": iana_id,
        "abuse_email": _vcard_value(abuse, "email"),
        "registrant_published": _find_entity(payload.get("entities"), "registrant") is not None,
        "registered": _event(events, "registration"),
        "expires": _event(events, "expiration"),
        "last_changed": _event(events, "last changed"),
        "status": payload.get("status", []),
        "nameservers": nameservers,
        "dnssec_signed": (payload.get("secureDNS") or {}).get("delegationSigned"),
    }


def _to_dt(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

def legacy_whois(domain: str) -> dict:
    """Port-43 WHOIS lookup, used only when RDAP is unavailable."""
    result = {"registrar": None, "created": None, "expires": None, "error": None}
    try:
        import whois

        record = whois.whois(domain)

        def first(value):
            return value[0] if isinstance(value, list) and value else value

        created, expires = first(record.creation_date), first(record.expiration_date)
        result["registrar"] = record.registrar
        result["created"] = str(created) if created else None
        result["expires"] = str(expires) if expires else None
    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {type(exc).__name__}: {exc}"
    return result


@register
class WhoisModule(ReconModule):
    id = "whois"
    name = "WHOIS / RDAP"
    description = "Registrar, dates, status flags and nameservers from the registry"
    tier = "passive"
    source = "RDAP registry data (WHOIS as fallback)"
    accepts = ("domain",)

    def _date_observations(self, registered, expires, changed):
        now = datetime.now(timezone.utc)
        observations = []
        if registered:
            observations.append(self.observe(
                f"Domain registered {registered.date()} ({(now - registered).days} days ago)", CATEGORY))
        if expires:
            left = (expires - now).days
            observations.append(self.observe(
                f"Registration expires {expires.date()} ({left} days left)" if left >= 0
                else f"Registration expired {expires.date()} ({-left} days ago)", CATEGORY))
        if changed:
            observations.append(self.observe(f"Record last changed {changed.date()}", CATEGORY))
        return observations

    def _rdap_observations(self, info, base):
        observations = []
        if info["registrar"]:
            suffix = f" (IANA ID {info['iana_id']})" if info["iana_id"] else ""
            observations.append(self.observe(f"Registrar: {info['registrar']}{suffix}", CATEGORY, base))
        observations += self._date_observations(
            _to_dt(info["registered"]), _to_dt(info["expires"]), _to_dt(info["last_changed"]))
        if info["status"]:
            observations.append(self.observe("Status flags: " + ", ".join(info["status"]), CATEGORY))
        if info["nameservers"]:
            observations.append(self.observe(
                f"{len(info['nameservers'])} nameserver(s) registered", CATEGORY,
                ", ".join(info["nameservers"])))
        if info["dnssec_signed"] is not None:
            observations.append(self.observe(
                "Registry reports the delegation is DNSSEC-signed" if info["dnssec_signed"]
                else "Registry reports the delegation is not DNSSEC-signed", CATEGORY))
        if not info["registrant_published"]:
            observations.append(self.observe("No registrant contact is published", CATEGORY))
        if info["abuse_email"]:
            observations.append(self.observe("Registrar abuse contact is published", CATEGORY, info["abuse_email"]))
        return observations

    def _from_legacy(self, target, reason):
        info = legacy_whois(target)
        if info["error"]:
            raise RuntimeError(f"{reason}; WHOIS also failed: {info['error']}")

        data = {
            "source": "whois",
            "rdap_unavailable_reason": reason,
            "registrar": info["registrar"],
            "created": info["created"],
            "expires": info["expires"],
        }
        observations = [self.observe(f"RDAP was not used ({reason}); WHOIS data is shown instead", CATEGORY)]
        if info["registrar"]:
            observations.append(self.observe(f"Registrar: {info['registrar']}", CATEGORY))
        observations += self._date_observations(_to_dt(info["created"]), _to_dt(info["expires"]), None)
        return data, observations

    def collect(self, target):
        try:
            payload, base = rdap_lookup(target)
        except RdapUnavailable as exc:
            return self._from_legacy(target, str(exc))

        info = parse_rdap(payload)
        return {"source": "rdap", "rdap_server": base, **info}, self._rdap_observations(info, base)