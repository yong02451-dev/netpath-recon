import geoip2.database
import geoip2.errors
import ipaddress

CITY_DB_PATH = "app/geoip/GeoLite2-city.mmdb"
ASN_DB_PATH = "app/geoip/GeoLite2-ASN.mmdb"

# Open these once, at module load time — not inside the function,
# since reopening the file on every hop lookup would be wasteful.
city_reader = geoip2.database.Reader(CITY_DB_PATH)
asn_reader = geoip2.database.Reader(ASN_DB_PATH)


def is_private_ip(ip: str) -> bool:
    """Return True if this is a private/local IP (no geo data will exist)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def enrich_ip(ip: str) -> dict:
    """
    Look up location + ASN for one IP using local GeoLite2 databases.

    Returns:
    {
        "ip": str,
        "city": str or None,
        "country": str or None,
        "asn": int or None,
        "asn_org": str or None,
        "note": str or None,
    }
    """
    result = {
        "ip": ip,
        "city": None,
        "country": None,
        "asn": None,
        "asn_org": None,
        "note": None,
    }

    if ip is None:
        result["note"] = "no IP (hop timed out)"
        return result

    if is_private_ip(ip):
        result["note"] = "private IP, no geo data"
        return result

    try:
        city_response = city_reader.city(ip)
        result["city"] = city_response.city.name
        result["country"] = city_response.country.name
    except geoip2.errors.AddressNotFoundError:
        result["note"] = "IP not found in city database"

    try:
        asn_response = asn_reader.asn(ip)
        result["asn"] = asn_response.autonomous_system_number
        result["asn_org"] = asn_response.autonomous_system_organization
    except geoip2.errors.AddressNotFoundError:
        if result["note"] is None:
            result["note"] = "IP not found in ASN database"

    return result


if __name__ == "__main__":
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", None]
    for ip in test_ips:
        print(enrich_ip(ip))