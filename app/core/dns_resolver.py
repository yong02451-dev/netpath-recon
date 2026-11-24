import dns.resolver
import ipaddress

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
    
def resolve_dns(domain: str) -> dict:
    
    result = {
        "query": domain,
        "resolved_ip": None,
        "ttl": None,
        "resolver": None,
        "all_ips": [],
        "error": None,
    }
    
    if is_ip(domain):
        result["resolved_ip"] = domain
        result["all_ips"] = [domain]
        return result
    try: 
        answer = dns.resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        result["error"] = f"Domain does not exist: {domain}"
        return result
    except dns.resolver.NoAnswer:
        result["error"] = f"No A record found for: {domain}"
        return result
    except dns.resolver.Timewout:
        result["error"] = f"DNS resolution timed out for: {domain}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected DNS error: {e}"
        return result
    
    all_ips = [str(ip) for ip in answer]
    result["all_ips"] = all_ips
    result["resolved_ip"] = all_ips[0]
    result["ttl"] = answer.rrset.ttl
    result["resolver"] = ", ".join(dns.resolver.default_resolver.nameservers)
    
    return result

if __name__=="__main__":
    test_targets = [
        "google.com",
        "youtube.com",
        "claude.ai",
    ]
    for target in test_targets:
        print(resolve_dns(target))