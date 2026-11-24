import socket
import ssl
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
except ImportError:  # optional dependency: report it instead of breaking the whole app
    x509 = None

from app.core.base import ReconModule
from app.core.dns_resolver import resolve_dns
from app.core.registry import register
from app.core.validation import ensure_public_destination

PORT = 443
TIMEOUT = 8
_VERSIONS = {"TLSv1.3": ssl.TLSVersion.TLSv1_3, "TLSv1.2": ssl.TLSVersion.TLSv1_2}


def _handshake(ip, hostname, context):
    sock = socket.create_connection((ip, PORT), timeout=TIMEOUT)
    try:
        return context.wrap_socket(sock, server_hostname=hostname)
    except Exception:
        sock.close()
        raise


def _no_verify_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def fetch_certificate(ip, hostname):
    """Certificate (DER bytes), negotiated version and cipher, ignoring validity."""
    tls = _handshake(ip, hostname, _no_verify_context())
    try:
        return tls.getpeercert(binary_form=True), tls.version(), (tls.cipher() or (None,))[0]
    finally:
        tls.close()


def check_verification(ip, hostname) -> dict:
    """Does the certificate validate against this machine's trust store?"""
    try:
        _handshake(ip, hostname, ssl.create_default_context()).close()
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message}
    except (ssl.SSLError, OSError) as exc:
        return {"valid": None, "error": f"{type(exc).__name__}: {exc}"}
    return {"valid": True, "error": None}


def supports(ip, hostname, version):
    """True / False / None (unknown) for whether the server accepts one TLS version."""
    context = _no_verify_context()
    context.minimum_version = version
    context.maximum_version = version
    try:
        _handshake(ip, hostname, context).close()
    except ssl.SSLError:
        return False
    except OSError:
        return None
    return True


def _attr(name, oid):
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def describe_key(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size} bits"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(public_key).__name__


def parse_certificate(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    try:
        scts = len(cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value)
    except x509.ExtensionNotFound:
        scts = 0

    ocsp = []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp = [a.access_location.value for a in aia if a.access_method == AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        pass

    try:
        signature_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    except Exception:
        signature_hash = "n/a"

    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": _attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "age_days": (now - not_before).days,
        "san": san[:100],
        "san_count": len(san),
        "key": describe_key(cert.public_key()),
        "signature_hash": signature_hash,
        "self_signed": cert.subject == cert.issuer,
        "embedded_scts": scts,
        "ocsp": ocsp,
    }


@register
class TlsDetailModule(ReconModule):
    id = "tls"
    name = "TLS and certificate detail"
    description = "Live certificate fields, key, signature, validity and protocol support"
    tier = "active"   # it makes several TLS handshakes with the target
    source = "Target TLS handshake"
    accepts = ("domain",)

    def _observe_all(self, version, cipher, cert, verification, protocols):
        observations = []

        def add(text, category="Certificates", evidence=None):
            observations.append(self.observe(text, category, evidence))

        add(f"Negotiated {version} with {cipher}", "TLS")
        for name, result in protocols.items():
            state = {True: "accepts", False: "does not accept", None: "could not be tested for"}[result]
            add(f"Server {state} {name}", "TLS")
        add("TLS 1.0 and 1.1 were not tested (most current OpenSSL builds refuse them client-side)", "TLS")

        if verification["valid"] is True:
            add("Certificate validates against this machine's trust store")
        elif verification["valid"] is False:
            add(f"Certificate failed validation: {verification['error']}")
        else:
            add("Certificate validation could not be completed", evidence=verification["error"])

        days = cert["days_left"]
        end = cert["not_after"][:10]
        add(f"Certificate expires {end} ({days} days left)" if days >= 0
            else f"Certificate expired {end} ({-days} days ago)")
        add(f"Certificate issued {cert['not_before'][:10]} ({cert['age_days']} days ago)")
        add(f"Issued by {cert['issuer_org'] or cert['issuer_cn'] or cert['issuer']}",
            evidence=cert["issuer"][:200])

        wildcards = sum(1 for n in cert["san"] if n.startswith("*."))
        add(f"Subject: {cert['subject_cn'] or cert['subject']}; covers {cert['san_count']} names "
            f"({wildcards} wildcards)", evidence=", ".join(cert["san"][:10]))
        add(f"Public key: {cert['key']}; signature hash: {cert['signature_hash']}")

        if cert["self_signed"]:
            add("Certificate is self-signed")
        add(f"Certificate carries {cert['embedded_scts']} embedded Certificate Transparency timestamp(s)"
            if cert["embedded_scts"] else "No embedded Certificate Transparency timestamps found")
        if cert["ocsp"]:
            add("OCSP responder is listed", evidence=cert["ocsp"][0][:200])
        add("The intermediate certificate chain is not listed by this module")
        return observations

    def collect(self, target):
        if x509 is None:
            raise RuntimeError("The cryptography package is not installed (pip install cryptography)")

        dns_result = resolve_dns(target)
        if dns_result["error"]:
            raise RuntimeError(dns_result["error"])
        ensure_public_destination(dns_result["all_ips"])
        ip = dns_result["resolved_ip"]   # connect to the exact address that was just checked

        der, version, cipher = fetch_certificate(ip, target)
        cert = parse_certificate(der)
        verification = check_verification(ip, target)
        protocols = {name: supports(ip, target, v) for name, v in _VERSIONS.items()}

        data = {
            "negotiated": {"version": version, "cipher": cipher},
            "verification": verification,
            "certificate": cert,
            "protocols": protocols,
            "not_checked": ["TLS 1.0 and 1.1", "Intermediate certificate chain"],
        }
        return data, self._observe_all(version, cipher, cert, verification, protocols)