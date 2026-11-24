import socket
import ssl
import time

import requests

from app.core.http_fetch import safe_get


def tcp_connect(ip: str, port: int = 443, timeout: float = 5):
    """
    Open a raw TCP connection and measure connect time.
    Returns a tuple: (result_dict, socket_or_None)
    """
    result = {
        "ip": ip,
        "port": port,
        "connected": False,
        "connect_time_ms": None,
        "error": None,
    }

    start = time.time()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        result["error"] = f"Connection to {ip}:{port} timed out"
        return result, None
    except ConnectionRefusedError:
        result["error"] = f"Connection to {ip}:{port} refused"
        return result, None
    except OSError as e:
        result["error"] = f"Connection error: {e}"
        return result, None

    result["connected"] = True
    result["connect_time_ms"] = (time.time() - start) * 1000
    return result, sock


def tls_handshake(sock, hostname: str) -> dict:
    """Wrap an existing TCP socket in TLS and capture handshake details."""
    result = {
        "tls_version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expires": None,
        "error": None,
    }

    if sock is None:
        result["error"] = "No TCP socket available (connection failed earlier)"
        return result

    context = ssl.create_default_context()
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=hostname)
    except ssl.SSLError as e:
        result["error"] = f"TLS handshake failed: {e}"
        return result
    except socket.timeout:
        result["error"] = "TLS handshake timed out"
        return result

    result["tls_version"] = tls_sock.version()

    cipher = tls_sock.cipher()
    if cipher:
        result["cipher"] = cipher[0]

    cert = tls_sock.getpeercert()
    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["cert_subject"] = subject.get("commonName")
        result["cert_issuer"] = issuer.get("commonName")
        result["cert_expires"] = cert.get("notAfter")

    tls_sock.close()
    return result


def http_request(url: str, timeout: float = 5) -> dict:
    """
    One HTTPS request with every redirect hop checked.
    The body is not downloaded and Set-Cookie values are left out.
    """
    result = {
        "status_code": None,
        "headers": {},
        "response_time_ms": None,
        "redirects": 0,
        "error": None,
    }

    try:
        response, chain = safe_get(url, timeout=timeout)
    except ValueError as exc:
        result["error"] = f"Request blocked: {exc}"
        return result
    except requests.exceptions.Timeout:
        result["error"] = f"HTTP request to {url} timed out"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Request failed: {exc}"
        return result

    try:
        result["status_code"] = response.status_code
        result["headers"] = {
            k: v for k, v in response.headers.items() if k.lower() != "set-cookie"
        }
        result["response_time_ms"] = response.elapsed.total_seconds() * 1000
        result["redirects"] = len(chain) - 1
    finally:
        response.close()
    return result