"""Importing this package registers every module. Add one line per new module."""
from app.modules import (  # noqa: F401
    cert_transparency,
    dns_records,
    email_security,
    security_headers,
    tls_detail,
    whois_info,
    zone_transfer,
)