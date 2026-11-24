import time
from datetime import datetime, timezone

from app.core.connection import http_request, tcp_connect, tls_handshake
from app.core.dns_resolver import resolve_dns
from app.core.hop_tracer import trace_hops
from app.core.ip_enrichment import enrich_ip
from app.core.orchestrator import run_modules
from app.core.validation import ensure_public_destination, normalize_target


def run_trace_stream(
    target: str,
    port: int = 443,
    module_ids: list[str] | None = None,
    allow_active: bool = False,
):
    start_time = time.time()

    def make_event(stage: str, data: dict) -> dict:
        return {
            "stage": stage,
            "data": data,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": round((time.time() - start_time) * 1000, 2),
        }

    # Validate BEFORE anything touches DNS, subprocess, or sockets
    try:
        target = normalize_target(target)
    except ValueError as e:
        yield make_event("error", {"message": f"Invalid target: {e}"})
        return

    dns_result = resolve_dns(target)
    yield make_event("dns", dns_result)

    if dns_result["error"]:
        yield make_event("error", {"message": "DNS resolution failed, stopping trace"})
        return

    # SSRF guard: refuse to trace or connect to non-public addresses
    try:
        ensure_public_destination(dns_result["all_ips"])
    except ValueError as e:
        yield make_event("error", {"message": str(e)})
        return

    resolved_ip = dns_result["resolved_ip"]

    for hop in trace_hops(resolved_ip):
        yield make_event("hop", {**hop, **enrich_ip(hop["ip"])})

    tcp_result, sock = tcp_connect(resolved_ip, port)
    yield make_event("tcp", tcp_result)

    if sock:
        yield make_event("tls", tls_handshake(sock, target))

    yield make_event("http", http_request(f"https://{target}"))

    # Recon: one event per module, same shape as /ws/recon
    count = 0
    try:
        for result in run_modules(target, module_ids, allow_active=allow_active):
            count += 1
            yield make_event("module", result.model_dump())
    except ValueError as e:
        yield make_event("error", {"message": str(e)})
        return

    yield make_event("done", {"count": count})


def run_trace(
    target: str,
    port: int = 443,
    module_ids: list[str] | None = None,
    allow_active: bool = False,
) -> dict:
    """Non-streaming version: collects every event into one dict."""
    combined = {"target": target, "hops": [], "modules": []}

    for event in run_trace_stream(target, port, module_ids, allow_active):
        stage, data = event["stage"], event["data"]
        if stage == "hop":
            combined["hops"].append(data)
        elif stage == "module":
            combined["modules"].append(data)
        elif stage != "done":
            combined[stage] = data

    return combined


if __name__ == "__main__":
    for event in run_trace_stream("google.com"):
        print(f"[{event['timestamp_utc']}] (+{event['elapsed_ms']}ms) {event['stage']}")