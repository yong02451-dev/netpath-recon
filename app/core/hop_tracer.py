import subprocess
import re


def trace_hops(target: str):
    """
    Generator version — yields one hop dict at a time, as tracert
    actually produces each line, instead of waiting for the full
    command to finish.
    """

    hop_pattern = re.compile(r"^\s*(\d+)\s+(.*)$")

    process = subprocess.Popen(
        ["tracert", "-d", "-4", target],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,          # line-buffered
    )

    for line in process.stdout:
        match = hop_pattern.match(line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        ip_match = re.search(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([0-9a-fA-F:]+:[0-9a-fA-F:]+)",
            rest
        )
        ip = ip_match.group(0) if ip_match else None

        rtt_matches = re.findall(r"(<?\d+)\s*ms", rest)
        rtt_ms = None
        if rtt_matches:
            values = [float(r.replace("<", "")) for r in rtt_matches]
            rtt_ms = sum(values) / len(values)

        yield {"hop": hop_num, "ip": ip, "rtt_ms": rtt_ms}

    process.wait()