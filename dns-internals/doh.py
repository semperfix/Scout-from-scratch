#!/usr/bin/env python3
"""DNS-over-HTTPS (RFC 8484) -- OPTIONAL, needs live network.

Sends the raw wire-format query built by dns.py inside an HTTPS request
(`Accept: application/dns-message`) and parses the wire-format reply with
dns.py. Everything else in this skill is offline; this module is the one
place where packets actually leave the machine.

No third-party deps: urllib + ssl from the stdlib.
"""
import base64
import ssl
import urllib.request

from dns import build_query, parse_message

DEFAULT_URL = "https://dns.google/dns-query"


def doh_query(name, qtype="A", url=DEFAULT_URL, timeout=10):
    """Resolve via DNS-over-HTTPS. Returns the parsed message dict.

    Raises URLError / ssl.SSLError / TimeoutError when the network (or the
    resolver) is unreachable -- callers should treat this as 'no network',
    not as a code bug.
    """
    wire = build_query(name, qtype)
    b64 = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    req = urllib.request.Request(
        f"{url}?dns={b64}",
        headers={"Accept": "application/dns-message",
                 "User-Agent": "scout-skills-dns-internals/1.0"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        if resp.status != 200:
            raise IOError(f"DoH resolver returned HTTP {resp.status}")
        ctype = resp.headers.get("Content-Type", "")
        if "dns-message" not in ctype:
            raise IOError(f"unexpected DoH content type: {ctype!r}")
        return parse_message(resp.read())


if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    try:
        msg = doh_query(name)
    except Exception as exc:  # noqa: BLE001 -- network is optional here
        print(f"DoH unavailable (offline?): {type(exc).__name__}: {exc}")
        raise SystemExit(2)
    for rr in msg["answers"]:
        print(f"{rr['name']} {rr['ttl']} {rr['type']} {rr['rdata']}")
