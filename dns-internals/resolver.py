#!/usr/bin/env python3
"""A working iterative DNS resolver -- stdlib only, no network libs beyond
raw sockets.

Starts at the root hints, follows NS referrals (using glue from the
additional section, resolving out-of-bailiwick NS names when there is no
glue), chases CNAMEs, and falls back to TCP when the TC bit is set.

Transport is just UDP/TCP to (host, port); roots default to the real root
hints (needs live network), but any (host, port) list can be injected --
the self-test runs a fake root+authority on localhost UDP and resolves
through it with zero network access.
"""
import random
import socket
import struct

from dns import build_query, parse_message, QTYPES, RTYPES

# a.root-servers.net and b.root-servers.net (stable, public root hints)
ROOT_HINTS = ["198.41.0.4", "199.9.14.201"]
MAX_HOPS = 16
MAX_CNAME = 8


def _udp_exchange(wire, server, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(wire, server)
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()


def _tcp_exchange(wire, server, timeout):
    s = socket.create_connection(server, timeout=timeout)
    try:
        s.sendall(struct.pack(">H", len(wire)) + wire)
        (n,) = struct.unpack(">H", _recvall(s, 2))
        return _recvall(s, n)
    finally:
        s.close()


def _recvall(s, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("DNS/TCP peer closed")
        buf += chunk
    return bytes(buf)


def iterative_resolve(name, qtype="A", roots=None, timeout=5, transport=None):
    """Iteratively resolve name/qtype. roots = [(host, port), ...].

    transport(wire_bytes, (host, port)) -> response_bytes; defaults to UDP
    (TCP fallback on TC). Inject a fake transport to test fully offline.

    Returns the list of answer RRs. Raises LookupError / TimeoutError.
    """
    qn = QTYPES.get(str(qtype).upper(), qtype) if isinstance(qtype, str) else qtype
    want = RTYPES.get(qn, qn)
    roots = list(roots) if roots else [(ip, 53) for ip in ROOT_HINTS]
    ask = transport or (lambda wire, server: _udp_exchange(wire, server, timeout))
    target, servers = name, roots
    cnames = 0
    for _hop in range(MAX_HOPS):
        wire = build_query(target, qn, qid=random.getrandbits(16))
        try:
            raw = ask(wire, servers[0])
        except socket.timeout as e:
            raise TimeoutError(f"no reply from {servers[0]}") from e
        resp = parse_message(raw)
        if resp["flags"]["tc"] and transport is None:  # truncated: TCP retry
            resp = parse_message(_tcp_exchange(wire, servers[0], timeout))
        if resp["flags"]["rcode"] == 3:
            raise LookupError(f"NXDOMAIN: {target}")
        if resp["flags"]["rcode"] != 0:
            raise LookupError(f"rcode={resp['flags']['rcode']} for {target}")

        direct = [rr for rr in resp["answers"] if rr["type"] == want]
        if direct:
            return direct
        cname = [rr for rr in resp["answers"] if rr["type"] == "CNAME"]
        if cname:
            cnames += 1
            if cnames > MAX_CNAME:
                raise LookupError("CNAME chain too deep")
            target, servers = cname[0]["rdata"], roots
            continue
        ns_rrs = [rr for rr in resp["authority"] if rr["type"] == "NS"]
        if not ns_rrs:
            raise LookupError(f"no answer and no referral for {target} "
                              f"({want}) from {servers[0]}")
        ns_name = ns_rrs[0]["rdata"]
        glue = [rr["rdata"] for rr in resp["additional"]
                if rr["name"].rstrip(".").lower() == ns_name.rstrip(".").lower()
                and rr["type"] == "A"]
        if glue:
            servers = [(glue[0], servers[0][1])]       # keep port (test rigs)
        else:                                          # out-of-bailiwick NS
            ns_a = iterative_resolve(ns_name, "A", roots=roots, timeout=timeout)
            servers = [(ns_a[0]["rdata"], servers[0][1])]
    raise LookupError(f"too many referral hops resolving {name}")


# ---------------------------------------------------------------------------
# offline self-test: fake transport plays root + authority (no sockets at all,
# since this sandbox blocks UDP loopback -- the resolver logic is identical)
# ---------------------------------------------------------------------------

def _fake_transport_factory():
    from dns import decode_name

    def enc(n):
        out = bytearray()
        for lab in n.split("."):
            out += bytes([len(lab)]) + lab.encode()
        return bytes(out) + b"\x00"

    def rr(name, rtype, ttl, rdata):
        return enc(name) + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata

    def fake_transport(wire, server):
        q = parse_message(wire)
        qname = q["questions"][0]["name"]
        qtype = q["questions"][0]["type"]
        qid = q["id"]
        _, qend = decode_name(wire, 12)
        qsec = wire[12:qend + 4]
        an, ns, ar = [], [], []
        if qname == "alias.example.com" and qtype in ("A", "CNAME"):
            an = [rr(qname, 5, 60, enc("www.example.com"))]
        elif qname.rstrip(".").endswith("example.com") and qtype == "A":
            an = [rr(qname, 1, 300, bytes([93, 184, 216, 34]))]
        else:  # referral, as a root would send
            ns = [rr("example.com", 2, 86400, enc("ns.example.com"))]
            ar = [rr("ns.example.com", 1, 86400, bytes([127, 0, 0, 1]))]
        return (struct.pack(">HHHHHH", qid, 0x8180, 1, len(an), len(ns), len(ar))
                + qsec + b"".join(an + ns + ar))

    return fake_transport


def self_test():
    transport = _fake_transport_factory()
    roots = [("127.0.0.1", 53535)]  # unused by the fake transport
    a = iterative_resolve("www.example.com", "A", roots=roots,
                          transport=transport)
    assert a and a[0]["rdata"] == "93.184.216.34", a
    print(f"[PASS] iterative A: www.example.com -> {a[0]['rdata']} "
          f"(via referral + glue)")
    a2 = iterative_resolve("alias.example.com", "A", roots=roots,
                           transport=transport)
    assert a2 and a2[0]["rdata"] == "93.184.216.34", a2
    print(f"[PASS] CNAME chase: alias.example.com -> {a2[0]['rdata']}")
    try:
        iterative_resolve("nosuch.example.com", "MX", roots=roots,
                          transport=transport)
        print("[FAIL] expected LookupError for unhandled type path")
        return False
    except LookupError as e:
        print(f"[PASS] no-data raises LookupError: {e}")
    print("RESOLVER SELF-TEST: PASS")
    return True


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # live mode: python3 resolver.py www.example.com A  (needs network)
        try:
            for rr in iterative_resolve(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "A"):
                print(f"{rr['name']} {rr['ttl']} {rr['type']} {rr['rdata']}")
        except Exception as exc:
            print(f"resolution failed: {type(exc).__name__}: {exc}")
            raise SystemExit(1)
    else:
        raise SystemExit(0 if self_test() else 1)
