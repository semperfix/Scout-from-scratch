#!/usr/bin/env python3
"""certcheck -- X.509 certificate forensics triage CLI.

Reads certificates (never modifies anything, never authenticates):

    python3 certcheck.py example.com            # fetch TLS chain, full triage
    python3 certcheck.py example.com:8443       # non-standard port
    python3 certcheck.py --pem chain.pem [--host example.com]
    python3 certcheck.py --ct example.com       # CT-log subdomain OSINT

Chain fetching uses `openssl s_client` purely as a read-only TLS client;
every byte after that is parsed and verified by the from-scratch code in
der.py / x509.py / ecc.py / verify.py.
"""

import base64  # noqa: F401
import sys

from der import split_pems, pem_to_der
from x509 import parse_cert, load_pem_file
from verify import build_chain, check_hostname, triage, cert_times_ok

TRUST_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

_anchors = None


def trust_anchors():
    global _anchors
    if _anchors is None:
        _anchors = load_pem_file(TRUST_BUNDLE, skip_bad=True)
    return _anchors


def _proxy_connect(host: str, port: int, timeout=30):
    """Retrieve the presented chain via openssl s_client through the
    sandbox egress proxy (HTTP CONNECT). Read-only TLS client handshake;
    every byte afterwards is parsed/verified by from-scratch code.
    Proxy credentials come from the standard https_proxy env var and are
    passed to openssl via its own flags (never logged or echoed).
    """
    import os
    import subprocess
    import urllib.parse

    proxy_url = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-showcerts"]
    if proxy_url:
        u = urllib.parse.urlparse(proxy_url)
        cmd += ["-proxy", f"{u.hostname}:{u.port or 3128}"]
        if u.username:
            cmd += ["-proxy_user", u.username, "-proxy_pass",
                    "pass:" + urllib.parse.unquote(u.password or "")]
    p = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    blocks = split_pems(out)
    if not blocks:
        err = p.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"no certificates retrieved from {host}:{port}\n{err[-400:]}")
    return blocks


def fetch_chain(host: str, port: int = 443):
    """Return PEM blocks for the presented chain (read-only TLS client)."""
    return _proxy_connect(host, port)


def fmt_time(t):
    return "%04d-%02d-%02d %02d:%02d:%02dZ" % t


def show_cert(cert, idx=0):
    spki = cert["spki"]
    keydesc = f"{spki['alg_name']} {spki.get('bits', '?')}-bit"
    if spki["alg_name"] == "ecPublicKey":
        keydesc += f" ({spki.get('curve')})"
    sans = (cert["extensions"].get("subjectAltName", {}).get("parsed") or [])
    dns = [v for (t, v) in sans if t == "dns"]
    print(f"--- cert[{idx}] ---")
    print(f"  subject : {cert['subject_str'][:100]}")
    print(f"  issuer  : {cert['issuer_str'][:100]}")
    print(f"  serial  : {cert['serial_hex']}")
    print(f"  sig alg : {cert['sig_alg']}")
    print(f"  key     : {keydesc}")
    print(f"  validity: {fmt_time(cert['not_before'])} .. {fmt_time(cert['not_after'])}")
    if dns:
        shown = ", ".join(dns[:8]) + (f" (+{len(dns) - 8} more)" if len(dns) > 8 else "")
        print(f"  SANs    : {shown}")
    aki = (cert["extensions"].get("authorityKeyIdentifier", {}).get("parsed") or {}).get("keyid")
    ski = (cert["extensions"].get("subjectKeyIdentifier", {}).get("parsed"))
    if ski:
        print(f"  SKI     : {ski[:24]}...")
    if aki:
        print(f"  AKI     : {aki[:24]}...")


def triage_pems(pems, hostname=None):
    certs = [parse_cert(pem_to_der(b)) for b in pems]
    anchors = trust_anchors()
    leaf = certs[0]
    for i, c in enumerate(certs):
        show_cert(c, i)
    print()
    res = build_chain(leaf, certs[1:], anchors)
    print(f"chain: {res['status']} -- {res['detail']}")
    for n in res["notes"]:
        print(f"  {n}")
    # per-cert time validity across the built chain
    for c in res["chain"]:
        ok, why = cert_times_ok(c)
        if not ok:
            print(f"  TIME: {c['subject_str'][:60]}: {why}")
    print()
    findings = triage(leaf, chain_status=res["status"], hostname=hostname)
    # phishing-relevant context: free DV issuer on a lookalike-ish name
    order = {"crit": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order[f[0]])
    if not findings:
        print("no findings.")
    for sev, code, msg in findings:
        print(f"[{sev.upper():4}] {code}: {msg}")
    verdict = "TRUSTED" if res["status"] == "TRUSTED" and \
        not any(s == "crit" for s, _, _ in findings) else \
        ("SUSPICIOUS" if any(s == "crit" for s, _, _ in findings) else "UNTRUSTED")
    print(f"\nverdict: {verdict}")
    return verdict


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == "--ct":
        from ctlog import ct_search, subdomains, interesting
        domain = argv[2]
        entries = ct_search(domain)
        subs = subdomains(entries, domain)
        print(f"{len(subs)} unique names in CT logs for *.{domain}:")
        for s in subs:
            print(f"  {s}")
        hot = interesting(subs)
        if hot:
            print("\ninfra-smelling names:")
            for s in hot:
                print(f"  {s}")
        return 0
    if argv[1] == "--pem":
        path = argv[2]
        host = None
        if "--host" in argv:
            host = argv[argv.index("--host") + 1]
        with open(path) as f:
            pems = split_pems(f.read())
        triage_pems(pems, hostname=host)
        return 0
    target = argv[1]
    host, _, port = target.partition(":")
    pems = fetch_chain(host, int(port) if port else 443)
    print(f"retrieved {len(pems)} certificate(s) from {host}\n")
    triage_pems(pems, hostname=host)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
