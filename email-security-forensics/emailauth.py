#!/usr/bin/env python3
"""emailauth: verify SPF, DKIM and DMARC for a raw email file -- offline.

Given a raw RFC 5322 message plus a DNS stub (JSON), this tool:
  * lists Authentication-Results / Received-SPF headers found in the message
  * verifies every DKIM-Signature (body hash + RSA-SHA256 signature)
  * evaluates SPF for --ip / --mailfrom against the stub's TXT records
  * evaluates DMARC alignment for the From: domain

Live DNS needs network and is out of scope; pass --dns-stub with a JSON file:
  {"txt": {"example.com": "v=spf1 ...",
           "sel1._domainkey.example.com": "v=DKIM1; k=rsa; p=...",
           "_dmarc.example.com": "v=DMARC1; p=reject; ..."},
   "a": {...}, "mx": {...}}

Exit 0 if DMARC passes (or is 'none'), 1 if DMARC fails, 2 on usage errors.
"""
import argparse
import json
import re
import sys

from dkim import split_email, verify_raw_email
from spf import evaluate_spf
from dmarc import evaluate_dmarc


def _header_values(headers, name):
    want = name.lower().encode()
    return [v for n, v in headers if n.lower().strip() == want]


def _addr_domain(header_value: bytes):
    """Extract domain from 'Name <user@domain>' or 'user@domain'."""
    s = header_value.decode("utf-8", "replace")
    m = re.search(r"[\w.+-]+@([\w.-]+)", s)
    return m.group(1).lower() if m else None


def analyze(raw: bytes, dns: dict, ip: str, mailfrom: str):
    headers, _body = split_email(raw)
    out = {"warnings": []}

    # --- headers present in the message -----------------------------------
    for h in ("authentication-results", "received-spf"):
        vals = _header_values(headers, h)
        out[h] = [v.decode("utf-8", "replace").strip() for v in vals]

    # --- DKIM --------------------------------------------------------------
    dns_txt = lambda name: (dns.get("txt") or {}).get(name.lower().rstrip("."))  # noqa: E731
    dkim_reports = verify_raw_email(raw, dns_txt)
    out["dkim"] = dkim_reports
    if not dkim_reports:
        out["warnings"].append("no DKIM-Signature headers found")

    # --- SPF ---------------------------------------------------------------
    if not mailfrom:
        rp = _header_values(headers, "return-path")
        mailfrom = _addr_domain(rp[0]) or ""
        mailfrom = ("postmaster@" + mailfrom) if "@" not in mailfrom and mailfrom else mailfrom
    spf_domain = mailfrom.split("@")[-1] if "@" in mailfrom else None
    txt = (dns.get("txt") or {})
    spf_record = txt.get(spf_domain, "") if spf_domain else ""
    if spf_record.startswith("v=spf1"):
        spf_res, spf_term, spf_why = evaluate_spf(spf_record, ip, spf_domain, dns)
    else:
        spf_res, spf_term, spf_why = "none", None, "no SPF record published"
    out["spf"] = {"result": spf_res, "domain": spf_domain, "term": spf_term,
                  "detail": spf_why, "ip": ip, "mailfrom": mailfrom}

    # --- DMARC --------------------------------------------------------------
    from_vals = _header_values(headers, "from")
    from_domain = _addr_domain(from_vals[0]) if from_vals else None
    dmarc_record = txt.get(f"_dmarc.{from_domain}") if from_domain else None
    dkim_simple = [{"d": r.get("d", ""), "status": r.get("status", "")}
                   for r in dkim_reports]
    dmarc_out = evaluate_dmarc(dmarc_record, from_domain or "", spf_res,
                               spf_domain, dkim_simple)
    out["dmarc"] = dmarc_out
    out["from_domain"] = from_domain
    return out


def report(analysis):
    L = []
    L.append(f"From domain: {analysis['from_domain']}")
    for h in ("authentication-results", "received-spf"):
        for v in analysis[h]:
            L.append(f"{h}: {v[:120]}")
    L.append("")
    L.append("DKIM:")
    for r in analysis["dkim"]:
        L.append(f"  d={r.get('d')} s={r.get('s')} a={r.get('a')}: "
                 f"{r.get('status', '?').upper()} -- {r.get('detail', '')} "
                 f"(bh_match={r.get('bh_match')}, sig_valid={r.get('sig_valid')})")
    if not analysis["dkim"]:
        L.append("  (none)")
    s = analysis["spf"]
    L.append(f"SPF: {s['result'].upper()} (ip={s['ip']}, mailfrom={s['mailfrom']}, "
             f"domain={s['domain']}) -- {s['detail']}")
    d = analysis["dmarc"]
    L.append(f"DMARC: {d['dmarc'].upper()} (policy p={d['policy']}, "
             f"disposition={d['disposition']}) -- {d['detail']}")
    for w in analysis["warnings"]:
        L.append(f"warning: {w}")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="emailauth",
        description="Verify SPF, DKIM and DMARC for a raw email using a "
                    "stub DNS JSON file (offline; live DNS needs network).")
    ap.add_argument("email", help="raw RFC 5322 message file")
    ap.add_argument("--dns-stub", required=True, help="JSON stub DNS file")
    ap.add_argument("--ip", default="192.0.2.44",
                    help="connecting client IP for SPF (default 192.0.2.44)")
    ap.add_argument("--mailfrom", default="",
                    help="envelope-from for SPF (default: Return-Path header)")
    args = ap.parse_args(argv)

    try:
        with open(args.email, "rb") as f:
            raw = f.read()
    except OSError as e:
        sys.exit(f"error: cannot read {args.email}: {e}")
    try:
        with open(args.dns_stub) as f:
            dns = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"error: cannot load --dns-stub: {e}")

    analysis = analyze(raw, dns, args.ip, args.mailfrom)
    print(report(analysis))
    return 1 if analysis["dmarc"]["dmarc"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
