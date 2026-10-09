#!/usr/bin/env python3
"""SPF (RFC 7208) record parsing and evaluation -- no network, no libraries.

DNS is injected as a plain dict so everything is testable offline::

    dns = {
        "txt": {"example.com": "v=spf1 ip4:192.0.2.0/24 -all"},
        "a":   {"example.com": ["192.0.2.10"]},
        "mx":  {"example.com": ["mail.example.com"]},
    }
    evaluate_spf(dns["txt"]["example.com"], "192.0.2.10", "example.com", dns)
    # -> ("pass", "ip4:192.0.2.0/24", "matched ip4:192.0.2.0/24")

Live DNS is deliberately out of scope here (needs network); the dns-internals
skill in this repo builds a real resolver that could back this.
"""
import ipaddress
import re

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
RESULT_OF_QUAL = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def parse_spf(record):
    """Parse an SPF record string.

    Returns (terms, modifiers) where terms = [(qualifier, mechanism, arg), ...]
    and modifiers = {"redirect": domain, "exp": domain}. Raises ValueError on
    malformed records (permerror in evaluation).
    """
    record = record.strip()
    if not record.startswith("v=spf1"):
        raise ValueError("not an SPF record (must start with v=spf1)")
    terms, modifiers = [], {}
    for tok in record.split()[1:]:
        if "=" in tok and not tok.startswith(tuple("+-~?")):
            # modifier (redirect= / exp=); a mechanism never has a bare '='
            k, _, v = tok.partition("=")
            modifiers[k.lower()] = v
            continue
        q = "+"
        if tok[:1] in QUALIFIERS:
            q, tok = tok[0], tok[1:]
        m = re.match(r"^([a-z][a-z0-9]*)(?::([^/]*))?(?:/(\d+))?$", tok, re.I)
        if not m:
            raise ValueError(f"bad SPF term: {tok!r}")
        mech, arg, cidr = m.group(1).lower(), m.group(2), m.group(3)
        if mech not in ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"):
            raise ValueError(f"unknown SPF mechanism: {mech!r}")
        terms.append((q, mech, arg, int(cidr) if cidr else None))
    return terms, modifiers


def _dns_txt(dns, name):
    return (dns.get("txt") or {}).get(name.lower().rstrip("."))


def _dns_a(dns, name):
    return (dns.get("a") or {}).get(name.lower().rstrip("."), [])


def _dns_mx(dns, name):
    return (dns.get("mx") or {}).get(name.lower().rstrip("."), [])


def _ip_in(ip, addr, cidr):
    try:
        net = ipaddress.ip_network(f"{addr}/{cidr}" if cidr else addr,
                                   strict=False)
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _mech_match(mech, arg, cidr, ip, domain, dns, depth):
    """Does this mechanism match the client IP? Returns True/False/None(err)."""
    if mech == "all":
        return True
    if mech == "ip4":
        return _ip_in(ip, arg, cidr or 32)
    if mech == "ip6":
        return _ip_in(ip, arg, cidr or 128)
    if mech == "a":
        target = arg or domain
        return any(_ip_in(ip, a, cidr if cidr else (128 if ":" in a else 32))
                   for a in _dns_a(dns, target))
    if mech == "mx":
        target = arg or domain
        hosts = _dns_mx(dns, target)
        addrs = [a for h in hosts for a in _dns_a(dns, h)]
        return any(_ip_in(ip, a, None) for a in addrs)
    if mech == "include":
        rec = _dns_txt(dns, arg)
        if not rec or not rec.startswith("v=spf1"):
            return None  # permerror territory
        res, _, _ = evaluate_spf(rec, ip, arg, dns, depth + 1)
        return res == "pass"
    if mech == "exists":
        return bool(_dns_a(dns, arg))
    if mech == "ptr":
        return False  # deprecated, SHOULD NOT publish; treat as non-match
    return False


def evaluate_spf(record, ip, domain, dns, depth=0):
    """Evaluate an SPF record. Returns (result, matched_term, explanation).

    result in pass/fail/softfail/neutral/permerror/temperror/none.
    """
    if depth > 10:
        return "permerror", None, "include/redirect recursion too deep"
    try:
        terms, modifiers = parse_spf(record)
    except ValueError as e:
        return "permerror", None, str(e)
    for q, mech, arg, cidr in terms:
        try:
            m = _mech_match(mech, arg, cidr, ip, domain, dns, depth)
        except Exception:  # noqa: BLE001 -- any DNS weirdness -> temperror
            return "temperror", None, "DNS error during evaluation"
        if m is None:
            return "permerror", f"{q}{mech}", "mechanism lookup failed"
        if m:
            res = RESULT_OF_QUAL[q]
            label = q + mech + (f":{arg}" if arg else "") + (f"/{cidr}" if cidr else "")
            return res, label, f"matched {label}"
    if "redirect" in modifiers:
        rec = _dns_txt(dns, modifiers["redirect"])
        if not rec:
            return "permerror", None, "redirect target has no SPF record"
        return evaluate_spf(rec, ip, modifiers["redirect"], dns, depth + 1)
    return "neutral", None, "no mechanism matched (default)"


def self_test():
    dns = {
        "txt": {
            "example.com": "v=spf1 ip4:192.0.2.0/24 include:_spf.other.net -all",
            "_spf.other.net": "v=spf1 ip4:198.51.100.7 ~all",
        },
        "a": {"example.com": ["192.0.2.10"]},
        "mx": {"example.com": ["mail.example.com"]},
    }
    cases = [
        # (record, ip, domain, expected_result)
        ("v=spf1 ip4:192.0.2.0/24 -all", "192.0.2.44", "example.com", "pass"),
        ("v=spf1 ip4:192.0.2.0/24 -all", "203.0.113.9", "example.com", "fail"),
        ("v=spf1 ip4:192.0.2.0/24 ~all", "203.0.113.9", "example.com", "softfail"),
        ("v=spf1 ip4:192.0.2.0/24 ?all", "203.0.113.9", "example.com", "neutral"),
        ("v=spf1 a -all", "192.0.2.10", "example.com", "pass"),
        ("v=spf1 a -all", "192.0.2.11", "example.com", "fail"),
        ("v=spf1 include:_spf.other.net -all", "198.51.100.7", "example.com", "pass"),
        ("v=spf1 include:_spf.other.net -all", "203.0.113.9", "example.com", "fail"),
        ("v=spf1 ip4:192.0.2.1/32 -all", "192.0.2.1", "example.com", "pass"),
        ("v=spf1 redirect=_spf.other.net", "198.51.100.7", "example.com", "pass"),
        ("v=spf1", "1.2.3.4", "example.com", "neutral"),
        ("v=spf2 ip4:1.2.3.4 -all", "1.2.3.4", "example.com", "permerror"),
    ]
    fails = 0
    for record, ip, domain, want in cases:
        got, term, why = evaluate_spf(record, ip, domain, dns)
        ok = got == want
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {record!r} ip={ip} -> {got} "
              f"(want {want}) [{why}]")
    print("SPF SELF-TEST:", "PASS" if not fails else f"{fails} FAILURES")
    return fails == 0


if __name__ == "__main__":
    raise SystemExit(0 if self_test() else 1)
