#!/usr/bin/env python3
"""DMARC (RFC 7489) record parsing and alignment evaluation -- stdlib only.

Simplification (documented): organizational-domain detection uses the last
two DNS labels instead of the Public Suffix List, e.g. org("a.b.example.com")
== "example.com". Good enough for learning; a production check needs the PSL.
"""
import re


def parse_dmarc(record):
    """Parse a DMARC TXT record -> dict of lowercase tags. Raises ValueError."""
    record = record.strip()
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    if tags.get("v", "").upper() != "DMARC1":
        raise ValueError("not a DMARC record (must start with v=DMARC1)")
    return tags


def org_domain(domain):
    """Naive organizational domain: last two labels. (No PSL -- see module doc.)"""
    labels = domain.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def aligned(auth_domain, from_domain, mode):
    """Check identifier alignment. mode: 'r' (relaxed) or 's' (strict)."""
    auth_domain = auth_domain.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")
    if mode == "s":
        return auth_domain == from_domain
    # relaxed: same organizational domain
    return org_domain(auth_domain) == org_domain(from_domain)


def evaluate_dmarc(dmarc_record, from_domain, spf_result, spf_domain,
                   dkim_results):
    """Evaluate DMARC for one message.

    dkim_results: list of dicts with keys d (domain), status ('pass'/...).
    Returns dict: dmarc ('pass'/'fail'/'none'), policy, disposition, detail.
    """
    if dmarc_record is None:
        return {"dmarc": "none", "policy": None, "disposition": "none",
                "detail": "no DMARC record published"}
    try:
        tags = parse_dmarc(dmarc_record)
    except ValueError as e:
        return {"dmarc": "none", "policy": None, "disposition": "none",
                "detail": f"bad DMARC record: {e}"}
    policy = tags.get("p", "none").lower()
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()

    dkim_aligned = any(r.get("status") == "pass"
                       and aligned(r.get("d", ""), from_domain, adkim)
                       for r in dkim_results)
    spf_aligned = (spf_result == "pass" and spf_domain
                   and aligned(spf_domain, from_domain, aspf))

    if dkim_aligned or spf_aligned:
        return {"dmarc": "pass", "policy": policy, "disposition": "none",
                "detail": f"aligned auth: dkim={dkim_aligned} spf={spf_aligned}"}
    disp = {"none": "none", "quarantine": "quarantine",
            "reject": "reject"}.get(policy, "none")
    return {"dmarc": "fail", "policy": policy, "disposition": disp,
            "detail": f"no aligned pass (dkim_aligned={dkim_aligned}, "
                      f"spf_aligned={spf_aligned}); policy p={policy}"}


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    r = parse_dmarc("v=DMARC1; p=reject; adkim=s; aspf=r; pct=100")
    check("parse p/adkim/aspf", r["p"] == "reject" and r["adkim"] == "s")

    rec = "v=DMARC1; p=quarantine;"
    dkim = [{"d": "example.com", "status": "pass"}]
    out = evaluate_dmarc(rec, "example.com", "fail", "other.net", dkim)
    check("dkim relaxed aligned -> pass",
          out["dmarc"] == "pass" and out["disposition"] == "none")

    out = evaluate_dmarc("v=DMARC1; p=reject; adkim=s", "example.com",
                         "fail", None, [{"d": "mail.example.com", "status": "pass"}])
    check("dkim strict misaligned -> fail/reject",
          out["dmarc"] == "fail" and out["disposition"] == "reject")

    out = evaluate_dmarc("v=DMARC1; p=reject; adkim=r", "example.com",
                         "fail", None, [{"d": "mail.example.com", "status": "pass"}])
    check("dkim relaxed subdomain aligned -> pass", out["dmarc"] == "pass")

    out = evaluate_dmarc("v=DMARC1; p=none", "example.com",
                         "pass", "example.com", [])
    check("spf aligned -> pass", out["dmarc"] == "pass")

    out = evaluate_dmarc("v=DMARC1; p=quarantine", "example.com",
                         "fail", "evil.net", [{"d": "evil.net", "status": "pass"}])
    check("nothing aligned -> fail/quarantine",
          out["dmarc"] == "fail" and out["disposition"] == "quarantine")

    out = evaluate_dmarc(None, "example.com", "pass", "example.com", [])
    check("no record -> none", out["dmarc"] == "none")

    print("DMARC SELF-TEST:", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if self_test() else 1)
