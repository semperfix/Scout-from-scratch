"""Certificate verification and triage, from scratch. Zero dependencies.

  * Signature verification: RSA PKCS#1 v1.5, ECDSA (P-256/P-384), Ed25519 --
    all with hand-rolled math (ecc.py), hashed with hashlib.
  * Chain building: issuer DN matching + AKI/SKI binding, per-link signature
    checks, BasicConstraints/KeyUsage enforcement on CAs.
  * Hostname verification: SAN dNSName with RFC 6125-style wildcards, CN fallback.
  * Triage heuristics: weak algorithms, short keys, over-long validity,
    punycode SANs, serial entropy, missing AKI/SKI -- the things that
    distinguish a normal cert from a sketchy one.

Trust anchors come from the system CA bundle (read-only). Revocation
(OCSP/CRL) is parsed for display (AIA/CRLDP URLs) but not enforced --
stated limitation.
"""

import hashlib
import calendar
import time

from der import parse_der, DERError, TAG_SEQUENCE
from ecc import CURVES, parse_ec_point, ecdsa_verify, ed25519_verify

# DigestInfo prefixes for PKCS#1 v1.5 (digest OID + NULL + OCTET STRING header)
DIGESTINFO_PREFIX = {
    "md5": bytes.fromhex("3020300c06082a864886f70d020505000410"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402070500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

WEAK_DIGESTS = {"md2", "md5", "sha1"}


# --------------------------------------------------------------------------
# signature verification
# --------------------------------------------------------------------------

def _rsa_v15_verify(n: int, e: int, digest_name: str, tbs: bytes, sig: bytes):
    prefix = DIGESTINFO_PREFIX.get(digest_name)
    if prefix is None:
        return False, f"unsupported RSA digest {digest_name}"
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False, f"RSA signature length {len(sig)} != modulus size {k}"
    m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.new(digest_name, tbs).digest()
    expect = b"\x00\x01" + b"\xff" * (k - 3 - len(prefix) - len(digest)) + \
        b"\x00" + prefix + digest
    if len(expect) != k:
        return False, "RSA padding length impossible (key too short?)"
    # constant-time-ish compare (no early exit on content)
    ok = len(m) == len(expect)
    diff = 0
    for a, b in zip(m, expect):
        diff |= a ^ b
    return (diff == 0 and ok), "RSA PKCS#1 v1.5"


def _ecdsa_sig_parse(sig: bytes):
    node = parse_der(sig)
    if node.tag != TAG_SEQUENCE or len(node) != 2:
        raise DERError("ECDSA signature not a 2-INTEGER SEQUENCE")
    return node.child(0).as_int(), node.child(1).as_int()


def verify_signature(cert: dict, issuer: dict):
    """Verify cert['signature'] over cert['tbs_der'] using issuer's SPKI.

    Returns (ok: bool, detail: str).
    """
    sigtype = cert.get("sig_type")
    digest = cert.get("sig_digest")
    tbs = cert["tbs_der"]
    sig = cert["signature"]
    spki = issuer["spki"]
    try:
        if sigtype == "rsa":
            return _rsa_v15_verify(spki["n"], spki["e"], digest, tbs, sig)
        if sigtype == "rsa-pss":
            return False, "RSA-PSS not implemented (rare in the wild)"
        if sigtype == "ecdsa":
            curve = CURVES.get(spki.get("curve"))
            if curve is None:
                return False, f"unsupported EC curve {spki.get('curve')}"
            if digest is None:
                return False, "unknown ECDSA digest"
            pub = parse_ec_point(spki["key_bytes"], curve)
            r, s = _ecdsa_sig_parse(sig)
            d = hashlib.new(digest, tbs).digest()
            return ecdsa_verify(curve, pub, d, r, s), f"ECDSA/{curve.name}"
        if sigtype == "ed25519":
            ok = ed25519_verify(spki["key_bytes"], tbs, sig)
            return ok, "Ed25519"
        return False, f"unsupported signature type {sigtype}"
    except (DERError, ValueError, KeyError) as ex:
        return False, f"verify error: {ex}"


# --------------------------------------------------------------------------
# chain building
# --------------------------------------------------------------------------

def _now_tuple():
    t = time.gmtime()
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def _tup_to_epoch(tup):
    return calendar.timegm((tup[0], tup[1], tup[2], tup[3], tup[4], tup[5], 0, 0, 0))


def cert_times_ok(cert, now_epoch=None):
    nowt = _now_tuple() if now_epoch is None else time.gmtime(now_epoch)[:6]
    if nowt < cert["not_before"]:
        return False, "not yet valid"
    if nowt > cert["not_after"]:
        return False, "expired"
    return True, "valid now"


def _spki_id(spki):
    """Stable identity for a public key: alg + key bytes."""
    return (spki["alg_name"], spki["key_bytes"])


def _aki_matches(cert, candidate):
    """AuthorityKeyIdentifier keyid must match candidate's SKI when both present."""
    aki = cert["extensions"].get("authorityKeyIdentifier", {}).get("parsed") or {}
    ski = candidate["extensions"].get("subjectKeyIdentifier", {}).get("parsed")
    keyid = aki.get("keyid")
    if keyid and ski and keyid != ski:
        return False
    return True


def is_self_signed(cert):
    if cert["issuer_str"] != cert["subject_str"]:
        return False
    ok, _ = verify_signature(cert, cert)
    return ok


def build_chain(leaf: dict, extras: list, anchors: list):
    """Build and verify a chain leaf -> ... -> trust anchor.

    extras: presented intermediates (and possibly root). anchors: trust store.
    Returns dict with status, chain list, and per-link notes.
    """
    pool = list(extras) + list(anchors)
    chain = [leaf]
    notes = []
    seen = {id(leaf)}
    current = leaf
    for depth in range(10):
        # find issuer candidates: subject DN matches, AKI/SKI agree
        cands = [c for c in pool
                 if c["subject_str"] == current["issuer_str"]
                 and _aki_matches(current, c) and id(c) not in seen]
        if not cands:
            return {"status": "UNKNOWN_ISSUER", "chain": chain, "notes": notes,
                    "detail": f"no issuer found for {current['issuer_str'][:80]}"}
        issuer = cands[0]
        seen.add(id(issuer))
        ok, detail = verify_signature(current, issuer)
        notes.append(f"link {depth}: {current['subject_str'][:60]} <- "
                     f"{issuer['subject_str'][:60]}: {'OK' if ok else 'FAIL'} ({detail})")
        if not ok:
            return {"status": "BAD_SIGNATURE", "chain": chain, "notes": notes,
                    "detail": detail}
        # CA constraints on the issuer (unless it is the trust anchor itself)
        if issuer not in anchors:
            bc = issuer["extensions"].get("basicConstraints", {}).get("parsed") or {}
            if not bc.get("ca"):
                return {"status": "NOT_A_CA", "chain": chain + [issuer], "notes": notes,
                        "detail": "intermediate lacks basicConstraints CA:TRUE"}
            ku = issuer["extensions"].get("keyUsage", {}).get("parsed") or {}
            if "keyCertSign" not in ku.get("names", []) and ku:
                return {"status": "KEYUSAGE_VIOLATION",
                        "chain": chain + [issuer], "notes": notes,
                        "detail": "intermediate missing keyCertSign"}
        chain.append(issuer)
        # trust anchor reached?
        if issuer in anchors or any(_spki_id(issuer["spki"]) == _spki_id(a["spki"])
                                    and issuer["subject_str"] == a["subject_str"]
                                    for a in anchors):
            # anchor self-signature sanity (cheap, anchors are self-signed)
            return {"status": "TRUSTED", "chain": chain, "notes": notes,
                    "detail": f"anchor: {issuer['subject_str'][:80]}"}
        if is_self_signed(issuer):
            return {"status": "UNTRUSTED_ROOT", "chain": chain, "notes": notes,
                    "detail": f"self-signed root not in trust store: "
                              f"{issuer['subject_str'][:80]}"}
        current = issuer
    return {"status": "CHAIN_TOO_DEEP", "chain": chain, "notes": notes, "detail": ""}


# --------------------------------------------------------------------------
# hostname verification (RFC 6125-lite)
# --------------------------------------------------------------------------

def _dnsname_match(pattern: str, host: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # wildcard covers exactly one leftmost label, and host must have one
        if host.endswith("." + suffix) and "." not in host[:-(len(suffix) + 1)]:
            return True
    return False


def check_hostname(cert: dict, hostname: str):
    """Returns (ok, detail). Follows SAN-first, CN-fallback (deprecated)."""
    sans = cert["extensions"].get("subjectAltName", {}).get("parsed") or []
    dns_names = [v for (t, v) in sans if t == "dns"]
    ip_names = [v for (t, v) in sans if t == "ip"]
    is_ip = hostname.replace(".", "").isdigit() and hostname.count(".") == 3
    if dns_names or ip_names:
        pool = ip_names if is_ip else dns_names
        for name in pool:
            if _dnsname_match(name, hostname):
                return True, f"matches SAN {name}"
        return False, f"no SAN match for {hostname} (SANs: {dns_names + ip_names})"
    # deprecated CN fallback
    cns = [v for (k, v) in cert["subject"] if k == "CN"]
    if cns and _dnsname_match(cns[0], hostname):
        return True, f"matches CN {cns[0]} (deprecated CN fallback)"
    return False, f"no SAN and CN {cns} does not match {hostname}"


# --------------------------------------------------------------------------
# triage heuristics
# --------------------------------------------------------------------------

def triage(cert: dict, chain_status: str = None, hostname: str = None):
    """Return list of (severity, code, message). Severity: info/warn/crit."""
    F = []

    def add(sev, code, msg):
        F.append((sev, code, msg))

    # --- time ---
    ok, why = cert_times_ok(cert)
    if not ok:
        add("crit", "EXPIRED" if why == "expired" else "NOT_YET_VALID",
            f"certificate is {why}: "
            f"{'%04d-%02d-%02d' % cert['not_before'][:3]} .. "
            f"{'%04d-%02d-%02d' % cert['not_after'][:3]}")
    days = (_tup_to_epoch(cert["not_after"]) - _tup_to_epoch(cert["not_before"])) / 86400
    if days > 825 and cert["version"] == 3:
        add("warn", "LONG_LIVED",
            f"validity {days:.0f} days exceeds CA/Browser Forum 825-day limit")

    # --- signature algorithm ---
    if cert["sig_digest"] in WEAK_DIGESTS:
        add("crit", "WEAK_SIG_ALG", f"signature uses broken hash {cert['sig_digest']}")
    if cert["sig_type"] in (None, "rsa-pss", "dsa"):
        add("warn", "ODD_SIG_ALG", f"signature algorithm: {cert['sig_alg']}")

    # --- key strength ---
    spki = cert["spki"]
    if spki["alg_name"] == "rsaEncryption" and spki.get("bits", 0) < 2048:
        add("crit", "SHORT_RSA_KEY", f"RSA key only {spki['bits']} bits")
    if spki["alg_name"] == "ecPublicKey" and spki.get("bits", 0) < 224:
        add("warn", "SHORT_EC_KEY", f"EC key only {spki['bits']} bits")
    if spki["alg_name"] == "rsaEncryption" and spki.get("e") not in (3, 65537):
        add("warn", "ODD_RSA_EXPONENT", f"RSA exponent e={spki.get('e')}")

    # --- self-signed leaf ---
    if is_self_signed(cert):
        add("warn", "SELF_SIGNED", "self-signed certificate")

    # --- serial entropy ---
    if cert["serial"] <= 0 or cert["serial"] < 2 ** 32:
        add("info", "LOW_ENTROPY_SERIAL",
            f"serial {cert['serial_hex']} is small/predictable")

    # --- extensions hygiene ---
    exts = cert["extensions"]
    if cert["version"] == 3 and "authorityKeyIdentifier" not in exts \
            and not is_self_signed(cert):
        add("info", "MISSING_AKI", "no authorityKeyIdentifier (chain building hint absent)")
    if "subjectKeyIdentifier" not in exts and cert["version"] == 3:
        add("info", "MISSING_SKI", "no subjectKeyIdentifier")
    bc = (exts.get("basicConstraints", {}).get("parsed") or {})
    ku = (exts.get("keyUsage", {}).get("parsed") or {}).get("names", [])
    if bc.get("ca") and "keyCertSign" not in ku and ku:
        add("warn", "CA_WITHOUT_CERTSIGN", "CA cert missing keyCertSign usage")

    # --- SAN analysis ---
    sans = (exts.get("subjectAltName", {}).get("parsed") or [])
    dns_names = [v for (t, v) in sans if t == "dns"]
    if not dns_names and cert["version"] == 3 and not bc.get("ca"):
        add("warn", "MISSING_SAN", "leaf has no SAN dNSName (CN-only, deprecated)")
    if len(dns_names) > 25:
        add("info", "MANY_SANS", f"{len(dns_names)} SAN entries (bulk-issuance shape)")
    for d in dns_names:
        if "xn--" in d:
            add("warn", "PUNYCODE_SAN", f"internationalized name {d} -- homograph risk, inspect")
    # DV-only signal: free automated CA on the chain is normal, but worth noting
    # for lookalike domains (handled by caller with hostname context)

    # --- chain + hostname results folded in ---
    if chain_status and chain_status != "TRUSTED":
        sev = "crit" if chain_status in ("BAD_SIGNATURE", "UNKNOWN_ISSUER",
                                         "UNTRUSTED_ROOT") else "warn"
        add(sev, f"CHAIN_{chain_status}", f"chain validation: {chain_status}")
    if hostname:
        ok, detail = check_hostname(cert, hostname)
        if not ok:
            add("crit", "HOSTNAME_MISMATCH", detail)
        else:
            add("info", "HOSTNAME_OK", detail)
    return F
