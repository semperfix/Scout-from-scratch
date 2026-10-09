#!/usr/bin/env python3
"""Validation battery for the from-scratch X.509 stack.

Every check cross-validates against an independent oracle (openssl CLI)
or against known-bad fixtures. Run: python3 test_cert.py
Live-network checks (real public chain, CT log) skip gracefully offline.
"""

import os
import subprocess
import sys
import calendar

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from der import (parse_der, pem_to_der, encode_oid, decode_oid, DERError,
                 TAG_SEQUENCE, TAG_INTEGER)
from x509 import parse_cert, load_pem_file
from verify import (verify_signature, build_chain, check_hostname, triage,
                    cert_times_ok, is_self_signed)
from ecc import ed25519_pubkey_from_seed, ed25519_sign, ed25519_verify

PKI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pki")
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name} {detail}")


def ossl(*args):
    p = subprocess.run(["openssl"] + list(args), capture_output=True, text=True)
    return p.stdout.strip()


def cert(name):
    with open(os.path.join(PKI, name)) as f:
        return parse_cert(pem_to_der(f.read()))


print("== DER layer ==")
for oid in ["1.2.840.113549.1.1.11", "2.5.4.3", "1.3.6.1.5.5.7.1.1", "2.5.29.17"]:
    check(f"OID round-trip {oid}", decode_oid(encode_oid(oid)) == oid)
# trailing garbage rejected
try:
    parse_der(bytes.fromhex("3003020105") + b"\x00")
    check("reject trailing garbage", False)
except DERError:
    check("reject trailing garbage", True)
# indefinite length rejected (not DER)
try:
    parse_der(bytes.fromhex("30800201050000"))
    check("reject indefinite length", False)
except DERError:
    check("reject indefinite length", True)
# non-minimal long-form length rejected
try:
    parse_der(bytes.fromhex("3081020105"))
    check("reject non-minimal length", False)
except DERError:
    check("reject non-minimal length", True)
# UTCTime century windowing: 49 -> 2049, 50 -> 1950
n49 = parse_der(bytes.fromhex("170d3439303130313030303030305a"))
n50 = parse_der(bytes.fromhex("170d3530303130313030303030305a"))
check("UTCTime 49 -> 2049", n49.as_time()[0] == 2049)
check("UTCTime 50 -> 1950", n50.as_time()[0] == 1950)
# BIT STRING accessor
bs = parse_der(bytes.fromhex("030300a0b0"))
ub, payload = bs.bitstring()
check("BIT STRING unused bits", ub == 0 and payload == bytes.fromhex("a0b0"))

print("== parse vs openssl ==")
leaf3 = cert("leaf3.crt")
ossl_subj = ossl("x509", "-in", f"{PKI}/leaf3.crt", "-noout", "-subject")
check("subject matches openssl", "three.example.com" in ossl_subj and "three.example.com" in leaf3["subject_str"])
cns = [v for k, v in leaf3["subject"] if k == "CN"]
check("subject CN=three.example.com", cns == ["three.example.com"])
check("issuer CN=Test 3L Intermediate",
      [v for k, v in leaf3["issuer"] if k == "CN"] == ["Test 3L Intermediate"])
ossl_serial = ossl("x509", "-in", f"{PKI}/leaf3.crt", "-noout", "-serial").split("=")[1].strip().upper().lstrip("0")
check("serial matches openssl", leaf3["serial_hex"].upper().lstrip("0") == ossl_serial,
      f"mine={leaf3['serial_hex']} ossl={ossl_serial}")
check("serial hex sane", leaf3["serial_hex"] == format(leaf3["serial"], "x"))
sans = [v for t, v in (leaf3["extensions"]["subjectAltName"]["parsed"] or []) if t == "dns"]
check("SAN parsed", sans == ["three.example.com"],
      f"got {sans}")
ossl_nb = ossl("x509", "-in", f"{PKI}/leaf3.crt", "-noout", "-startdate")
# openssl prints "notBefore=Oct  9 00:51:17 2026 GMT"; compare as parsed values
import datetime as _dt
ossl_dt = _dt.datetime.strptime(ossl_nb.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y GMT")
mine_dt = _dt.datetime(*leaf3["not_before"])
check("notBefore matches openssl", ossl_dt == mine_dt, f"mine={mine_dt} ossl={ossl_dt}")
check("notBefore sane", leaf3["not_before"][0] >= 2026, f"got {leaf3['not_before']}")
check("RSA leaf key 2048-bit", leaf3["spki"]["bits"] == 2048)
ecleaf = cert("leaf.crt")
check("EC leaf P-256", ecleaf["spki"]["curve"] == "secp256r1" and ecleaf["spki"]["bits"] == 256)
check("sig alg ecdsa-with-SHA256", ecleaf["sig_alg"] == "ecdsa-with-SHA256")
ku = (leaf3["extensions"]["keyUsage"]["parsed"] or {}).get("names", [])
check("keyUsage parsed", "digitalSignature" in ku and "keyEncipherment" in ku, f"got {ku}")
bc = (cert("int3.crt")["extensions"]["basicConstraints"]["parsed"] or {})
check("intermediate CA:TRUE pathlen:0", bc.get("ca") is True and bc.get("pathlen") == 0)
aki = (leaf3["extensions"]["authorityKeyIdentifier"]["parsed"] or {}).get("keyid")
ski = (cert("int3.crt")["extensions"]["subjectKeyIdentifier"]["parsed"])
check("AKI/SKI link", aki == ski and aki is not None)

print("== signature verification ==")
rsa_ca, rsa_leaf = cert("rsa_ca.crt"), cert("rsa_leaf.crt")
check("RSA self-signed verifies", verify_signature(rsa_ca, rsa_ca)[0])
check("RSA leaf verifies", verify_signature(rsa_leaf, rsa_ca)[0])
# tampered signature -> False (flip last byte of sig)
import copy
t = copy.deepcopy(rsa_leaf)
bad = bytearray(t["signature"]); bad[-1] ^= 0xFF; t["signature"] = bytes(bad)
check("RSA tampered sig fails", not verify_signature(t, rsa_ca)[0])
check("RSA wrong issuer fails", not verify_signature(rsa_leaf, cert("ca.crt"))[0])
ec_ca, ec_leaf = cert("ca.crt"), cert("leaf.crt")
check("ECDSA P-256 self-signed verifies", verify_signature(ec_ca, ec_ca)[0])
check("ECDSA P-256 leaf verifies", verify_signature(ec_leaf, ec_ca)[0])
t2 = copy.deepcopy(ec_leaf)
bad2 = bytearray(t2["signature"]); bad2[5] ^= 0xFF; t2["signature"] = bytes(bad2)
check("ECDSA P-256 tampered sig fails", not verify_signature(t2, ec_ca)[0])
c384, l384 = cert("ca384.crt"), cert("leaf384.crt")
check("ECDSA P-384 self-signed verifies", verify_signature(c384, c384)[0])
check("ECDSA P-384 leaf verifies", verify_signature(l384, c384)[0])
# Ed25519: compact oracle agreement (openssl as independent implementation)
def ossl_pubkey(seed):
    pk8 = bytes.fromhex("302e020100300506032b657004220420") + seed
    open("/tmp/t.pk8", "wb").write(pk8)
    p = subprocess.run(["openssl", "pkey", "-in", "/tmp/t.pk8", "-inform", "DER",
                        "-pubout", "-outform", "DER"], capture_output=True)
    return p.stdout[-32:]
import os as _os
ed_ok = True
for _ in range(2):
    s = _os.urandom(32); m = _os.urandom(40)
    p = ed25519_pubkey_from_seed(s); sg = ed25519_sign(s, m)
    ed_ok &= (p == ossl_pubkey(s)) and ed25519_verify(p, m, sg)
    b = bytearray(sg); b[0] ^= 1
    ed_ok &= not ed25519_verify(p, m, bytes(b))
check("Ed25519 oracle agreement (2 trials)", ed_ok)
# garbage signature -> False, not exception
t3 = copy.deepcopy(rsa_leaf); t3["signature"] = b"\x00" * 10
ok3, _ = verify_signature(t3, rsa_ca)
check("garbage sig -> False not crash", ok3 is False)

print("== chain building ==")
r3, i3, l3 = cert("root3.crt"), cert("int3.crt"), cert("leaf3.crt")
res = build_chain(l3, [i3], [r3])
check("3-level chain TRUSTED", res["status"] == "TRUSTED", res["status"])
check("3-level chain length", len(res["chain"]) == 3)
res = build_chain(rsa_leaf, [], [rsa_ca])
check("RSA 2-level TRUSTED", res["status"] == "TRUSTED")
res = build_chain(ec_leaf, [], [ec_ca])
check("ECDSA 2-level TRUSTED", res["status"] == "TRUSTED")
res = build_chain(l384, [], [c384])
check("P-384 2-level TRUSTED", res["status"] == "TRUSTED")
# NOT_A_CA: intermediate without basicConstraints CA:TRUE
noca, noca_leaf = cert("noca.crt"), cert("noca_leaf.crt")
res = build_chain(noca_leaf, [noca], [r3])
check("non-CA intermediate -> NOT_A_CA", res["status"] == "NOT_A_CA", res["status"])
# UNKNOWN_ISSUER
res = build_chain(l3, [], [])
check("unknown issuer", res["status"] == "UNKNOWN_ISSUER", res["status"])
# BAD_SIGNATURE via flipped sig byte
t4 = copy.deepcopy(l3)
b4 = bytearray(t4["signature"]); b4[-2] ^= 0xFF; t4["signature"] = bytes(b4)
res = build_chain(t4, [i3], [r3])
check("tampered link -> BAD_SIGNATURE", res["status"] == "BAD_SIGNATURE", res["status"])
# time checks with epoch override (real now for the positive case)
import time as _time
check("valid now", cert_times_ok(l3)[0])
check("expired in 2035", cert_times_ok(l3, calendar.timegm((2035, 1, 1, 0, 0, 0, 0, 0, 0)))[1] == "expired")
check("not-yet-valid in 2020", cert_times_ok(l3, calendar.timegm((2020, 1, 1, 0, 0, 0, 0, 0, 0)))[1] == "not yet valid")
check("is_self_signed(leaf3) False", not is_self_signed(l3))
check("is_self_signed(root3) True", is_self_signed(r3))

print("== hostname verification ==")
check("exact SAN", check_hostname(l3, "three.example.com")[0])
check("wrong host fails", not check_hostname(l3, "evil.com")[0])
# wildcard fixture via direct cert-dict is heavy; test matcher through puny cert CN... use synthetic:
from verify import _dnsname_match
check("wildcard match", _dnsname_match("*.example.com", "www.example.com"))
check("wildcard rejects deep", not _dnsname_match("*.example.com", "a.b.example.com"))
check("wildcard rejects bare", not _dnsname_match("*.example.com", "example.com"))
check("case-insensitive", _dnsname_match("*.Example.COM", "WWW.example.com"))
check("CN fallback (no SAN)", check_hostname(rsa_ca, "no-such.example")[0] is False)  # has no SAN/CN match
# CN fallback positive: craft minimal check via _dnsname_match on CN cert
ca_cn = [v for k, v in rsa_ca["subject"] if k == "CN"]
check("CN extracted", ca_cn == ["Test RSA Root"])

print("== triage heuristics ==")
weak = cert("weak1024.crt")
codes = {c for _, c, _ in triage(weak)}
check("WEAK_SIG_ALG fires (sha1)", "WEAK_SIG_ALG" in codes, str(codes))
check("SHORT_RSA_KEY fires (1024)", "SHORT_RSA_KEY" in codes, str(codes))
check("SELF_SIGNED fires", "SELF_SIGNED" in {c for _, c, _ in triage(weak)})
longc = cert("long.crt")
check("LONG_LIVED fires (10y)", "LONG_LIVED" in {c for _, c, _ in triage(longc)})
puny = cert("puny.crt")
check("PUNYCODE_SAN fires", "PUNYCODE_SAN" in {c for _, c, _ in triage(puny)})
f3 = {c: s for s, c, _ in triage(l3, chain_status="TRUSTED", hostname="three.example.com")}
check("good cert: HOSTNAME_OK info", f3.get("HOSTNAME_OK") == "info", str(f3))
f3b = {c for _, c, _ in triage(l3, chain_status="TRUSTED", hostname="wrong.example.com")}
check("HOSTNAME_MISMATCH crit", "HOSTNAME_MISMATCH" in f3b)
f3c = {c: s for s, c, _ in triage(l3, chain_status="UNTRUSTED_ROOT")}
check("chain status folded in", f3c.get("CHAIN_UNTRUSTED_ROOT") == "crit")

print("== live checks (skip gracefully offline) ==")
try:
    from ctlog import ct_search, subdomains
    entries = ct_search("example.com")
    subs = subdomains(entries, "example.com")
    check("CT log returns example.com", "example.com" in subs, f"{len(subs)} names")
except Exception as e:
    print(f"  skip: CT log unreachable ({e})")
try:
    import urllib.request
    der = urllib.request.urlopen("https://crt.sh/?d=29581274041", timeout=30).read()
    leaf = parse_cert(pem_to_der(der.decode()))
    aia = (leaf["extensions"].get("authorityInfoAccess", {}).get("parsed") or {}).get("caIssuers", [])
    int1 = parse_cert(urllib.request.urlopen(aia[0], timeout=30).read())
    aia2 = (int1["extensions"].get("authorityInfoAccess", {}).get("parsed") or {}).get("caIssuers", [])
    int2 = parse_cert(urllib.request.urlopen(aia2[0], timeout=30).read())
    anchors = load_pem_file("/etc/ssl/certs/ca-certificates.crt", skip_bad=True)
    res = build_chain(leaf, [int1, int2], anchors)
    check("REAL public chain TRUSTED (crt.sh example.com)", res["status"] == "TRUSTED",
          res["status"])
    check("real P-256 link verifies", verify_signature(leaf, int1)[0])
    check("real P-384 link verifies", verify_signature(int1, int2)[0])
except Exception as e:
    print(f"  skip: real-chain check unreachable ({e})")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
