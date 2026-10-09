"""Validation battery for expedition 23: QR code forensics from scratch.

Run: python3 test_qr.py
Covers: GF(256), Reed-Solomon, tables, format/version info, encode/decode
round-trips, segno cross-validation (independent encoder), OpenCV
cross-validation (independent decoder), image detection incl. rotations and
noise, damage resilience, and quishing triage.
"""
import random
import sys

import numpy as np
from PIL import Image

from gf256 import mul, div, inv, EXP, LOG
from rs import rs_encode, rs_decode, rs_check, RSDecodeError
from qr_tables import VERSIONS, format_bits, version_bits, data_capacity
from qr_codec import (encode, decode_matrix, build_function_matrix,
                      dimension, QRError)
from qr_render import render, flip_data_modules, paste_patch
from qr_detect import detect, QRDetectError
from qr_triage import triage_image, score_url, classify

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print(f"  FAIL: {name} {detail}")


def main():
    print("== GF(256) ==")
    for a in range(1, 256):
        assert EXP[LOG[a]] == a
    check("exp/log round-trip", True)
    check("alpha primitive (period 255)", EXP[255] == 1 and all(EXP[i] != 1 for i in range(1, 255)))
    check("mul/inv", all(mul(a, inv(a)) == 1 for a in (1, 2, 17, 99, 255)))

    print("== Reed-Solomon ==")
    random.seed(1234)
    ok = True
    for _ in range(400):
        k = random.randint(1, 60)
        nsym = random.choice([7, 10, 13, 15, 17, 18, 20, 22, 24, 26, 28, 30])
        data = [random.randrange(256) for _ in range(k)]
        cw = rs_encode(data, nsym)
        assert rs_check(cw, nsym)
        nerr = random.randint(0, nsym // 2)
        bad = list(cw)
        for p in random.sample(range(len(cw)), nerr):
            bad[p] ^= random.randint(1, 255)
        fixed, n = rs_decode(bad, nsym)
        if fixed != cw or n != nerr:
            ok = False
            break
    check("RS fuzz 400 trials (correct count + recovery)", ok)
    loud = 0
    for _ in range(40):
        data = [random.randrange(256) for _ in range(20)]
        cw = rs_encode(data, 10)
        bad = list(cw)
        for p in random.sample(range(30), 8):
            bad[p] ^= 0xFF
        try:
            rs_decode(bad, 10)
        except RSDecodeError:
            loud += 1
    check("beyond capacity fails loudly", loud == 40, f"{loud}/40")

    print("== tables ==")
    ok = True
    for v, t in VERSIONS.items():
        for ec, (ecpb, groups) in t["ec"].items():
            if sum(n * (k + ecpb) for n, k in groups) != t["total"]:
                ok = False
    check("block-table invariant (40 rows sum to total)", ok)
    check("format info: 32 codewords distinct",
          len({tuple(format_bits(e, m)) for e in "LMQH" for m in range(8)}) == 32)
    check("version info: 18 bits each", all(len(version_bits(v)) == 18 for v in (7, 10)))

    print("== self round-trip ==")
    payloads = [b"HELLO WORLD", b"1234567890" * 4, b"https://example.com/a?b=1",
                "ünïcodé ✓".encode(), b"A" * 150, b"X" * 250, b"", b"1",
                bytes(range(1, 256))]
    n = 0
    for p in payloads:
        for ec in "LMQH":
            try:
                m, info = encode(p, ec)
            except QRError:
                continue
            back, dinfo = decode_matrix(m)
            assert back == p and dinfo["eclevel"] == ec
            assert dinfo["version"] == info["version"] and dinfo["mask"] == info["mask"]
            n += 1
    check(f"encode->decode round-trip ({n} cases)", n > 30)
    try:
        encode(b"Z" * 500, "H")
        check("oversize rejected", False)
    except QRError:
        check("oversize rejected", True)

    print("== segno cross-validation (independent encoder) ==")
    import segno

    def ver(q):
        v = q.version
        return int(v) if isinstance(v, str) and v.isdigit() else v

    n = 0
    for p in ["HELLO WORLD", "1234567890" * 3, "https://example.com/x?y=2",
              "ünïcodé ✓", "A" * 100, "z" * 200, "MIXED case 123!"]:
        for ec in "lmqh":
            q = segno.make(p, error=ec, boost_error=False)
            v = ver(q)
            if not isinstance(v, int) or v > 10:
                continue
            back, info = decode_matrix([list(row) for row in q.matrix])
            assert back == p.encode() and info["version"] == v
            assert info["eclevel"] == q.error
            n += 1
    check(f"segno matrix -> my decoder ({n} cases)", n > 15)
    # function modules bit-identical (this caught the real finder bug)
    probes = {1: "probe", 2: "probe", 5: "probe-" * 8, 7: "probe-" * 20, 10: "probe-" * 30}
    ok = True
    for v, probe in probes.items():
        q = segno.make(probe, error="m", version=v, boost_error=False)
        sm = [list(row) for row in q.matrix]
        dim = dimension(v)
        vals, _ = build_function_matrix(v)
        if v >= 7:
            from qr_codec import place_version_info
            place_version_info(vals, dim, v)
        bad = [(r, c) for r in range(dim) for c in range(dim)
               if vals[r][c] is not None and vals[r][c] != sm[r][c]]
        if bad:
            ok = False
    check("function modules bit-identical vs segno (v1,2,5,7,10)", ok)

    print("== opencv cross-validation (independent decoder) ==")
    import cv2
    det = cv2.QRCodeDetector()
    n = 0
    for p in [b"HELLO WORLD", b"https://example.com/x?y=2", "ünïcodé ✓".encode(),
              b"A" * 100, b"0123456789" * 20]:
        for ec in "LMQH":
            try:
                m, _ = encode(p, ec)
            except QRError:
                continue
            data, _, _ = det.detectAndDecode(np.asarray(render(m, scale=10, quiet=4)))
            assert data.encode() == p, (p[:20], ec, data[:20])
            n += 1
    check(f"my encoder -> opencv decoder ({n} cases)", n > 15)

    print("== image detection ==")
    n = 0
    for p in [b"HELLO WORLD", b"https://example.com/pay?to=1", "ünïcodé ✓".encode(), b"A" * 120]:
        for ec in "LMQH":
            try:
                m, info = encode(p, ec)
            except QRError:
                continue
            m2, dinfo = detect(render(m, scale=8, quiet=4))
            back, binfo = decode_matrix(m2)
            assert back == p and binfo["version"] == info["version"]
            n += 1
    check(f"render->detect->decode ({n} cases)", n > 10)
    m, _ = encode(b"rotation test", "M")
    img = render(m, scale=8, quiet=6)
    ok = True
    for angle in (90, 180, 270):
        back, _ = decode_matrix(detect(img.rotate(angle, expand=True))[0])
        ok = ok and back == b"rotation test"
    check("90/180/270 rotation", ok)
    m, _ = encode(b"noisy sim", "Q")
    r = render(m, scale=6, quiet=4).rotate(7, expand=True, fillcolor="white")
    arr = np.asarray(r).astype(float)
    arr = np.clip(arr + np.random.default_rng(0).normal(0, 18, arr.shape), 0, 255).astype(np.uint8)
    back, _ = decode_matrix(detect(Image.fromarray(arr))[0])
    check("7-degree rotation + noise", back == b"noisy sim")

    print("== damage resilience ==")
    m, info = encode(b"damage resilience demo payload", "Q")
    _, func = build_function_matrix(info["version"])
    ok = True
    for nflips, seed in ((5, 1), (12, 2)):
        d = flip_data_modules(m, func, nflips, seed=seed)
        back, di = decode_matrix(d)
        ok = ok and back == b"damage resilience demo payload" and di["ec_corrected"] <= di["ec_capacity"]
    check("random flips corrected, count reported", ok)
    d = paste_patch(m, 13, 13, 6, 6, value=0)
    back, di = decode_matrix(d)
    check("6x6 patch (sticker) still decodes", back == b"damage resilience demo payload")
    d = flip_data_modules(m, func, 400, seed=99)
    try:
        decode_matrix(d)
        check("beyond capacity fails loudly", False)
    except (QRError, RSDecodeError):
        check("beyond capacity fails loudly", True)

    print("== quishing triage ==")
    check("punycode flagged high", any(s == "high" and "punycode" in f for s, f in score_url("https://xn--exmple-cua.com/")))
    check("IP host flagged high", any(s == "high" and "IP-literal" in f for s, f in score_url("http://10.0.0.1/x")))
    check("@ trick flagged high", any(s == "high" and "@" in f for s, f in score_url("https://a.com@b.com/")))
    check("shortener flagged", any("shortener" in f for _, f in score_url("https://bit.ly/abc")))
    check("benign URL clean", score_url("https://example.com/menu") == [])
    check("classify wifi", classify(b"WIFI:T:WPA;S:x;P:y;;")[0] == "wifi")
    check("classify bitcoin", classify(b"bitcoin:abc123")[0] == "bitcoin")
    m, _ = encode(b"https://xn--exmple-cua.com/login", "M")
    render(m, scale=8, quiet=4, path="/tmp/qr_triage_test.png")
    rep = triage_image("/tmp/qr_triage_test.png")
    check("end-to-end triage SUSPICIOUS", rep["ok"] and rep["verdict"] == "SUSPICIOUS")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failures:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
