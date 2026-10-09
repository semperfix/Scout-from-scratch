#!/usr/bin/env python3
"""dnscheck: entry-point CLI for the dns-internals skill.

  --parse HEX    decode a hex DNS wire message and pretty-print it
  --build NAME   build a query packet (prints hex); --qtype A/AAAA/MX/...
  --file PATH    parse a captured DNS packet from a file
  --dga DOMAIN   score a domain with the DGA/tunneling heuristic
                 (entropy + consonant-ratio + digit-ratio per label)
"""
import argparse
import math
import sys

from dns import build_query, parse_message, format_message


# ---------------------------------------------------------------------------
# DGA / DNS-tunneling heuristic (statistical flag, NOT a classifier)
# ---------------------------------------------------------------------------

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return max(0.0, -sum(c / len(s) * math.log2(c / len(s)) for c in freq.values()))


def score_label(label):
    """Return (score 0..1, metrics dict) for one DNS label."""
    lab = label.lower()
    alpha = [c for c in lab if c.isalpha()]
    ent = _entropy(lab)
    cons = (sum(c in CONSONANTS for c in alpha) / len(alpha)) if alpha else 0.0
    digits = sum(c.isdigit() for c in lab) / len(lab) if lab else 0.0
    # normalized components (english text ~= low, random ~= high)
    e_n = min(1.0, max(0.0, (ent - 2.0) / 2.5))          # entropy 2.0->4.5
    c_n = min(1.0, max(0.0, (cons - 0.55) / 0.35))        # cons ratio .55->.90
    d_n = min(1.0, digits * 2.0)                          # digit-heavy labels
    l_n = min(1.0, max(0.0, (len(lab) - 12) / 28))        # len 12->40
    score = 0.40 * e_n + 0.25 * c_n + 0.20 * d_n + 0.15 * l_n
    return score, {"entropy": round(ent, 2), "consonant_ratio": round(cons, 2),
                   "digit_ratio": round(digits, 2), "length": len(lab)}


def dga_assess(domain):
    """Score each label; the domain score is the max label score."""
    labels = [l for l in domain.lower().rstrip(".").split(".") if l]
    scored = [(l, *score_label(l)) for l in labels]
    worst = max(scored, key=lambda t: t[1]) if scored else ("", 0, {})
    score = worst[1]
    verdict = ("DGA/TUNNEL-LIKELY" if score > 0.60 else
               "SUSPICIOUS" if score > 0.35 else "likely-legit")
    return scored, worst[0], round(score, 3), verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dnscheck",
        description="Inspect DNS wire-format packets and score domains with "
                    "a DGA/tunneling heuristic. Fully offline.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--parse", metavar="HEX", help="decode a hex wire message")
    g.add_argument("--build", metavar="NAME", help="build a query packet (hex out)")
    g.add_argument("--file", metavar="PATH", help="parse a captured packet file")
    g.add_argument("--dga", metavar="DOMAIN", help="DGA/tunneling heuristic score")
    ap.add_argument("--qtype", default="A", help="query type for --build (default A)")
    ap.add_argument("--qid", default="0x1234", help="query id for --build (hex)")
    args = ap.parse_args(argv)

    if args.build:
        qid = int(args.qid, 16) if args.qid.startswith("0x") else int(args.qid)
        wire = build_query(args.build, args.qtype, qid=qid)
        print(wire.hex())
        return 0
    if args.parse:
        try:
            data = bytes.fromhex(args.parse)
        except ValueError:
            sys.exit("error: --parse needs a hex string")
        print(format_message(parse_message(data)))
        return 0
    if args.file:
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except OSError as e:
            sys.exit(f"error: {e}")
        print(f"# {args.file} ({len(data)} bytes)")
        print(format_message(parse_message(data)))
        return 0
    if args.dga:
        scored, worst, score, verdict = dga_assess(args.dga)
        print(f"domain: {args.dga}")
        for label, s, m in scored:
            print(f"  label {label!r:34} score={s:.3f} "
                  f"entropy={m['entropy']} cons={m['consonant_ratio']} "
                  f"digits={m['digit_ratio']} len={m['length']}")
        print(f"worst label: {worst!r}  overall={score}  VERDICT: {verdict}")
        print("(heuristic only -- high entropy also matches CDNs, URL shorteners, "
              "and some legit generated hostnames)")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
