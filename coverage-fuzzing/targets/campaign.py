#!/usr/bin/env python3
"""Fuzz campaign: DER parser first, then PE parser. Saves minimized crashes."""
import os
import sys
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from fuzzer import Fuzzer
from harness import (target_der, target_pe, DER_DICT, PE_DICT,
                     DERError, PEError, EXP29, EXP19)

FINDINGS = os.path.join(HERE, "..", "findings")


def load_der_seeds():
    seeds = []
    for pat in ["pki/*.crt", "pki/*.der", "*.der", "fixtures/*"]:
        for p in glob.glob(os.path.join(EXP29, pat)):
            try:
                with open(p, "rb") as f:
                    raw = f.read()
                if b"BEGIN" in raw[:64]:
                    for pem in __import__("der").split_pems(raw.decode()):
                        seeds.append(__import__("der").pem_to_der(pem))
                else:
                    seeds.append(raw)
            except Exception:
                pass
    # minimal valid DER seeds so the fuzzer isn't stuck at the front door
    seeds += [b"\x30\x00", b"\x02\x01\x05", b"\x05\x00", b"\x30\x03\x02\x01\x01"]
    return [s for s in seeds if s]


def load_pe_seeds():
    seeds = []
    for p in glob.glob(os.path.join(EXP19, "fixtures", "*")):
        with open(p, "rb") as f:
            seeds.append(f.read())
    for p in glob.glob(os.path.join(EXP19, "*.exe")):
        with open(p, "rb") as f:
            seeds.append(f.read()[:65536])
    # minimal MZ stub
    seeds.append(b"MZ" + b"\x00" * 62)
    return [s for s in seeds if s]


def campaign(name, target, seeds, allowed, expected, dictionary,
             max_execs, max_secs):
    print(f"=== campaign: {name} ({len(seeds)} seeds) ===", flush=True)
    fz = Fuzzer(target, seeds, allowed, expected_exc=expected,
                dictionary=dictionary, timeout=5, seed=0x31)
    fz.run(max_execs=max_execs, max_secs=max_secs, log_every=5000)
    print(fz.report())
    # minimize + save each unique crash
    for i, (sig, c) in enumerate(fz.crashes.items()):
        mini = fz.minimize(c["data"], sig)
        path = os.path.join(FINDINGS, f"{name}_crash{i}.bin")
        with open(path, "wb") as f:
            f.write(mini)
        exc, frames = sig
        print(f"saved {path}: {exc} {len(c['data'])} -> {len(mini)} bytes")
        for fn, fnname, ln in frames[-3:]:
            print(f"    {fn}:{fnname}:{ln}")
    for i, h in enumerate(fz.hangs[:5]):
        path = os.path.join(FINDINGS, f"{name}_hang{i}.bin")
        with open(path, "wb") as f:
            f.write(h)
        print(f"saved hang {path} ({len(h)} bytes)")
    return fz


if __name__ == "__main__":
    os.makedirs(FINDINGS, exist_ok=True)
    which = sys.argv[1] if len(sys.argv) > 1 else "der"
    if which == "der":
        campaign("der", target_der, load_der_seeds(), [EXP29],
                 (DERError,), DER_DICT, 15000, 240)
    elif which == "pe":
        campaign("pe", target_pe, load_pe_seeds(), [EXP19],
                 (PEError,), PE_DICT, 20000, 300)
