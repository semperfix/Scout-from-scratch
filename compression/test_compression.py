#!/usr/bin/env python3
"""Validation for the from-scratch compression stack.

Every check compares against ground truth: system gzip/zlib, mathematical
bounds (entropy, Kraft), or byte-exact roundtrips.
"""
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bits import BitWriter, BitReader
from huffman import (HuffmanEncoder, HuffmanDecoder, build_lengths,
                     canonical_codes, kraft_sum, optimal_avg_length,
                     reverse_bits)
from lz77 import tokenize, detokenize
from lzw import compress as lzw_c, decompress as lzw_d
from deflate import (decompress_raw, decompress_gzip, compress_fixed,
                     _fixed_litlen_code, LENGTH_BASE, DIST_BASE)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def gzip_bytes(data, level=9, name=None):
    """Ground truth: real gzip via the system binary."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        cmd = ['gzip', f'-{level}', '-c']
        if name:
            cmd += ['-N']
        # -N uses the input filename; rename to control FNAME
        if name:
            npath = path + "_" + name
            os.rename(path, npath)
            path = npath
        out = subprocess.run(cmd + [path], capture_output=True, check=True).stdout
        return out
    finally:
        os.unlink(path)


random.seed(20261008)

# ---- 1. bit I/O roundtrip ----
w = BitWriter()
w.write_bits(0b101, 3)
w.write_bits(0xAB, 8)
w.write_bits_msb(0b1101, 4)
blob = w.bytes()
r = BitReader(blob)
check("bit roundtrip", r.read_bits(3) == 0b101 and r.read_bits(8) == 0xAB
      and [r.read_bit() for _ in range(4)] == [1, 1, 0, 1])

# ---- 2. Huffman ----
text = (b"the quick brown fox jumps over the lazy dog. " * 50)
enc = HuffmanEncoder(text)
w = BitWriter()
enc.encode(text, w)
dec = HuffmanDecoder(enc.codes)
r = BitReader(w.bytes())
rt = bytes(dec.decode_symbol(r) for _ in range(len(text)))
check("huffman roundtrip (text)", rt == text)

rnd = bytes(random.randrange(256) for _ in range(3000))
enc2 = HuffmanEncoder(rnd)
w = BitWriter()
enc2.encode(rnd, w)
dec2 = HuffmanDecoder(enc2.codes)
r = BitReader(w.bytes())
check("huffman roundtrip (random)", bytes(dec2.decode_symbol(r) for _ in range(len(rnd))) == rnd)

check("kraft inequality", kraft_sum(enc.lengths) <= 1.0 + 1e-9)
H, avg = optimal_avg_length({b: text.count(b) for b in set(text)})
check("entropy lower bound (avg_len >= H)", avg >= H - 1e-9, f"{avg} vs {H}")
check("huffman near-optimal (avg-H < 1)", avg - H < 1.0, f"{avg - H}")

# canonical codes: RFC 1951 fixed code for literal 0 is 8-bit 0x30 -> packed reversed
code, ln = _fixed_litlen_code(0)
check("fixed code lit 0", (code, ln) == (reverse_bits(0x30, 8), 8))
code, ln = _fixed_litlen_code(256)
check("fixed code EOB", (code, ln) == (0, 7))
code, ln = _fixed_litlen_code(280)
check("fixed code lit 280", ln == 8)

# single-symbol edge case
enc1 = HuffmanEncoder(b"\x41" * 100)
w = BitWriter()
enc1.encode(b"\x41" * 100, w)
dec1 = HuffmanDecoder(enc1.codes)
r = BitReader(w.bytes())
check("huffman single symbol", bytes(dec1.decode_symbol(r) for _ in range(100)) == b"\x41" * 100)

# ---- 3. LZ77 ----
check("lz77 roundtrip text", detokenize(tokenize(text)) == text)
check("lz77 roundtrip random", detokenize(tokenize(rnd)) == rnd)
run = b"A" * 10000
check("lz77 run-length", detokenize(tokenize(run)) == run)
check("lz77 empty", detokenize(tokenize(b"")) == b"")
check("lz77 1 byte", detokenize(tokenize(b"Z")) == b"Z")
check("lz77 overlap copy", detokenize([('lit', 65), ('match', 1, 258)]) == b"A" * 259)
far = b"0123456789ABCDEF" * 3000  # distance reuse across window
check("lz77 windowed", detokenize(tokenize(far)) == far)

# ---- 4. LZW ----
check("lzw roundtrip text", lzw_d(lzw_c(text)) == text)
check("lzw roundtrip random", lzw_d(lzw_c(rnd)) == rnd)
check("lzw roundtrip empty", lzw_d(lzw_c(b"")) == b"")
check("lzw KwKwK trigger", lzw_d(lzw_c(b"A" * 40)) == b"A" * 40)
check("lzw all bytes", lzw_d(lzw_c(bytes(range(256)) * 4)) == bytes(range(256)) * 4)
# fuzz
fuzz_ok = True
for _ in range(30):
    d = bytes(random.randrange(256) for _ in range(random.randrange(1, 800)))
    if lzw_d(lzw_c(d)) != d:
        fuzz_ok = False
        break
check("lzw fuzz 30x", fuzz_ok)

# ---- 5. DEFLATE decode vs system gzip (the crown-jewel tests) ----
cases = {
    "empty": b"",
    "one-byte": b"Q",
    "text": text,
    "random-5k": rnd,
    "run": run,
    "all-bytes": bytes(range(256)) * 20,
    "zeros": b"\x00" * 5000,
    "lorem": ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200).encode(),
}
for cname, data in cases.items():
    for level in (1, 6, 9):  # this gzip build rejects -0; stored blocks are
        # covered separately via zlib.compress(data, 0) below
        gz = gzip_bytes(data, level=level)
        try:
            mine = decompress_gzip(gz)
            good = mine == data
        except Exception as e:  # noqa: BLE001
            good = False
            print(f"         {cname}/L{level} raised {e}")
        check(f"gzip decode {cname} level={level}", good)

# FNAME header path
gz = gzip_bytes(text, name="hello.txt")
check("gzip decode FNAME header", decompress_gzip(gz) == text)

# stored-block-only stream (level 0) exercises BTYPE=00
check("stored block path", decompress_raw(
    __import__('zlib').compress(text, 0)[2:-4]) == text)

# fixed-block stream from my encoder decoded by *system* zlib: proves my
# emitted bitstream is standards-conformant, not just self-consistent
import zlib
for cname, data in cases.items():
    mine_raw = compress_fixed(data)
    try:
        sys_out = zlib.decompress(mine_raw, -15)
        good = sys_out == data
    except Exception as e:  # noqa: BLE001
        good = False
        print(f"         {cname} raised {e}")
    check(f"system-zlib decodes my encoder: {cname}", good)

# my decoder on my encoder
for cname, data in cases.items():
    check(f"self roundtrip deflate: {cname}", decompress_raw(compress_fixed(data)) == data)

# corruption detection: flip bits inside the actual DEFLATE body (past the
# gzip header incl. FNAME) -> must raise, never silently return garbage
gz = bytearray(gzip_bytes(text))
# locate the deflate body: skip 10-byte header + NUL-terminated FNAME
body_start = bytes(gz).index(b'\x00', 10) + 1
body_end = len(gz) - 8  # before CRC32+ISIZE trailer
corrupt_ok = True
for off in range(0, min(12, body_end - body_start - 1)):
    mut = bytearray(gz)
    mut[body_start + off] ^= 0x40
    try:
        out = decompress_gzip(bytes(mut))
        if out == text:
            print(f"         body flip @{off}: decoded IDENTICALLY (suspicious)")
            corrupt_ok = False
        # else: decoded to *different* bytes but CRC passed?? impossible here
        # since decompress_gzip verifies CRC32; reaching this means no raise
        # but wrong output -- treat as failure
        corrupt_ok = False
    except Exception:  # noqa: BLE001
        pass
check("corrupt gzip body raises", corrupt_ok)

# bad magic rejected
try:
    decompress_gzip(b"not a gzip stream at all........")
    check("bad magic rejected", False)
except ValueError:
    check("bad magic rejected", True)

# ---- 6. compression sanity: real ratios ----
import zlib as _z
for cname, data in [("text", text), ("random", rnd)]:
    mine = len(compress_fixed(data))
    ref = len(_z.compress(data, 9)) - 6
    if cname == "text":
        check("my ratio within 15% of zlib-9 on text", mine <= ref * 1.15,
              f"mine={mine} zlib={ref}")
    else:
        check("incompressible ~stored size", mine <= len(data) * 1.05 + 100,
              f"mine={mine} raw={len(data)}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
