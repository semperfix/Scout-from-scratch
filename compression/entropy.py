"""Information theory measurements: Shannon entropy, redundancy, and a
head-to-head bench of every codec in this directory against real data.

The entropy bound is the referee: no lossless code over an iid symbol model
can average fewer than H bits per symbol. LZ77 beats the bound by modeling
*dependence* between symbols -- that gap is the whole story of compression.
"""
import math
from collections import Counter


def shannon_entropy(data):
    n = len(data)
    if n == 0:
        return 0.0
    freqs = Counter(data)
    return -sum((f / n) * math.log2(f / n) for f in freqs.values())


def histogram(data):
    return Counter(data)


def bits_per_symbol(compressed_len_bytes, original_len):
    return 8.0 * compressed_len_bytes / original_len if original_len else 0.0


def bench(data, label="data"):
    """Run every codec; return a dict of name -> (compressed_bytes, ratio)."""
    from bits import BitWriter
    from huffman import HuffmanEncoder
    from lz77 import tokenize
    from lzw import compress as lzw_c
    from deflate import compress_fixed, decompress_raw
    import zlib

    results = {}
    n = len(data)
    H = shannon_entropy(data)

    # 1. pure Huffman (table stored separately, not counted -- model cost shown)
    enc = HuffmanEncoder(data)
    w = BitWriter()
    enc.encode(data, w)
    huff_bytes = len(w.bytes())
    results['huffman'] = (huff_bytes, huff_bytes / n if n else 0)

    # 2. LZW
    lz = lzw_c(data)
    results['lzw'] = (len(lz), len(lz) / n if n else 0)

    # 3. raw DEFLATE (my fixed-Huffman encoder over LZ77 tokens)
    df = compress_fixed(data)
    results['deflate-fixed(mine)'] = (len(df), len(df) / n if n else 0)

    # 4. reference: real zlib level 9 (dynamic Huffman + optimal parsing)
    zl = zlib.compress(data, 9)
    # strip zlib wrapper (2-byte header, 4-byte adler) to compare raw deflate
    results['deflate-dynamic(zlib)'] = (len(zl) - 6, (len(zl) - 6) / n if n else 0)

    return {
        'label': label,
        'bytes': n,
        'entropy_bps': H,
        'entropy_bytes': H * n / 8,
        'codecs': results,
    }


def report(bench_result):
    b = bench_result
    lines = [f"== {b['label']} ({b['bytes']} bytes) ==",
             f"Shannon entropy: {b['entropy_bps']:.3f} bits/symbol "
             f"(lower bound: {b['entropy_bytes']:.0f} bytes)"]
    for name, (cb, ratio) in b['codecs'].items():
        bps = bits_per_symbol(cb, b['bytes'])
        lines.append(f"  {name:22s} {cb:8d} B  ratio {ratio:.3f}  {bps:.3f} bits/sym")
    return "\n".join(lines)
