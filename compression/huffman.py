"""Canonical Huffman coding from scratch.

Two views of the same thing:
  1. Adaptive coder: build optimal prefix codes from observed symbol
     frequencies, serialize as a (symbol -> code) table, roundtrip data.
  2. Canonical decoder (the DEFLATE view): given only code *lengths* per
     symbol, rebuild the exact same codes the encoder assigned, per the
     RFC 1951 canonical algorithm. This is what inflate() uses.
"""
import heapq
from collections import Counter


def build_lengths(freqs, max_len=None):
    """Huffman tree via the classic two-queue/heap merge; returns dict
    symbol -> code length. freqs: dict symbol -> count."""
    # heap of (freq, tiebreak, [symbols])
    heap = [(f, i, [s]) for i, (s, f) in enumerate(freqs.items()) if f > 0]
    heapq.heapify(heap)
    if len(heap) == 1:
        return {heap[0][2][0]: 1}
    depths = {s: 0 for s in freqs if freqs[s] > 0}
    n = len(heap)
    while len(heap) > 1:
        f1, _, s1 = heapq.heappop(heap)
        f2, _, s2 = heapq.heappop(heap)
        for s in s1:
            depths[s] += 1
        for s in s2:
            depths[s] += 1
        heapq.heappush(heap, (f1 + f2, n, s1 + s2))
        n += 1
    return depths


def canonical_codes(lengths):
    """RFC 1951 3.2.2: from {symbol: length} build {symbol: (code, length)}
    where codes are assigned in increasing numeric order within each length,
    symbols sorted by length then symbol value. Returns dict symbol ->
    (code_msb_first, length)."""
    # sort by (length, symbol)
    items = sorted(((l, s) for s, l in lengths.items() if l > 0))
    codes = {}
    code = 0
    prev_len = 0
    for length, sym in items:
        code <<= (length - prev_len)
        codes[sym] = (code, length)
        code += 1
        prev_len = length
    return codes


def reverse_bits(code, length):
    """DEFLATE packs Huffman codes LSB-first, so the canonical MSB-first code
    must be bit-reversed before emission."""
    r = 0
    for _ in range(length):
        r = (r << 1) | (code & 1)
        code >>= 1
    return r


class HuffmanEncoder:
    """Builds an optimal table from data and encodes it. The table itself is
    serialized as raw code lengths so a decoder can rebuild canonical codes
    without any tree."""
    def __init__(self, data):
        freqs = Counter(data)
        lengths = build_lengths(freqs)
        self.codes = canonical_codes(lengths)
        self.lengths = lengths

    def encode(self, data, writer):
        for b in data:
            code, length = self.codes[b]
            writer.write_bits(reverse_bits(code, length), length)

    def serialize_table(self):
        # 256 bytes of lengths, one per symbol 0..255
        return bytes(self.lengths.get(s, 0) for s in range(256))

    @staticmethod
    def deserialize_table(raw):
        lengths = {s: raw[s] for s in range(256) if raw[s]}
        return canonical_codes(lengths)


class HuffmanDecoder:
    """Fast-enough canonical decoder: walks bits one at a time against a
    (length, code) lookup. Fine for correctness; a table-driven decoder would
    be the production speedup."""
    def __init__(self, codes):
        # codes: {symbol: (code_msb, length)} -> build reversed-code lookup
        self.table = {}
        for sym, (code, length) in codes.items():
            self.table[(length, reverse_bits(code, length))] = sym

    def decode_symbol(self, reader):
        code = 0
        for length in range(1, 33):
            code |= (reader.read_bit() << (length - 1))
            sym = self.table.get((length, code))
            if sym is not None:
                return sym
        raise ValueError("invalid Huffman code in stream")


def kraft_sum(lengths):
    """Sanity: sum(2^-l) must be <= 1 for a valid prefix code."""
    return sum(2.0 ** -l for l in lengths.values() if l > 0)


def optimal_avg_length(freqs):
    """Entropy lower bound vs Huffman achieved average length."""
    total = sum(freqs.values())
    import math
    entropy = -sum((f / total) * math.log2(f / total) for f in freqs.values())
    lengths = build_lengths(freqs)
    avg = sum((freqs[s] / total) * lengths[s] for s in freqs)
    return entropy, avg
