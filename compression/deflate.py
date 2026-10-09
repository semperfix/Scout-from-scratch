"""DEFLATE decompressor from scratch (RFC 1951), plus a gzip wrapper (RFC 1952).

Supports: stored blocks, fixed Huffman blocks, dynamic Huffman blocks
(code-length alphabet 16/17/18 repeats, canonical rebuild). LZ77 matches
with overlapping copies.

The dynamic-block code-length code itself is Huffman-coded, and the length
alphabet is permuted by CL_ORDER -- the whole thing is Huffman codes
describing Huffman codes describing the data. Turtles all the way down.
"""
from bits import BitReader, BitWriter
from huffman import HuffmanDecoder, canonical_codes, reverse_bits

# RFC 1951 3.2.7: permutation of the code-length alphabet
CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

# length code 257..285 -> (base length, extra bits)
LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
               35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]

# distance code 0..29 -> (base distance, extra bits)
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
             257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
             8193, 12289, 16385, 24577]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
              7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]


def _fixed_tables():
    litlen = {}
    for s in range(0, 144):
        litlen[s] = 8
    for s in range(144, 256):
        litlen[s] = 9
    for s in range(256, 280):
        litlen[s] = 7
    for s in range(280, 288):
        litlen[s] = 8
    dist = {s: 5 for s in range(32)}
    return (HuffmanDecoder(canonical_codes(litlen)),
            HuffmanDecoder(canonical_codes(dist)))

_FIXED_LITLEN, _FIXED_DIST = _fixed_tables()


def _read_dynamic_tables(r):
    hlit = r.read_bits(5) + 257   # # of literal/length codes
    hdist = r.read_bits(5) + 1    # # of distance codes
    hclen = r.read_bits(4) + 4    # # of code-length codes
    cl_lens = {}
    for i in range(hclen):
        cl_lens[CL_ORDER[i]] = r.read_bits(3)
    cl_dec = HuffmanDecoder(canonical_codes(cl_lens))
    # now read hlit+hdist code lengths using the code-length code
    lengths = []
    while len(lengths) < hlit + hdist:
        sym = cl_dec.decode_symbol(r)
        if sym <= 15:
            lengths.append(sym)
        elif sym == 16:
            rep = r.read_bits(2) + 3
            lengths += [lengths[-1]] * rep
        elif sym == 17:
            rep = r.read_bits(3) + 3
            lengths += [0] * rep
        elif sym == 18:
            rep = r.read_bits(7) + 11
            lengths += [0] * rep
        else:
            raise ValueError("bad code-length symbol")
    if len(lengths) != hlit + hdist:
        raise ValueError("length count mismatch")
    litlen = {s: lengths[s] for s in range(hlit)}
    dist = {s: lengths[hlit + s] for s in range(hdist)}
    return HuffmanDecoder(canonical_codes(litlen)), HuffmanDecoder(canonical_codes(dist))


def _decode_block(r, litlen_dec, dist_dec, out):
    while True:
        sym = litlen_dec.decode_symbol(r)
        if sym < 256:
            out.append(sym)
        elif sym == 256:
            return
        else:
            li = sym - 257
            length = LENGTH_BASE[li] + r.read_bits(LENGTH_EXTRA[li])
            dsym = dist_dec.decode_symbol(r)
            if dsym > 29:
                raise ValueError(f"invalid distance symbol {dsym}")
            dist = DIST_BASE[dsym] + r.read_bits(DIST_EXTRA[dsym])
            if dist > len(out):
                raise ValueError("distance too far back")
            for _ in range(length):
                out.append(out[-dist])  # overlapping copy = correct LZ77


def decompress_raw(data):
    """Decompress a raw DEFLATE stream (no zlib/gzip wrapper)."""
    r = BitReader(data)
    out = bytearray()
    while True:
        bfinal = r.read_bit()
        btype = r.read_bits(2)
        if btype == 0b00:  # stored
            r.align()
            length = int.from_bytes(r.read_bytes(2), 'little')
            nlen = int.from_bytes(r.read_bytes(2), 'little')
            if length ^ nlen != 0xFFFF:
                raise ValueError("stored block LEN/NLEN mismatch")
            out += r.read_bytes(length)
        elif btype == 0b01:  # fixed Huffman
            _decode_block(r, _FIXED_LITLEN, _FIXED_DIST, out)
        elif btype == 0b10:  # dynamic Huffman
            litlen_dec, dist_dec = _read_dynamic_tables(r)
            _decode_block(r, litlen_dec, dist_dec, out)
        else:
            raise ValueError("reserved BTYPE 0b11")
        if bfinal:
            return bytes(out)


def decompress_gzip(data):
    """Decompress a .gz member; verifies magic, method, CRC32 and ISIZE."""
    import binascii
    if data[:2] != b'\x1f\x8b':
        raise ValueError("not a gzip stream")
    if data[2] != 8:
        raise ValueError(f"unknown gzip method {data[2]}")
    flg = data[3]
    pos = 10
    if flg & 0x04:  # FEXTRA
        xlen = int.from_bytes(data[pos:pos + 2], 'little')
        pos += 2 + xlen
    if flg & 0x08:  # FNAME
        pos = data.index(b'\x00', pos) + 1
    if flg & 0x10:  # FCOMMENT
        pos = data.index(b'\x00', pos) + 1
    if flg & 0x02:  # FHCRC
        pos += 2
    body = data[pos:-8]
    crc_stored, isize = int.from_bytes(data[-8:-4], 'little'), int.from_bytes(data[-4:], 'little')
    out = decompress_raw(body)
    if binascii.crc32(out) & 0xFFFFFFFF != crc_stored:
        raise ValueError("gzip CRC32 mismatch")
    if len(out) & 0xFFFFFFFF != isize:
        raise ValueError("gzip ISIZE mismatch")
    return out


# ---------------------------------------------------------------- encoder
# A simple DEFLATE *encoder*: LZ77 tokenize, then emit fixed-Huffman blocks.
# Enough to prove the format understanding round-trips through a real
# decoder (system gzip / zlib).

def _fixed_litlen_code(sym):
    """Return (reversed_code, length) for fixed Huffman literal/length sym."""
    if 0 <= sym <= 143:
        length = 8
        code = 0b00110000 + sym
    elif 144 <= sym <= 255:
        length = 9
        code = 0b110010000 + (sym - 144)
    elif 256 <= sym <= 279:
        length = 7
        code = sym - 256
    elif 280 <= sym <= 287:
        length = 8
        code = 0b11000000 + (sym - 280)
    else:
        raise ValueError(sym)
    return reverse_bits(code, length), length


def _fixed_dist_code(sym):
    return reverse_bits(sym, 5), 5


def _length_code(length):
    for i, (base, extra) in enumerate(zip(LENGTH_BASE, LENGTH_EXTRA)):
        if base <= length <= base + (1 << extra) - 1:
            return 257 + i, (length - base, extra)
    raise ValueError(length)


def _dist_code(dist):
    for i, (base, extra) in enumerate(zip(DIST_BASE, DIST_EXTRA)):
        if base <= dist <= base + (1 << extra) - 1:
            return i, (dist - base, extra)
    raise ValueError(dist)


def compress_fixed(data, tokens=None):
    """Encode data as a single fixed-Huffman DEFLATE block. Returns raw
    DEFLATE bytes (wrap with gzip_header() for a .gz file)."""
    from lz77 import tokenize
    if tokens is None:
        tokens = tokenize(data)
    w = BitWriter()
    w.write_bits(1, 1)      # BFINAL
    w.write_bits(0b01, 2)   # BTYPE = fixed Huffman
    for tok in tokens:
        if tok[0] == 'lit':
            code, length = _fixed_litlen_code(tok[1])
            w.write_bits(code, length)
        else:
            _, dist, length = tok
            lsym, (lextra_val, lextra_n) = _length_code(length)
            code, clen = _fixed_litlen_code(lsym)
            w.write_bits(code, clen)
            if lextra_n:
                w.write_bits(lextra_val, lextra_n)
            dsym, (dextra_val, dextra_n) = _dist_code(dist)
            code, dlen = _fixed_dist_code(dsym)
            w.write_bits(code, dlen)
            if dextra_n:
                w.write_bits(dextra_val, dextra_n)
    code, length = _fixed_litlen_code(256)  # end of block
    w.write_bits(code, length)
    return w.bytes()


def gzip_wrap(raw_deflate, mtime=0, fname=None):
    import binascii
    hdr = bytearray(b'\x1f\x8b\x08')
    flg = 0x08 if fname else 0x00
    hdr.append(flg)
    hdr += mtime.to_bytes(4, 'little')
    hdr += b'\x00\xff'  # XFL=0, OS=255 (unknown)
    if fname:
        hdr += fname.encode() + b'\x00'
    return bytes(hdr) + raw_deflate
