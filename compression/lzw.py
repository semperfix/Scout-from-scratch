"""LZW from scratch (the GIF/TIFF/old-Unix-compress dictionary coder).

Variable-width codes starting at 9 bits, dictionary seeded with all 256
single bytes, CLEAR=256 / EOI=257, code width grows 9->12 bits; when the
table fills (4096 entries) we freeze (no clear) — the "no-reset" variant.
Includes the classic KwKwK edge case (code == next available slot).
"""
from bits import BitWriter, BitReader

CLEAR = 256
EOI = 257
MAX_BITS = 12
TABLE_SIZE = 1 << MAX_BITS


def compress(data):
    w = BitWriter()
    # dictionary: bytes -> code
    table = {bytes([i]): i for i in range(256)}
    next_code = 258
    width = 9
    w.write_bits(CLEAR, width)  # LSB-first packing like GIF
    s = b""
    for byte in data:
        c = bytes([byte])
        sc = s + c
        if sc in table:
            s = sc
        else:
            code = table[s]
            w.write_bits(code, width)
            if next_code < TABLE_SIZE:
                table[sc] = next_code
                next_code += 1
                if next_code >= (1 << width) and width < MAX_BITS:
                    width += 1
            s = c
    if s:
        w.write_bits(table[s], width)
    w.write_bits(EOI, width)
    return w.bytes()


def decompress(blob):
    r = BitReader(blob)
    # dictionary: code -> bytes
    table = {i: bytes([i]) for i in range(256)}
    next_code = 258
    width = 9
    out = bytearray()
    prev = None
    while True:
        try:
            code = r.read_bits(width)
        except EOFError:
            break
        if code == CLEAR:
            table = {i: bytes([i]) for i in range(256)}
            next_code = 258
            width = 9
            prev = None
            continue
        if code == EOI:
            break
        if code in table:
            entry = table[code]
        elif code == next_code and prev is not None:
            # KwKwK case: code refers to prev + prev[0]
            entry = prev + prev[:1]
        else:
            raise ValueError(f"bad LZW code {code}")
        out += entry
        if prev is not None and next_code < TABLE_SIZE:
            table[next_code] = prev + entry[:1]
            next_code += 1
            # NOTE: the decoder's table lags the encoder's by exactly one
            # entry (the first code after CLEAR adds nothing: prev is None),
            # so the code width must grow one entry *early* -- when next_code
            # hits 2**width - 1 -- to switch widths on the same bit position
            # the encoder used. Growing at 2**width instead misaligns every
            # subsequent code (caught by fuzz roundtrips).
            if next_code >= (1 << width) - 1 and width < MAX_BITS:
                width += 1
        prev = entry
    return bytes(out)
