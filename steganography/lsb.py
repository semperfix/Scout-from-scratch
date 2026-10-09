"""LSB steganography core: embed/extract with length header + CRC32.

Two modes:
  'sequential' - bits go into LSBs in raster order (naive, chi-square bait)
  'spread'     - pixel-channel order shuffled by a password-seeded PRNG
                 (Fisher-Yates with random.Random(password); NOT cryptographic,
                  but defeats the sequential chi-square attack shape)
Payload framing: 4-byte big-endian length + 4-byte CRC32 of payload, then payload.
"""
import random
import zlib
from bmp import flatten, unflatten

HEADER_BYTES = 8  # 4 length + 4 crc


def _order(n, mode, password):
    idx = list(range(n))
    if mode == "spread":
        rng = random.Random(password)
        for i in range(n - 1, 0, -1):
            j = rng.randrange(i + 1)
            idx[i], idx[j] = idx[j], idx[i]
    elif mode != "sequential":
        raise ValueError(mode)
    return idx


def embed(pixels, payload: bytes, mode="sequential", password=""):
    """Returns new flat channel-byte list with payload embedded in LSBs."""
    flat = flatten(pixels)
    frame = len(payload).to_bytes(4, "big") + zlib.crc32(payload).to_bytes(4, "big") + payload
    nbits = len(frame) * 8
    assert nbits <= len(flat), f"payload too big: need {nbits} bits, have {len(flat)}"
    bits = [(frame[i // 8] >> (7 - i % 8)) & 1 for i in range(nbits)]
    out = flat[:]
    order = _order(len(flat), mode, password)
    for k, bit in enumerate(bits):
        p = order[k]
        out[p] = (out[p] & 0xFE) | bit
    return out


def extract(flat, mode="sequential", password=""):
    """Returns payload bytes, or raises ValueError on bad length/CRC."""
    order = _order(len(flat), mode, password)

    def getbits(n):
        vals = [flat[order[i]] & 1 for i in range(n)]
        out = bytearray()
        for i in range(0, n, 8):
            byte = 0
            for b in vals[i:i + 8]:
                byte = (byte << 1) | b
            out.append(byte)
        return bytes(out)

    length = int.from_bytes(getbits(32), "big")
    if length > len(flat) // 8 - HEADER_BYTES:
        raise ValueError(f"implausible length {length}")
    frame = getbits(32 + 32 + length * 8)
    payload = frame[HEADER_BYTES:]
    crc = int.from_bytes(frame[4:8], "big")
    if zlib.crc32(payload) != crc:
        raise ValueError("CRC mismatch - wrong mode/password or not a stego image")
    return payload
