"""Hand-rolled 24-bit uncompressed BMP reader/writer (pure stdlib).

Why BMP: uncompressed raster, so every LSB I write survives byte-for-byte.
No codec, no dependencies, no surprises — ideal carrier for LSB stego work.
"""
import struct


def make_bmp(width, height, pixels):
    """pixels: list of (r,g,b) rows, top row first. Returns BMP bytes."""
    row_bytes = width * 3
    pad = (4 - row_bytes % 4) % 4
    body = bytearray()
    for row in reversed(pixels):          # BMP stores rows bottom-up
        for (r, g, b) in row:
            body += bytes((b, g, r))          # BMP stores BGR
        body += b"\x00" * pad
    dib = struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0,
                      len(body), 2835, 2835, 0, 0)
    header = struct.pack("<2sIHHI", b"BM", 54 + len(body), 0, 0, 54)
    return header + dib + bytes(body)


def read_bmp(data):
    """Returns (width, height, pixels) with pixels as list of (r,g,b) rows, top row first."""
    assert data[:2] == b"BM", "not a BMP"
    offset = struct.unpack("<I", data[10:14])[0]
    dib = struct.unpack("<IIIHHIIIIII", data[14:54])
    (hsz, width, height, planes, bpp, comp) = dib[:6]
    assert hsz == 40 and bpp == 24 and comp == 0, "need uncompressed 24-bit"
    row_bytes = width * 3
    pad = (4 - row_bytes % 4) % 4
    stride = row_bytes + pad
    pixels = []
    for y in range(height):
        row_off = offset + (height - 1 - y) * stride   # BMP rows are bottom-up
        row = []
        for x in range(width):
            b, g, r = data[row_off + x * 3: row_off + x * 3 + 3]
            row.append((r, g, b))
        pixels.append(row)
    return width, height, pixels


def flatten(pixels):
    """Rows of (r,g,b) -> flat list of channel bytes."""
    return [c for row in pixels for (r, g, b) in row for c in (r, g, b)]


def unflatten(width, height, flat):
    """Inverse of flatten -> rows of (r,g,b)."""
    it = iter(flat)
    return [[(next(it), next(it), next(it)) for _ in range(width)]
            for _ in range(height)]
