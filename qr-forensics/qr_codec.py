"""QR matrix construction, encoding, and matrix-level decoding.

Matrix representation: list of lists, values 0 (light) / 1 (dark).
Function-module map built identically for encode and decode.
Zero dependencies (uses qr_tables, rs).
"""
from qr_tables import (VERSIONS, EC_BITS, EC_LEVELS, MODES, MODE_NAMES,
                       ALPHANUMERIC_CHARSET, ALPHANUMERIC_MAP, MASKS,
                       format_bits, version_bits, all_format_codewords,
                       data_capacity, count_bits_for)
from rs import rs_encode, rs_decode, RSDecodeError


class QRError(Exception):
    pass


def dimension(version):
    return 17 + 4 * version


def version_from_dimension(dim):
    if (dim - 17) % 4 != 0:
        raise QRError(f"dimension {dim} is not a valid QR size")
    v = (dim - 17) // 4
    if not 1 <= v <= 40:
        raise QRError(f"version {v} out of range")
    return v


# --------------------------------------------------------------------------
# function patterns
# --------------------------------------------------------------------------

def _finder(vals, func, r0, c0):
    # 7x7: dark outer ring (d==3), light ring (d==2), dark 3x3 center (d<=1)
    for dr in range(7):
        for dc in range(7):
            d = max(abs(dr - 3), abs(dc - 3))
            vals[r0 + dr][c0 + dc] = 1 if d != 2 else 0
            func[r0 + dr][c0 + dc] = True


def _separator(vals, func, dim, r0, c0):
    # white ring around the 7x7 finder at (r0,c0): row r0+7 / r0-1, col c0+7 / c0-1
    r1 = r0 + 7 if r0 == 0 else r0 - 1
    c1 = c0 + 7 if c0 == 0 else c0 - 1
    rr = range(r0 - 1, r0 + 8) if r0 != 0 else range(0, 8)
    cc = range(c0 - 1, c0 + 8) if c0 != 0 else range(0, 8)
    for r in rr:
        if 0 <= r < dim and 0 <= c1 < dim and not func[r][c1]:
            vals[r][c1] = 0
            func[r][c1] = True
    for c in cc:
        if 0 <= r1 < dim and 0 <= c < dim and not func[r1][c]:
            vals[r1][c] = 0
            func[r1][c] = True


def build_function_matrix(version):
    """Returns (vals, is_func). vals has 0/1 on function modules, None elsewhere."""
    dim = dimension(version)
    vals = [[None] * dim for _ in range(dim)]
    func = [[False] * dim for _ in range(dim)]

    # finders + separators
    for (r0, c0) in ((0, 0), (0, dim - 7), (dim - 7, 0)):
        _finder(vals, func, r0, c0)
    for (r0, c0) in ((0, 0), (0, dim - 7), (dim - 7, 0)):
        _separator(vals, func, dim, r0, c0)

    # timing
    for i in range(8, dim - 8):
        v = 1 if i % 2 == 0 else 0
        vals[6][i] = v
        func[6][i] = True
        vals[i][6] = v
        func[i][6] = True

    # alignment patterns
    apos = VERSIONS[version]["align"]
    for r in apos:
        for c in apos:
            # skip the three finder corners
            if (r == 6 or r == apos[-1]) and (c == 6 or c == apos[-1]):
                if (r, c) in ((6, 6), (6, apos[-1]), (apos[-1], 6)):
                    continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    d = max(abs(dr), abs(dc))
                    vals[r + dr][c + dc] = 1 if (d == 2 or d == 0) else 0
                    func[r + dr][c + dc] = True

    # dark module
    vals[dim - 8][8] = 1
    func[dim - 8][8] = True

    # reserve format-info cells (values filled later)
    p1, p2 = _format_positions(dim)
    for (r, c) in p1 + p2:
        func[r][c] = True
    # reserve version-info cells (v7+)
    if version >= 7:
        for r in range(6):
            for c in range(dim - 11, dim - 8):
                func[r][c] = True
                vals[r][c] = 0  # placeholder, filled by place_version_info
        for r in range(dim - 11, dim - 8):
            for c in range(6):
                func[r][c] = True
                vals[r][c] = 0
    return vals, func


def _format_positions(dim):
    p1 = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
          (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    p2 = ([(dim - 1 - i, 8) for i in range(7)] +
          [(8, dim - 8 + i) for i in range(8)])
    return p1, p2


def place_format_info(vals, dim, eclevel, mask):
    bits = format_bits(eclevel, mask)
    p1, p2 = _format_positions(dim)
    for (r, c), b in zip(p1, bits):
        vals[r][c] = b
    for (r, c), b in zip(p2, bits):
        vals[r][c] = b


def place_version_info(vals, dim, version):
    """18-bit codeword placed LSB-first, row-major: bit i at
    (i//3, dim-11 + i%3); bottom-left block is the transpose.
    (Placement verified bit-for-bit against segno's independent encoder.)"""
    bits = version_bits(version)[::-1]  # LSB-first
    for i in range(18):
        r, c = i // 3, (dim - 11) + i % 3
        vals[r][c] = bits[i]  # top-right 6x3 block
        vals[c][r] = bits[i]  # bottom-left 3x6 block (transpose)


# --------------------------------------------------------------------------
# data placement zigzag
# --------------------------------------------------------------------------

def data_module_order(vals, func):
    """Zigzag placement order over non-function modules: list of (r, c)."""
    dim = len(vals)
    order = []
    col = dim - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(dim - 1, -1, -1) if upward else range(dim)
        for r in rows:
            for c in (col, col - 1):
                if not func[r][c]:
                    order.append((r, c))
        upward = not upward
        col -= 2
    return order


# --------------------------------------------------------------------------
# encoder
# --------------------------------------------------------------------------

def _pick_mode(payload: bytes):
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return "byte", None
    if all(ch.isdigit() for ch in text):
        return "numeric", text
    if all(ch in ALPHANUMERIC_MAP for ch in text):
        return "alphanumeric", text
    return "byte", None


def _encode_bits(mode, text, payload, version):
    bits = []

    def put(val, n):
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)

    put(MODES[mode], 4)
    nbits = count_bits_for(version, mode)
    if mode == "byte":
        put(len(payload), nbits)
        for b in payload:
            put(b, 8)
    else:
        put(len(text), nbits)
        if mode == "numeric":
            i = 0
            while i < len(text):
                chunk = text[i:i + 3]
                put(int(chunk), {3: 10, 2: 7, 1: 4}[len(chunk)])
                i += 3
        elif mode == "alphanumeric":
            i = 0
            while i < len(text):
                if i + 1 < len(text):
                    put(45 * ALPHANUMERIC_MAP[text[i]] + ALPHANUMERIC_MAP[text[i + 1]], 11)
                    i += 2
                else:
                    put(ALPHANUMERIC_MAP[text[i]], 6)
                    i += 1
    return bits


def _finalize_data_codewords(bits, capacity_cw):
    cap_bits = capacity_cw * 8
    # terminator: up to 4 zero bits
    term = min(4, cap_bits - len(bits))
    bits = bits + [0] * term
    # pad to byte
    while len(bits) % 8:
        bits.append(0)
    out = []
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        out.append(b)
    # pad bytes
    for i in range(capacity_cw - len(out)):
        out.append(0xEC if i % 2 == 0 else 0x11)
    return out


def _mask_penalty(vals, func):
    """Standard N1..N4 mask penalty (lower is better)."""
    dim = len(vals)
    score = 0
    # N1: runs of 5+ in rows/cols
    for r in range(dim):
        run = 1
        for c in range(1, dim):
            if vals[r][c] == vals[r][c - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)
    for c in range(dim):
        run = 1
        for r in range(1, dim):
            if vals[r][c] == vals[r - 1][c]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        if run >= 5:
            score += 3 + (run - 5)
    # N2: 2x2 same-color blocks
    for r in range(dim - 1):
        for c in range(dim - 1):
            v = vals[r][c]
            if vals[r][c + 1] == v and vals[r + 1][c] == v and vals[r + 1][c + 1] == v:
                score += 3
    # N3: finder-like patterns 10111010000 / 00001011101
    pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for r in range(dim):
        row = vals[r]
        for c in range(dim - 10):
            seg = row[c:c + 11]
            if seg == pat1 or seg == pat2:
                score += 40
    for c in range(dim):
        col = [vals[r][c] for r in range(dim)]
        for r in range(dim - 10):
            seg = col[r:r + 11]
            if seg == pat1 or seg == pat2:
                score += 40
    # N4: dark ratio
    dark = sum(sum(row) for row in vals)
    pct = dark * 100 / (dim * dim)
    score += 10 * int(abs(pct - 50) // 5)
    return score


def encode(payload: bytes, eclevel="M"):
    """Encode payload -> (matrix, info dict). Smallest version that fits."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    mode, text = _pick_mode(payload)
    version = None
    bitstream = None
    for v in range(1, 11):
        cap = data_capacity(v, eclevel)
        bits = _encode_bits(mode, text, payload, v)
        remaining = cap * 8 - len(bits)
        if remaining < 0:
            continue  # payload bits alone don't fit; try a bigger version
        need = len(bits) + min(4, remaining)  # + terminator
        need = ((need + 7) // 8) * 8  # after byte-padding
        if need <= cap * 8:
            version, bitstream = v, bits
            break
    if version is None:
        raise QRError("payload too large for version 10")
    cap = data_capacity(version, eclevel)
    data_cw = _finalize_data_codewords(bitstream, cap)

    # split into blocks, RS-encode, interleave
    ec_per_block, groups = VERSIONS[version]["ec"][eclevel]
    blocks = []
    off = 0
    for nblocks, k in groups:
        for _ in range(nblocks):
            blocks.append(data_cw[off:off + k])
            off += k
    ec_blocks = [rs_encode(b, ec_per_block)[len(b):] for b in blocks]
    interleaved = []
    maxk = max(len(b) for b in blocks)
    for i in range(maxk):
        for b in blocks:
            if i < len(b):
                interleaved.append(b[i])
    for i in range(ec_per_block):
        for eb in ec_blocks:
            interleaved.append(eb[i])

    dim = dimension(version)
    vals, func = build_function_matrix(version)
    order = data_module_order(vals, func)
    total_cw = VERSIONS[version]["total"]
    assert len(order) == total_cw * 8 + VERSIONS[version]["rem"], (
        len(order), total_cw * 8 + VERSIONS[version]["rem"])
    bitpos = 0
    for (r, c) in order:
        if bitpos < len(interleaved) * 8:
            vals[r][c] = (interleaved[bitpos // 8] >> (7 - bitpos % 8)) & 1
            bitpos += 1
        else:
            vals[r][c] = 0  # remainder bits

    # choose mask by penalty
    best, best_mask = None, 0
    for m in range(8):
        trial = [row[:] for row in vals]
        mf = MASKS[m]
        for r in range(dim):
            for c in range(dim):
                if not func[r][c] and mf(r, c):
                    trial[r][c] ^= 1
        place_format_info(trial, dim, eclevel, m)
        s = _mask_penalty(trial, func)
        if best is None or s < best:
            best, best_mask = s, m
    mf = MASKS[best_mask]
    for r in range(dim):
        for c in range(dim):
            if not func[r][c] and mf(r, c):
                vals[r][c] ^= 1
    place_format_info(vals, dim, eclevel, best_mask)
    if version >= 7:
        place_version_info(vals, dim, version)
    return vals, {"version": version, "eclevel": eclevel, "mask": best_mask,
                  "mode": mode, "dim": dim}


# --------------------------------------------------------------------------
# matrix decoder
# --------------------------------------------------------------------------

def _decode_format(vals, dim):
    p1, p2 = _format_positions(dim)
    reads = []
    for pos in (p1, p2):
        reads.append([vals[r][c] for (r, c) in pos])
    table = all_format_codewords()
    results = []
    for read in reads:
        best = None
        for (ec, m), code in table.items():
            d = sum(a != b for a, b in zip(read, code))
            if best is None or d < best[0]:
                best = (d, ec, m)
        results.append(best)
    # take the copy with fewer errors; require <= 3
    results.sort()
    dist, ec, mask = results[0]
    if dist > 3:
        raise QRError(f"format info uncorrectable (best distance {dist})")
    return ec, mask, dist


def decode_matrix(matrix):
    """Decode a module matrix -> (payload bytes, info dict)."""
    dim = len(matrix)
    version = version_from_dimension(dim)
    if version > 10:
        raise QRError(f"decoder supports versions 1-10, got {version}")
    vals = [row[:] for row in matrix]
    _, func = build_function_matrix(version)
    eclevel, mask, fmt_dist = _decode_format(vals, dim)

    # unmask
    mf = MASKS[mask]
    for r in range(dim):
        for c in range(dim):
            if not func[r][c] and mf(r, c):
                vals[r][c] ^= 1

    # read codewords in zigzag order
    order = data_module_order(vals, func)
    total_cw = VERSIONS[version]["total"]
    bits = [vals[r][c] for (r, c) in order[:total_cw * 8]]
    codewords = []
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        codewords.append(b)

    # deinterleave + RS-correct per block
    ec_per_block, groups = VERSIONS[version]["ec"][eclevel]
    block_data_lens = []
    for nblocks, k in groups:
        block_data_lens += [k] * nblocks
    nblocks = len(block_data_lens)
    data_cw_total = sum(block_data_lens)
    data_part, ec_part = codewords[:data_cw_total], codewords[data_cw_total:]
    blocks = [[] for _ in range(nblocks)]
    it = iter(data_part)
    for i in range(max(block_data_lens)):
        for bi, k in enumerate(block_data_lens):
            if i < k:
                blocks[bi].append(next(it))
    ec_blocks = [[] for _ in range(nblocks)]
    it = iter(ec_part)
    for i in range(ec_per_block):
        for bi in range(nblocks):
            ec_blocks[bi].append(next(it))

    corrected_total = 0
    raw_data = []
    for b, eb in zip(blocks, ec_blocks):
        fixed, nerr = rs_decode(b + eb, ec_per_block)
        corrected_total += nerr
        raw_data += fixed[:len(b)]

    # parse segments
    bits = []
    for byte in raw_data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    payload = bytearray()
    modes_seen = []
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(bits):
            raise QRError(f"segment overruns bitstream at bit {pos} (need {n})")
        v = 0
        for _ in range(n):
            v = (v << 1) | bits[pos]
            pos += 1
        return v

    while pos + 4 <= len(bits):
        mode = take(4)
        if mode == MODES["terminator"]:
            break
        name = MODE_NAMES.get(mode)
        if name is None:
            if mode == 0b0011:  # structured append: skip 16 bits
                pos += 16
                continue
            raise QRError(f"unknown mode {mode:04b} at bit {pos-4}")
        modes_seen.append(name)
        if name == "eci":
            first = take(8)
            if first & 0x80 == 0:
                pass
            elif first & 0xC0 == 0x80:
                take(8)
            else:
                take(16)
            continue
        count = take(count_bits_for(version, name))
        if name == "byte":
            for _ in range(count):
                payload.append(take(8))
        elif name == "numeric":
            n = count
            while n >= 3:
                payload += f"{take(10):03d}".encode()
                n -= 3
            if n == 2:
                payload += f"{take(7):02d}".encode()
            elif n == 1:
                payload += f"{take(4)}".encode()
        elif name == "alphanumeric":
            n = count
            while n >= 2:
                v = take(11)
                payload += (ALPHANUMERIC_CHARSET[v // 45] +
                            ALPHANUMERIC_CHARSET[v % 45]).encode()
                n -= 2
            if n == 1:
                payload += ALPHANUMERIC_CHARSET[take(6)].encode()
        elif name == "kanji":
            raw = bytearray()
            for _ in range(count):
                v = take(13)
                raw += bytes([(v >> 8) & 0xFF, v & 0xFF])
            try:
                payload += raw.decode("shift_jis").encode("utf-8")
            except Exception:
                payload += raw
    return bytes(payload), {
        "version": version, "eclevel": eclevel, "mask": mask,
        "format_errors": fmt_dist, "ec_corrected": corrected_total,
        "ec_capacity": sum(ec_per_block // 2 for _ in block_data_lens),
        "modes": modes_seen, "dim": dim,
    }
