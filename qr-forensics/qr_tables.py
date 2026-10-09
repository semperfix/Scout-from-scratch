"""QR code constant tables (ISO 18004), versions 1-10.

Block table verified by the invariant: sum over groups of
nblocks * (data_cw + ec_cw) == total_cw for every row, and total_cw
follows from the module count. Alignment centers and remainder bits
from the spec tables.
"""

# EC level -> 2-bit format-info code
EC_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}
EC_LEVELS = ["L", "M", "Q", "H"]

# version -> dict with total codewords, per-level (ec_per_block, [(nblocks, data_cw)...]),
# alignment pattern centers, remainder bits
VERSIONS = {
    1: dict(total=26, align=[], rem=0,
            ec={"L": (7, [(1, 19)]), "M": (10, [(1, 16)]),
                "Q": (13, [(1, 13)]), "H": (17, [(1, 9)])}),
    2: dict(total=44, align=[6, 18], rem=7,
            ec={"L": (10, [(1, 34)]), "M": (16, [(1, 28)]),
                "Q": (22, [(1, 22)]), "H": (28, [(1, 16)])}),
    3: dict(total=70, align=[6, 22], rem=7,
            ec={"L": (15, [(1, 55)]), "M": (26, [(1, 44)]),
                "Q": (18, [(2, 17)]), "H": (22, [(2, 13)])}),
    4: dict(total=100, align=[6, 26], rem=7,
            ec={"L": (20, [(1, 80)]), "M": (18, [(2, 32)]),
                "Q": (26, [(2, 24)]), "H": (16, [(4, 9)])}),
    5: dict(total=134, align=[6, 30], rem=7,
            ec={"L": (26, [(1, 108)]), "M": (24, [(2, 43)]),
                "Q": (18, [(2, 15), (2, 16)]), "H": (22, [(2, 11), (2, 12)])}),
    6: dict(total=172, align=[6, 34], rem=7,
            ec={"L": (18, [(2, 68)]), "M": (16, [(4, 27)]),
                "Q": (24, [(4, 19)]), "H": (28, [(4, 15)])}),
    7: dict(total=196, align=[6, 22, 38], rem=0,
            ec={"L": (20, [(2, 78)]), "M": (18, [(4, 31)]),
                "Q": (18, [(2, 14), (4, 15)]), "H": (26, [(4, 13), (1, 14)])}),
    8: dict(total=242, align=[6, 24, 42], rem=0,
            ec={"L": (24, [(2, 97)]), "M": (22, [(2, 38), (2, 39)]),
                "Q": (22, [(4, 18), (2, 19)]), "H": (26, [(4, 14), (2, 15)])}),
    9: dict(total=292, align=[6, 26, 46], rem=0,
            ec={"L": (30, [(2, 116)]), "M": (22, [(3, 36), (2, 37)]),
                "Q": (20, [(4, 16), (4, 17)]), "H": (24, [(4, 12), (4, 13)])}),
    10: dict(total=346, align=[6, 28, 50], rem=0,
            ec={"L": (18, [(2, 68), (2, 69)]), "M": (26, [(4, 43), (1, 44)]),
                "Q": (24, [(6, 19), (2, 20)]), "H": (28, [(6, 15), (2, 16)])}),
}

# mode indicators (4 bits)
MODES = {"numeric": 0b0001, "alphanumeric": 0b0010, "byte": 0b0100,
         "kanji": 0b1000, "eci": 0b0111, "terminator": 0b0000}
MODE_NAMES = {v: k for k, v in MODES.items()}

# character-count indicator lengths: (numeric, alphanumeric, byte, kanji)
# by version group
COUNT_BITS = {
    (1, 9):   {"numeric": 10, "alphanumeric": 9, "byte": 8, "kanji": 8},
    (10, 26): {"numeric": 12, "alphanumeric": 11, "byte": 16, "kanji": 10},
    (27, 40): {"numeric": 14, "alphanumeric": 13, "byte": 16, "kanji": 12},
}

ALPHANUMERIC_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
ALPHANUMERIC_MAP = {c: i for i, c in enumerate(ALPHANUMERIC_CHARSET)}

# mask pattern formulas: (row, col) -> True means "invert this data module"
MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]

FORMAT_MASK = 0b101010000010010
FORMAT_GEN = 0x537  # x^10+x^8+x^5+x^4+x^2+x+1, BCH(15,5)
VERSION_GEN = 0x1F25  # BCH(18,6) generator


def _bch_remainder(data_bits, n_data, gen, gen_deg):
    """Remainder of (data_bits << gen_deg) / gen, returned as gen_deg bits."""
    d = data_bits << gen_deg
    # polynomial long division over GF(2)
    while d.bit_length() - 1 >= gen_deg:
        d ^= gen << (d.bit_length() - 1 - gen_deg)
    return d


def format_bits(eclevel, mask):
    """15-bit format string (already masked), MSB-first list of 15 ints."""
    data = (EC_BITS[eclevel] << 3) | mask
    rem = _bch_remainder(data, 5, FORMAT_GEN, 10)
    code = ((data << 10) | rem) ^ FORMAT_MASK
    return [(code >> i) & 1 for i in range(14, -1, -1)]


def version_bits(version):
    """18-bit version string, MSB-first list (versions 7+ only)."""
    rem = _bch_remainder(version, 6, VERSION_GEN, 12)
    code = (version << 12) | rem
    return [(code >> i) & 1 for i in range(17, -1, -1)]


def all_format_codewords():
    """The 32 valid (masked) 15-bit format codewords: (eclevel, mask) -> bits."""
    out = {}
    for ec in EC_LEVELS:
        for m in range(8):
            out[(ec, m)] = format_bits(ec, m)
    return out


def data_capacity(version, eclevel):
    """Number of DATA codewords (excludes EC) for version/level."""
    _, groups = VERSIONS[version]["ec"][eclevel]
    return sum(n * k for n, k in groups)


def count_bits_for(version, mode):
    for (lo, hi), table in COUNT_BITS.items():
        if lo <= version <= hi:
            return table[mode]
    raise ValueError(f"version {version} out of range")
