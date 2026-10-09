"""GF(2^8) arithmetic for QR codes.

QR's field: irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D),
generator alpha = 2. NOTE: this is NOT the AES field (AES uses 0x11B:
x^8+x^4+x^3+x+1) -- same construction idea as expedition 8's AES work,
different polynomial, so AES test vectors do not apply here.
Zero dependencies.
"""

_POLY = 0x11D

# exp[i] = alpha^i for i in 0..510 (doubled table so no mod needed on lookup)
EXP = [0] * 512
# log[a] = i such that alpha^i = a, for a in 1..255
LOG = [0] * 256


def _init():
    x = 1
    for i in range(255):
        EXP[i] = x
        LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _POLY
    for i in range(255, 512):
        EXP[i] = EXP[i - 255]


_init()


def add(a, b):
    return a ^ b


def sub(a, b):
    return a ^ b  # characteristic 2


def mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def div(a, b):
    if b == 0:
        raise ZeroDivisionError("gf256 div by zero")
    if a == 0:
        return 0
    return EXP[(LOG[a] - LOG[b]) % 255]


def inv(a):
    if a == 0:
        raise ZeroDivisionError("gf256 inv of zero")
    return EXP[255 - LOG[a]]


def pow_(a, n):
    """a^n for integer n (may be negative)."""
    if a == 0:
        return 1 if n == 0 else 0
    return EXP[(LOG[a] * n) % 255]


def poly_eval(coeffs, x):
    """Evaluate polynomial (coeffs[i] = coeff of x^i) at x."""
    y = 0
    # Horner from the top
    for c in reversed(coeffs):
        y = add(mul(y, x), c)
    return y


def poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if ca:
            for j, cb in enumerate(b):
                if cb:
                    out[i + j] ^= mul(ca, cb)
    return out


def poly_add(a, b):
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0) for i in range(n)]


def poly_mod(a, b):
    """Remainder of a / b (b monic assumed for RS use)."""
    a = list(a)
    db = len(b) - 1
    while len(a) >= len(b) and any(a):
        # strip leading zeros
        while len(a) > 1 and a[-1] == 0:
            a.pop()
        if len(a) < len(b):
            break
        coef = a[-1]  # b is monic so no division needed
        shift = len(a) - len(b)
        for i in range(len(b)):
            a[shift + i] ^= mul(b[i], coef)
        a.pop()
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a
