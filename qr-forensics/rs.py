"""Reed-Solomon encode/decode over GF(256), as used by QR codes.

Convention: the public message list is in TRANSMISSION order (data bytes
first, EC bytes last -- the QR codeword order). Internally the codeword
polynomial is c(x) = c_0 x^{n-1} + c_1 x^{n-2} + ... + c_{n-1}, i.e. the
internal coefficient list is the reversed message.

Encoder: generator g(x) = (x - a^0)(x - a^1)...(x - a^{nsym-1});
c(x) = m(x)*x^{nsym} - (m(x)*x^{nsym} mod g(x)).

Decoder (errors-only): syndromes -> Berlekamp-Massey -> Chien search ->
Forney magnitudes. Corrects up to floor(nsym/2) errors.
Zero dependencies (uses gf256).
"""
from gf256 import EXP, mul, div, poly_eval, poly_mul, poly_mod


class RSDecodeError(Exception):
    pass


def rs_generator_poly(nsym):
    g = [1]
    for i in range(nsym):
        g = poly_mul(g, [EXP[i], 1])  # (x + a^i); char 2 so x - a^i = x + a^i
    return g


def _to_poly(msg):
    """Transmission order -> internal (index j = coeff of x^j)."""
    return msg[::-1]


def rs_encode(data, nsym):
    """data: list of ints (transmission order). Returns data + nsym EC bytes."""
    g = rs_generator_poly(nsym)
    # m(x)*x^nsym in internal form: internal(data) shifted up by nsym
    shifted = [0] * nsym + _to_poly(data)
    rem = poly_mod(shifted, g)
    rem += [0] * (nsym - len(rem))
    # codeword poly = shifted + rem; back to transmission order
    cw_internal = [(shifted[i] if i < len(shifted) else 0) ^ (rem[i] if i < nsym else 0)
                   for i in range(len(shifted))]
    return cw_internal[::-1]


def _syndromes(msg, nsym):
    internal = _to_poly(msg)
    return [poly_eval(internal, EXP[i]) for i in range(nsym)]


def _berlekamp_massey(synd, nsym):
    C = [1]
    B = [1]
    L = 0
    m = 1
    b = 1
    for n in range(nsym):
        d = synd[n]
        for i in range(1, L + 1):
            d ^= mul(C[i] if i < len(C) else 0, synd[n - i])
        if d == 0:
            m += 1
            continue
        T = list(C)
        coef = div(d, b)
        need = m + len(B)
        if len(C) < need:
            C += [0] * (need - len(C))
        for i, bv in enumerate(B):
            C[m + i] ^= mul(coef, bv)
        if 2 * L <= n:
            L = n + 1 - L
            B = T
            b = d
            m = 1
        else:
            m += 1
    return C[: L + 1]


def _find_error_positions(err_loc, n):
    """Chien search over INTERNAL indices j (err_loc(a^{-j}) == 0).
    Returns transmission-order indices p = n-1-j."""
    pos = []
    for j in range(n):
        if poly_eval(err_loc, EXP[(255 - j) % 255]) == 0:
            pos.append(n - 1 - j)
    return pos


def _forney(synd, err_loc, err_pos_internal, nsym):
    # Omega(x) = (S(x) * Lambda(x)) mod x^nsym
    omega = poly_mul(synd, err_loc)[:nsym]
    # formal derivative (char 2: odd powers only)
    deriv = [0] * max(1, len(err_loc) - 1)
    for i in range(1, len(err_loc)):
        if i % 2 == 1:
            deriv[i - 1] = err_loc[i]
    magnitudes = {}
    for j in err_pos_internal:
        X = EXP[j % 255]  # a^j : the error's "location number"
        x_inv = EXP[(255 - j) % 255]  # a^{-j}
        num = poly_eval(omega, x_inv)
        den = poly_eval(deriv, x_inv)
        if den == 0:
            raise RSDecodeError("zero derivative in Forney")
        # e = X * Omega(X^-1) / Lambda'(X^-1); derived from
        # S(x) = sum_j e_j / (1 - X_j x): evaluating Omega/Lambda' at X_j^-1
        # leaves -e_j / X_j (char 2: sign vanishes).
        magnitudes[j] = mul(X, div(num, den))
    return magnitudes


def rs_decode(msg, nsym):
    """Correct up to nsym//2 errors. Returns (corrected_list, n_corrected).
    Raises RSDecodeError if uncorrectable."""
    msg = list(msg)
    n = len(msg)
    if n < nsym:
        raise RSDecodeError("message shorter than nsym")
    synd = _syndromes(msg, nsym)
    if all(s == 0 for s in synd):
        return msg, 0
    err_loc = _berlekamp_massey(synd, nsym)
    err_pos_tx = _find_error_positions(err_loc, n)
    if len(err_pos_tx) == 0 or len(err_pos_tx) != len(err_loc) - 1:
        raise RSDecodeError(
            f"locator degree {len(err_loc)-1} != roots found {len(err_pos_tx)}"
        )
    err_pos_internal = [n - 1 - p for p in err_pos_tx]
    mags = _forney(synd, err_loc, err_pos_internal, nsym)
    for j, e in mags.items():
        p = n - 1 - j
        msg[p] ^= e
    if any(_syndromes(msg, nsym)):
        raise RSDecodeError("correction failed verification")
    return msg, len(err_pos_tx)


def rs_check(msg, nsym):
    """True if msg has valid EC (all syndromes zero)."""
    return all(s == 0 for s in _syndromes(msg, nsym))
