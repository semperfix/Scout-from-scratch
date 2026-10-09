#!/usr/bin/env python3
"""foxchess - a chess engine from scratch. Zero dependencies.

Bitboard board representation (Python ints as 64-bit bitboards), hyperbola-
quintessence sliding attacks, Zobrist hashing, alpha-beta + quiescence +
transposition table, iterative deepening. Move legality proven by exact
perft counts against the standard reference positions.
"""

import sys
import time

# ---------------------------------------------------------------- constants
WHITE, BLACK = 0, 1
PAWN, KNIGHT, BISHOP, ROOK, QUEEN, KING = range(6)
VAL = [100, 320, 330, 500, 900, 0]
MATE = 100000
INF = 10 ** 9
MASK64 = 0xFFFFFFFFFFFFFFFF
STARTPOS = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"

FILES = "abcdefgh"


def sq_name(s):
    return FILES[s & 7] + str((s >> 3) + 1)


def sq_of(name):
    return FILES.index(name[0]) + (int(name[1]) - 1) * 8


# ------------------------------------------------------- bit-twiddling kit
REV16 = [0] * 65536
for _i in range(65536):
    _v, _x = 0, _i
    for _ in range(16):
        _v = (_v << 1) | (_x & 1)
        _x >>= 1
    REV16[_i] = _v


def rev64(x):
    x &= MASK64
    return ((REV16[x & 0xFFFF] << 48) | (REV16[(x >> 16) & 0xFFFF] << 32) |
            (REV16[(x >> 32) & 0xFFFF] << 16) | REV16[(x >> 48) & 0xFFFF])


def popcount(x):
    c = 0
    while x:
        x &= x - 1
        c += 1
    return c


def bits(x):
    while x:
        lsb = x & -x
        yield lsb.bit_length() - 1
        x ^= lsb


# ------------------------------------------------- precomputed attack data
def _jumps(s, deltas):
    r, f = s >> 3, s & 7
    a = 0
    for dr, df in deltas:
        nr, nf = r + dr, f + df
        if 0 <= nr < 8 and 0 <= nf < 8:
            a |= 1 << (nr * 8 + nf)
    return a


_KN = [(1, 2), (2, 1), (2, -1), (1, -2), (-1, -2), (-2, -1), (-2, 1), (-1, 2)]
_KG = [(1, 1), (1, 0), (1, -1), (0, 1), (0, -1), (-1, 1), (-1, 0), (-1, -1)]
KNIGHT_A = [_jumps(s, _KN) for s in range(64)]
KING_A = [_jumps(s, _KG) for s in range(64)]

PAWN_A = [[0] * 64 for _ in range(2)]  # squares attacked BY a pawn of color on sq
for _s in range(64):
    _r, _f = _s >> 3, _s & 7
    if _r < 7:
        if _f > 0:
            PAWN_A[WHITE][_s] |= 1 << (_s + 7)
        if _f < 7:
            PAWN_A[WHITE][_s] |= 1 << (_s + 9)
    if _r > 0:
        if _f > 0:
            PAWN_A[BLACK][_s] |= 1 << (_s - 9)
        if _f < 7:
            PAWN_A[BLACK][_s] |= 1 << (_s - 7)

RANK_M, FILE_M, DIAG_M, ANTI_M = [0] * 64, [0] * 64, [0] * 64, [0] * 64
for _s in range(64):
    _r, _f = _s >> 3, _s & 7
    for _t in range(64):
        _tr, _tf = _t >> 3, _t & 7
        if _tr == _r:
            RANK_M[_s] |= 1 << _t
        if _tf == _f:
            FILE_M[_s] |= 1 << _t
        if _tr - _tf == _r - _f:
            DIAG_M[_s] |= 1 << _t
        if _tr + _tf == _r + _f:
            ANTI_M[_s] |= 1 << _t


def line_attacks(s, occ, mask):
    """Hyperbola quintessence: slider attacks on one line, O(1) bitwise ops."""
    b = 1 << s
    o = occ & mask
    fwd = (o - (b << 1)) & MASK64
    bwd = rev64((rev64(o) - (rev64(b) << 1)) & MASK64)
    return (fwd ^ bwd) & mask


def rook_attacks(s, occ):
    return line_attacks(s, occ, RANK_M[s]) | line_attacks(s, occ, FILE_M[s])


def bishop_attacks(s, occ):
    return line_attacks(s, occ, DIAG_M[s]) | line_attacks(s, occ, ANTI_M[s])


# ----------------------------------------------------------------- zobrist
def _xorshift(seed):
    x = seed
    while True:
        x ^= (x << 13) & MASK64
        x ^= x >> 7
        x ^= (x << 17) & MASK64
        x &= MASK64
        yield x


_rng = _xorshift(0x9E3779B97F4A7C15)
Z_PIECE = [[next(_rng) for _ in range(64)] for _ in range(12)]
Z_SIDE = next(_rng)
Z_CASTLE = [next(_rng) for _ in range(16)]
Z_EP = [next(_rng) for _ in range(8)]


def compute_key(b):
    k = 0
    for c in (0, 1):
        for p in range(6):
            for s in bits(b.bb[c * 6 + p]):
                k ^= Z_PIECE[c * 6 + p][s]
    if b.side == BLACK:
        k ^= Z_SIDE
    k ^= Z_CASTLE[b.castle]
    if b.ep != -1:
        k ^= Z_EP[b.ep & 7]
    return k


# ------------------------------------------------------------------- board
# castling rights bits: 1=WK 2=WQ 4=BK 8=BQ
# CASTLE_KEEP[sq]: rights surviving a move from/to sq
CASTLE_KEEP = [15] * 64
CASTLE_KEEP[4] = 12    # e1: king move clears WK,WQ
CASTLE_KEEP[7] = 14    # h1 rook
CASTLE_KEEP[0] = 13    # a1 rook
CASTLE_KEEP[60] = 3    # e8
CASTLE_KEEP[63] = 11   # h8 rook
CASTLE_KEEP[56] = 7    # a8 rook


class Board:
    __slots__ = ("bb", "occ", "side", "castle", "ep", "half", "full", "zkey")

    def __init__(self):
        self.bb = [0] * 12
        self.occ = [0, 0]
        self.side = WHITE
        self.castle = 0
        self.ep = -1
        self.half = 0
        self.full = 1
        self.zkey = 0


def set_fen(fen):
    b = Board()
    parts = fen.split()
    for r, row in enumerate(parts[0].split("/")):
        rank = 7 - r
        f = 0
        for ch in row:
            if ch.isdigit():
                f += int(ch)
            else:
                color = WHITE if ch.isupper() else BLACK
                piece = "pnbrqk".index(ch.lower())
                b.bb[color * 6 + piece] |= 1 << (rank * 8 + f)
                f += 1
    b.side = WHITE if parts[1] == "w" else BLACK
    if len(parts) > 2 and parts[2] != "-":
        for ch in parts[2]:
            b.castle |= {"K": 1, "Q": 2, "k": 4, "q": 8}[ch]
    b.ep = sq_of(parts[3]) if len(parts) > 3 and parts[3] != "-" else -1
    b.half = int(parts[4]) if len(parts) > 4 else 0
    b.full = int(parts[5]) if len(parts) > 5 else 1
    _refresh_occ(b)
    b.zkey = compute_key(b)
    return b


def _refresh_occ(b):
    b.occ[0] = b.occ[1] = 0
    for i in range(6):
        b.occ[0] |= b.bb[i]
        b.occ[1] |= b.bb[6 + i]


def piece_on(b, color, sq):
    bit = 1 << sq
    base = color * 6
    for p in range(6):
        if b.bb[base + p] & bit:
            return p
    return -1


def king_sq(b, color):
    return (b.bb[color * 6 + KING]).bit_length() - 1

# ---------------------------------------------------------- move generation
# move = (fr, to, promo, flags); flags: 1=capture 2=double-push 4=en-passant
#                                      8=castle-K 16=castle-Q
def gen_pseudo(b):
    moves = []
    add = moves.append
    us, them = b.side, b.side ^ 1
    own, enemy = b.occ[us], b.occ[them]
    occ = own | enemy

    # ---- pawns
    for s in bits(b.bb[us * 6 + PAWN]):
        r = s >> 3
        if us == WHITE:
            one = s + 8
            if not (occ >> one) & 1:
                if r == 6:
                    for pr in (QUEEN, ROOK, BISHOP, KNIGHT):
                        add((s, one, pr, 0))
                else:
                    add((s, one, 0, 0))
                    if r == 1 and not (occ >> (s + 16)) & 1:
                        add((s, s + 16, 0, 2))
            for t in bits(PAWN_A[WHITE][s] & enemy):
                if r == 6:
                    for pr in (QUEEN, ROOK, BISHOP, KNIGHT):
                        add((s, t, pr, 1))
                else:
                    add((s, t, 0, 1))
            if b.ep != -1 and (PAWN_A[WHITE][s] >> b.ep) & 1:
                add((s, b.ep, 0, 5))
        else:
            one = s - 8
            if not (occ >> one) & 1:
                if r == 1:
                    for pr in (QUEEN, ROOK, BISHOP, KNIGHT):
                        add((s, one, pr, 0))
                else:
                    add((s, one, 0, 0))
                    if r == 6 and not (occ >> (s - 16)) & 1:
                        add((s, s - 16, 0, 2))
            for t in bits(PAWN_A[BLACK][s] & enemy):
                if r == 1:
                    for pr in (QUEEN, ROOK, BISHOP, KNIGHT):
                        add((s, t, pr, 1))
                else:
                    add((s, t, 0, 1))
            if b.ep != -1 and (PAWN_A[BLACK][s] >> b.ep) & 1:
                add((s, b.ep, 0, 5))

    # ---- knights, kings, sliders
    for s in bits(b.bb[us * 6 + KNIGHT]):
        for t in bits(KNIGHT_A[s] & ~own):
            add((s, t, 0, 1 if (enemy >> t) & 1 else 0))
    for s in bits(b.bb[us * 6 + BISHOP]):
        for t in bits(bishop_attacks(s, occ) & ~own):
            add((s, t, 0, 1 if (enemy >> t) & 1 else 0))
    for s in bits(b.bb[us * 6 + ROOK]):
        for t in bits(rook_attacks(s, occ) & ~own):
            add((s, t, 0, 1 if (enemy >> t) & 1 else 0))
    for s in bits(b.bb[us * 6 + QUEEN]):
        for t in bits((rook_attacks(s, occ) | bishop_attacks(s, occ)) & ~own):
            add((s, t, 0, 1 if (enemy >> t) & 1 else 0))

    # ---- king + castling
    ks = king_sq(b, us)
    for t in bits(KING_A[ks] & ~own):
        add((ks, t, 0, 1 if (enemy >> t) & 1 else 0))
    if us == WHITE and ks == 4:
        if (b.castle & 1) and not (occ & 0x60) and (b.bb[ROOK] >> 7) & 1:
            if not (is_attacked(b, 4, BLACK) or is_attacked(b, 5, BLACK)
                    or is_attacked(b, 6, BLACK)):
                add((4, 6, 0, 8))
        if (b.castle & 2) and not (occ & 0xE) and (b.bb[ROOK] >> 0) & 1:
            if not (is_attacked(b, 4, BLACK) or is_attacked(b, 3, BLACK)
                    or is_attacked(b, 2, BLACK)):
                add((4, 2, 0, 16))
    elif us == BLACK and ks == 60:
        if (b.castle & 4) and not (occ & 0x6000000000000000) and (b.bb[6 + ROOK] >> 63) & 1:
            if not (is_attacked(b, 60, WHITE) or is_attacked(b, 61, WHITE)
                    or is_attacked(b, 62, WHITE)):
                add((60, 62, 0, 8))
        if (b.castle & 8) and not (occ & 0x0E00000000000000) and (b.bb[6 + ROOK] >> 56) & 1:
            if not (is_attacked(b, 60, WHITE) or is_attacked(b, 59, WHITE)
                    or is_attacked(b, 58, WHITE)):
                add((60, 58, 0, 16))
    return moves


def is_attacked(b, sq, by):
    r, f = sq >> 3, sq & 7
    atk = 0
    if by == WHITE:
        if r > 0:
            if f < 7:
                atk |= 1 << (sq - 7)
            if f > 0:
                atk |= 1 << (sq - 9)
    else:
        if r < 7:
            if f > 0:
                atk |= 1 << (sq + 7)
            if f < 7:
                atk |= 1 << (sq + 9)
    if atk & b.bb[by * 6 + PAWN]:
        return True
    if KNIGHT_A[sq] & b.bb[by * 6 + KNIGHT]:
        return True
    if KING_A[sq] & b.bb[by * 6 + KING]:
        return True
    occ = b.occ[0] | b.occ[1]
    if rook_attacks(sq, occ) & (b.bb[by * 6 + ROOK] | b.bb[by * 6 + QUEEN]):
        return True
    if bishop_attacks(sq, occ) & (b.bb[by * 6 + BISHOP] | b.bb[by * 6 + QUEEN]):
        return True
    return False


# ---------------------------------------------------------------- make/unmake
def make(b, m):
    fr, to, promo, flags = m
    us, them = b.side, b.side ^ 1
    pc = piece_on(b, us, fr)
    cap, cap_sq = -1, to
    if flags & 4:  # en passant: captured pawn sits behind the target square
        cap = PAWN
        cap_sq = to - 8 if us == WHITE else to + 8
    elif (b.occ[them] >> to) & 1:
        cap = piece_on(b, them, to)

    undo = (b.zkey, b.castle, b.ep, b.half, pc, cap, cap_sq, promo, flags, fr, to)

    b.zkey ^= Z_PIECE[us * 6 + pc][fr]
    if b.ep != -1:
        b.zkey ^= Z_EP[b.ep & 7]
    b.zkey ^= Z_CASTLE[b.castle]

    b.bb[us * 6 + pc] ^= 1 << fr
    if cap != -1:
        b.bb[them * 6 + cap] ^= 1 << cap_sq
        b.zkey ^= Z_PIECE[them * 6 + cap][cap_sq]
    placed = promo if promo else pc
    b.bb[us * 6 + placed] ^= 1 << to
    b.zkey ^= Z_PIECE[us * 6 + placed][to]

    if flags & 8:  # castle kingside: rook h-file -> f-file
        rs, rd = (7, 5) if us == WHITE else (63, 61)
        b.bb[us * 6 + ROOK] ^= (1 << rs) | (1 << rd)
        b.zkey ^= Z_PIECE[us * 6 + ROOK][rs] ^ Z_PIECE[us * 6 + ROOK][rd]
    elif flags & 16:  # castle queenside: rook a-file -> d-file
        rs, rd = (0, 3) if us == WHITE else (56, 59)
        b.bb[us * 6 + ROOK] ^= (1 << rs) | (1 << rd)
        b.zkey ^= Z_PIECE[us * 6 + ROOK][rs] ^ Z_PIECE[us * 6 + ROOK][rd]

    b.castle &= CASTLE_KEEP[fr] & CASTLE_KEEP[to]
    b.ep = (fr + to) // 2 if (flags & 2) else -1
    if b.ep != -1:
        b.zkey ^= Z_EP[b.ep & 7]
    b.zkey ^= Z_CASTLE[b.castle]
    b.zkey ^= Z_SIDE

    b.half = 0 if (pc == PAWN or cap != -1) else b.half + 1
    b.side ^= 1
    _refresh_occ(b)
    return undo


def unmake(b, m, undo):
    zkey, castle, ep, half, pc, cap, cap_sq, promo, flags, fr, to = undo
    us, them = b.side ^ 1, b.side
    placed = promo if promo else pc
    b.bb[us * 6 + placed] ^= 1 << to
    b.bb[us * 6 + pc] ^= 1 << fr
    if cap != -1:
        b.bb[them * 6 + cap] ^= 1 << cap_sq
    if flags & 8:
        rs, rd = (7, 5) if us == WHITE else (63, 61)
        b.bb[us * 6 + ROOK] ^= (1 << rs) | (1 << rd)
    elif flags & 16:
        rs, rd = (0, 3) if us == WHITE else (56, 59)
        b.bb[us * 6 + ROOK] ^= (1 << rs) | (1 << rd)
    b.zkey, b.castle, b.ep, b.half = zkey, castle, ep, half
    b.side ^= 1
    _refresh_occ(b)


def gen_legal(b):
    us, them = b.side, b.side ^ 1
    res = []
    for m in gen_pseudo(b):
        undo = make(b, m)
        if not is_attacked(b, king_sq(b, us), them):
            res.append(m)
        unmake(b, m, undo)
    return res


def perft(b, depth):
    if depth == 0:
        return 1
    n = 0
    for m in gen_legal(b):
        undo = make(b, m)
        n += perft(b, depth - 1)
        unmake(b, m, undo)
    return n


def move_str(m):
    fr, to, promo, _ = m
    s = sq_name(fr) + sq_name(to)
    if promo:
        s += "nbrq"[promo - 1]  # KNIGHT->n BISHOP->b ROOK->r QUEEN->q
    return s

# -------------------------------------------------------------- evaluation
# Piece-square tables, written rank-8-first (index 0 = a8). White indexes
# with sq^56, black with sq directly: both measure "how far advanced".
_PST = {
PAWN: [
 0,  0,  0,  0,  0,  0,  0,  0,
 50, 50, 50, 50, 50, 50, 50, 50,
 10, 10, 20, 30, 30, 20, 10, 10,
 5,  5, 10, 25, 25, 10,  5,  5,
 0,  0,  0, 20, 20,  0,  0,  0,
 5, -5,-10,  0,  0,-10, -5,  5,
 5, 10, 10,-20,-20, 10, 10,  5,
 0,  0,  0,  0,  0,  0,  0,  0],
KNIGHT: [
 -50,-40,-30,-30,-30,-30,-40,-50,
 -40,-20,  0,  0,  0,  0,-20,-40,
 -30,  0, 10, 15, 15, 10,  0,-30,
 -30,  5, 15, 20, 20, 15,  5,-30,
 -30,  0, 15, 20, 20, 15,  0,-30,
 -30,  5, 10, 15, 15, 10,  5,-30,
 -40,-20,  0,  5,  5,  0,-20,-40,
 -50,-40,-30,-30,-30,-30,-40,-50],
BISHOP: [
 -20,-10,-10,-10,-10,-10,-10,-20,
 -10,  0,  0,  0,  0,  0,  0,-10,
 -10,  0,  5, 10, 10,  5,  0,-10,
 -10,  5,  5, 10, 10,  5,  5,-10,
 -10,  0, 10, 10, 10, 10,  0,-10,
 -10, 10, 10, 10, 10, 10, 10,-10,
 -10,  5,  0,  0,  0,  0,  5,-10,
 -20,-10,-10,-10,-10,-10,-10,-20],
ROOK: [
 0,  0,  0,  0,  0,  0,  0,  0,
 5, 10, 10, 10, 10, 10, 10,  5,
 -5,  0,  0,  0,  0,  0,  0, -5,
 -5,  0,  0,  0,  0,  0,  0, -5,
 -5,  0,  0,  0,  0,  0,  0, -5,
 -5,  0,  0,  0,  0,  0,  0, -5,
 -5,  0,  0,  0,  0,  0,  0, -5,
 0,  0,  0,  5,  5,  0,  0,  0],
QUEEN: [
 -20,-10,-10, -5, -5,-10,-10,-20,
 -10,  0,  0,  0,  0,  0,  0,-10,
 -10,  0,  5,  5,  5,  5,  0,-10,
 -5,  0,  5,  5,  5,  5,  0, -5,
 0,  0,  5,  5,  5,  5,  0, -5,
 -10,  5,  5,  5,  5,  5,  0,-10,
 -10,  0,  5,  0,  0,  0,  0,-10,
 -20,-10,-10, -5, -5,-10,-10,-20],
KING: [
 -30,-40,-40,-50,-50,-40,-40,-30,
 -30,-40,-40,-50,-50,-40,-40,-30,
 -30,-40,-40,-50,-50,-40,-40,-30,
 -30,-40,-40,-50,-50,-40,-40,-30,
 -20,-30,-30,-40,-40,-30,-30,-20,
 -10,-20,-20,-20,-20,-20,-20,-10,
 20, 20,  0,  0,  0,  0, 20, 20,
 20, 30, 10,  0,  0, 10, 30, 20],
}


def evaluate(b):
    """Centipawns, white's perspective."""
    s = 0
    for p in range(6):
        t = _PST[p]
        for sq in bits(b.bb[p]):
            s += VAL[p] + t[sq ^ 56]
        for sq in bits(b.bb[6 + p]):
            s -= VAL[p] + t[sq]
    return s


def insufficient(b):
    if (b.bb[PAWN] | b.bb[6 + PAWN] | b.bb[ROOK] | b.bb[6 + ROOK] |
            b.bb[QUEEN] | b.bb[6 + QUEEN]):
        return False
    minors = popcount(b.bb[KNIGHT] | b.bb[6 + KNIGHT] |
                      b.bb[BISHOP] | b.bb[6 + BISHOP])
    return minors <= 1


# ------------------------------------------------------------------ search
nodes = 0
TT = {}          # zkey -> (depth, score, flag, bestmove); flag: 0 exact 1 lower 2 upper
killers = {}     # ply -> [m1, m2]


def _order(b, moves, tt_move, ply):
    us, them = b.side, b.side ^ 1
    scored = []
    km = killers.get(ply, [])
    for m in moves:
        fr, to, promo, flags = m
        if tt_move is not None and m == tt_move:
            scored.append((10**9, m))
            continue
        sc = 0
        if flags & 1 or promo:
            victim = PAWN if (flags & 4) else piece_on(b, them, to)
            sc = 10000 + 10 * VAL[victim] - VAL[piece_on(b, us, fr)]
            if promo:
                sc += 9000 + VAL[promo]
        elif m in km:
            sc = 5000 - km.index(m)
        scored.append((sc, m))
    scored.sort(key=lambda x: -x[0])
    return [m for _, m in scored]


def quiescence(b, alpha, beta, ply):
    global nodes
    nodes += 1
    us, them = b.side, b.side ^ 1
    in_check = is_attacked(b, king_sq(b, us), them)
    if not in_check:
        stand = evaluate(b) if us == WHITE else -evaluate(b)
        if stand >= beta:
            return beta
        if stand > alpha:
            alpha = stand
    moves = gen_legal(b)
    if in_check:
        if not moves:
            return -MATE + ply
    else:
        moves = [m for m in moves if (m[3] & 1) or m[2]]
    for m in _order(b, moves, None, ply):
        undo = make(b, m)
        score = -quiescence(b, -beta, -alpha, ply + 1)
        unmake(b, m, undo)
        if score >= beta:
            return beta
        if score > alpha:
            alpha = score
    return alpha


def negamax(b, alpha, beta, depth, ply):
    global nodes
    nodes += 1
    if b.half >= 100 or insufficient(b):
        return 0
    us, them = b.side, b.side ^ 1
    in_check = is_attacked(b, king_sq(b, us), them)
    if depth <= 0:
        return quiescence(b, alpha, beta, ply)
    alpha = max(alpha, -MATE + ply)
    beta = min(beta, MATE - ply - 1)
    if alpha >= beta:
        return alpha

    tt_move = None
    entry = TT.get(b.zkey)
    if entry and entry[0] >= depth:
        _, escore, eflag, emove = entry
        tt_move = emove
        if eflag == 0:
            return escore
        if eflag == 1 and escore >= beta:
            return escore
        if eflag == 2 and escore <= alpha:
            return escore

    moves = gen_legal(b)
    if not moves:
        return -MATE + ply if in_check else 0
    moves = _order(b, moves, tt_move, ply)

    a0 = alpha
    best, best_move = -INF, None
    for m in moves:
        undo = make(b, m)
        score = -negamax(b, -beta, -alpha, depth - 1, ply + 1)
        unmake(b, m, undo)
        if score > best:
            best, best_move = score, m
        if score > alpha:
            alpha = score
        if alpha >= beta:
            if not (m[3] & 1) and not m[2]:
                km = killers.get(ply, [])
                if m not in km:
                    killers[ply] = [m, km[0]] if km else [m]
            break
    if best >= beta:
        flag = 1
    elif best > a0:
        flag = 0
    else:
        flag = 2
    if len(TT) < 2000000:
        TT[b.zkey] = (depth, best, flag, best_move)
    return best


def search(b, max_depth):
    """Iterative deepening. Returns (score, bestmove) from side-to-move's view."""
    global nodes, TT, killers
    nodes = 0
    TT = {}
    killers = {}
    best_move, best_score = None, 0
    for depth in range(1, max_depth + 1):
        moves = gen_legal(b)
        if not moves:
            us, them = b.side, b.side ^ 1
            chk = is_attacked(b, king_sq(b, us), them)
            return (-MATE if chk else 0), None
        moves = _order(b, moves, best_move, 0)
        alpha, cur_best, cur_move = -INF, -INF, None
        for m in moves:
            undo = make(b, m)
            score = -negamax(b, -INF, -alpha, depth - 1, 1)
            unmake(b, m, undo)
            if score > cur_best:
                cur_best, cur_move = score, m
            if score > alpha:
                alpha = score
        best_score, best_move = cur_best, cur_move
        if abs(best_score) >= MATE - 1000:
            break
    return best_score, best_move


# -------------------------------------------------------------------- misc
def _sq_char(b, s):
    p = piece_on(b, WHITE, s)
    if p != -1:
        return "PNBRQK"[p]
    p = piece_on(b, BLACK, s)
    if p != -1:
        return "pnbrqk"[p]
    return "."


def print_board(b):
    print("  +-----------------+")
    for r in range(7, -1, -1):
        print("%d | %s |" % (r + 1, " ".join(_sq_char(b, r * 8 + f) for f in range(8))))
    print("  +-----------------+")
    print("    a b c d e f g h")
    print("side=%s castle=%d ep=%s half=%d eval=%d" %
          ("w" if b.side == WHITE else "b", b.castle,
           sq_name(b.ep) if b.ep != -1 else "-", b.half, evaluate(b)))

# ------------------------------------------------------------------- tests
def _naive_slider(s, occ, deltas):
    r, f = s >> 3, s & 7
    a = 0
    for dr, df in deltas:
        nr, nf = r + dr, f + df
        while 0 <= nr < 8 and 0 <= nf < 8:
            t = nr * 8 + nf
            a |= 1 << t
            if (occ >> t) & 1:
                break
            nr += dr
            nf += df
    return a


def run_tests():
    import random
    ok = fail = 0

    def check(name, cond):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("  PASS %s" % name)
        else:
            fail += 1
            print("  FAIL %s" % name)

    print("== hyperbola quintessence vs naive rays (2000 random occupancies) ==")
    rook_d = [(1, 0), (-1, 0), (0, 1), (0, -1)]
    bish_d = [(1, 1), (1, -1), (-1, 1), (-1, -1)]
    rng = random.Random(1234)
    bad = 0
    for _ in range(2000):
        occ = rng.getrandbits(64)
        s = rng.randrange(64)
        occ |= 1 << s
        if rook_attacks(s, occ) != _naive_slider(s, occ, rook_d):
            bad += 1
        if bishop_attacks(s, occ) != _naive_slider(s, occ, bish_d):
            bad += 1
    check("slider-attacks differential (4000 cases)", bad == 0)

    print("== perft reference positions ==")
    b = set_fen(STARTPOS)
    check("startpos legal moves == 20", len(gen_legal(b)) == 20)
    for depth, want in ((1, 20), (2, 400), (3, 8902)):
        got = perft(b, depth)
        check("startpos perft(%d)==%d (got %d)" % (depth, want, got), got == want)
    b = set_fen(STARTPOS)
    t0 = time.time()
    got = perft(b, 4)
    dt = time.time() - t0
    check("startpos perft(4)==197281 (got %d, %.1fs)" % (got, dt), got == 197281)

    kiwipete = "r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1"
    b = set_fen(kiwipete)
    for depth, want in ((1, 48), (2, 2039), (3, 97862)):
        got = perft(b, depth)
        check("kiwipete perft(%d)==%d (got %d)" % (depth, want, got), got == want)

    pos3 = "8/2p5/3p4/KP5r/1R3p1k/8/4P1P1/8 w - - 0 1"
    b = set_fen(pos3)
    for depth, want in ((1, 14), (2, 191), (3, 2812), (4, 43238)):
        got = perft(b, depth)
        check("pos3 perft(%d)==%d (got %d)" % (depth, want, got), got == want)

    pos4 = "r3k2r/Pppp1ppp/1b3nbN/nP6/BBP1P3/q4N2/Pp1P2PP/R2Q1RK1 w kq - 0 1"
    b = set_fen(pos4)
    for depth, want in ((1, 6), (2, 264), (3, 9467)):
        got = perft(b, depth)
        check("pos4 perft(%d)==%d (got %d)" % (depth, want, got), got == want)

    print("== rules: pins, en passant, promotion, castling rights ==")
    b = set_fen("4r3/8/8/8/8/8/4R3/4K3 w - - 0 1")  # Re2 pinned to Ke1 by Re8
    rook_moves = [m for m in gen_legal(b) if m[0] == 12]  # e2 = 12
    check("pinned rook: all moves stay on e-file or capture e8",
          all((m[1] & 7) == 4 for m in rook_moves) and len(rook_moves) == 6)

    b = set_fen("8/8/8/3pP3/8/8/8/4K2k w - d6 0 1")
    ep = [m for m in gen_legal(b) if m[3] & 4]
    check("en passant capture generated", len(ep) == 1 and move_str(ep[0]) == "e5d6")
    undo = make(b, ep[0])
    check("ep removes the right pawn",
          piece_on(b, WHITE, sq_of("d6")) == PAWN and not (b.bb[6 + PAWN] >> sq_of("d5")) & 1)
    unmake(b, ep[0], undo)

    b = set_fen("8/1P6/8/8/8/1k6/8/4K3 w - - 0 1")
    promos = [m for m in gen_legal(b) if m[2]]
    check("4 promotion options on b8", len(promos) == 4)
    q = [m for m in promos if m[2] == QUEEN][0]
    undo = make(b, q)
    check("promotion places a queen", piece_on(b, WHITE, sq_of("b8")) == QUEEN)
    unmake(b, q, undo)

    b = set_fen("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1")
    n0 = len(gen_legal(b))
    m = [x for x in gen_legal(b) if move_str(x) == "e1g1"][0]
    undo = make(b, m)
    check("O-O: king on g1, rook on f1",
          piece_on(b, WHITE, 6) == KING and piece_on(b, WHITE, 5) == ROOK)
    check("king move clears white castling rights", b.castle == 12)
    unmake(b, m, undo)
    m = [x for x in gen_legal(b) if move_str(x) == "a1a8"][0]
    undo = make(b, m)
    check("rook capture on a8 clears black queenside right", not (b.castle & 8))
    unmake(b, m, undo)
    check("unmake restores move count", len(gen_legal(b)) == n0)

    print("== zobrist + make/unmake integrity ==")
    b = set_fen(STARTPOS)
    rng = random.Random(99)
    good = True
    for _ in range(60):
        if b.zkey != compute_key(b):
            good = False
            break
        moves = gen_legal(b)
        if not moves:
            break
        m = rng.choice(moves)
        snap = (tuple(b.bb), b.side, b.castle, b.ep, b.half, b.zkey)
        undo = make(b, m)
        if b.zkey != compute_key(b):
            good = False
            break
        unmake(b, m, undo)
        if (tuple(b.bb), b.side, b.castle, b.ep, b.half, b.zkey) != snap:
            good = False
            break
    check("60 random make/unmake round-trips, key always matches full recompute", good)

    print("== mates, stalemate, draws ==")
    scholar = "r1bqkbnr/pppp1ppp/2n5/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 4 4"
    b = set_fen(scholar)
    t0 = time.time()
    score, mv = search(b, 3)
    check("scholar's mate: finds Qxf7# (got %s score %d, %.1fs)" %
          (move_str(mv) if mv else None, score, time.time() - t0),
          mv is not None and move_str(mv) == "h5f7" and score >= MATE - 100)

    fools = "rnb1kbnr/pppp1ppp/8/4p3/6Pq/5P2/PPPPP2P/RNBQKBNR w KQkq - 1 3"
    b = set_fen(fools)
    us, them = b.side, b.side ^ 1
    check("fool's mate: white has no legal moves and is in check",
          gen_legal(b) == [] and is_attacked(b, king_sq(b, us), them))
    score, mv = search(b, 2)
    check("fool's mate: search reports mated (score %d)" % score, score <= -MATE + 100)

    stale = "k7/8/1Q6/8/8/8/8/K7 b - - 0 1"
    b = set_fen(stale)
    score, mv = search(b, 3)
    check("stalemate: search scores 0 (got %d)" % score, score == 0)

    b = set_fen("8/8/8/4k3/8/4K3/8/8 w - - 0 1")
    check("K vs K insufficient material", insufficient(b))
    b = set_fen("8/8/8/4k3/8/4KB2/8/8 w - - 0 1")
    check("KB vs K insufficient material", insufficient(b))
    b = set_fen("8/8/8/4k3/8/4K3/8/8 w - - 100 90")
    score, _ = search(b, 2)
    check("fifty-move rule scores 0 (got %d)" % score, score == 0)

    print("== search sanity ==")
    b = set_fen("r1bqkbnr/pppp1ppp/2n5/4p3/2B1P3/8/PPPP1PPP/RNBQK1NR w KQkq - 0 1")
    t0 = time.time()
    score, mv = search(b, 4)
    dt = time.time() - t0
    nps = nodes / dt if dt > 0 else 0
    check("depth-4 search completes: %s score %d, %d nodes, %.0f nps" %
          (move_str(mv) if mv else None, score, nodes, nps),
          mv is not None and abs(score) < MATE - 1000)
    print("RESULT: %d passed, %d failed" % (ok, fail))
    return fail == 0


# --------------------------------------------------------------------- CLI
def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print("usage: chess.py perft <depth> [fen] | bestmove <depth> [fen] |")
        print("               play <depth> [max_plies] [fen] | test")
        return 2
    cmd = argv[1]
    if cmd == "test":
        return 0 if run_tests() else 1
    if cmd == "perft":
        depth = int(argv[2])
        b = set_fen(argv[3] if len(argv) > 3 else STARTPOS)
        t0 = time.time()
        n = perft(b, depth)
        print("perft(%d) = %d  (%.2fs)" % (depth, n, time.time() - t0))
        return 0
    if cmd == "bestmove":
        depth = int(argv[2])
        b = set_fen(argv[3] if len(argv) > 3 else STARTPOS)
        t0 = time.time()
        score, mv = search(b, depth)
        dt = time.time() - t0
        tag = ""
        if mv and abs(score) >= MATE - 1000:
            tag = "  mate in %d" % ((MATE - abs(score) + 1) // 2)
        print("bestmove %s  score %d%s  (%d nodes, %.2fs, %.0f nps)" %
              (move_str(mv) if mv else "(none)", score, tag, nodes, dt,
               nodes / dt if dt > 0 else 0))
        return 0
    if cmd == "play":
        depth = int(argv[2])
        max_plies = int(argv[3]) if len(argv) > 3 else 80
        b = set_fen(argv[4] if len(argv) > 4 else STARTPOS)
        hist = []
        result = "*"
        for _ in range(max_plies):
            if b.half >= 100 or insufficient(b):
                result = "1/2-1/2 (draw)"
                break
            t0 = time.time()
            score, mv = search(b, depth)
            dt = time.time() - t0
            if mv is None:
                us, them = b.side, b.side ^ 1
                result = "0-1 (mate)" if is_attacked(b, king_sq(b, us), them) else "1/2-1/2"
                if b.side == BLACK:
                    result = "1-0 (mate)" if result.startswith("0-1") else result
                break
            hist.append(move_str(mv))
            print("%3d. %-7s score %+6d  (%d nodes %.1fs)" %
                  (len(hist), move_str(mv), score, nodes, dt))
            make(b, mv)
        print("moves:", " ".join(hist))
        print("result:", result)
        print_board(b)
        return 0
    print("unknown command: %s" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
