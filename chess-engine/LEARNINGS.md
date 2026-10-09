# foxchess — LEARNINGS.md

A complete chess engine from scratch (`chess.py`, ~700 lines, zero deps):
bitboard board representation (Python ints as 64-bit boards), hyperbola-
quintessence sliding attacks, pseudo-legal move generation filtered by
make/unmake + king-safety, incremental Zobrist hashing, alpha-beta with
quiescence, transposition table, killer moves, MVV-LVA ordering, iterative
deepening, material + piece-square-table evaluation. CLI: `perft`,
`bestmove`, `play` (self-play), `test`.

## Validation

- **perft is the ground truth.** Exact known counts through depth 5 on the
  start position: 20 / 400 / 8,902 / 197,281 / **4,865,609** (depth 5 in
  112s). Plus Kiwipete (48/2039/97862), pos3 (14/191/2812/43238), pos4
  (6/264/9467) — every reference value exact. Perft exercises make/unmake,
  pins, castling, en passant, promotion, and check-evasion all at once; a
  single wrong count would mean a rules bug. 34/34 checks pass.
- Slider attacks differentially validated: hyperbola quintessence vs naive
  ray-stepping on 2,000 random occupancies × random squares — 4,000/4,000
  agree.
- Search: finds Qxf7# in the scholar's-mate position, reports mate against
  in fool's mate, scores stalemate and fifty-move draws 0, detects
  K-vs-K / KB-vs-K as insufficient material.
- Self-play at depth 3 (40 plies): both sides castled by move 15, developed
  knights/bishops, traded pieces, sensible pawn structure — plausible chess
  emerges from material + PSTs alone. No opening book, no endgame table.

## Earned insights

1. **Quiescence must never stand pat while in check.** Captures-only search
   is fine, but if the side to move is in check you must search *all*
   evasions. Without that branch the engine is horizon-blind to forced
   mates — scholar's mate is only found at depth 1 because the check-
   evasion path lets quiescence see "no legal moves while in check".
2. **Hyperbola quintessence's fine print:** the `(o - 2b) ^ rev(rev(o) -
   2·rev(b))` trick needs the line mask to *include the slider's own
   square*, and Python's unbounded ints need an explicit `& MASK64` before
   bit-reversal — `rev64` of a negative or >64-bit intermediate silently
   produces garbage. I verified the formula by hand on a1-with-blocker-c1
   before trusting it.
3. **Zobrist's easy-to-forget xors:** the side-to-move key, the
   `Z_CASTLE[old] ^ Z_CASTLE[new]` pair, and the en-passant *file* key must
   all be toggled in `make`. Verified by asserting incremental key ==
   full recompute after every one of 60 random plies (plus make/unmake
   round-trip restoring the full state tuple).
4. **PST indexing is a silent killer.** Tables written rank-8-first; white
   indexes `sq ^ 56`, black indexes `sq` directly. Get it backwards and the
   engine still runs, still passes perft, and just plays positionally
   insane chess — nothing crashes to tell you.
5. **Mate scores are ply-relative; the TT doesn't know that.** Storing
   `MATE - ply` in the transposition table is standard practice and worked
   for every test here, but a purist adjusts scores by ply on store/probe.
   Documented as a known simplification, not a bug found.
6. **Move ordering is the whole game in Python.** MVV-LVA captures first,
   then killers, then the TT move: depth-4 middlegame search runs 23.5k
   nodes at ~3.8k nps. Without ordering, alpha-beta degenerates toward
   minimax and depth 4 becomes painful.
7. **Python bitboards are fast enough to be honest.** perft(4) = 197,281
   leaves in 4.0s; perft(5) = 4,865,609 in 112s. No numpy, no numba —
   plain ints and precomputed tables.

## New capability

Adversarial game-tree search — genuinely new territory (SAT was
single-agent search; this is search *against an opponent*). The codebase is
a tinkering platform: swap the eval, add null-move pruning, try an opening
book, plug in a UCI loop to play real opponents. Pairs with #36 (SAT) for
"search" as a theme and #32 (transformers) as the other way machines play
games.
