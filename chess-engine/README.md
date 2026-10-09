# foxchess — A Chess Engine from Scratch

A complete chess engine in ~700 lines of stdlib-only Python (`chess.py`):
bitboard board representation (Python ints as 64-bit boards), hyperbola-
quintessence sliding attacks, pseudo-legal move generation filtered by
make/unmake + king-safety, incremental Zobrist hashing, alpha-beta with
quiescence search, transposition table, killer moves, MVV-LVA move
ordering, iterative deepening, and material + piece-square-table
evaluation. CLI: `perft`, `bestmove`, `play` (self-play), `test`.

**Move legality is proven, not hoped for:** perft counts match the exact
reference values through depth 5 on the start position — 20 / 400 /
8,902 / 197,281 / **4,865,609** — plus Kiwipete (48/2039/97862), pos3
(14/191/2812/43238), and pos4 (6/264/9467). A single wrong count would
mean a rules bug, and every reference value is exact. **34/34 checks pass.**
Slider attacks are differentially validated (hyperbola quintessence vs
naive ray-stepping: 4,000/4,000 agree on random occupancies), and the
search finds Qxf7# in the scholar's-mate position and reports mate in
fool's mate.

## Dependencies

Stdlib only. No pip packages.

## How to run

```
python3 chess.py test                        # 34/34: perft, attacks, Zobrist, search, mates, draws
python3 chess.py perft 4                     # exact leaf counts (depth 5 takes ~2 min)
python3 chess.py bestmove 3                  # search the start position to depth 3
python3 chess.py play 3 40                   # self-play, depth 3, up to 40 plies
```

## Usage example

```python
import chess  # not importable as-is (script-style); drive via CLI or paste a FEN:
# python3 chess.py bestmove 3 "r1bqkbnr/pppp1ppp/2n5/4p3/2B1P3/5N2/PPPP1PPP/RNBQK2R w KQkq - 4 4"
```

CLI examples with expected output:

```
$ python3 chess.py perft 3
perft(3) = 8902  (0.31s)

$ python3 chess.py bestmove 2
bestmove e2e4  score 25  (1839 nodes, 0.48s, 3831 nps)
```

## Limitations

- **Slow by engine standards:** ~3.8k nodes/sec in Python, so depth 3–4 is
  the realistic ceiling. It's a correctness-first engine, not a blitz one.
- **No UCI loop** — you can't plug it into Arena/Cutechess directly; it
  speaks its own tiny CLI. A UCI wrapper is an obvious follow-up.
- **No opening book, no endgame tablebases.** It emerges from material +
  PSTs alone (self-play at depth 3 castles, develops, trades sensibly —
  but it has never seen a real opening).
- **Mate scores are ply-relative in the transposition table** (stored as
  `MATE - ply` without adjustment on store/probe). Standard-practice
  shortcut; a purist would adjust. Documented, not found-broken.
- **Python ints need `& MASK64` discipline** before bit-reversal — the
  hyperbola-quintessence code does this, but anyone extending it should
  know unbounded ints will silently produce garbage otherwise.
- PSTs are written rank-8-first; white indexes `sq ^ 56`, black indexes
  `sq` directly. Get it backwards and it still runs, still passes perft,
  and just plays positionally insane chess.

## Files

- `chess.py` — the whole engine: bitboards, movegen, search, CLI
- `LEARNINGS.md` — the full expedition writeup (perft table, earned insights)
