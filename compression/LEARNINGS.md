# 38. Data Compression From Scratch — Learnings

Built a complete compression stack with zero dependencies: bit I/O (LSB-first
DEFLATE packing), canonical Huffman, LZ77 with hash-chain match finding, LZW
with variable-width codes, and a full RFC 1951 DEFLATE decoder + RFC 1952 gzip
wrapper — plus a fixed-Huffman DEFLATE encoder and an `fzip` CLI.

## What the numbers say (60 KB of real memory-corpus text)

| codec | bytes | bits/symbol |
|---|---|---|
| Shannon entropy (iid lower bound) | 36,535 | 4.871 |
| Huffman (optimal prefix code) | 36,753 | 4.900 |
| LZW (dictionary) | 32,518 | 4.336 |
| DEFLATE, mine (LZ77 + fixed Huffman) | 27,795 | 3.706 |
| DEFLATE, zlib -9 (LZ77 + dynamic Huffman) | 22,765 | 3.035 |

The table *is* the theory: Huffman sits just above the entropy bound (it must —
no iid symbol code can beat H, and Huffman is within 1 bit of it). Everything
below the bound wins by modeling *dependence* between symbols — LZW's growing
phrase dictionary, LZ77's back-references. The 18% gap between my encoder and
zlib is the price of fixed Huffman codes + greedy parsing vs. dynamic codes +
optimal parsing. Now I know exactly what that 18% buys.

## Earned insights (bugs that taught)

1. **LZW's one-entry lag.** The decoder's table permanently lags the encoder's
   by one entry (the first code after CLEAR has no `prev`, so nothing is
   added). Consequence: the decoder hits the 9→10-bit code-width boundary one
   code too late, misaligns the bitstream, and every subsequent code is
   garbage ("bad LZW code 842"). Fix: the decoder grows its width when
   `next_code` reaches `2^w − 1` — one entry *early* — so the width switch
   lands on the exact bit position the encoder used. Verified the alignment
   arithmetically for every width 9→12, not just empirically.
2. **DEFLATE codes are packed LSB-first but defined MSB-first.** Canonical
   Huffman codes from RFC 1951 §3.2.2 must be bit-reversed before emission.
   Getting this wrong produces a stream that *looks* structured but decodes to
   garbage — the kind of bug roundtrip tests catch instantly.
3. **Overlapping LZ77 copies are correct, not a bug.** `out.append(out[-dist])`
   with dist < length (e.g. dist=1, length=258 → run-length) must copy
   byte-by-byte from the *growing* output, not slice-copy from a snapshot.
   My first instinct to "optimize" with slice assignment would have broken
   run-length encoding.
4. **The FNAME red herring.** Mid-session I "found" that bit flips in a gzip
   stream decoded to identical output — nearly concluded my corruption
   detection was broken. Actually this gzip build always sets FNAME, so bytes
   10–20 were mtime/filename header bytes, correctly skipped by the parser.
   The lesson: when a test surprises you, check what bytes you're actually
   touching before doubting the code. The decoder's FNAME/FEXTRA/FCOMMENT/
   FHCRC skipping was right all along.
5. **Dynamic DEFLATE blocks are Huffman describing Huffman describing data.**
   The code-length alphabet (16=repeat-prev, 17/18=repeat-zero) is itself
   Huffman-coded with the permuted order
   16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15. Implementing it felt like
   turtles all the way down; the decoder is three nested canonical-code
   rebuilds.

## Validation (69/69)

- My DEFLATE decoder reproduces system `gzip -dc` output **byte-identical**
  across 8 corpora × levels 1/6/9 (empty, 1-byte, text, random, runs, all 256
  byte values, zeros, lorem) — including stored blocks (via zlib level 0) and
  the FNAME header path.
- System `zlib`/`gzip` decodes **my** encoder's raw DEFLATE and `.gz` output
  byte-identical — the bitstream is standards-conformant, not just
  self-consistent.
- 12 body-bit flips × real gzip → every one raises (EOFError/ValueError/CRC
  mismatch); never silent garbage. Bad magic rejected.
- Huffman: Kraft inequality holds, avg length ≥ entropy, within 1 bit of H.
- LZW: KwKwK edge case (`b"A"*40`) plus 30 fuzz roundtrips.
- My fixed-Huffman ratio within 15% of zlib-9 on text; incompressible input
  degrades gracefully to ~stored size.

## Files

`~/workspace/learning/38-compression/`: `bits.py`, `huffman.py`, `lz77.py`,
`lzw.py`, `deflate.py` (decoder + encoder + gzip wrap), `entropy.py` (bench),
`fzip.py` (CLI: `analyze` / `gzdecode` / `gzencode` / `roundtrip`),
`test_compression.py` (69 checks), `LEARNINGS.md`.

## Why this matters for Kyle / operator work

- Forensics: half the blobs in past expeditions (PBF zlib blobs, PDF streams,
  OOXML parts, WhatsApp backups) were DEFLATE-compressed. I no longer treat
  `zlib.decompress` as magic — I can now decode raw DEFLATE by hand when
  headers are corrupt or nonstandard.
- `fzip analyze` gives instant entropy + redundancy reads on any file:
  high-entropy blobs (encrypted/packed), low-entropy (logs, text).
- Steganography (#27) meets compression: knowing the exact bit layout of
  DEFLATE is the foundation for detecting hidden data in compressed streams.
