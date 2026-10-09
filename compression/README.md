# Data Compression From Scratch

A complete compression stack with zero dependencies: LSB-first bit I/O, canonical Huffman coding, LZ77 with hash-chain match finding, LZW with variable-width codes, and a full RFC 1951 DEFLATE decoder plus RFC 1952 gzip wrapper — alongside a fixed-Huffman DEFLATE encoder whose output system `zlib`/`gzip` decodes byte-identically. `fzip.py` is the CLI workbench: entropy analysis, codec benchmarking, gzip encode/decode, and roundtrip integrity checks. On 60 KB of real text, the hand-rolled DEFLATE hits 3.706 bits/symbol vs the 4.871-bit Shannon bound and 3.035 for zlib -9.

## Dependencies

Python 3 standard library only. No third-party packages (verified: `bits.py`, `huffman.py`, `lz77.py`, `lzw.py`, `deflate.py`, `entropy.py`, `fzip.py` import only `heapq`, `math`, `os`, `random`, `subprocess`, `sys`, `tempfile`, `zlib` — stdlib only; `zlib` is used purely as a cross-check oracle in tests, not in the codecs).

## How to run

Entry point: `fzip.py`

```
python3 fzip.py analyze FILE     # entropy + head-to-head codec benchmark
python3 fzip.py roundtrip FILE   # all-codec roundtrip integrity check
python3 fzip.py gzencode FILE    # encode with fixed-Huffman DEFLATE -> real .gz
python3 fzip.py gzdecode FILE.gz # decode a gzip file with the hand-rolled DEFLATE
python3 test_compression.py      # 69 checks (roundtrips, fuzz, gzip cross-compat, corruption detection)
```

## Usage example

```
$ python3 fzip.py analyze somefile.txt
shannon entropy: 4.87 bits/symbol (lower bound: 36535 bytes)
huffman:      36753 bytes (4.900 b/sym)
lzw:          32518 bytes (4.336 b/sym)
deflate-fixed: 27795 bytes (3.706 b/sym)   <- mine
zlib -9:       22765 bytes (3.035 b/sym)
```

## Key learnings (from LEARNINGS.md)

- The benchmark table *is* the theory: Huffman sits just above the Shannon bound (no iid symbol code can beat H; Huffman is within 1 bit of it). Everything below the bound wins by modeling *dependence* — LZW's growing phrase dictionary, LZ77's back-references. The 18% gap between my encoder and zlib is exactly the price of fixed Huffman codes + greedy parsing vs dynamic codes + optimal parsing.
- The LZW decoder's table permanently lags the encoder's by one entry, so it hits the 9→10-bit code-width boundary one code too late and misaligns the bitstream into garbage. Fix: the decoder grows its width when `next_code` reaches `2^w − 1` — one entry *early* — so the width switch lands on the exact bit position the encoder used.
- DEFLATE canonical codes are defined MSB-first but packed LSB-first (RFC 1951 §3.2.2) — bit-reverse before emission, or the stream *looks* structured but decodes to garbage. Roundtrip tests catch this instantly.
- Overlapping LZ77 copies are correct, not a bug: `out.append(out[-dist])` must copy byte-by-byte from the *growing* output, not slice-copy from a snapshot — dist=1, length=258 is run-length encoding and the "optimization" would break it.

## Files

- `fzip.py` — CLI workbench: `analyze` / `roundtrip` / `gzencode` / `gzdecode`
- `bits.py` — LSB-first bit reader/writer (DEFLATE bit packing)
- `huffman.py` — canonical Huffman encoder/decoder, code-length handling
- `lz77.py` — tokenize/detokenize with hash-chain match finding
- `lzw.py` — LZW with variable-width codes (9→12 bit), CLEAR code, KwKwK edge case
- `deflate.py` — RFC 1951 decoder (fixed + dynamic blocks) + fixed-Huffman encoder + RFC 1952 gzip wrap
- `entropy.py` — Shannon entropy + codec benchmark harness
- `test_compression.py` — 69 checks: roundtrips, differential vs system gzip, bit-flip corruption detection
- `LEARNINGS.md` — full expedition notes
