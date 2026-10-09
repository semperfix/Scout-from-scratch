# Learning expedition #51 — HTTP/2 + HPACK from scratch

## What was built (`~/workspace/learning/51-http2/`)

- **`hpack.py`** — complete RFC 7541: N-bit-prefix integer codec (§5.1),
  Huffman codec over the fixed Appendix B table (§5.2), the 61-entry static
  table (App. A), dynamic table with §4.1 size accounting + FIFO eviction,
  and all five §6 header-field representations. Encoder (Huffman selection,
  dynamic-table indexing, never-indexed sensitive fields) + Decoder (strict
  padding/EOS validation, table-size ceilings, header-list-size guard).
- **`http2.py`** — RFC 7540 framing: 9-byte frame header, all ten frame types,
  client connection preface, SETTINGS negotiation, stream multiplexing with
  per-stream state, two-level flow control with exact WINDOW_UPDATE math,
  HEADERS/CONTINUATION fragmentation in both directions, PING/GOAWAY/RST
  handling, HPACK on every header block.
- **`h2tls.py`** — TLS 1.3 handshake reusing the #42 stack, with ALPN
  negotiation (`h2`, `http/1.1`) and the server's selection parsed out of
  EncryptedExtensions. Required one backwards-compatible change to #42:
  `build_client_hello(..., alpn_protos=(b'http/1.1',))` (default = old bytes;
  #42's suite still 58/58).
- **`h2fetch.py`** — CLI: `get` (single fetch), `multi` (concurrent
  multiplexed streams), `frames` (forensic dump of captured raw bytes with
  HPACK-decoded header blocks — pairs with #16's stream carver).
- **`test_http2.py`** (82/82), **`test_live.py`** (10/10 vs nghttp2.org).

## Real insights (earned, not read)

1. **The RFC's hex column lies; the bits column tells the truth.** Appendix B
   lists symbol 30's hex as `fffffa` (24 bits) next to a 28-bit bit-pattern and
   `[28]`. My canonical-sequentiality check flagged it: the real code is
   `0xFFFFFFA` (bits are authoritative). Same class of slip for symbol 31 in my
   own transcription. Transcription errors in a 257-entry table are near-
   certain; structural checks (Kraft == 1, canonical sequentiality) catch them
   where eyeballing can't.
2. **§6.2.1's prefix is 6 bits, not 4.** I first wrote 4-bit from fuzzy memory
   of the diagram. The RFC's own C.3.2 example convicts it: byte `0x58` decodes
   to name index 24 (`01|011000`), impossible with a 4-bit prefix. The
   differential test against python-hpack caught this before any RFC vector
   did (C.3.1's small indices pass under both).
3. **HPACK is stateful compression — the tables are the protocol.** A header
   block is meaningless without the dynamic-table state built by all previous
   blocks on that connection. Consequence for forensics: you cannot decode a
   captured HEADERS frame in isolation; `h2fetch frames` replays the whole
   capture through one decoder for exactly this reason.
4. **Huffman padding discipline is a security boundary.** Decoder must reject:
   EOS symbol mid-string, padding longer than 7 bits, padding with any zero
   bit. (This is the same "don't let the compressor become an oracle" lineage
   as the CRIME discussion in §7 — never-indexed literals exist so secrets
   like `authorization` never enter the shared table; my encoder honors that.)
5. **Flow control is two independent windows** (connection + per-stream), each
   starting at 65535, decremented by DATA wire length *including padding*,
   topped up with WINDOW_UPDATE. Verified to exact-increment arithmetic
   (32768-byte top-up after crossing the 32768 threshold), not just "it works".
6. **SETTINGS_INITIAL_WINDOW_SIZE adjusts live streams by delta** (RFC 7540
   §6.9.2) — easy to forget; the fake-server test asserts the adjustment.
7. **Multiplexing falls out of the dispatch design.** `pump_until(sid)` pumps
   *all* arriving frames into per-stream buffers and returns when *its* stream
   completes — so two `request_start` calls followed by two `pump_until`s is
   genuine concurrent multiplexing on one connection (proven live: streams 3
   and 5, JSON intact on the right stream).
8. **The egress proxy forwards ALPN cleanly.** Offering `(h2, http/1.1)` got
   `h2` selected with CertificateVerify+Finished validating — same clean-pipe
   behavior #50 found for damus.io.
9. **Test-harness bugs outnumbered implementation bugs ~2:1** (recurring
   theme across all 51 expeditions): comparing the oracle's `str` headers to
   my `bytes`; reusing the stateful oracle encoder across trials; a 14-bit
   "prefix"; one 40000-byte DATA frame (max is 16384); byte-comparing
   `/httpbin/get` (it echoes User-Agent); forgetting L2 consumed stream 1.
   Suspect the harness first — again.

## Validation

- `test_http2.py` **82/82**: integer vectors (C.1), Huffman table structure
  (Kraft, canonicality, EOS), Huffman byte-exact vectors (C.4.1/C.6.1/C.6.3),
  padding/EOS rejections, all 19 Appendix C decode vectors incl. dynamic-table
  evolution and 256-octet evictions, encoder behaviors (indexed repeats,
  never-indexed, size updates, error paths), frame roundtrips, fake-server
  handshake/ack/ping, fragmentation, flow-control math, RST/GOAWAY, trailers,
  padding, unknown-type tolerance.
- **Differential vs python-hpack**: 256/256 Huffman symbols byte-identical;
  300/300 random header lists decode-equal in both directions.
- `test_live.py` **10/10** against nghttp2.org: ALPN=h2, GET / byte-identical
  to curl (6324 bytes), multiplexed streams 3+5, 2nd-request header block
  `82 87 be 84` (fully indexed via dynamic table), PING roundtrip.
- `h2fetch.py get` body == curl; `frames` dumps a synthetic capture with
  HPACK-decoded headers, RST/GOAWAY/WINDOW_UPDATE annotation.

## New capability

A complete, dependency-free HTTP/2 client: fetch any h2 site through the
hand-rolled TLS 1.3 stack with multiplexed concurrent streams on one
connection, plus a forensic frame/HPACK dump mode for captured sessions.
Natural upgrade path for the #14 crawler (one connection, many concurrent
fetches) and the #16 pcap pipeline (carve → `h2fetch frames` → read the
headers).
