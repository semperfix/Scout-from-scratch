# HTTP/2 + HPACK — A Client from Scratch

A complete, dependency-free HTTP/2 client stack: `hpack.py` (complete
RFC 7541: N-bit-prefix integer codec, Huffman codec over the fixed
Appendix B table, the 61-entry static table, dynamic table with §4.1 size
accounting + FIFO eviction, and all five §6 header-field representations
— encoder with Huffman selection, dynamic-table indexing, and
never-indexed sensitive fields + a strict decoder), `http2.py` (RFC 7540
framing: 9-byte frame header, all ten frame types, client connection
preface, SETTINGS negotiation, stream multiplexing with per-stream state,
two-level flow control with exact WINDOW_UPDATE math, HEADERS/CONTINUATION
fragmentation, PING/GOAWAY/RST), `h2tls.py` (TLS 1.3 handshake reusing the
hand-rolled `#42` stack with ALPN negotiation), `h2fetch.py` (CLI: `get`
single fetch, `multi` concurrent multiplexed streams, `frames` forensic
dump of captured raw bytes with HPACK-decoded header blocks).

**Validation: `test_http2.py` 82/82** — integer vectors (C.1), Huffman
table structure (Kraft, canonicality, EOS), byte-exact Huffman vectors
(C.4.1/C.6.1/C.6.3), padding/EOS rejections, all 19 Appendix C decode
vectors incl. dynamic-table evolution and 256-octet evictions, encoder
behaviors, frame roundtrips, fake-server handshake/ack/ping,
fragmentation, flow-control math, RST/GOAWAY, trailers, padding,
unknown-type tolerance. **Differential vs `python-hpack`: 256/256 Huffman
symbols byte-identical; 300/300 random header lists decode-equal both
directions.** Live (`test_live.py`): 10/10 against nghttp2.org —
ALPN=h2, GET / byte-identical to curl, genuinely multiplexed streams,
PING roundtrip.

## Dependencies

- `hpack.py`, `http2.py`, `test_http2.py` — **stdlib only.**
- `h2tls.py`, `h2fetch.py`, `test_live.py` — stdlib **plus the
  `tls13.py` module from the sibling `../tls13/` skill directory** on the
  import path (`h2tls.py` does `import tls13`); the live tests also need
  network access to the target server.

## How to run

Offline (no network, no tls13 module needed):

```
python3 test_http2.py                        # 82/82: HPACK vectors, framing, flow control, fake server
```

Live fetches over real TLS 1.3 (needs `../tls13/tls13.py` on the path):

```
PYTHONPATH=../tls13 python3 h2fetch.py get https://nghttp2.org/
PYTHONPATH=../tls13 python3 h2fetch.py multi https://nghttp2.org/ https://nghttp2.org/httpbin/get
PYTHONPATH=../tls13 python3 h2fetch.py frames capture.bin     # forensic dump, no network needed
```

`test_live.py` hits **real external servers** (nghttp2.org via the egress
proxy's CONNECT tunnel) — it is documented here but **not run as part of
the offline smoke test**; run it deliberately when you have network:
`PYTHONPATH=../tls13 python3 test_live.py` (10/10 at build time).

## Usage example

Decode a header block with HPACK (the `82 87 be 84` sequence is a real
2nd-request block: fully indexed via the dynamic table):

```python
from hpack import Decoder

d = Decoder()
# simulate prior traffic that populated the dynamic table, then:
hdrs = d.decode(bytes.fromhex("8287be84"))
print(hdrs)   # [(b':method', b'GET'), (b':scheme', b'http'), ...]
```

Forensic dump of a captured session (replays the whole capture through
one stateful decoder — required, since header blocks are meaningless
without the dynamic-table state built by prior blocks):

```
python3 h2fetch.py frames capture.bin
```

## Limitations

- **Client only.** No server side, no `h2c` prior-knowledge server —
  `h2fetch` is a client and `http2.py` speaks the client preface.
- **TLS 1.3 only** (via the hand-rolled stack); no TLS 1.2 fallback, no
  plaintext upgrade. ALPN must select `h2`.
- **No PUSH_PROMISE handling** — a server that pushes gets its pushed
  streams ignored rather than processed.
- **HPACK is stateful across the whole connection** — you cannot decode a
  captured HEADERS frame in isolation; `frames` mode replays captures
  from the first byte for exactly this reason.
- **Flow control is honest but naive:** exact WINDOW_UPDATE arithmetic,
  but no auto-tuning — a slow reader can stall a fast server. Fine for a
  fetch tool, not a high-throughput crawler (that was the planned #14
  upgrade).
- `test_live.py` depends on nghttp2.org being up and speaking h2 the way
  it did at build time; byte-compare checks (`/httpbin/get` echoes
  User-Agent) are inherently brittle against server changes.

## Files

- `hpack.py` — RFC 7541: integers, Huffman, static/dynamic tables, encoder + decoder
- `http2.py` — RFC 7540 framing + multiplexed client
- `h2tls.py` — TLS 1.3 + ALPN (imports `tls13` from the sibling `../tls13/` skill)
- `h2fetch.py` — CLI: get / multi / frames
- `test_http2.py` — 82 offline checks (stdlib only)
- `test_live.py` — 10 live checks vs nghttp2.org (**hits real servers; run deliberately**)
- `LEARNINGS.md` — the full expedition writeup
