# HTTP from Raw Sockets

A complete HTTP/1.1 client on raw sockets — no HTTP library. Hand-built URL
parsing, request building, status-line/header parsing, all three body
framings (Content-Length, chunked with extensions and trailers, and
close-delimited), redirect following (301/302/303/307/308 with relative
resolution and method rewriting), keep-alive connection reuse, and forward
proxy support (absolute-URI for http, CONNECT tunnel + TLS for https).
**Verified byte-identical to curl** against a local test server.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — `socket`, `ssl`, `urllib.parse` (URL splitting only; all
  HTTP semantics are hand-rolled)

## How to run

Entry point is `httpfetch.py` (argparse). Start the test server first:

```bash
python3 test_server.py 18333 &   # raw-socket server: chunked+trailers, redirects, ...

python3 httpfetch.py http://127.0.0.1:18333/chunked
python3 httpfetch.py http://127.0.0.1:18333/redirect   # 302 -> /chunked, followed
python3 httpfetch.py http://127.0.0.1:18333/length --output body.bin
python3 httpfetch.py https://example.com/ --head       # needs network
python3 httpfetch.py http://example.com/ --proxy http://127.0.0.1:8080
```

Library use:

```python
from http_raw import Session

s = Session()                                   # keep-alive session
r = s.get("http://127.0.0.1:18333/chunked")
print(r.status, len(r.body), r.trailers)        # 200 37 {'x-checksum': [...]}
r = s.post("http://127.0.0.1:18333/echo-method", body=b"hi")
s.close()
```

## Example

```bash
$ python3 httpfetch.py http://127.0.0.1:18333/chunked
URL: http://127.0.0.1:18333/chunked
status: 200 OK
headers:
  transfer-encoding: chunked
  connection: keep-alive
trailers:
  x-checksum: deadbeef
  x-chunks: 3
body: 37 bytes  sha256=f36e1059ff461e5d1d0afbc4582a2143c8f7c09676b25d3efeb00a2553874fd0
preview: b'Hello, chunked chunked chunked world!'

$ python3 httpfetch.py http://127.0.0.1:18333/redirect
URL: http://127.0.0.1:18333/chunked
redirects (1):
  -> http://127.0.0.1:18333/redirect
status: 200 OK
...
body: 37 bytes  sha256=f36e1059ff461e5d1d0afbc4582a2143c8f7c09676b25d3efeb00a2553874fd0
```

Curl parity (all byte-identical):

```
[PASS] byte-identical to curl: /length (100B)
[PASS] byte-identical to curl: /chunked (37B)
[PASS] byte-identical to curl: /close (38B)
[PASS] byte-identical to curl: /redirect (followed)
```

## Key learnings

- **Chunked extensions and trailers are the parts every tutorial skips.**
  The decoder is a small state machine: `size[;ext]* CRLF, data, CRLF`
  repeating, then a `0`-chunk followed by *trailer headers* and a final
  CRLF. The test server emits extensions on every chunk and two trailers,
  and the client surfaces them in `resp.trailers` — verified byte-identical
  to curl's body output.
- **Redirect method-rewriting is where clients diverge.** 301/302 + POST →
  GET (browser convention, not the RFC letter), 303 → GET (except HEAD),
  307/308 → preserve method *and* body. The smoke test asserts a POST
  through a 307 arrives as POST with its body intact.
- **Keep-alive correctness showed up as a "failure".** The first smoke run
  expected 1 server-side connection but saw 2 — because `/close` sends
  `Connection: close`, and the client *correctly* dropped the pooled socket
  and opened a new one. The test expectation was wrong, not the code.
- **A forward proxy changes the request line, not the protocol.**
  Pointing `Session(proxy=...)` at the test server proved the absolute-URI
  form (`GET http://example.com/echo HTTP/1.1`) is generated; the server's
  echo confirmed it arrived intact.

## Files

| File | What it does |
|---|---|
| `httpfetch.py` | **Entry point**: argparse CLI — fetch a URL, print status/headers/trailers/body info |
| `http_raw.py` | The client: URL parse, raw socket + TLS, request build, header parse, chunked/Content-Length/close-delimited bodies, redirects, keep-alive pool, proxy (absolute-URI + CONNECT) |
| `test_server.py` | Raw-socket test server: chunked+extensions+trailers, relative 302, 307, close-delimited, echo routes, connection counting |

## Limitations

- HTTP/1.1 only — no HTTP/2 or HTTP/3.
- No `Transfer-Encoding: gzip` decompression (sends `Accept-Encoding: identity`).
- Digest auth, client certificates, and SOCKS proxies are not implemented.
- The stale-pooled-connection retry assumes idempotent reads; a write that
  half-succeeded before a RST could theoretically double-submit (same caveat
  every keep-alive client lives with).
