# DNS Internals

Full RFC 1035 wire format by hand (message encode/decode with compression
pointers, A/AAAA/MX/TXT/NS/SOA/CNAME/PTR/RRSIG/DNSKEY rdata), a working
iterative resolver (root hints → referrals → glue → CNAME chasing, TCP
fallback on truncation), DNS-over-HTTPS, and one-link DNSSEC RRSIG
verification with hand-rolled RSA/SHA-256 over the RFC 4034 canonical form.
Plus a DGA/DNS-tunneling heuristic (entropy + consonant-ratio scoring).
Almost everything runs offline; only live resolution needs network.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages (`socket`, `ssl`, `urllib`, `struct`)

## How to run

Entry point is `dnscheck.py` (argparse):

```bash
python3 dnscheck.py --help
python3 dnscheck.py --build www.example.com --qtype A     # build a query (hex out)
python3 dnscheck.py --parse <hex>                         # decode a wire message
python3 dnscheck.py --file fixtures/response.bin          # parse a capture
python3 dnscheck.py --dga xkq9zvm2wrtplbncxaa19384.example.com

# module self-tests (all offline)
python3 dns.py        # wire format round-trips, compression pointers
python3 dnssec.py     # RRSIG sign -> verify, tamper + wrong-key rejection
python3 resolver.py   # iterative resolution against a fake root (no network)

# live modes (need network; degrade gracefully without it)
python3 doh.py example.com            # DNS-over-HTTPS via dns.google
python3 resolver.py www.example.com   # full iterative resolution from root hints
```

Library use:

```python
from dns import build_query, parse_message
from resolver import iterative_resolve

wire = build_query("example.com", "MX")
msg = parse_message(wire)                       # {'questions': [...], ...}

answers = iterative_resolve("www.example.com", "A")   # needs network
```

## Example

```bash
$ python3 dnscheck.py --file fixtures/response.bin
# fixtures/response.bin (92 bytes)
id=0xabcd qr=1 opcode=0 rcode=0 qd=1 an=1 ns=1 ar=0
  Q: www.example.com A
  AN: www.example.com 300 A 93.184.216.34
  AU: example.com 86400 NS a.iana-servers.net

$ python3 dnscheck.py --dga xkq9zvm2wrtplbncxaa19384fjdksla.example.com
domain: xkq9zvm2wrtplbncxaa19384fjdksla.example.com
  label 'xkq9zvm2wrtplbncxaa19384fjdksla'  score=0.824 entropy=4.54 cons=0.88 digits=0.23 len=31
  ...
worst label: 'xkq9zvm2wrtplbncxaa19384fjdksla'  overall=0.824  VERDICT: DGA/TUNNEL-LIKELY
(heuristic only -- high entropy also matches CDNs, URL shorteners, and some legit generated hostnames)

$ python3 resolver.py
[PASS] iterative A: www.example.com -> 93.184.216.34 (via referral + glue)
[PASS] CNAME chase: alias.example.com -> 93.184.216.34
[PASS] no-data raises LookupError: too many referral hops resolving nosuch.example.com
RESOLVER SELF-TEST: PASS
```

## Key learnings

- **Compression pointers are the whole game in DNS parsing.** Every name in
  a response can be a pointer into any earlier part of the message; the
  decoder needs loop protection (`seen` set) and must distinguish "offset to
  continue parsing" from "offset after the pointer". The fixtures exercise
  this: the answer name is `c0 0c`, pointing back at the question.
- **The resolver's transport is injectable for a reason.** The sandbox blocks
  UDP loopback (`PermissionError` on `sendto`), so the self-test uses a fake
  in-process transport serving canned root/authority packets. The referral,
  glue, and CNAME logic under test is byte-identical to the live path — only
  the socket is swapped. Test the logic, not the kernel.
- **DNSSEC verification is one link, not a chain.** `verify_rrsig()` proves
  "this key signed this RRset" via the RFC 4034 canonical form (lowercased
  uncompressed names, original TTL, canonical RRset order, RRSIG fields minus
  signature). A full validator still needs the DS chain up to the root KSK
  trust anchor plus inception/expiration checks — documented, not faked.
- **The DGA heuristic is a flag, not a verdict.** `www` scores 0.250
  (likely-legit), a 31-char random label scores 0.824 — but so would some
  CDN hostnames. It belongs in a triage pipeline next to query volume and
  NXDOMAIN rates, not as a classifier.
- **RRSIG `labels` counts the *owner* name's labels**, not the signer's —
  an easy spec misread when the signer is the parent zone.

## Files

| File | What it does |
|---|---|
| `dnscheck.py` | **Entry point**: argparse CLI — `--parse`/`--build`/`--file`/`--dga` |
| `dns.py` | RFC 1035 wire codec: header, questions, RR parsing (A/AAAA/MX/TXT/NS/SOA/CNAME/PTR/RRSIG/DNSKEY), compression pointers, `key_tag` |
| `resolver.py` | Iterative resolver: root hints → referrals → glue → CNAME, TCP fallback; injectable transport; offline self-test |
| `doh.py` | DNS-over-HTTPS (RFC 8484) via `urllib`; optional, exits 2 without network |
| `dnssec.py` | RRSIG/DNSKEY parsing, RFC 4034 canonical signing form, RSA/SHA-256 verify (hand-rolled RSA + PKCS#1 v1.5), demo signing side |
| `make_fixtures.py` | Hand-crafts `fixtures/query.bin` + `fixtures/response.bin` with `struct` |
| `fixtures/` | `query.bin`, `response.bin` — parser inputs, independent of `dns.py` |

## Limitations

- **Live resolution needs network** (`resolver.py` argv mode, `doh.py`).
  Everything else — parsing, building, DNSSEC one-link verify, DGA scoring,
  resolver logic — is offline.
- No TCP fallback test against a real truncated reply (logic present, needs
  a live server that truncates).
- DNSSEC: single-link verification only; no chain-to-root, no NSEC/NSEC3
  denial-of-existence validation, no inception/expiration enforcement.
- DGA heuristic has no training data behind it — thresholds are reasonable
  guesses, documented as such.
