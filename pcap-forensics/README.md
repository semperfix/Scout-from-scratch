# Network Traffic (pcap) Forensics

Hand-rolled packet forensics with zero Wireshark/tshark: libpcap and pcapng
readers (per-section endianness, timestamp resolutions), Ethernet/IPv4/IPv6
TCP/UDP dissectors, and full per-direction TCP stream reassembly (sequence
ordering, overlap trimming, retransmit accounting — including the classic
SYN-consumes-a-sequence-number accounting). App-layer dissectors pull HTTP
requests/responses (Content-Length and chunked), TLS ClientHello SNIs, and DNS
queries from the streams. The triage engine flags port scans, beaconing
(periodicity + inter-arrival CV test), large transfers, and lists TLS SNIs,
DNS queries, and top talkers; `--carve` dumps every direction of every stream
to disk. Answers "what is this thing actually phoning home to" for any
suspicious capture.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages.

## How to run

**Triage a capture** (entry point `pcapcheck.py`):

```bash
python3 pcapcheck.py capture.pcap
python3 pcapcheck.py capture.pcapng --carve carved/   # dump every stream direction
python3 pcapcheck.py capture.pcap --json
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `SUSPICIOUS`).

**Rebuild the fixtures:**

```bash
python3 make_fixtures.py    # crafts fixtures/http.pcap and dns.pcapng with struct
```

## Example

```bash
$ python3 pcapcheck.py fixtures/http.pcap
file: fixtures/http.pcap  (libpcap, 7 packets, 0 skipped)
tcp streams: 1
  192.168.1.10:43210 <-> 93.184.216.34:80  pkts=6 bytes=156 retrans=0 syn=True fin=False dir0=78B dir1=78B
http:
  [request] 192.168.1.10:43210: GET /index.html HTTP/1.1  (body 0B)
  [response] 93.184.216.34:80: HTTP/1.1 200 OK  (body 13B)
dns queries: example.com
top talkers:
  192.168.1.10: 313 bytes
  93.184.216.34: 276 bytes
VERDICT: CLEAN -- no indicators

$ python3 pcapcheck.py /tmp/scan.pcap
findings:
  [!!] possible port scan: 192.168.1.10 -> 93.184.216.34 probed 16 ports
VERDICT: SUSPICIOUS -- high-severity indicators
```

## What it does

- **libpcap reader** — magic-driven endianness (µs and ns variants),
  global header, per-packet ts/caplen/len headers.
- **pcapng reader** — Section Header Blocks (endianness per section, so
  mixed-endian files work), Interface Description Blocks with `if_tsresol`
  option parsing, Enhanced Packet Blocks with 32-bit alignment handling.
- **Dissectors** — Ethernet (with single VLAN tag), IPv4 (IHL-aware), IPv6
  (extension-header walk), TCP/UDP. ARP and non-IP ethertypes are noted as
  skipped, not crashed on.
- **TCP reassembly, per direction** — each side of a 4-tuple has its own
  sequence space; segments are ordered, overlaps trimmed, retransmits
  counted, SYN/FIN sequence consumption honored, gaps NUL-padded
  (documented, not hidden).
- **App layer** — HTTP/1.x request/response parsing with Content-Length and
  chunked bodies, TLS ClientHello SNI extraction (extension-walking, not
  regex), DNS message parsing with compression-pointer support (UDP).
- **Triage** — port scan (≥10 SYN-only ports, one src→dst), beaconing
  (CV of inter-arrival times < 0.25 over ≥6 connections), large transfers
  (≥1 MB), top talkers, SNI and DNS query lists.

## Key learnings

- **TCP is full-duplex — never merge directions into one sequence space.**
  The first build did exactly that and the carve came out as request + 4KB
  of NUL padding + response. Per-direction reassembly is the fix; the bug
  was caught by reading the carved bytes, not by packet counts.
- **pcapng block lengths include header + trailer.** Double-counting the
  12-byte framing in the fixture made the reader bail at the first EPB;
  the file walked fine by hand but `pos + blen > len(data)` told the truth.
- **The SHB byte-order magic is at body offset 0**, not 8 — the 8-byte block
  header (type + length) is already stripped before the body starts.
- **SNI parsing needs the extension walk, not a string search.** The
  server_name extension nests list-length → name-type → name-length → name;
  a `find(b"evil")` would false-positive on any coincidental bytes.
- **Beaconing needs an isolated pair.** A host doing a port scan *and*
  beaconing won't trip the periodicity test on the mixed pair — the CV is
  honestly high. That's correct behavior, not a miss.

## Files

| File | What it does |
|---|---|
| `pcapcheck.py` | **Entry point**: readers, dissectors, reassembly, app-layer, triage, carver |
| `make_fixtures.py` | Crafts fixtures with `struct` (no scapy): handshake + split HTTP GET + DNS |
| `fixtures/http.pcap` | libpcap LE: TCP handshake, HTTP GET split across 2 segments, HTTP 200, DNS query |
| `fixtures/dns.pcapng` | pcapng: SHB + IDB + EPB carrying one DNS query |

## Limitations

- Link types: Ethernet and raw IP only (no 802.11, PPP, loopback).
- No IP checksum/TCP checksum validation (fixture checksums are zeroed).
- TLS: ClientHello SNI only — no decryption, no other handshake messages.
- DNS: UDP only; TCP DNS and EDNS options skipped.
- Beaconing/port-scan are heuristics. Verify before acting.

## Source material

See `SKILLS.md` (skill #16) in the repo root for the full expedition notes.
