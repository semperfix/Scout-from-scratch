# BGP / Internet Routing Forensics — Learnings

## The wire formats (RFC 6396 + RFC 4271, from implementation)

- **MRT common header** is 12 bytes: `timestamp u32, type u16, subtype u16, length u32`
  (big-endian). Everything else keys off (type, subtype).
- **BGP4MP records have an Address Family field** (u16, after Interface Index)
  that I initially missed — my first cut tried to *guess* v4/v6 by hunting for
  the BGP marker, which failed on 3 real records. The AFI makes it
  deterministic: 1 → 4-byte addrs, 2 → 16-byte. Lesson: when a binary format
  seems to require heuristics, you misread the spec.
- **BGP UPDATE**: withdrawn-len, withdrawn, attr-len, attrs, NLRI. Path
  attributes are TLV with a flags byte: bit 0x10 = extended (2-byte) length.
  AS_PATH segments: type (1=SET, 2=SEQUENCE), count, then ASNs.
- **TABLE_DUMP_V2 always uses 4-byte ASNs** in AS_PATH (RFC 6396); BGP4MP
  MESSAGE_AS4 too. Only legacy MESSAGE (subtype 1) uses 2-byte ASNs, and then
  **AS4_PATH must be merged per RFC 6793** (replace trailing AS_TRANS
  placeholders) — implemented and tested.
- **NLRI prefix encoding**: 1 length byte + ceil(n/8) bytes, and real dumps
  rely on you masking trailing bits — canonicalize or comparisons lie.

## The memory problem and its solution

- rrc00 full table: **1.16M v4 + 267k v6 prefixes, 46.16M RIB entries**.
  A Python dict of per-prefix state would need ~1GB; the sandbox had ~184MB
  free. Solution: **external bucket sort** — stream once, append fixed-size
  binary records (15B v4 / 27B v6: plen, addr, origin, pathlen, flags,
  peer_as) into 512 bucket files keyed by first address byte, then sort and
  sweep each bucket in RAM. Flat memory, ~2× temp disk.
- **plen<8 prefixes span buckets** (e.g. a /7 covers two first-bytes), so a
  pure per-bucket sweep misses cross-bucket covering prefixes. Fix: collect
  "tiny" prefixes globally and check each bucket's prefixes against them
  (with real origin sets, so DEAGG comparison still works).
- **Single-pass attribute scan**: instead of fully decoding 46M attribute
  blocks, one tight walk extracts (origin, path length, AS_SET?, AS_TRANS?)
  — the only fields the detectors need. Full decode happens only for flagged
  prefixes via a targeted re-scan that skips non-matching records by offset
  math.

## Detectors and what they mean (honest framing)

- **MOAS** (multi-origin AS): same prefix from >1 origin. Often benign
  (anycast, multi-homing) — it's a lead, not a verdict.
- **DEAGG_ORIGIN_CHANGE**: a more-specific whose origin set is *disjoint*
  from its covering prefix — the exact shape of the 2008 YouTube/Pakistan
  Telecom hijack (a /24 announced inside someone else's /22). Strongest
  signal in the set.
- **BOGON_ORIGIN**: AS0, AS_TRANS surviving into a 4-byte table, private
  (64512–65534) or reserved ASNs as origin.
- **LONG_PATH / AS_SET / AS_TRANS_LEAK**: path-length outliers, aggregation
  obscuring origin, legacy-speaker leakage.
- **Valley-free (Gao-Rexford)**: path must read uphill (c2p)*, ≤1 peering,
  downhill (p2c)* from observer toward origin. A down-then-up "valley" is the
  route-leak signature. Needs CAIDA as-rel data; unknown links → INCONCLUSIVE,
  never forced into a verdict. Sibling-AS (same org) links aren't in as-rel —
  known blind spot, documented not hidden.
- **Live updates analysis** (5-min window): 268k UPDATEs → per-prefix
  last-origin tracking; 177 origin-change events, 14 blackhole (65535:666)
  announcements, and a route-flap storm (200.23.137.0/24 announced 10,316×
  in 5 minutes). Origin *changes* in the update stream are the closest thing
  to a live hijack alarm; oscillation between two origins usually means
  anycast/multi-homing rather than attack — the tool surfaces, the analyst
  decides.

## The DEAGG false-positive saga (the most instructive bug)

- First run: **819,477 DEAGG findings** — more than half the table. Obviously
  wrong. Root cause: the v4 default route **0.0.0.0/0** (leaked by 11 peers,
  11 different origins) was acting as "covering prefix" for *every* prefix
  via the cross-bucket tiny-prefix mechanism. A /0 says nothing about who
  holds an address block — it's default routing, not an aggregate. Fix:
  covering prefixes must be usable: /0s (default routes, often
  multi-origin) are excluded outright; other sub-/8 prefixes only count
  with a single unambiguous origin.
- Second run: **172,960 DEAGG**. Still mostly benign — and cross-checking
  against CAIDA as-rel proved it: **53% are covering-origin-is-provider-of-
  origin** (the classic legitimate pattern: provider announces the aggregate,
  customer announces their /24). 35% have no known relationship, 10% are
  covering-is-customer-of-origin, 1.5% peers.
- The honest end state: DEAGG is a *candidate generator*, not a verdict.
  The **hijack_hunt.py shortlist** ranks /24s (v4) inside single-origin
  aggregates, drops clear provider→customer delegation via as-rel, then
  verifies with full AS paths from a targeted re-scan: **covering origin in
  path → benign** (82/400), **absent → hijack-shaped lead** (318/400).
  Caveat documented in the code: multi-homed sub-allocations announced
  independently of the aggregate holder look *exactly* like hijacks without
  RPKI or time-series data. The tool ranks; the analyst decides.
- **Valley-free leak check** on 1,500 sampled hijack-shaped paths: 347 OK,
  44 LEAK, 9 INCONCLUSIVE. The LEAKs are real export-rule violations per the
  Gao-Rexford model (e.g. peer-learned route exported to a provider), each
  carrying the caveats: as-rel may be stale, sibling ASes (same org) are
  invisible in the data, edge-peering can look like a valley.

## Final numbers (RIPE RIS rrc00, 2026-10-08 00:00 UTC, 109 peers)

- 1,428,977 prefixes (1.16M v4 + 267k v6), 54,643,276 RIB entries
- MOAS 7,138 · BOGON_ORIGIN 945 · DEAGG_ORIGIN_CHANGE 181,578 ·
  LONG_PATH 613 · AS_SET 263 · AS_TRANS_LEAK 0
- 5-minute updates window: 268,439 UPDATEs, 611k announced NLRI,
  177 origin-change events, 14 blackhole (65535:666) announcements,
  worst flap storm: 200.23.137.0/24 announced 10,316× (origin AS7087)

## Validation

- `test_mrt.py` 28/28: synthetic round-trips (BGP4MP, TABLE_DUMP_V2 v4/v6,
  RFC 6793 merge) + **differential vs mrtparse on the real updates file**:
  record count, UPDATE count, announced and withdrawn NLRI counts all match
  exactly (268,439 UPDATEs).
- `test_pipeline.py` 11/11: planted MOAS / bogon / in-bucket DEAGG /
  cross-bucket DEAGG via tiny prefix / AS_SET / LONG_PATH all detected, no
  false DEAGG on the legitimate covering prefix.
- `leaks.py` 11/11: hand-built paths (OK / LEAK / LOOP / INCONCLUSIVE).
- The AFI bug above was caught by the differential test, not by reading —
  oracles beat eyeballs.
