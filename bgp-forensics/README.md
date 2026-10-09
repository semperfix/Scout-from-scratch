# BGP / Internet Routing Forensics

A from-scratch BGP/MRT toolkit in stdlib-only Python: a hand-rolled MRT
parser (RFC 6396 TABLE_DUMP_V2 + RFC 4271 BGP4MP updates), a
memory-bounded RIB pipeline (external bucket sort, so a 46M-entry table
never sits in RAM), anomaly detectors (MOAS, bogon origins,
DEAGG_ORIGIN_CHANGE, LONG_PATH, AS_SET, AS_TRANS_LEAK), a Gao–Rexford
valley-free route-leak checker against CAIDA AS-relationship data, a live
updates-window churn monitor, and a ranked hijack-hunt shortlist with
full-path verification.

Validated end-to-end against the real internet: on a RIPE RIS `rrc00`
snapshot (2026-10-08 00:00 UTC, 109 peers) it processed **1,428,977
prefixes / 54,643,276 RIB entries** and produced **7,138 MOAS · 945
BOGON_ORIGIN · 181,578 DEAGG_ORIGIN_CHANGE · 613 LONG_PATH · 263 AS_SET**;
in a 5-minute updates window it found **177 origin-change events, 14
blackhole (65535:666) announcements**, and a route-flap storm
(`200.23.137.0/24` announced 10,316×).

`test_mrt.py` **24/24 pass** (28/28 with a fetched updates dump — see
[Data](#data)): synthetic MRT round-trips (BGP4MP, TABLE_DUMP_V2 v4/v6,
RFC 6793 AS4_PATH merge) + differential vs `mrtparse` on real data
(record/UPDATE/announced/withdrawn counts all match exactly).
`test_pipeline.py` **11/11** (planted MOAS/bogon/in-bucket and
cross-bucket DEAGG/AS_SET/LONG_PATH, no false DEAGG). `leaks.py`
**11/11** (OK / LEAK / LOOP / INCONCLUSIVE).

## Dependencies

Stdlib only for the core pipeline. No pip packages. The *optional*
`test_mrt.py` differential check imports `mrtparse` (`pip install
mrtparse`) only when a real updates dump is present — it skips cleanly
otherwise.

## Data

The working datasets are **not shipped** — ~1.4 GB for the original run —
but everything is re-fetchable from the public route collectors:

```
# full-table RIB dump (TABLE_DUMP_V2) — 396 MB for the 2026-10-08 snapshot
curl -o data/bview.mrt.gz \
  https://data.ris.ripe.net/rrc00/2026.10/bview.20261008.0000.gz
# or from RouteViews: https://www.routeviews.org/routeviews/
#   http://archive.routeviews.org/bgpdata/2026.10/RIBS/rib.20261008.0000.bz2

# 5-minute BGP update stream (BGP4MP) — 8 MB
curl -o data/updates.mrt.gz \
  https://data.ris.ripe.net/rrc00/2026.10/updates.20261008.0000.gz

# CAIDA AS relationships (serial-2 format, ~2 MB bzipped)
curl -o as-rel2.txt.bz2 \
  https://publicdata.caida.org/datasets/as-relationships/serial-2/as-rel2.txt.bz2
```

`as-rel2.txt.bz2` (2 MB) **is** shipped because `leaks.py` needs it for the
valley-free check — refresh it with the command above. The pipeline
defaults read `data/bview.mrt.gz` and `data/updates.mrt.gz` relative to
this directory, or set `BGP_RIB` / `BGP_UPDATES` to point anywhere:

```
export BGP_RIB=~/data/bview.20261008.0000.gz
export BGP_UPDATES=~/data/updates.20261008.0000.gz
```

## How to run

The full pipeline, in order (needs a fetched `bview` dump):

```
python3 rib.py                          # TABLE_DUMP_V2 -> buckets/bv4_NNN.bin (pass 1)
python3 aggregate.py                    # sort + sweep buckets -> *.agg (pass 2a)
python3 aggregate.py buckets phaseb     # anomaly detection -> findings (pass 2b)
python3 hijack_hunt.py 400              # ranked hijack-shaped shortlist (needs findings.jsonl)
```

Faster entry points that don't need data:

```
python3 test_mrt.py        # parser round-trips (differential vs mrtparse skipped without data)
python3 test_pipeline.py   # end-to-end pipeline on a synthetic RIB with planted anomalies
python3 leaks.py           # valley-free check unit tests
python3 bgpwatch.py --help # CLI: stats, findings, lookup, updates, leakcheck (needs buckets/)
python3 updates_watch.py updates.mrt.gz   # 5-minute updates-window churn report
```

## Usage example

```python
import gzip
import mrt

with gzip.open('data/updates.mrt.gz', 'rb') as f:
    for ts, typ, sub, payload in mrt.iter_mrt_records(f):
        if typ == mrt.BGP4MP and sub in (mrt.BGP4MP_MESSAGE, mrt.BGP4MP_MESSAGE_AS4):
            info = mrt.parse_bgp_message(payload, asn4=(sub == mrt.BGP4MP_MESSAGE_AS4))
            if info['bgp_type'] == mrt.BGP_UPDATE:
                u = info['update']
                print(ts, 'announced:', u['announced'][:3], 'withdrawn:', len(u['withdrawn']))
```

Valley-free leak check on a hand-built path (needs `as-rel2.txt.bz2`):

```python
from leaks import load_asrel, valley_free

rel = load_asrel('as-rel2.txt.bz2')
print(valley_free([701, 3356, 15169], rel))   # ('OK', ...) / ('LEAK', ...) / ('INCONCLUSIVE', ...)
```

Targeted full-path fetch for any prefix straight out of the dump (needs `BGP_RIB`):

```python
from deepdive import paths_for_prefixes
r = paths_for_prefixes('data/bview.mrt.gz', {'8.8.8.0/24'})
print({p for _, paths, _, _ in r['8.8.8.0/24'] for p in [paths[-1]]})  # origins
```

## Key learnings

- **External bucket sort beats 1 GB of dicts.** A full table is 46M RIB
  entries; fixed-size binary records (15 B v4 / 27 B v6) streamed into 512
  bucket files keyed by first address byte, sorted and swept in RAM —
  flat memory, ~2× temp disk. `plen<8` prefixes span buckets, so
  sub-/8 prefixes are collected globally and checked against every bucket.
- **DEAGG is a candidate generator, not a verdict.** The first run flagged
  819,477 prefixes — the v4 default route `0.0.0.0/0` was "covering" every
  prefix. After excluding /0s and requiring single-origin covers, 53% of
  remaining candidates were benign provider→customer delegation (proved
  via CAIDA as-rel). The honest end state: rank the shortlist, verify
  with full paths (`covering origin in path → benign`), and hand the
  ranked leads to the analyst.
- **Unknown links → INCONCLUSIVE, never forced into a verdict.**
  Sibling ASes (same org) aren't in as-rel data — a known blind spot,
  documented not hidden. Multi-homed sub-allocations announced
  independently of the aggregate holder look *exactly* like hijacks
  without RPKI or time-series data.
- **The AFI field is not optional.** Guessing v4/v6 by hunting for the
  BGP marker failed on 3 real records; reading the Address Family field
  made it deterministic. When a binary format seems to require
  heuristics, you misread the spec.

## Limitations

- **No RPKI validation** — origin authorization is not checked; the
  tools rank leads, a human (or RPKI data) decides.
- **as-rel data goes stale** and sibling-AS links are invisible in it;
  leak verdicts carry both caveats.
- **Single-pass scan only extracts (origin, path length, AS_SET?,
  AS_TRANS?)** per attribute block; full decode happens only for flagged
  prefixes via targeted re-scan.
- The differential `test_mrt.py` check needs a real updates dump and
  `mrtparse`; without them it skips (24/24 instead of 28/28).

## Files

- `mrt.py` — MRT/MRT+TABLE_DUMP_V2/BGP4MP parser (RFC 6396, RFC 4271, RFC 6793 AS4 merge)
- `rib.py` — streaming RIB builder: bview → per-bucket entry files (pass 1)
- `aggregate.py` — bucket sort/sweep + anomaly detectors → `findings.jsonl` (pass 2)
- `leaks.py` — CAIDA as-rel loader + Gao–Rexford valley-free leak checker
- `hijack_hunt.py` — ranked DEAGG shortlist with full-path verification
- `bgpwatch.py` — CLI: stats / findings / lookup / updates / leakcheck
- `updates_watch.py` — 5-minute updates-window churn + origin-change monitor
- `deepdive.py` — targeted full-AS-path fetch for any prefix from a bview dump
- `test_mrt.py` — 28/28 parser tests (incl. differential vs mrtparse, skips without data)
- `test_pipeline.py` — 11/11 synthetic end-to-end pipeline tests
- `as-rel2.txt.bz2` — CAIDA AS-relationship snapshot (serial-2) for `leaks.py`
- `LEARNINGS.md` — the full expedition writeup
