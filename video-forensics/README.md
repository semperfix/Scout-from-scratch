# Video Forensics From Scratch

Hand-rolled MP4 box parser and H.264 stream analyzer (SPS decoding,
GOP/frame-type classification). Detects splices via IDR anomalies, timeline
surgery via stts timestamps, and documents why pasted-region ELA heatmaps
are out of reach for stdlib-only code. Completes the media-forensics trio
with image and audio.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** -- `struct`, `argparse`.

## How to run

**Triage a video file or raw stream** (entry point `vidcheck.py` --
auto-detects MP4 by `ftyp` vs H.264 Annex-B by start code):

```bash
python3 vidcheck.py clip.mp4
python3 vidcheck.py stream.264
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `TIMELINE-SUSPECT` / `SPLICE-LIKELY`).

**Build the test fixtures** (hand-crafted with `struct`, no encoder):

```bash
python3 mkfixtures.py   # writes ./fixtures/
```

**Use the parsers as a library:**

```python
from mp4parse import analyze_mp4
a = analyze_mp4(open("clip.mp4", "rb").read())
print(a["mvhd"])                 # {'timescale': 1000, 'duration': 4000, ...}
print(a["tracks"][0]["codecs"])  # ['avc1']

from h264parse import analyze_stream
s = analyze_stream(open("stream.264", "rb").read())
print(s["sps"])                  # {'profile_idc': 66, 'level': '3.0', ...}
print(s["idr_intervals"])        # [30, 30]
```

## Example

```bash
$ python3 vidcheck.py fixtures/tiny.264
file: fixtures/tiny.264  (H.264 Annex-B, 63 NAL units)
SPS: profile 66 level 3.0 1280x720
NAL census: SPSx1, PPSx1, slice(IDR)x3, slice(non-IDR)x58
frames: I:3, P:58  (IDR at frame idx [0, 30, 60])
IDR intervals: 30, 30
VERDICT: CLEAN (container and GOP structure consistent)

$ python3 vidcheck.py fixtures/surgery.mp4
...
track 1: vide (VideoHandler) codecs=avc1
  mdhd: 4.000s (timescale 90000), tkhd: 4.000s, stts: 60 samples -> 2.000s, 1 chunks
  stts entries: (60x3000)
VERDICT: TIMELINE-SUSPECT -- track 1: stts duration 2.000s != mdhd duration 4.000s (timeline surgery: samples removed/added)
```

## Key learnings

- **The container keeps two clocks, and liars forget one.** `mvhd`/`mdhd`
  durations are claims; the `stts` sample table is evidence. Timeline
  surgery (cutting samples but leaving headers) shows up as the two
  disagreeing -- the fixture proves it: 2.0 s of samples under a 4.0 s
  claim.
- **A single identity edit list is benign.** The first draft flagged *any*
  `elst` as suspicious, which false-positived on the clean fixture -- most
  encoders write one `elst` entry (media_time=0, rate=1) by default. Only
  non-trivial edit lists (re-timing, gaps, multi-entry) drive the verdict.
- **IDR rhythm is the splice tell.** Encoders place IDR frames on a regular
  GOP cadence; a splice point almost always forces an IDR that breaks the
  rhythm. The anomaly fixture's rogue IDR (interval 5 vs typical 30) is
  exactly what a join looks like.
- **Exp-Golomb round-trips are the only honest SPS test.** With no reference
  decoder in stdlib, the writer and reader validate each other: the fixture
  SPS encodes 1280x720 baseline and the parser decodes 1280x720 baseline.
  Self-consistency can't catch a shared misreading of the spec, so the
  field order was checked against the H.264 spec text (ISO 14496-10 7.3.2.1.1)
  by hand.
- **hdlr names live at payload+24, not +20.** The 12 reserved bytes after
  the handler fourcc are easy to undercount; the first draft read the name
  from inside the reserved field and got an empty string.

## Files

| File | What it does |
|---|---|
| `vidcheck.py` | **Entry point**: triage CLI -- MP4 box/timeline report or H.264 GOP report + verdict |
| `mp4parse.py` | Hand-rolled ISO BMFF box walk: ftyp, mvhd, trak/mdia (tkhd/mdhd/hdlr), stbl (stsd/stts/stsc/stsz/stco), edts/elst; timeline-surgery comparison |
| `h264parse.py` | Annex-B NAL split, emulation-prevention strip, Exp-Golomb bit reader, SPS decode, slice-header I/P/B classification, IDR-interval anomaly detection |
| `mkfixtures.py` | Byte-by-byte fixture builder: `tiny.mp4`, `surgery.mp4`, `tiny.264`, `anomaly.264` |
| `fixtures/` | Generated test videos (regenerate with `mkfixtures.py`; MP4s are structural -- boxes only, no mdat) |

## Limitations

- **No ELA heatmaps for pasted regions.** Those need decoded frames and the
  stdlib has no H.264 decoder -- stated honestly instead of faked. The
  IDR/GOP timeline analysis is the implemented proxy for splice detection.
- MP4 fixtures are structural (no `mdat` media); the parser reads boxes, not
  samples, so this is sufficient for everything it claims.
- Slice parsing classifies frame type from the slice header only; it does
  not decode macroblocks or motion vectors.
- Only Annex-B H.264 and ISO BMFF MP4 are covered -- no HEVC, VP9, MKV, or
  fragmented (`moof`) MP4 yet.
