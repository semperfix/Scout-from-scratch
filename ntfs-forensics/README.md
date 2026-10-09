# NTFS Filesystem Forensics

A from-scratch NTFS reader in stdlib-only Python — boot sector parsing,
update-sequence (fixup) torn-write detection, MFT records, resident and
non-resident attributes, signed-delta runlists, `$I30` directory indexes,
path reconstruction, `$Bitmap` cross-checks, deleted-file carving with
honest verdicts (OK / PARTIAL / GONE), `$SI`-vs-`$FN` timestomp detection,
ADS enumeration, and a triage CLI (`summary`, `ls`, `cat`, `istat`,
`deleted`, `timestomp`, `ads`, `timeline`).

Because the sandbox had no `mkntfs`, it also ships `mkfs_ntfs.py` — a
minimal from-scratch NTFS *formatter* — and `surgery.py`, a surgical file
injector that hand-crafts MFT records, updates bitmaps, inserts `$I30`
entries, and simulates deletion to build the test volume.

**63/63 checks pass** (`test_ntfs.py`: codecs, fixup tamper, boot, MFT,
fragmented reassembly byte-identical, ADS, bitmap bits, deleted carve
byte-identical, PARTIAL carve with zero-filled reallocated clusters,
timestomp flags exactly MFT 13, hostile inputs raise cleanly), plus
**13/13 differential checks vs The Sleuth Kit** (`diff_tsk.py`): TSK opens
the volume via autodetect, lists directories, and reads every file
byte-identical — including the 3-run fragmented file, the ADS, and the
deleted record. The format is genuinely valid NTFS, not just
self-consistent.

## Dependencies

Stdlib only. The optional `diff_tsk.py` differential test needs
`pytsk3` (`pip install pytsk3`).

## How to run

The two 64 MB fixture images are **not** shipped — regenerate them with
the built-in formatter (no `ntfs-3g` required):

```
python3 make_fixtures.py fixture.img   # format + surgical injection of all fixtures
```

Then:

```
python3 test_ntfs.py          # 63/63 checks (exits 2 if fixture.img is missing)
python3 diff_tsk.py           # 13/13 differential vs TSK (needs pytsk3)
python3 ntfscheck.py --help   # triage CLI
```

## Usage example

```
python3 ntfscheck.py summary fixture.img      # volume layout
python3 ntfscheck.py ls fixture.img /        # directory listing
python3 ntfscheck.py cat fixture.img /hello.txt
python3 ntfscheck.py timestomp fixture.img   # $SI vs $FN skew
python3 ntfscheck.py ads fixture.img         # alternate data streams
python3 ntfscheck.py deleted fixture.img     # carved records with OK/PARTIAL/GONE verdicts
python3 ntfscheck.py timeline fixture.img    # $SI-based timeline
```

As a library:

```python
from ntfs import Volume

v = Volume('fixture.img')
print(v.root.name, v.bpb.cluster_size)   # boot + boot sector fields
rec = v.mft_record(7)                    # /hello.txt
print(v.read_attribute(rec, '$DATA'))    # b'Hello NTFS forensics!\n'
v.close()
```

## Key learnings

- **The update sequence is a torn-write detector.** Every MFT/INDX
  record's sector ends must equal the USN, with original bytes in the USA
  array. A tampered sector end must *raise*, not parse.
- **`$SI` vs `$FN` is the timestomp detector.** The filesystem maintains
  `$FILE_NAME` on every rename/write; anti-forensics tools typically
  rewrite only `$STANDARD_INFORMATION`. Skew > 1 s is the tell.
- **Deleted-recovery verdicts need the bitmap.** OK = runs intact and
  clusters free; PARTIAL = some clusters reallocated (zero-fill those —
  never return someone else's data as the deleted file's); GONE = runs
  destroyed. The bitmap cross-check separates forensics from wishful
  carving.
- **Differential tests must model tool behavior, not just data.** Two
  "TSK failures" were my harness: TSK's `open_dir` lists unallocated
  (deleted) names by design, and TSK *errors* on read-past-EOF instead of
  returning `b""`. Both looked like format bugs until investigated.
- **When a library hides errors, check for exported error accessors.**
  `pytsk3` swallows the inner error, but calling `tsk_fs_open_img` +
  `tsk_error_get_errstr` directly via ctypes revealed `unknown version:
  0.0` instantly (my formatter wrote a bogus `$VOLUME_INFORMATION`
  version; real NTFS is 3.1).

## Limitations

- **No `$ATTRIBUTE_LIST`** (multi-record MFT entries), no `$LogFile`
  replay. The parser *reads* `$INDEX_ALLOCATION`/INDX subnodes, but the
  injector doesn't create them — no large-directory fixtures.
- No `$Secure`/`$UpCase`/`$Extend` system files (TSK tolerates their absence).
- No compressed/encrypted attribute handling beyond sparse runs.
- `diff_tsk.py` needs `pytsk3` installed; the format was validated against
  TSK at build time (13/13).

## Files

- `ntfs.py` — the reader: boot, fixup, MFT, attributes, runlists, indexes, bitmap, carve, timestomp, ADS
- `mkfs_ntfs.py` — minimal from-scratch NTFS formatter (boot + $MFT/$MFTMirr/root/$Bitmap/$Volume)
- `surgery.py` — surgical file injector / fixture factory (hand-crafted MFT records, bitmap updates, deletion)
- `make_fixtures.py` — builds `fixture.img`: format via `mkntfs` if present, else `mkfs_ntfs.py`, then inject all fixtures
- `ntfscheck.py` — triage CLI: summary/ls/cat/istat/deleted/timestomp/ads/timeline
- `test_ntfs.py` — 63/63 unit + fixture checks
- `diff_tsk.py` — 13/13 differential checks vs The Sleuth Kit (needs `pytsk3`)
- `LEARNINGS.md` — the full expedition writeup
