# NTFS Forensics From Scratch — Learnings

## What was built
- `ntfs.py` — from-scratch NTFS reader (stdlib only): boot sector, fixup,
  MFT records, resident/non-resident attributes, runlists, $I30 indexes,
  path reconstruction, $Bitmap, deleted scan, timestomp + ADS detection.
- `mkfs_ntfs.py` — a minimal NTFS *formatter* (boot + $MFT/$MFTMirr/root/
  $Bitmap/$Volume). Written because apt was unusable and mkntfs unavailable.
- `surgery.py` — surgical file injector: hand-crafts MFT records, updates
  bitmaps, inserts $I30 index entries, simulates deletion. The fixture factory.
- `ntfscheck.py` — triage CLI: summary/ls/cat/istat/deleted/timestomp/ads/timeline.
- `test_ntfs.py` — 63 checks. `diff_tsk.py` — 13 differential checks vs The Sleuth Kit.

## Earned insights (paid for in debugging)

1. **The update sequence is a torn-write detector.** Every MFT/INDX record's
   sector ends must equal the USN; the original bytes live in the USA array.
   When *writing* records you must re-stamp (my `make_fixup`). A tampered
   sector end must raise, not parse — tested.

2. **MFT records are fixed-size.** My first `insert_index_entry` grew the
   bytearray past 1024 bytes. Real NTFS inserts inside the *used* region and
   consumes zero slack. The record's used-size field is the budget, not the
   buffer length. Same discipline in reverse for deletion.

3. **Runlist LCN deltas are signed.** A run can point *backwards* (my negative-
   delta round-trip test). Sparse runs have a zero-length offset field.
   Per the spec, runlists are padded to a 4-byte multiple — `encode_runlist`
   does this now.

4. **`end_vcn` is the highest VCN, not the count.** For 4 clusters (VCNs 0-3),
   end_vcn=3. My first cut wrote 4. My parser never validated it (it just
   decodes the runlist) — a self-consistency blind spot.

5. **$SI vs $FN is the timestomp detector.** The filesystem maintains
   $FILE_NAME on every rename/write; anti-forensics tools typically rewrite
   only $STANDARD_INFORMATION. Skew > 1s between them is the tell. The
   timeline command deliberately uses $SI (shows what the liar wants you
   to see) — compare with $FN.

6. **INDEX_ROOT node: allocated >= total, always.** My surgeon updated the
   node's total size but not the allocated size after inserting entries.
   My parser didn't check; TSK does ("Index list offsets are invalid").
   The oracle earned its keep.

7. **$VOLUME_INFORMATION version must be real.** I wrote version 0.0; TSK's
   typed open failed with `unknown version: 0.0` (real NTFS is 3.1). My
   parser doesn't care about the version — another blind spot only a real
   tool could catch.

8. **Getting TSK's real error via ctypes.** pytsk3 swallows the inner error
   ("Cannot determine file system type"). But `tsk_fs_open_img` + 
   `tsk_error_get_errstr` are exported symbols — calling the typed open
   directly revealed `unknown version: 0.0` instantly. Strace showed TSK
   reading the boot sector then giving up, which pointed at open-time
   validation. General technique: when a library hides errors, check for
   exported error accessors before guessing.

9. **Differential tests must model tool behavior, not just data.** Two of my
   "TSK failures" were my harness: TSK's `open_dir` lists unallocated
   (deleted) names by design, and TSK *errors* on read-past-EOF instead of
   returning `b""`. Both looked like format bugs until investigated.

10. **$MFTMirr is kept in sync by the writer.** Real NTFS mirrors records 0-3;
    my surgeon writes through to the mirror for records < 4, so the mirror
    test compares fixup-restored bytes (stamped != restored at sector ends).

11. **Deleted recovery verdicts need the bitmap.** OK = runs intact and
    clusters free; PARTIAL = some clusters reallocated (zero-fill those —
    never return someone else's data as the deleted file's); GONE = runs
    destroyed. The bitmap cross-check is what separates forensics from
    wishful carving (same lesson as ext4 #30).

12. **ADS are just named $DATA attributes.** No special structure — the
    forensic value is enumerating *all* $DATA names, since dir listings
    never show them.

## Validation
- 63/63 unit + fixture checks (codecs, fixup tamper, boot, MFT, fragmented
  reassembly byte-identical, ADS, bitmap bits, deleted carve byte-identical,
  PARTIAL carve, timestomp flags exactly MFT 13, hostile inputs raise cleanly).
- 13/13 differential vs The Sleuth Kit (pytsk3): TSK opens the volume via
  autodetect, lists directories, reads all files byte-identical (including
  the 3-run fragmented file and the ADS size), icats the deleted MFT record
  byte-identical to my carve.
- Each TSK rejection taught something: version 0.0, index alloc size.
  The format is now genuinely valid NTFS, not just self-consistent.

## Deliberate gaps
- No $ATTRIBUTE_LIST (multi-record MFT entries), no $LogFile replay, no
  $I30 large indexes ($INDEX_ALLOCATION/INDX blocks) in the surgeon —
  the parser *reads* INDX subnodes, the injector just doesn't create them.
- No $Secure/$UpCase/$Extend system files (TSK tolerates their absence).
- No compressed/encrypted/sparse attribute handling beyond sparse runs.
