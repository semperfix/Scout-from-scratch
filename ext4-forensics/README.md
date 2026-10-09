# ext4 Filesystem Forensics From Scratch

Hand-rolled ext4 parser, fully read-only and zero-dependency: superblock
(magic 0xEF53, block size, label), group descriptor table walk, 256-byte
inodes (mode/size/timestamps/dtime/links/flags), extent-tree walker (index
and leaf levels, extent header magic 0xF30A), linear directory entries with
deleted-entry skipping, block-bitmap allocation checks, and a JBD2 journal
scanner (big-endian descriptor/commit parsing, chained tags, newest-copy-wins
map of journaled blocks). Deleted-file recovery: scan the inode table for
`links==0 && dtime!=0`, walk the (usually still intact) extent trees, and
cross-check every data block against the block bitmap — verdicts
**OK / PARTIAL / GONE**. The `fscheck` CLI does summary/ls/deleted/journal.
A hand-crafted 16-block fixture image exercises every path: one live file,
one cleanly recoverable deleted file, one partially overwritten, one fully
reallocated.

## Dependencies

- **Python 3** (3.10+ recommended) — **stdlib only**, no numpy needed.
  Everything is `struct` unpacking and byte arithmetic.

## How to run

**Rebuild the fixtures** (writes `fixture.img` and `fixture.journal`):

```bash
python3 make_fixture.py
```

**Triage an image** (entry point `fscheck.py`, fully read-only):

```bash
python3 fscheck.py --image fixture.img --summary
python3 fscheck.py --image fixture.img --ls
python3 fscheck.py --image fixture.img --deleted
python3 fscheck.py --journal fixture.journal
```

**Use the parser as a library:**

```python
from ext4 import Ext4Image

img = Ext4Image("fixture.img")
print(img.label, img.block_size)          # FORENSIC-TEST 1024

for e in img.list_dir(2):                 # root directory
    print(e["inode"], e["file_type"], e["name"])

for ino in img.deleted_inodes():          # links==0 && dtime!=0
    v = img.recover_verdict(ino)
    print(ino["inum"], v["verdict"], v["good_blocks"], v["gap_blocks"])
    data = img.read_inode_data(ino)       # reallocated blocks read as zeros

import journal
res = journal.scan_journal(open("fixture.journal","rb").read(), 1024)
print(res["newest_copies"])               # {100: 2048}
```

## Example

```bash
$ python3 fscheck.py --image fixture.img --summary
image:  fixture.img
label:  FORENSIC-TEST
block size:        1024
blocks:            16 total, 3 free
inodes:            16 total, 10 free
inodes per group:  16
first data block:  1
groups:            1

$ python3 fscheck.py --image fixture.img --ls
directory listing for inode 2:
       2  dir      .
       2  dir      ..
      12  file     hello.txt

$ python3 fscheck.py --image fixture.img --deleted
inode 13: size=24 dtime=2023-11-14 22:13:20 UTC
  extents: log0->phys11x1
  recoverable blocks: [11]
  reallocated (gaps): (none)
  VERDICT: OK
  carved 24 bytes, head=b'deleted but recoverable\n'
inode 14: size=2048 dtime=2023-11-14 22:13:21 UTC
  extents: log0->phys12x2
  recoverable blocks: [13]
  reallocated (gaps): [12]
  VERDICT: PARTIAL
  carved 2048 bytes, head=b'\x00\x00\x00...'
inode 15: size=1024 dtime=2023-11-14 22:13:22 UTC
  extents: log0->phys14x1
  recoverable blocks: (none)
  reallocated (gaps): [14]
  VERDICT: GONE

$ python3 fscheck.py --journal fixture.journal
journal: fixture.journal  (blocksize 1024, 3 tagged blocks)
  jblock 0: superblock_v2
  jblock 1: descriptor seq=7 tags=fsblk100
  jblock 3: commit seq=7
newest-copy map: 1 journaled block(s)
  fs block 100 -> journal offset 2048
```

## Key learnings

- **JBD2 is big-endian; ext4 is little-endian.** The single most common
  triage mistake. `journal_header_t` is 12 bytes, so `s_blocksize` sits at
  offset 12 — parse everything in `journal.py` with `">"`.
- **Block-bitmap cross-checking is what separates a forensic verdict from
  wishful carving.** The extent tree of a deleted file usually survives
  intact; what matters is whether each block was reallocated since. OK =
  all blocks still free, PARTIAL = some reallocated (carved as zero gaps),
  GONE = all reallocated or no extent tree left.
- **A freed inode gets reused fast.** Unlinking zeroes the directory entry
  but leaves the inode and extents behind — the fixture models this: the
  root dir shows only the live file while three deleted inodes still have
  full extent trees.
- **Extent trees recurse.** The walker handles depth>0 index nodes
  (`ei_leaf_lo/hi` → child block) even though the fixture only needs leaf
  level; the header magic 0xF30A is validated at every node.

## Files

| File | What it does |
|---|---|
| `fscheck.py` | **Entry point**: `--summary`, `--ls`, `--deleted`, `--journal` triage CLI |
| `ext4.py` | Superblock/group-descriptor/inode parsing, extent-tree walker, linear directory reader, block-bitmap checks, deleted-inode scan + OK/PARTIAL/GONE verdicts, carving |
| `journal.py` | JBD2 scanner: journal superblock, descriptor tag chains, commit blocks, newest-copy-wins block map |
| `make_fixture.py` | Builds `fixture.img` (16-block ext4) and `fixture.journal` from scratch |
| `fixture.img` | Hand-crafted ext4 image: live file + 3 deleted inodes (OK/PARTIAL/GONE) |
| `fixture.journal` | Hand-crafted 4-block JBD2 area for the journal scanner |

## Limitations

- 32-bit block/inode counts only (no 64bit feature); single group exercised,
  multi-group walks by the same code path.
- No `huge_file`, inline data, inline extents, or extent-tree depth > 1 in
  the fixture (the walker supports index levels; untested against real
  multi-level trees).
- Linear directories only — no htree/dx indexed directories.
- Journal tags use the 12-byte tag layout; 64-bit high-blocknr and UUID tag
  variants are detected and skipped, not decoded. No journal replay —
  `journal.py` is a scanner, not a recovery engine.
