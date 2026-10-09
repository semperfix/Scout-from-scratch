# ext4 Filesystem Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled ext4 parser with zero dependencies, fully read-only: superblock (64-bit block counts, label, feature flags), 64-bit group descriptors, 256-byte inodes (mode/size/timestamps/dtime/links/flags), extent-tree walker (index/leaf levels, uninitialized extents — a fragmented test file's physical ranges reproduced exactly: 2073-2074/2079/2085-2086/9255-10785), linear directory entries with deleted-entry skipping, block-bitmap allocation checks, and a JBD2 journal scanner (big-endian descriptor/commit parsing, chained descriptors, newest-copy-wins map of journaled blocks). Deleted-file recovery: scan the inode table for `links==0 && dtime!=0` inodes, walk their (usually still intact) extent trees, cross-check every block against the block bitmap — verdicts OK / PARTIAL (zero-filled gaps where blocks were reallocated) / GONE. The `fscheck` CLI does summary/ls/cat/extents/deleted/carve/journal. Earned insights: JBD2 is big-endian while ext4 is little-endian (hexdump caught it, and journal_header_t is 12 bytes so s_blocksize is at offset 12); debugfs checkpoints the journal on close so live journals are usually empty (parser validated against hand-injected transactions instead); a freed inode gets reused fast — one test left a "ghost" name pointing at another file's data; block-bitmap cross-checking is what separates a forensic verdict from wishful carving. Validated 33/33 against debugfs/dumpe2fs ground truth (all live files sha256-identical, deleted scan finds exactly the 3 deleted inodes, a deleted-then-recovered file carves byte-identical, two overwritten deleted files correctly report GONE) + 8/8 synthetic checks (journal transaction map/parse, PARTIAL carve with a reallocated block zero-filled). The tool for "what was deleted here and what can still be pulled back" — pairs with the SQLite (#10), mailbox (#21), and chat-backup (#17) carving skills.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #30) in the repo root for the full expedition notes.
