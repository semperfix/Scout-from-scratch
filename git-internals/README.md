# Git Internals

A hand-rolled git object-store reader with zero git tooling: loose object
parsing (zlib + header decode), a full packfile parser (variable-length
type/size headers, OFS_DELTA/REF_DELTA resolution, delta opcode VM),
pack-index v2 with fanout binary search, ref resolution (packed-refs, HEAD
symref, reflogs), tag peeling, commit-graph log, recursive ls-tree,
cat-file, and fsck-lite. Validated byte-identical against real git —
including delta chains resolving to exact blobs and fsck-lite surfacing a
deleted branch's commit. Can read any repo's history without git installed,
recover "deleted" commits from packfiles and reflogs, and audit what's
stored vs. what's reachable.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — `zlib` for object inflation, `struct` for pack/index parsing.

## How to run

```bash
python3 gitread.py --git-dir /path/to/.git log --oneline
python3 gitread.py --git-dir /path/to/.git log --all        # every ref
python3 gitread.py ls-tree -r HEAD        # --git-dir found by walking up
python3 gitread.py cat-file -p HEAD:src/main.py
python3 gitread.py cat-file -t <sha>
python3 gitread.py show-refs
python3 gitread.py fsck                    # dangling objects (reflogs excluded)
```

`--git-dir` defaults to `.git` found by walking up from the cwd. Exit 0 on
success, 1 with an error on stderr.

**Run the validation battery** (builds a throwaway repo with the real git
CLI, then diffs every object):

```bash
python3 test_gitread.py    # 8 checks, all against real git output
```

## Example

```bash
$ python3 gitread.py --git-dir /tmp/gittest/.git log --oneline
250ad7c add near-duplicate big file
bdcb1de tweak big file
bf3aeb2 add big file
f94b902 first commit

$ python3 gitread.py --git-dir /tmp/gittest/.git fsck
dangling blob 894b24d52a6a18c426701a35fe92ca0877a2572f
dangling commit 451aa83b58bcce36158bd69369b875c78a1ef354
dangling tree ae704fd562ce5efc6e6ff85fa3cea7d367d30d8f

$ python3 gitread.py --git-dir /tmp/gittest/.git cat-file -p 451aa83b58bcce36158bd69369b875c78a1ef354 | head -6
tree ae704fd562ce5efc6e6ff85fa3cea7d367d30d8f
parent bdcb1dee230de67448dde62d79cf33fde237def9
author Scout <scout@example.com> 1791520310 +0000
committer Scout <scout@example.com> 1791520310 +0000

doomed commit
```

The deleted branch's commit is gone from every ref — but the pack still has
it, and `fsck` + `cat-file -p` bring it back.

## What it does

- **Loose objects** — `objects/ab/cdef…`, zlib inflate, `<type> <size>\0`
  header split (commit/tree/blob/tag).
- **Packfiles** — `PACK` magic, version check, variable-length object
  headers (type in bits 4–6, size as MSB-continued varint), zlib streams
  located via `decompressobj.unused_data` so object boundaries are exact.
- **Delta VM** — `apply_delta` implements the real opcode set: copy-from-base
  (offset/size byte-presence bitmaps, size 0 → 0x10000) and insert-literal,
  with base-size and result-size validation. OFS_DELTA uses git's
  `((ofs+1) << 7)` negative-offset encoding; REF_DELTA resolves the 20-byte
  base SHA through the pack index.
- **Pack-index v2** — magic check, 256-entry fanout table, binary search over
  the sorted SHA table, CRC table skipped, 32-bit offsets with MSB-escaped
  64-bit overflow table.
- **Refs** — `HEAD` symref and detached HEAD, loose `refs/` files,
  `packed-refs`, plus `logs/HEAD` reflog entries surfaced as
  `reflog:logs/HEAD:<short>` pseudo-refs for recovery.
- **Commands** — `log` (commit walk, newest-first), `ls-tree -r`, `cat-file
  -p/-t` (with minimal `<ref>:<path>` rev-parse), `show-refs`, `fsck`
  (reachability DFS from all refs).

## Key learnings

- **The delta base-size check is load-bearing.** A wrong OFS_DELTA decode
  silently produces garbage; asserting `base_size == len(base)` and
  `len(out) == result_size` turns silent corruption into a loud error.
- **TCP-style lesson, git edition: `zlib.decompressobj().unused_data` is the
  only honest way to find object boundaries** in a pack — you can't know the
  compressed length up front, and guessing breaks on the next object.
- **git fsck hides reflog-reachable objects.** `git fsck --dangling` showed
  nothing for the deleted commit because the HEAD reflog still referenced it;
  fsck-lite deliberately excludes reflogs from its roots — for forensics,
  "reachable only via reflog" *is* the interesting case.
- **Tree modes are zero-padded in git's display** (`040000`, not `40000`).
  The raw tree object stores `40000`; byte-identical `cat-file -p` output
  needs the padding. Caught by diffing, not by reading.
- **OFS_DELTA's offset encoding is `((ofs+1) << 7) | bits`**, not plain
  base-128 — the `+1` per byte is the part everyone misremembers.

## Files

| File | What it does |
|---|---|
| `gitread.py` | **Entry point**: repo reader + `log` / `ls-tree` / `cat-file` / `show-refs` / `fsck` |
| `test_gitread.py` | Validation battery: builds a real repo with the git CLI, diffs everything |

## Limitations

- Pack-index v1 not supported (v2 only — what git writes by default).
- No thin packs, promisor packs, commit-graph, or multi-pack-index.
- Delta bases in *another* pack resolve only if that pack is present with its index.
- Rev-parse is minimal: `<ref>:<path>` only (no `~`, `^`, `@{n}`).
- No signature verification, no merges, no checkout — reading and recovery only.

## Source material

See `SKILLS.md` (skill #15) in the repo root for the full expedition notes.
