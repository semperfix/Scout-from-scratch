# OCI / Container Image Forensics — Learnings

## What was built
`~/workspace/learning/45-oci/`: `tar.py` (hand-rolled tar parser, ~200 lines),
`oci.py` (registry client + layout parser + layer applier + triage, ~450 lines),
`ociforensic.py` CLI (`pull`/`triage`/`layers`/`dockerfile`/`cat`),
`test_oci.py` (53 checks, stdlib `tarfile` as the write-oracle).

## tar: the format is simpler than its edge cases
- The header checksum is the *only* integrity in the format — no magic, no
  signatures. Verifying it is what turns "reads files" into "forensics".
- GNU base-256 numerics: `0x80` in the top byte is a *marker bit* (clear it to
  get the value); `0xFF` means negative two's complement. My first cut forgot
  to clear the marker and decoded size 5 as 2^95+5 — a hand-crafted fixture
  per the spec caught it, no oracle needed.
- Two parallel longname mechanisms exist (GNU `L`/`K` entries and pax `x`
  `path=`/`linkpath=` overrides) and they compose: pax applies first, then a
  pending GNU longname wins. Order matters and is undocumented in one place.
- Strict end-of-archive discipline (≥1 zero block required) turns truncated
  downloads into loud errors instead of silently-short file lists. For a
  forensic tool, "the archive just ends" is a finding, not a shrug.
- `str.lstrip("./")` strips *characters*, not the prefix `"./"` — it ate the
  leading dot off `.wh.*` whiteout files and broke root-level whiteouts. Now
  strips only literal leading `./` and `/`. Lesson re-learned: never use
  lstrip for prefix removal.

## OCI: the tag is a lie, the digest is the truth
- Pull flow: anonymous token from `auth.docker.io` → manifest (with
  `Docker-Content-Digest` header verified against sha256 of the body) →
  manifest-list platform selection → config + layer blobs, every blob
  hash-verified on download.
- The chain of trust I verified end-to-end on real pulls (busybox, python):
  **manifest digest → config → `rootfs.diff_ids[i]` == sha256(uncompressed
  layer tar i)**. 5/5 diff_ids verified. If any link breaks, something was
  tampered with between the registry and you.
- Layer application = overlay semantics: later layers override; `.wh.<name>`
  whiteouts delete a path; `<dir>/.wh..wh..opq` (opaque dir) wipes all
  earlier children of that dir. Implemented exactly, tested synthetically.

## The big forensic insight: whiteout ≠ deletion
A file "deleted" by a later layer still exists in the lower layer's blob —
anyone holding the image can read it. So triage scans *every* layer's blobs
and reports `buried_secrets`: hits in layers where the file is absent from
the final tree. Tested: secret in layer 0, whited out in layer 1 → invisible
to final-tree scan, caught by the buried scan. This is the #1 real-world use:
people `rm` secrets in a later Dockerfile step and ship them anyway.

## Triage heuristics that survived contact with real images
- **Text-only secret scanning**: secret regexes over ELF binaries are pure
  noise. Skip blobs with NUL in the first 4 KiB. (busybox's 1 MB binary
  matched `password=` patterns before this.)
- **Vendor-path tiering**: `/usr`, `/lib`, `/bin`, `/sbin`, `/opt` run only
  high-signal patterns (AWS keys, private keys, GitHub/Slack tokens); the
  generic `password=` pattern is suppressed there. Cut python:3.13-alpine
  from 48 "secrets" (stdlib `.py` sources mentioning passwords) to 2 real
  config-file hits. Known residual FPs, documented not hidden:
  `etc/nsswitch.conf` matches on `passwd: files`; `openssl.cnf` on
  `password = secret` (sample values). Heuristics flag; humans judge.
- **Hardlinks are content**: busybox is 410 hardlinks to one binary. Without
  hardlink→target resolution, 96% of the image's paths are unscannable and
  `cat` can't read them. Symlink chains resolve too (`/bin/sh` → `bin/[` →
  ELF bytes, verified with `cmp`).
- Config-env scan caught `GPG_KEY` in python's image — which is a *public*
  key ID, not a secret. Env triage needs the human step; the tool surfaces,
  doesn't convict.
- Dockerfile reconstruction from `history[].created_by` (skipping
  `empty_layer`) reproduced the real build steps (`ADD
  alpine-minirootfs…`, the `apk add` RUN lines) — useful for answering
  "how was this thing built".

## Validation summary
- 53/53 checks: tar round-trips (ustar/gnu/pax/prefix), checksum-tamper and
  truncation rejection, base-256, whiteout/opaque semantics, per-layer diff
  counts, digest-mismatch rejection (stubbed), secret tiering, buried-secret
  recovery, hardlink resolution.
- Live: pulled `library/busybox:latest` (1 layer) and
  `library/python:3.13-alpine` (4 layers, 18.6 MiB) from Docker Hub;
  manifest digests, blob digests, and all 5 diff_ids verified; per-layer
  diffs and Dockerfile reconstruction sane; triage output reviewed by hand.
