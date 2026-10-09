# Git Internals From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled git object-store reader with zero git tooling: loose object parsing (zlib + header decode), full packfile parser (variable-length headers, OFS_DELTA/REF_DELTA resolution, delta opcode VM), pack-index v2 with fanout binary search, ref resolution (packed-refs, HEAD symref, reflogs), tag peeling, commit-graph log, recursive ls-tree, and fsck-lite. Validated byte-identical against real git — including delta chains resolving to exact 100KB blobs and reachability matching git's fsck. Can read any repo's history without git installed, recover "deleted" commits from packfiles and reflogs, and audit what's stored vs. what's reachable.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #15) in the repo root for the full expedition notes.
