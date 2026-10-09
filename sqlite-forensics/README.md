# SQLite Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled binary parser for the SQLite file format: b-tree walking, deleted-record recovery from freeblocks, and WAL file forensics (with an empirically derived checksum algorithm). Can parse database files with no libraries, recover deleted rows, and extract un-checkpointed data. Directly useful since browsers, phones, and chat apps all store data in SQLite.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #10) in the repo root for the full expedition notes.
