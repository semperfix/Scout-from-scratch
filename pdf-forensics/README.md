# PDF Document Forensics

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

A hand-rolled PDF parser that detects hidden JavaScript, embedded files, metadata inconsistencies, and incremental edits made after apparent signing. Can pull text from every revision of a document, including ones the viewer doesn't show you.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #5) in the repo root for the full expedition notes.
