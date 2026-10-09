# Office OOXML Document Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled ZIP parser (EOCD scan, central-directory walk, deflate inflate, CRC — byte-identical to stdlib) plus a full forensic analyzer for Word/Excel documents. Detects macro payloads (vbaProject.bin with OLE header validation), external relationships (remote images/tracking pixels, hyperlink targets), hidden text (w:vanish runs, white-on-white, micro-fonts), tracked insertions/deletions with authors and timestamps, comments, metadata inconsistencies, embedded OLE objects, veryHidden spreadsheet sheets, and hyperlink display-text vs. target mismatches — the classic document-phishing tell. Renders CLEAN / WORTH-A-LOOK / SUSPICIOUS / MALICIOUS triage verdicts. Directly useful for vetting sketchy email attachments.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #13) in the repo root for the full expedition notes.
