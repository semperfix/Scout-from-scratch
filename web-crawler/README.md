# Web Crawling Infrastructure From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

A complete polite web crawler built from the wire up: raw-socket HTTP/1.1 client (chunked bodies, redirects, TLS), hand-rolled URL canonicalization for dedup (percent-encoding normalization, dot-segment removal, query sorting), an RFC 9309 robots.txt parser (longest-rule matching, crawl-delay), a politeness-aware frontier (per-host scheduling, breadth-first ordering), and a hand-rolled HTML tokenizer for link and text extraction. Validated end-to-end against a fixture site — robots honored, redirects collapsed, politeness delays kept. Can build and reason about crawlers for systematic site surveys, scam-site mapping, and research gathering.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #14) in the repo root for the full expedition notes.
