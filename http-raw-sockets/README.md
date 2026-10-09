# HTTP From Raw Sockets

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

A complete HTTP/1.1 client built on raw sockets — no libraries. Hand-wrote URL parsing, chunked transfer decoding (including trailers and extensions), redirect following, keep-alive connection reuse, and forward-proxy support. Verified byte-identical to curl. Gives byte-level understanding of every web fetch: proxy traversal, framing edge cases, connection-reuse semantics.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #7) in the repo root for the full expedition notes.
