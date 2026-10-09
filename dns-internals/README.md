# DNS Internals From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Full RFC 1035 wire format by hand, DNS-over-HTTPS, a working iterative resolver, and DNSSEC root-key signature verification using the hand-built RSA from the crypto expedition. Can trace any domain's resolution path, verify DNSSEC chains, pull SPF/DMARC records for phishing analysis, and spot tunneling/DGA patterns in query logs.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #9) in the repo root for the full expedition notes.
