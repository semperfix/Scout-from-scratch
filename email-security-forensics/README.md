# Email Security Forensics

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

SPF, DKIM, and DMARC learned through hands-on DNS analysis, plus a DKIM signer/verifier built from scratch. Can evaluate suspicious email authentication headers and explain exactly how spoofing and phishing slip through (or get caught).

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #2) in the repo root for the full expedition notes.
