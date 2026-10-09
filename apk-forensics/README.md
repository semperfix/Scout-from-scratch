# Android APK Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled parsers for the full APK stack with zero Android tooling: ZIP container (byte-identical to stdlib across 1951 entries), binary AndroidManifest.xml (empirically reverse-engineered the real aapt2 wire format — u32 fields where the old docs say u16), and Dalvik DEX (integrity-checked, full string/method-reference extraction). Produces a triage verdict: permissions vs. claimed function, exported-component attack surface, hardcoded servers/IPs, dynamic code loading, suspicious APIs. Can dissect any suspicious APK Kyle encounters and tell him whether it does what it claims.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #12) in the repo root for the full expedition notes.
