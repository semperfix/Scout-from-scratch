# Cryptography From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

AES-128 built by hand (verified against official FIPS-197 test vectors), RSA with working attack demos (textbook malleability, small-message cube-root), and a Diffie-Hellman encrypted channel over real TCP. Can evaluate crypto claims from first principles — what "military-grade encryption" actually means, what padding and modes do, where MITM holes live.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #8) in the repo root for the full expedition notes.
