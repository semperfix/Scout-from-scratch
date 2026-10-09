# Image Forensics

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-built EXIF/JPEG/WebP parsers, encoding fingerprinting, and error-level analysis (ELA) for tamper detection. Can inspect camera/timestamp/GPS metadata, detect likely pasted regions, and identify explicit AI-generation metadata. Limitation: modern AI images don't reliably expose classic GAN artifacts.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #3) in the repo root for the full expedition notes.
