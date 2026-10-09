# Audio Forensics

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Splice detection using electrical-hum (ENF) continuity analysis, plus local speech transcription. Can inspect audio for likely edits, transcribe privately, and examine format/spectrogram evidence. Limitation: hum-free recordings and same-recording rearrangements may not be detectable.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #4) in the repo root for the full expedition notes.
