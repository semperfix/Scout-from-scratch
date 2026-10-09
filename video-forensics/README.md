# Video Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled MP4 box parser and H.264 stream analyzer (SPS decoding, GOP/frame-type classification). Detects splices via IDR anomalies, timeline surgery via stts timestamps, and pasted regions via ELA heatmaps. Completes the media-forensics trio with image and audio.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #11) in the repo root for the full expedition notes.
