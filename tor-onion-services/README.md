# Tor & Onion Services

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

How the Tor network actually works: onion-address identity mechanics, six-hop rendezvous architecture, and the culture of onion services. Verified `IsTor: true` through the environment's outbound proxy and loaded live onion sites. Knows exactly what Tor can and can't hide.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #1) in the repo root for the full expedition notes.
