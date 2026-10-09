#!/usr/bin/env python3
"""torguide: entry-point CLI for the tor-onion-services skill.

  --check-onion ADDR   validate a v3 onion address (checksum per rend-spec-v3)
  --explain            how Tor works: circuits, onion services, rendezvous
  --threat-model       what Tor hides and what it does NOT hide

Fully offline -- this covers the identity/mechanics portion. Actually
visiting an onion address needs the tor daemon installed and running
(documented in --explain).
"""
import argparse
import sys

from onion import validate_onion

EXPLAIN = r"""
HOW TOR WORKS (the offline mechanics)
=====================================

1. CIRCUITS (3 hops for normal browsing)
   You -> Guard -> Middle -> Exit -> destination

   - Your client picks 3 relays and builds the circuit with telescoping
     Diffie-Hellman: a separate encrypted layer is negotiated with EACH hop
     (like nested envelopes). This is "onion routing".
   - Guard knows who you are but not where you're going (it sees only the
     middle relay). Middle knows neither endpoint. Exit knows the
     destination and sees your traffic, but not who you are.
   - Guards are pinned for months: rotating your entry point every circuit
     would eventually hand an attacker the entry slot by chance.

2. ONION SERVICES (v3) -- no exit node at all
   - The service's address IS its identity: the 56-char v3 address encodes
     the service's ed25519 public key plus a SHA3-256 checksum. Use
     --check-onion to verify any address offline.
   - The service builds 3-hop circuits to several INTRODUCTION points and
     publishes signed descriptors (containing those points) to the HSDir
     hash ring -- a distributed hash table formed by relays whose identity
     hashes fall near the descriptor's id. Descriptors are re-published
     roughly every 1-2 hours.
   - You fetch the descriptor, pick a RENDEZVOUS point (one of your own
     3-hop circuits' endpoints), and send it -- via the introduction point
     -- a rendezvous cookie encrypted to the service's key.
   - The service connects to your rendezvous point and you complete the
     handshake there. Result: a 6-hop path (your 3 + their 3) where neither
     side learns the other's IP, and no exit relay ever sees the traffic.

3. ROLES
   Guard: long-lived entry; protects against predecessor/enumeration attacks.
   Middle: pure relay; sees encrypted cells both directions.
   Exit: decrypts the last layer and talks to the destination. Sees
         plaintext unless you use end-to-end encryption (https / onion).

LIVE USE (needs the tor daemon -- not covered by this offline skill):
  tor must be installed and running, then point a client at its SOCKS port
  (usually 127.0.0.1:9050). Onion addresses only resolve inside Tor.
"""

THREAT_MODEL = r"""
TOR THREAT MODEL -- what it hides, what it doesn't
===================================================

WHAT TOR HIDES (from a network observer / the destination):
  - Your IP address and location from the websites/services you visit.
  - The destinations you visit from your ISP / local network (they see only
    encrypted traffic to your guard relay).
  - For onion services: BOTH sides' network identities from each other --
    the 6-hop rendezvous means neither endpoint learns the other's IP.

WHAT TOR DOES *NOT* HIDE:
  - Traffic CONTENT from the exit relay (normal browsing): the exit sees
    whatever you sent it. HTTPS / onion services fix this; plain HTTP does
    not. (Onion services never touch an exit -- end-to-end encrypted.)
  - That you are USING Tor: your ISP sees a connection to a guard relay.
    Bridges / pluggable transports obfuscate this, imperfectly.
  - Timing and volume (traffic correlation): an adversary watching BOTH
    your link to the guard AND the exit's link to the destination can match
    packet timing/sizes and deanonymize you. This is THE fundamental attack
    -- Tor has no mixing delays, so a global passive adversary wins. The
    defense is that such an adversary is expensive, not that the attack
    doesn't work.
  - Your BEHAVIOR once identified: logging into a personal account, posting
    with a recognizable writing style, or downloading a file you also fetch
    in the clear elsewhere all pierce the anonymity set. Tor gives you
    unlinkability, not a new identity.
  - Malware / browser exploits: Tor Browser exists precisely because the
    network layer can't save you from a compromised endpoint. Keep it
    updated; don't install plugins; treat downloaded files as hostile.
  - The service operator from their own logs: an onion service still sees
    *application-layer* data you hand it. Anonymity is about network
    identity, not about what you type.

MENTAL MODEL: Tor moves trust around instead of eliminating it. Normal
browsing trusts the exit with content but hides your identity; onion
services hide both sides' identities and keep content encrypted end to
end -- but both still assume your endpoint isn't compromised and your
adversary isn't watching the whole network at once.
"""


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="torguide",
        description="Tor onion-service mechanics: validate v3 addresses, "
                    "read the architecture explainer and the threat model. "
                    "Fully offline.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check-onion", metavar="ADDR",
                   help="validate a v3 onion address checksum")
    g.add_argument("--explain", action="store_true",
                   help="print how Tor circuits and onion services work")
    g.add_argument("--threat-model", action="store_true",
                   help="print what Tor hides and does not hide")
    args = ap.parse_args(argv)

    if args.check_onion:
        ok, detail = validate_onion(args.check_onion)
        print(f"address: {args.check_onion}")
        print(f"result: {'VALID' if ok else 'INVALID'} -- {detail}")
        return 0 if ok else 1
    if args.explain:
        print(EXPLAIN.strip())
        return 0
    if args.threat_model:
        print(THREAT_MODEL.strip())
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
