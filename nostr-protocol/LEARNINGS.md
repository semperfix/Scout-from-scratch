# Learning expedition #50 — Nostr protocol from scratch

## What was built

`~/workspace/learning/50-nostr/`: a complete, working Nostr stack with zero
non-stdlib dependencies (plus a node-based interop harness in /tmp):

- `secp.py` — secp256k1 field/point arithmetic + SHA-256, vendored from #22,
  plus BIP-340's `lift_x` (x-only keys with enforced even y).
- `schnorr.py` — **BIP-340 Schnorr signatures** from scratch (tagged hashes,
  nonce derivation, challenge, verification via `s*G - e*P`).
- `event.py` — NIP-01 events: canonical-JSON id commitment, sign/verify, and
  NIP-19 `npub`/`nsec`/`note` bech32 identities.
- `ws.py` — minimal RFC 6455 WebSocket from scratch: client+server handshakes
  (hand-rolled SHA-1 for the accept key), masked/unmasked framing, 16-bit and
  64-bit extended lengths, ping/pong, close, fragmentation reassembly, and an
  egress-proxy CONNECT-tunnel fallback for wss://.
- `relay.py` — a working Nostr relay: EVENT/REQ/CLOSE/EOSE/NOTICE/OK (NIP-20),
  filter matching (ids/authors/kinds/since/until/limit/#e/#p), replaceable-event
  semantics (newest created_at wins per author+kind[+d-tag]), id+signature
  verification before storage, live broadcast to matching subscribers.
- `client.py` — Nostr client: publish (waits for relay OK), query-until-EOSE,
  verifies every received event by default.
- `nip04.py` — NIP-04 encrypted DMs: secp256k1 ECDH → x(shared) as AES-256 key,
  AES-256-CBC + PKCS#7 (block cipher vendored from #17), `ct?iv=` wire format.
- `nostrtool.py` — CLI: `keygen`, `pub`, `sub`, `verify`, `dm-send`, `dm-read`,
  `relay`.

## Validation (108/108 in `test_nostr.py`)

- **BIP-340 official vectors: 19/19 verify, 4/4 signing byte-exact, 4/4 pubkey
  derivation.** The vectors caught a real spec-subtlety bug (below).
- **Interop with the real `nostr-tools` JS library**: its `getEventHash`
  equals my event id, its `verifySignature` accepts my signatures, my code
  verifies its signed events; **NIP-04 encrypt/decrypt both directions**.
- AES-256 differential vs pycryptodome (30 sampled blocks match).
- **Live: fetched 10 real kind-1 notes from `wss://relay.damus.io` and
  verified every event's id commitment + Schnorr signature with my code.**
  TLS through the CONNECT tunnel presented damus.io's genuine Google-Trust-
  Services cert (checked with my #29 X.509 parser) — the tunnel is a clean
  TCP pipe, so the client uses a verifying TLS context there.

## Earned insights (bugs found by testing, not staring)

1. **BIP-340's aux hash uses the *negated* secret.** `t = d ⊕ H_aux(a)` where
   `d` is the secret *after* the odd-y negation — I first xored the original
   key bytes. Vectors 0–2 passed (their keys had even-y pubs); vector 3's
   odd-y key caught it. Same class of bug as #22's sighash subtleties: the
   spec sentence you skim is the one that bites.
2. **Case-sensitivity is a test-harness bug, not a crypto bug.** My `.hex()`
   is lowercase, the CSV is uppercase — three "failures" that were string
   comparison, fixed with `.lower()`. (Related: the NIP-04 "interop failure"
   was my harness regenerating fresh keys per node invocation — the
   implementation was fine. When an interop test fails, suspect the harness
   first; it has more moving parts.)
3. **Nostr's trust model is end-to-end, not transport.** The event id commits
   to every field and the Schnorr signature covers the id — so signature
   verification is the authenticity check, independent of TLS. That's why an
   unverified-TLS fallback is *tolerable* for public relay reads, and why the
   relay must verify before storing (it does — tampered publishes get
   `OK=false`).
4. **Replaceable events are a CRDT-ish idea in disguise.** Kinds 0/3/10000+/
   30000+ keep newest-wins per (author, kind, d-tag) — last-writer-wins
   registers, the same primitive #37/#38-adjacent distributed systems use.
5. **nostr-tools slices the *compressed* shared point.** `getSharedSecret`
   returns 33 bytes; `key.slice(1,33)` is the x-coordinate used directly as
   the AES key — no KDF. Confirmed by reading the bundled source, then proven
   by successful decryption both ways.
6. **Sandbox networking note:** direct outbound TLS to :443 fails
   (WRONG_VERSION_NUMBER — the egress layer intercepts it), but a CONNECT
   tunnel through `https_proxy` gives a clean pipe to the real host. My
   earlier "sandbox MITMs everything" mental model from #42 was too strong —
   the CONNECT path is not intercepted (verified: real damus.io cert).

## What's genuinely new vs the 49

BIP-340 Schnorr (a new signature scheme — #22 did ECDSA), x-only keys,
bech32 identity encoding in a new domain, the WebSocket protocol, and a
client+relay for a decentralized social protocol. Reused: secp256k1 math
(#22), AES-256 (#17), X.509 parsing (#29), the proxy-tunnel trick (#42).

## Operator value

- `nostrtool.py sub --relay wss://relay.damus.io --kinds 1 --limit N` reads
  any public relay with per-event signature verification — a topic-monitoring
  primitive for Kyle's research rabbit holes (conspiracy/tech discussion is
  heavy on Nostr).
- `dm-send`/`dm-read` give working encrypted DMs interoperable with every
  Nostr client (Amethyst, Damus, etc.).
- `relay` gives Kyle a personal relay he could actually run — censorship-
  resistant publishing with no account, no phone number, no permission.
- Natural follow-ups: NIP-44 (newer encryption), NIP-02 contact lists,
  kind 30023 long-form reading pipeline into the #24 search index.

## Files

`secp.py`, `schnorr.py`, `event.py`, `ws.py`, `relay.py`, `client.py`,
`nip04.py`, `nostrtool.py`, `test_nostr.py`, `bip0340.csv` (official vectors),
`LEARNINGS.md`.
