# Nostr Protocol — A Complete Stack from Scratch

A working Nostr stack in stdlib-only Python: `secp.py` (secp256k1 field/point
arithmetic + SHA-256, x-only keys via BIP-340 `lift_x`), `schnorr.py`
(**BIP-340 Schnorr signatures** from scratch), `event.py` (NIP-01 events:
canonical-JSON id commitment, sign/verify, NIP-19 `npub`/`nsec`/`note`
bech32 identities), `ws.py` (minimal RFC 6455 WebSocket from scratch:
handshakes with hand-rolled SHA-1 accept keys, masked/unmasked framing,
extended lengths, ping/pong, fragmentation reassembly, plus an
egress-proxy CONNECT-tunnel fallback for `wss://`), `relay.py` (a real
relay: EVENT/REQ/CLOSE/EOSE/NOTICE/OK (NIP-20), filter matching,
replaceable-event semantics, id+signature verification before storage,
live broadcast), `client.py` (publish w/ relay-OK, query-until-EOSE,
verify-everything-by-default), `nip04.py` (NIP-04 encrypted DMs:
secp256k1 ECDH → x(shared) as AES-256 key, AES-256-CBC + PKCS#7),
`nostrtool.py` (CLI: `keygen`, `pub`, `sub`, `verify`, `dm-send`,
`dm-read`, `relay`).

**Validation: 108/108 in `test_nostr.py`.** The BIP-340 official vectors
(`bip0340.csv`, kept here — small and required): **19/19 verify, 4/4
signing byte-exact, 4/4 pubkey derivation.** Interop proven against the
real `nostr-tools` JS library (its `getEventHash` == my event id, its
`verifySignature` accepts my signatures, my code verifies its events,
NIP-04 encrypt/decrypt both directions), AES-256 differential vs
pycryptodome (30 blocks match), and live against the real network:
**fetched 10 real kind-1 notes from `wss://relay.damus.io` and verified
every event's id commitment + Schnorr signature with this code.**

## Dependencies

Stdlib only. No pip packages. `bip0340.csv` is the official BIP-340 test
vector set (kept — it's small and `test_nostr.py` reads it directly).

## How to run

```
python3 test_nostr.py                        # 108/108: vectors, crypto, relay, client, NIP-04
python3 nostrtool.py keygen                  # new keypair -> nsec/npub
python3 nostrtool.py relay --port 7777       # run your own relay locally
python3 nostrtool.py pub --relay ws://127.0.0.1:7777 --nsec <nsec> --kind 1 --content "hello nostr"
python3 nostrtool.py sub --relay ws://127.0.0.1:7777 --kinds 1 --limit 10
python3 nostrtool.py verify <event-json>     # id commitment + Schnorr signature check
python3 nostrtool.py dm-send --nsec <nsec> --to <npub> --content "secret"
python3 nostrtool.py dm-read --nsec <nsec>
```

Note: `sub`/`pub` against public `wss://` relays need the egress-proxy
`https_proxy` env var in this sandbox (direct outbound :443 is
intercepted); the tunnel presents the relay's genuine certificate.

## Usage example

Sign and verify a Nostr event with nothing but this code:

```python
from secp import xonly_pubkey
from schnorr import sign
from event import sign_event, verify_event

sk = bytes.fromhex("e3b0" + "00"*30)          # any 32-byte secret
ev = sign_event(sk, kind=1, content="fox says hi", tags=[])
print(ev["id"])                                # event id = canonical-JSON SHA-256
print(ev["sig"][:32] + "...")
print(verify_event(ev))                        # True — id commitment + Schnorr both hold
```

## Limitations

- **NIP-04 only for DMs** (AES-256-CBC, no forward secrecy) — the modern
  standard is NIP-44 (ChaCha20-based); CBC with a static shared key is
  legacy and malleable. Use it as Nostr clients do (i.e. don't send
  anything life-critical through it).
- **`ws.py` is minimal RFC 6455**, not a full client: no extensions
  (permessage-deflate), no client certs, no graceful reconnection. The
  relay side is single-thread-per-connection with an in-memory store —
  fine for a personal relay, not for damus-scale traffic.
- **No NIP-02 contact lists, no NIP-05 DNS identities, no NIP-42 auth.**
  Event kinds beyond the common ones (1, 0, 3, 4, replaceables) aren't
  specially handled — though filter matching and storage are
  kind-agnostic.
- The relay verifies id+signature **before** storing (tampered publishes
  get `OK=false`) — but it does no rate-limiting, PoW checking, or spam
  filtering. Run it open to the internet at your own risk.
- Live interop tests were validated at build time against `nostr-tools`
  and `relay.damus.io`; public relays evolve, so re-run before trusting
  new NIP coverage.

## Files

- `secp.py`, `schnorr.py` — secp256k1 + BIP-340 Schnorr from scratch
- `event.py` — NIP-01 events, NIP-19 bech32 identities
- `ws.py` — minimal RFC 6455 WebSocket + proxy CONNECT-tunnel fallback
- `relay.py` — the relay (filters, replaceables, broadcast)
- `client.py` — publish / query-until-EOSE, verify-by-default
- `nip04.py` — NIP-04 encrypted DMs (AES-256-CBC)
- `nostrtool.py` — CLI: keygen, pub, sub, verify, dm-send, dm-read, relay
- `test_nostr.py` — 108 checks; `bip0340.csv` — official vectors it reads
- `LEARNINGS.md` — the full expedition writeup
