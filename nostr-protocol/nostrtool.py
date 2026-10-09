#!/usr/bin/env python3
"""nostrtool — CLI for the from-scratch Nostr stack.

  keygen                          new keypair (nsec/npub/hex)
  pub        --relay URL --nsec NSEC --kind K --content TEXT [--tags JSON]
  sub        --relay URL [--kinds 1,2] [--authors hex,..] [--limit N] [--since TS]
  verify     --file event.json
  dm-send    --from-nsec NSEC --to-npub NPUB --text TEXT   -> NIP-04 payload
  dm-read    --to-nsec NSEC --from-npub NPUB --payload P   -> plaintext
  relay      [--port 7777]   run the relay

Keys may be given as nsec... or raw hex. Relays: ws://localhost or wss://.
"""
import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secp import xonly_pubkey
from event import (sign_event, verify_event, hex_to_npub, hex_to_nsec,
                   npub_to_hex, bech32_decode, bech32_encode)
from client import NostrClient
from relay import Relay
from nip04 import nip04_encrypt, nip04_decrypt


def parse_secret(s: str) -> str:
    """nsec or hex -> hex secret."""
    s = s.strip()
    if s.startswith("nsec1"):
        hrp, raw = bech32_decode(s)
        assert hrp == "nsec" and len(raw) == 32, "bad nsec"
        return raw.hex()
    raw = bytes.fromhex(s)
    assert len(raw) == 32, "secret must be 32 bytes"
    return raw.hex()


def parse_pubkey(s: str) -> str:
    """npub or hex -> hex pubkey."""
    s = s.strip()
    if s.startswith("npub1"):
        return npub_to_hex(s)
    raw = bytes.fromhex(s)
    assert len(raw) == 32, "pubkey must be 32 bytes"
    return raw.hex()


def cmd_keygen(_):
    sk = os.urandom(32)
    print("nsec:", hex_to_nsec(sk.hex()))
    print("npub:", hex_to_npub(xonly_pubkey(sk).hex()))
    print("hex :", sk.hex(), "(KEEP SECRET)")


def cmd_pub(a):
    sk = parse_secret(a.nsec)
    tags = json.loads(a.tags) if a.tags else []
    ev = sign_event(sk, a.kind, a.content, tags=tags)
    c = NostrClient(a.relay)
    ok, msg = c.publish(ev)
    c.close()
    print("id:", ev["id"])
    print("note:", bech32_encode("note", bytes.fromhex(ev["id"])))
    print("relay OK:", ok, msg if msg else "")


def cmd_sub(a):
    f = {}
    if a.kinds:
        f["kinds"] = [int(k) for k in a.kinds.split(",")]
    if a.authors:
        f["authors"] = [parse_pubkey(x) for x in a.authors.split(",")]
    if a.limit:
        f["limit"] = a.limit
    if a.since:
        f["since"] = a.since
    c = NostrClient(a.relay)
    evs = c.query(f, timeout=a.timeout)
    c.close()
    print(f"{len(evs)} events (all signature-verified by client)")
    for ev in evs:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ev["created_at"]))
        body = ev["content"].replace("\n", " ")
        print(f"- [{when}] kind={ev['kind']} {ev['pubkey'][:12]}… {body[:100]}")


def cmd_verify(a):
    ev = json.load(open(a.file))
    ok, reason = verify_event(ev)
    print("VALID " if ok else "INVALID", "-", reason)
    sys.exit(0 if ok else 1)


def cmd_dm_send(a):
    print(nip04_encrypt(parse_secret(a.from_nsec), parse_pubkey(a.to_npub), a.text))


def cmd_dm_read(a):
    print(nip04_decrypt(parse_secret(a.to_nsec), parse_pubkey(a.from_npub), a.payload))


def cmd_relay(a):
    Relay().serve(port=a.port)


def main():
    p = argparse.ArgumentParser(description="Nostr from scratch")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    q = sub.add_parser("pub")
    q.add_argument("--relay", required=True)
    q.add_argument("--nsec", required=True)
    q.add_argument("--kind", type=int, default=1)
    q.add_argument("--content", required=True)
    q.add_argument("--tags", default=None)

    q = sub.add_parser("sub")
    q.add_argument("--relay", required=True)
    q.add_argument("--kinds", default=None)
    q.add_argument("--authors", default=None)
    q.add_argument("--limit", type=int, default=10)
    q.add_argument("--since", type=int, default=None)
    q.add_argument("--timeout", type=int, default=20)

    q = sub.add_parser("verify")
    q.add_argument("--file", required=True)

    q = sub.add_parser("dm-send")
    q.add_argument("--from-nsec", required=True)
    q.add_argument("--to-npub", required=True)
    q.add_argument("--text", required=True)

    q = sub.add_parser("dm-read")
    q.add_argument("--to-nsec", required=True)
    q.add_argument("--from-npub", required=True)
    q.add_argument("--payload", required=True)

    q = sub.add_parser("relay")
    q.add_argument("--port", type=int, default=7777)

    a = p.parse_args()
    {"keygen": cmd_keygen, "pub": cmd_pub, "sub": cmd_sub,
     "verify": cmd_verify, "dm-send": cmd_dm_send, "dm-read": cmd_dm_read,
     "relay": cmd_relay}[a.cmd](a)


if __name__ == "__main__":
    main()
