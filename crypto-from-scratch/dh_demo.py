#!/usr/bin/env python3
"""Diffie-Hellman encrypted channel over a localhost TCP socket.

  * Parameters: RFC 3526 2048-bit MODP group (p, g=2) -- hardcoded, since
    generating a fresh 2048-bit safe prime takes minutes and the point of
    this skill is the *protocol*, not prime generation.
  * Alice and Bob each pick a secret exponent, exchange public values over
    a plain TCP socket, and derive the channel key as
        key = SHA-256(str(shared_secret).encode())[:16]
  * The channel itself is AES-128-CBC (from aes.py) with a random IV per
    message; wire format is 4-byte big-endian length + IV + ciphertext.

Run as a script for a one-shot demo (server thread + client in-process), or
import and use serve()/client_exchange() separately.
"""
import hashlib
import os
import socket
import struct
import threading

from aes import cbc_encrypt, cbc_decrypt

# ---------------------------------------------------------------------------
# DH parameters: a 512-bit safe prime generated locally and cached in
# dh_params.json (safe prime p = 2q+1, both prime, verified at generation).
# Production code uses the RFC 3526 MODP groups instead; the protocol here
# is identical regardless of group size. 512 bits keeps the pure-Python
# demo fast while remaining a real (if modest) discrete-log problem.
# ---------------------------------------------------------------------------
import json as _json

_PARAMS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "dh_params.json")


def _load_or_generate_params(bits=512):
    if os.path.exists(_PARAMS_FILE):
        with open(_PARAMS_FILE) as f:
            d = _json.load(f)
        p, g = int(d["p"], 16), d["g"]
    else:
        from rsa import _is_probable_prime, _gen_prime
        while True:
            q = _gen_prime(bits - 1)
            p = 2 * q + 1
            if _is_probable_prime(p, rounds=24):
                break
        g = 2
        if pow(g, q, p) != 1:
            # want g of order q (the prime-order subgroup): try small g's
            g = next(g2 for g2 in range(2, 100) if pow(g2, q, p) == 1 and g2 != 1)
        with open(_PARAMS_FILE, "w") as f:
            _json.dump({"p": format(p, "x"), "g": g, "bits": bits,
                        "note": "locally generated safe prime, p=2q+1"}, f,
                       indent=2)
    return p, g


P, G = _load_or_generate_params()


def derive_key(shared_secret_int):
    """SHA-256 KDF: key = SHA256(decimal string of secret)[:16] (AES-128)."""
    return hashlib.sha256(str(shared_secret_int).encode()).digest()[:16]


def _recvall(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return bytes(buf)


def _send_pub(conn, pub):
    raw = pub.to_bytes((P.bit_length() + 7) // 8, "big")
    conn.sendall(struct.pack(">H", len(raw)) + raw)


def _recv_pub(conn):
    (n,) = struct.unpack(">H", _recvall(conn, 2))
    return int.from_bytes(_recvall(conn, n), "big")


class EncryptedChannel:
    """Length-prefixed AES-CBC message channel over an open socket."""

    def __init__(self, conn, key):
        self.conn, self.key = conn, key

    def send(self, plaintext: bytes):
        iv = os.urandom(16)
        ct = cbc_encrypt(self.key, iv, plaintext)
        self.conn.sendall(struct.pack(">I", len(iv) + len(ct)) + iv + ct)

    def recv(self):
        (n,) = struct.unpack(">I", _recvall(self.conn, 4))
        blob = _recvall(self.conn, n)
        return cbc_decrypt(self.key, blob[:16], blob[16:])


def _dh_exchange(conn, who):
    priv = 2 + int.from_bytes(os.urandom(64), "big") % (P - 3)
    pub = pow(G, priv, P)
    _send_pub(conn, pub)          # both sides send-then-recv; TCP is full-duplex
    peer_pub = _recv_pub(conn)
    if not 1 < peer_pub < P - 1:
        raise ValueError(f"{who}: peer public value out of range (bad/small-subgroup?)")
    return derive_key(pow(peer_pub, priv, P))


def serve(port, on_message, ready=None):
    """Block: accept one connection, DH exchange, then echo via on_message."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    if ready:
        ready.set()
    conn, _ = srv.accept()
    with conn, srv:
        key = _dh_exchange(conn, "server")
        ch = EncryptedChannel(conn, key)
        while True:
            try:
                msg = ch.recv()
            except ConnectionError:
                break
            reply = on_message(msg)
            if reply is None:
                break
            ch.send(reply)


def client_exchange(port, messages):
    """Connect, DH exchange, send messages, collect replies. Returns transcript."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    with conn:
        key = _dh_exchange(conn, "client")
        ch = EncryptedChannel(conn, key)
        transcript = []
        for m in messages:
            ch.send(m)
            r = ch.recv()
            transcript.append((m, r))
        return key, transcript


def demo(port=18321):
    """One-shot demo: server thread echoes reversed messages; client sends two."""
    ready = threading.Event()
    server_key = {}

    def on_message(msg):
        return b"echo: " + msg[::-1]

    def _srv():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        with conn, srv:
            server_key["k"] = _dh_exchange(conn, "server")
            ch = EncryptedChannel(conn, key=server_key["k"])
            for _ in range(2):
                ch.send(b"echo: " + ch.recv()[::-1])

    t = threading.Thread(target=_srv, daemon=True)
    t.start()
    ready.wait(timeout=10)
    key, transcript = client_exchange(port, [b"hello diffie", b"second message"])
    t.join(timeout=10)
    lines = [
        f"DH parameters: locally generated {P.bit_length()}-bit safe prime (p=2q+1), g={G}",
        f"client derived key: {key.hex()}",
        f"server derived key: {server_key['k'].hex()}",
        f"keys match: {key == server_key['k']}",
    ]
    for sent, got in transcript:
        lines.append(f"  sent {sent!r} -> got {got!r}")
    ok = key == server_key["k"] and all(got == b"echo: " + sent[::-1]
                                        for sent, got in transcript)
    return ok, "\n".join(lines)


if __name__ == "__main__":
    ok, report = demo()
    print(report)
    print("DH DEMO:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)
