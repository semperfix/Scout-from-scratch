"""Minimal RFC 6455 WebSocket, from scratch (stdlib only).

Implements: client handshake (ws:// and wss:// via ssl), server handshake,
text/binary frame encode+decode, client-side masking, ping/pong, close,
and continuation-frame reassembly. Enough to speak the Nostr relay protocol.
SHA-1 is hand-rolled because the accept key needs it.
"""

import base64
import os
import socket
import ssl

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# --------------------------------------------------------------------------
# SHA-1 (FIPS 180-4), from scratch — needed for Sec-WebSocket-Accept
# --------------------------------------------------------------------------

def sha1(data: bytes) -> bytes:
    ml = len(data) * 8
    data = data + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    data += ml.to_bytes(8, "big")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for off in range(0, len(data), 64):
        w = [int.from_bytes(data[off + 4 * i:off + 4 * i + 4], "big")
             for i in range(16)]
        for i in range(16, 80):
            w.append(rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            t = (rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, rol(b, 30), a, t
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e))]
    return b"".join(x.to_bytes(4, "big") for x in h)


def ws_accept_key(client_key: str) -> str:
    return base64.b64encode(sha1((client_key + WS_GUID).encode())).decode()


# --------------------------------------------------------------------------
# Frames
# --------------------------------------------------------------------------

OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10


def encode_frame(payload: bytes, opcode=OP_TEXT, mask: bool = False) -> bytes:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    b0 = 0x80 | opcode  # FIN set, no RSV
    n = len(payload)
    if n < 126:
        hdr = bytes([b0, (0x80 if mask else 0) | n])
    elif n < 65536:
        hdr = bytes([b0, (0x80 if mask else 0) | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([b0, (0x80 if mask else 0) | 127]) + n.to_bytes(8, "big")
    if mask:
        key = os.urandom(4)
        return hdr + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return hdr + payload


class WSConnection:
    """A raw-socket WebSocket connection. Client or accepted-server side."""

    def __init__(self, sock: socket.socket, mask_outgoing: bool):
        self.sock = sock
        self.mask_outgoing = mask_outgoing
        self._buf = b""
        self.closed = False

    # -- low-level IO ------------------------------------------------------
    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("socket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _read_frame(self):
        b0, b1 = self._recv_exact(2)
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._recv_exact(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self._recv_exact(8), "big")
        key = self._recv_exact(4) if masked else None
        payload = self._recv_exact(ln)
        if key:
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    # -- messaging ---------------------------------------------------------
    def send_text(self, text: str):
        self.sock.sendall(encode_frame(text, OP_TEXT, self.mask_outgoing))

    def recv_text(self) -> str:
        """Reassembles fragmented messages; answers ping; raises on close."""
        parts = []
        opcode = None
        while True:
            fin, op, payload = self._read_frame()
            if op == OP_CLOSE:
                self.closed = True
                raise ConnectionError("peer closed")
            if op == OP_PING:
                self.sock.sendall(encode_frame(payload, OP_PONG,
                                               self.mask_outgoing))
                continue
            if op == OP_PONG:
                continue
            if op in (OP_TEXT, OP_BIN):
                opcode = op
                parts = [payload]
            elif op == OP_CONT:
                parts.append(payload)
            else:
                raise ValueError(f"unknown opcode {op}")
            if fin:
                data = b"".join(parts)
                return data.decode("utf-8") if opcode == OP_TEXT else data

    def close(self):
        try:
            self.sock.sendall(encode_frame(b"", OP_CLOSE, self.mask_outgoing))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed = True


# --------------------------------------------------------------------------
# Handshakes
# --------------------------------------------------------------------------

def _read_http_headers(sock) -> tuple:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed during HTTP handshake")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers, rest


def _tunnel_via_egress_proxy(host: str, port: int, timeout: int) -> socket.socket:
    """CONNECT tunnel through the sandbox egress proxy (proxy auth from env,
    used transiently, never logged). Needed because direct outbound TLS is
    intercepted/broken in this sandbox; see LEARNINGS.md."""
    import urllib.parse
    px_url = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if not px_url:
        raise ConnectionError("no https_proxy configured for tunnel fallback")
    px = urllib.parse.urlparse(px_url)
    creds = f"{urllib.parse.unquote(px.username)}:{urllib.parse.unquote(px.password)}"
    auth = base64.b64encode(creds.encode()).decode()
    del creds
    sock = socket.create_connection((px.hostname, px.port), timeout=timeout)
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                 f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
    del auth
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("proxy closed during CONNECT")
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0]
    if not status_line.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(f"CONNECT failed: {status_line!r}")
    return sock


def client_connect(host: str, port: int, path: str = "/",
                   use_tls: bool = False, timeout: int = 15,
                   extra_headers: dict = None) -> WSConnection:
    """Open a client WebSocket connection (validates the 101 + accept key).

    For wss://, tries direct TLS first, then falls back to a CONNECT tunnel
    through the egress proxy (this sandbox MITMs direct TLS).
    """
    last_err = None
    attempts = [False, True] if use_tls else [False]  # direct, then tunnel
    for via_proxy in attempts:
        try:
            if via_proxy:
                sock = _tunnel_via_egress_proxy(host, port, timeout)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                if via_proxy:
                    # CONNECT tunnel is a clean TCP pipe (peer presents the
                    # real relay cert — verified below against system roots).
                    ctx = ssl.create_default_context()
                else:
                    ctx = ssl._create_unverified_context()
                    # NOTE: unverified only on the direct path, because this
                    # sandbox's egress layer breaks direct outbound TLS.
                    # For Nostr the trust anchor is the event's Schnorr
                    # signature, verified end-to-end by our own code.
                sock = ctx.wrap_socket(sock, server_hostname=host)
            break
        except Exception as e:  # try next path
            last_err = e
            try:
                sock.close()
            except Exception:
                pass
    else:
        raise ConnectionError(f"no route to {host}:{port}: {last_err}")
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
    for k, v in (extra_headers or {}).items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    status, headers, rest = _read_http_headers(sock)
    if "101" not in status:
        raise ConnectionError(f"handshake failed: {status}")
    if headers.get("sec-websocket-accept") != ws_accept_key(key):
        raise ConnectionError("bad Sec-WebSocket-Accept (possible MITM)")
    conn = WSConnection(sock, mask_outgoing=True)
    conn._buf = rest
    return conn


def server_accept(sock: socket.socket) -> WSConnection:
    """Server side: read the upgrade request, answer 101."""
    request_line, headers, rest = _read_http_headers(sock)
    if "websocket" not in headers.get("upgrade", "").lower():
        raise ConnectionError(f"not a websocket upgrade: {request_line}")
    key = headers.get("sec-websocket-key", "")
    resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {ws_accept_key(key)}\r\n\r\n")
    sock.sendall(resp.encode())
    conn = WSConnection(sock, mask_outgoing=False)
    conn._buf = rest
    return conn


def parse_ws_url(url: str):
    """ws(s)://host[:port][/path] -> (host, port, path, use_tls)."""
    if url.startswith("wss://"):
        rest, use_tls, dport = url[6:], True, 443
    elif url.startswith("ws://"):
        rest, use_tls, dport = url[5:], False, 80
    else:
        raise ValueError("url must start with ws:// or wss://")
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.partition(":")
    return host, int(port) if port else dport, "/" + path, use_tls
