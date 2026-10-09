#!/usr/bin/env python3
"""TLS 1.3 transport with ALPN negotiation for HTTP/2, from scratch.

Reuses the #42 hand-rolled TLS 1.3 stack (tls13.py): X25519 key exchange,
AES-128-GCM record protection, CertificateVerify/Finished validation.
The only addition over live_tls13.py is ALPN: we offer (h2, http/1.1)
in the ClientHello and read the server's selection out of the
EncryptedExtensions.

NOTE on secrets: the egress-proxy credential comes from the `https_proxy`
environment variable and is used transiently in-process to build the
CONNECT request. It is NEVER printed, logged, or written to disk.
"""
import base64
import os
import socket
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, '/home/hatch/workspace/learning/42-tls13')
import tls13 as T


def parse_encrypted_extensions_alpn(msg: bytes):
    """Return the server's ALPN selection (bytes) or None."""
    assert msg[0] == 0x08, 'expected EncryptedExtensions'
    body = msg[4:]
    total = int.from_bytes(body[:2], 'big')
    exts, off = body[2:2 + total], 2
    selected = None
    while off < 2 + total:
        t = int.from_bytes(body[off:off + 2], 'big')
        ln = int.from_bytes(body[off + 2:off + 4], 'big')
        val = body[off + 4:off + 4 + ln]
        if t == 0x0010:  # application_layer_protocol_negotiation
            llen = int.from_bytes(val[:2], 'big')
            p = val[2:2 + llen]
            slen = p[0]
            selected = p[1:1 + slen]
        off += 4 + ln
    return selected


class TLSAppTransport:
    """Application-data pipe over a completed TLS 1.3 handshake."""

    def __init__(self, sock, c_key, c_iv, s_key, s_iv):
        self.sock = sock
        self.c_key, self.c_iv = c_key, c_iv
        self.s_key, self.s_iv = s_key, s_iv
        self.c_seq = 0
        self.s_seq = 0
        self._rbuf = b''

    def send(self, data: bytes):
        rec = T.protect(self.c_key, self.c_iv, self.c_seq, 0x17, data)
        self.c_seq += 1
        self.sock.sendall(rec)

    # socket-like API for http2.H2Connection
    def sendall(self, data: bytes):
        self.send(data)

    def recv(self, n: int) -> bytes:
        while len(self._rbuf) < n:
            hdr = self._read_n(5)
            ln = int.from_bytes(hdr[3:5], 'big')
            rec = hdr + self._read_n(ln)
            ctype, inner = T.unprotect(self.s_key, self.s_iv, self.s_seq, rec)
            self.s_seq += 1
            if ctype == 0x17:
                self._rbuf += inner
            # tolerate NewSessionTicket / key updates mid-stream
        out, self._rbuf = self._rbuf[:n], self._rbuf[n:]
        return out

    def _read_n(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('socket closed')
            buf += chunk
        return buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def tls_connect(host: str, port: int = 443, alpn=(b'h2', b'http/1.1'),
                timeout: float = 20.0):
    """Full handshake through the egress proxy. Returns
    (transport, selected_alpn, cert_info)."""
    px = urllib.parse.urlparse(os.environ['https_proxy'])
    creds = f'{urllib.parse.unquote(px.username)}:{urllib.parse.unquote(px.password)}'
    auth = base64.b64encode(creds.encode()).decode()
    del creds
    sock = socket.create_connection((px.hostname, px.port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n'
                 f'Proxy-Authorization: Basic {auth}\r\n\r\n'.encode())
    del auth
    resp = b''
    while b'\r\n\r\n' not in resp:
        resp += sock.recv(4096)
    status = resp.split(b'\r\n', 1)[0]
    if not status.startswith(b'HTTP/1.1 200'):
        raise ConnectionError('CONNECT failed: %r' % status)

    priv = os.urandom(32)
    pub = T.x25519_pubkey(priv)
    ch_msg = T.build_client_hello(pub, host, os.urandom(32), os.urandom(32),
                                  alpn_protos=alpn)
    sock.sendall(T.wrap_handshake_record(ch_msg))
    tr = T.Transcript()
    tr.add(ch_msg)

    def read_record():
        hdr = b''
        while len(hdr) < 5:
            chunk = sock.recv(5 - len(hdr))
            if not chunk:
                raise ConnectionError('socket closed')
            hdr += chunk
        ln = int.from_bytes(hdr[3:5], 'big')
        body = b''
        while len(body) < ln:
            chunk = sock.recv(ln - len(body))
            if not chunk:
                raise ConnectionError('socket closed')
            body += chunk
        return hdr[0], body

    ctype, sh_body = read_record()
    assert ctype == 0x16, 'expected ServerHello'
    sh_msg = sh_body  # handshake record payload = handshake msg w/ 4-byte header
    suite, _rnd, server_pub = T.parse_server_hello(sh_msg)
    tr.add(sh_msg)

    shared = T.x25519(priv, server_pub)
    assert shared != b'\x00' * 32
    ks = T.key_schedule(shared, tr)
    s_key, s_iv = T.traffic_key_iv(ks['s_hs'])
    c_key, c_iv = T.traffic_key_iv(ks['c_hs'])
    s_seq = c_seq = 0

    ra = T.HSReassembler()
    selected_alpn, cert_cn, cv_scheme = None, None, None
    flight_done = False
    while not flight_done:
        ctype, rec = read_record()
        if ctype == 0x14:
            continue  # middlebox-compat CCS
        itype, inner = T.unprotect(s_key, s_iv, s_seq, b'\x17\x03\x03' +
                                   len(rec).to_bytes(2, 'big') + rec)
        s_seq += 1
        assert itype == 0x16
        ra.feed(inner)
        for m in ra.take():
            kind = m[0]
            if kind == 0x08:
                selected_alpn = parse_encrypted_extensions_alpn(m)
                tr.add(m)
            elif kind == 0x0b:
                certs = T.parse_certificate(m)
                pubkey = T.parse_spki(certs[0])
                cert_cn = T.cert_subject_cn(certs[0])
                tr.add(m)
            elif kind == 0x0f:
                scheme, sig = T.parse_certificate_verify(m)
                assert T.verify_certificate_verify(scheme, sig, pubkey, tr.hash())
                cv_scheme = scheme
                tr.add(m)
            elif kind == 0x14:
                expect = T.hmac_sha256(T.finished_key(ks['s_hs']), tr.hash())
                assert m[4:] == expect, 'server Finished MAC failed'
                tr.add(m)
                flight_done = True

    T.finish_handshake_schedule(ks, tr)
    c_ap, s_ap = T.app_traffic_secrets(ks, tr)
    c_ap_key, c_ap_iv = T.traffic_key_iv(c_ap)
    s_ap_key, s_ap_iv = T.traffic_key_iv(s_ap)
    fin_msg = b'\x14\x00\x00\x20' + T.hmac_sha256(T.finished_key(ks['c_hs']), tr.hash())
    sock.sendall(T.protect(c_key, c_iv, c_seq, 0x16, fin_msg))
    tr.add(fin_msg)

    transport = TLSAppTransport(sock, c_ap_key, c_ap_iv, s_ap_key, s_ap_iv)
    return transport, selected_alpn, {'suite': suite, 'cn': cert_cn,
                                     'cv_scheme': cv_scheme}


def connect_h2(host: str, port: int = 443, timeout: float = 20.0):
    """TLS + ALPN(h2) + HTTP/2 preface. Returns (H2Connection, info dict).

    Raises RuntimeError if the server did not negotiate h2."""
    import http2
    transport, alpn, info = tls_connect(host, port, timeout=timeout)
    if alpn != b'h2':
        transport.close()
        raise RuntimeError('server negotiated ALPN %r, not h2' % (alpn,))
    conn = http2.H2Connection(sock=transport)
    conn.send_preface()
    # wait for the server's SETTINGS (proves the preface parsed)
    deadline = time.time() + timeout
    while not conn._server_settings_seen and time.time() < deadline:
        conn._dispatch(conn.recv_frame())
    if not conn._server_settings_seen:
        raise TimeoutError('server never sent SETTINGS')
    info['alpn'] = alpn
    return conn, info
