#!/usr/bin/env python3
"""HTTP/2 framing (RFC 7540) from scratch, stdlib only.

Implements the binary framing layer: the 9-byte frame header, all ten
frame types, the client connection preface, SETTINGS negotiation, stream
multiplexing with per-stream state, connection- and stream-level flow
control, header-block fragmentation (CONTINUATION), PING/GOAWAY handling,
and HPACK (hpack.py) header compression on every header block.

Design: H2Connection owns one socket (or a byte buffer in tests), the
HPACK encoder/decoder pair, the stream table, and the flow-control
windows. Frames are dispatched to per-stream state; read_response()
pumps the wire until the requested stream completes, so concurrent
streams multiplex naturally.
"""
import socket

import hpack as HPACK

# --- connection preface -------------------------------------------------------
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

# --- frame types (RFC 7540 6) -------------------------------------------------
T_DATA = 0x0
T_HEADERS = 0x1
T_PRIORITY = 0x2
T_RST_STREAM = 0x3
T_SETTINGS = 0x4
T_PUSH_PROMISE = 0x5
T_PING = 0x6
T_GOAWAY = 0x7
T_WINDOW_UPDATE = 0x8
T_CONTINUATION = 0x9

TYPE_NAMES = {0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM',
              4: 'SETTINGS', 5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY',
              8: 'WINDOW_UPDATE', 9: 'CONTINUATION'}

# --- flags --------------------------------------------------------------------
F_END_STREAM = 0x1
F_END_HEADERS = 0x4
F_PADDED = 0x8
F_PRIORITY = 0x20
F_ACK = 0x1

# --- SETTINGS parameters (RFC 7540 6.5.2) --------------------------------------
S_HEADER_TABLE_SIZE = 0x1
S_ENABLE_PUSH = 0x2
S_MAX_CONCURRENT_STREAMS = 0x3
S_INITIAL_WINDOW_SIZE = 0x4
S_MAX_FRAME_SIZE = 0x5
S_MAX_HEADER_LIST_SIZE = 0x6

# --- error codes (RFC 7540 7) ---------------------------------------------------
E_NO_ERROR = 0x0
E_PROTOCOL_ERROR = 0x1
E_FLOW_CONTROL_ERROR = 0x3
E_STREAM_CLOSED = 0x5
E_FRAME_SIZE_ERROR = 0x6
E_COMPRESSION_ERROR = 0x9


class H2Error(Exception):
    """Connection-level error: the connection is broken."""


class H2StreamError(Exception):
    """Stream-level error."""


class Frame:
    __slots__ = ('type', 'flags', 'stream', 'payload')

    def __init__(self, type, flags, stream, payload):
        self.type = type
        self.flags = flags
        self.stream = stream & 0x7fffffff
        self.payload = payload

    def encode(self) -> bytes:
        if len(self.payload) > 0xffffff:
            raise H2Error('frame payload too large')
        hdr = (len(self.payload).to_bytes(3, 'big') + bytes([self.type, self.flags])
               + (self.stream & 0x7fffffff).to_bytes(4, 'big'))
        return hdr + self.payload

    @property
    def name(self):
        return TYPE_NAMES.get(self.type, 'UNKNOWN(%d)' % self.type)

    def __repr__(self):
        return '<Frame %s flags=0x%02x stream=%d len=%d>' % (
            self.name, self.flags, self.stream, len(self.payload))


class FrameReader:
    """Incremental frame parser over a byte stream."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        frames = []
        self.buf += data
        while len(self.buf) >= 9:
            length = int.from_bytes(self.buf[0:3], 'big')
            if len(self.buf) < 9 + length:
                break
            ftype, flags = self.buf[3], self.buf[4]
            stream = int.from_bytes(self.buf[5:9], 'big') & 0x7fffffff
            payload = bytes(self.buf[9:9 + length])
            del self.buf[:9 + length]
            frames.append(Frame(ftype, flags, stream, payload))
        return frames


def parse_settings(payload: bytes) -> dict:
    if len(payload) % 6:
        raise H2Error('SETTINGS payload not a multiple of 6')
    out = {}
    for i in range(0, len(payload), 6):
        pid = int.from_bytes(payload[i:i + 2], 'big')
        val = int.from_bytes(payload[i + 2:i + 6], 'big')
        out[pid] = val
    return out


def build_settings(params: dict) -> bytes:
    out = bytearray()
    for pid, val in params.items():
        out += pid.to_bytes(2, 'big') + (val & 0xffffffff).to_bytes(4, 'big')
    return bytes(out)


class Stream:
    """Client-side stream state."""

    def __init__(self, sid: int, initial_window: int):
        self.id = sid
        self.state = 'idle'          # idle/open/half-closed-local/
                                     # half-closed-remote/closed
        self.headers = []            # decoded response headers
        self.trailers = []
        self.data = bytearray()
        self.recv_window = 65535
        self.send_window = initial_window
        self.reset_code = None
        self._header_frag = None     # accumulated header block fragments
        self._pending_flags = None   # (flags, is_trailer) while fragmented

    @property
    def complete(self):
        return self.state in ('closed',) or self.reset_code is not None

    @property
    def end_stream(self):
        return self.state in ('half-closed-remote', 'closed')


class H2Connection:
    """An HTTP/2 client connection. Either wraps a live socket or works
    over injected bytes (tests / forensic frame dumps)."""

    def __init__(self, sock=None, client_settings=None):
        self.sock = sock
        self.reader = FrameReader()
        self.encoder = HPACK.Encoder()
        self.decoder = HPACK.Decoder()
        self.streams = {}
        self.next_stream_id = 1
        self.peer_settings = {
            S_HEADER_TABLE_SIZE: 4096,
            S_ENABLE_PUSH: 1,
            S_MAX_CONCURRENT_STREAMS: 2**31 - 1,
            S_INITIAL_WINDOW_SIZE: 65535,
            S_MAX_FRAME_SIZE: 16384,
            S_MAX_HEADER_LIST_SIZE: 2**31 - 1,
        }
        self.my_settings = dict(client_settings or {
            S_HEADER_TABLE_SIZE: 4096,
            S_ENABLE_PUSH: 0,
            S_MAX_CONCURRENT_STREAMS: 100,
            S_INITIAL_WINDOW_SIZE: 65535,
            S_MAX_FRAME_SIZE: 16384,
        })
        self.conn_recv_window = 65535
        self.conn_send_window = 65535
        self.peer_max_frame = 16384
        self.goaway = None            # (last_stream_id, error_code)
        self.pings_acked = 0
        self._server_settings_seen = False

    # -- wire I/O ------------------------------------------------------------
    def _send(self, data: bytes):
        if self.sock is None:
            raise H2Error('no socket attached')
        self.sock.sendall(data)

    def send_frame(self, ftype, flags, stream, payload=b''):
        self._send(Frame(ftype, flags, stream, payload).encode())

    def _recv_exact(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('socket closed')
            buf += chunk
        return buf

    def recv_frame(self) -> Frame:
        hdr = self._recv_exact(9)
        length = int.from_bytes(hdr[0:3], 'big')
        # our SETTINGS_MAX_FRAME_SIZE constrains what the peer may send us
        if length > self.my_settings[S_MAX_FRAME_SIZE]:
            raise H2Error('frame larger than our max frame size')
        payload = self._recv_exact(length) if length else b''
        return Frame(hdr[3], hdr[4], int.from_bytes(hdr[5:9], 'big'), payload)

    def inject(self, data: bytes):
        """Feed raw bytes (tests / captured sessions); dispatches frames."""
        for f in self.reader.feed(data):
            self._dispatch(f)

    # -- handshake -----------------------------------------------------------
    def send_preface(self, ack_server_settings=True):
        self._send(PREFACE)
        self.send_frame(T_SETTINGS, 0, 0, build_settings(self.my_settings))
        # raise our connection-level receive window proactively
        self.send_frame(T_WINDOW_UPDATE, 0, 0, (2**20).to_bytes(4, 'big'))
        self.conn_recv_window += 2**20

    def _get_stream(self, sid: int) -> Stream:
        st = self.streams.get(sid)
        if st is None:
            raise H2StreamError('frame for unknown stream %d' % sid)
        return st

    # -- frame dispatch ------------------------------------------------------
    def _dispatch(self, f: Frame):
        t = f.type
        if t == T_DATA:
            self._on_data(f)
        elif t == T_HEADERS:
            self._on_headers(f)
        elif t == T_PRIORITY:
            pass  # deprecated by RFC 9218; ignore
        elif t == T_RST_STREAM:
            self._on_rst(f)
        elif t == T_SETTINGS:
            self._on_settings(f)
        elif t == T_PUSH_PROMISE:
            raise H2Error('PUSH_PROMISE received with push disabled')
        elif t == T_PING:
            self._on_ping(f)
        elif t == T_GOAWAY:
            self._on_goaway(f)
        elif t == T_WINDOW_UPDATE:
            self._on_window_update(f)
        elif t == T_CONTINUATION:
            self._on_continuation(f)
        else:
            pass  # unknown frame types MUST be ignored (RFC 7540 5.5)

    def _check_stream_frame(self, f: Frame, what: str):
        if f.stream == 0:
            raise H2Error('%s on stream 0' % what)

    def _on_data(self, f: Frame):
        self._check_stream_frame(f, 'DATA')
        n = len(f.payload)
        pad = 0
        payload = f.payload
        if f.flags & F_PADDED:
            if not payload:
                raise H2Error('PADDED DATA with empty payload')
            pad = payload[0]
            payload = payload[1:]
            if pad >= len(payload):
                raise H2Error('bad DATA padding')
            payload = payload[:len(payload) - pad]
            n = len(f.payload)  # flow control counts the wire length incl pad
        st = self._get_stream(f.stream)
        if st.state not in ('open', 'half-closed-local'):
            raise H2StreamError('DATA on closed stream %d' % f.stream)
        self.conn_recv_window -= n
        st.recv_window -= n
        if self.conn_recv_window < 0 or st.recv_window < 0:
            raise H2Error('flow-control window exceeded')
        st.data += payload
        # top up windows (simple, correct; slightly chatty)
        if st.recv_window <= 32768:
            inc = 65535 - st.recv_window
            self.send_frame(T_WINDOW_UPDATE, 0, st.id, inc.to_bytes(4, 'big'))
            st.recv_window += inc
        if self.conn_recv_window <= 32768:
            inc = 65535 - self.conn_recv_window
            self.send_frame(T_WINDOW_UPDATE, 0, 0, inc.to_bytes(4, 'big'))
            self.conn_recv_window += inc
        if f.flags & F_END_STREAM:
            st.state = 'half-closed-remote' if st.state == 'open' else 'closed'

    def _header_block(self, st: Stream, first: bytes):
        st._header_frag = bytearray(first)

    def _end_header_block(self, st: Stream, flags: int, is_trailer: bool):
        try:
            fields = self.decoder.decode(bytes(st._header_frag))
        except HPACK.HPACKError as e:
            raise H2Error('HPACK compression error: %s' % e)
        st._header_frag = None
        if is_trailer:
            st.trailers = fields
        else:
            st.headers = fields
        if flags & F_END_STREAM:
            st.state = 'half-closed-remote' if st.state == 'open' else 'closed'
        elif st.state == 'idle':
            st.state = 'open'

    def _on_headers(self, f: Frame):
        self._check_stream_frame(f, 'HEADERS')
        st = self._get_stream(f.stream)
        payload = f.payload
        if f.flags & F_PADDED:
            if not payload:
                raise H2Error('PADDED HEADERS with empty payload')
            pad = payload[0]
            payload = payload[1:len(payload) - pad] if pad else payload[1:]
        if f.flags & F_PRIORITY:
            if len(payload) < 5:
                raise H2Error('HEADERS PRIORITY too short')
            payload = payload[5:]
        is_trailer = st.state in ('open', 'half-closed-local') and st.headers
        self._header_block(st, payload)
        if f.flags & F_END_HEADERS:
            self._end_header_block(st, f.flags, is_trailer)
        else:
            st._pending_flags = (f.flags, is_trailer)

    def _on_continuation(self, f: Frame):
        self._check_stream_frame(f, 'CONTINUATION')
        st = self._get_stream(f.stream)
        if st._header_frag is None:
            raise H2Error('CONTINUATION without HEADERS')
        st._header_frag += f.payload
        if f.flags & F_END_HEADERS:
            flags, is_trailer = st._pending_flags
            # END_STREAM lives on the HEADERS frame (carried in flags);
            # honor it on CONTINUATION too if a peer sets it there.
            self._end_header_block(st, flags, is_trailer)
            if f.flags & F_END_STREAM:
                st.state = 'half-closed-remote' if st.state == 'open' else 'closed'

    def _on_rst(self, f: Frame):
        self._check_stream_frame(f, 'RST_STREAM')
        if len(f.payload) != 4:
            raise H2Error('RST_STREAM length != 4')
        st = self._get_stream(f.stream)
        st.reset_code = int.from_bytes(f.payload, 'big')
        st.state = 'closed'

    def _on_settings(self, f: Frame):
        if f.stream != 0:
            raise H2Error('SETTINGS on non-zero stream')
        if f.flags & F_ACK:
            if f.payload:
                raise H2Error('SETTINGS ACK with payload')
            return
        if len(f.payload) % 6:
            raise H2Error('bad SETTINGS length')
        params = parse_settings(f.payload)
        if S_ENABLE_PUSH in params and params[S_ENABLE_PUSH] not in (0, 1):
            raise H2Error('bad ENABLE_PUSH')
        if S_INITIAL_WINDOW_SIZE in params and params[S_INITIAL_WINDOW_SIZE] > 2**31 - 1:
            raise H2Error('bad INITIAL_WINDOW_SIZE')
        if S_MAX_FRAME_SIZE in params and not 16384 <= params[S_MAX_FRAME_SIZE] <= 16777215:
            raise H2Error('bad MAX_FRAME_SIZE')
        old_init = self.peer_settings[S_INITIAL_WINDOW_SIZE]
        for pid, val in params.items():
            self.peer_settings[pid] = val
        # RFC 7540 6.9.2: adjust every stream's send window by the delta
        if S_INITIAL_WINDOW_SIZE in params:
            delta = params[S_INITIAL_WINDOW_SIZE] - old_init
            for st in self.streams.values():
                st.send_window += delta
        if S_HEADER_TABLE_SIZE in params:
            self.decoder.set_max_allowed(params[S_HEADER_TABLE_SIZE])
        self.peer_max_frame = self.peer_settings[S_MAX_FRAME_SIZE]
        self._server_settings_seen = True
        self.send_frame(T_SETTINGS, F_ACK, 0)

    def _on_ping(self, f: Frame):
        if f.stream != 0:
            raise H2Error('PING on non-zero stream')
        if len(f.payload) != 8:
            raise H2Error('PING length != 8')
        if f.flags & F_ACK:
            self.pings_acked += 1
        else:
            self.send_frame(T_PING, F_ACK, 0, f.payload)

    def _on_goaway(self, f: Frame):
        if f.stream != 0:
            raise H2Error('GOAWAY on non-zero stream')
        if len(f.payload) < 8:
            raise H2Error('GOAWAY too short')
        last = int.from_bytes(f.payload[0:4], 'big') & 0x7fffffff
        code = int.from_bytes(f.payload[4:8], 'big')
        self.goaway = (last, code)

    def _on_window_update(self, f: Frame):
        if len(f.payload) != 4:
            raise H2Error('WINDOW_UPDATE length != 4')
        inc = int.from_bytes(f.payload, 'big') & 0x7fffffff
        if inc == 0:
            raise H2Error('WINDOW_UPDATE with zero increment')
        if f.stream == 0:
            self.conn_send_window += inc
            if self.conn_send_window > 2**31 - 1:
                raise H2Error('connection window overflow')
        else:
            st = self._get_stream(f.stream)
            st.send_window += inc
            if st.send_window > 2**31 - 1:
                raise H2Error('stream window overflow')

    # -- client requests -------------------------------------------------------
    def _new_stream_id(self) -> int:
        if self.goaway is not None:
            raise H2Error('GOAWAY received; no new streams')
        sid = self.next_stream_id
        self.next_stream_id += 2
        return sid

    def send_headers(self, sid: int, headers, end_stream: bool = True):
        block = self.encoder.encode(headers)
        flags = F_END_HEADERS
        if end_stream:
            flags |= F_END_STREAM
        # fragment to the peer's max frame size
        chunks = [block[i:i + self.peer_max_frame]
                  for i in range(0, len(block), self.peer_max_frame)] or [b'']
        self.send_frame(T_HEADERS, flags if len(chunks) == 1 else 0, sid, chunks[0])
        for ch in chunks[1:-1]:
            self.send_frame(T_CONTINUATION, 0, sid, ch)
        if len(chunks) > 1:
            self.send_frame(T_CONTINUATION, F_END_HEADERS, sid, chunks[-1])
        st = self.streams[sid]
        st.state = 'half-closed-local' if end_stream else 'open'

    def request_start(self, authority: str, path: str, scheme: str = 'https',
                      extra: list | None = None) -> int:
        """Send a GET request's HEADERS; returns the stream id."""
        sid = self._new_stream_id()
        self.streams[sid] = Stream(sid, self.peer_settings[S_INITIAL_WINDOW_SIZE])
        headers = [(b':method', b'GET'), (b':scheme', scheme.encode()),
                   (b':authority', authority.encode()), (b':path', path.encode())]
        for k, v in (extra or []):
            headers.append((k.encode() if isinstance(k, str) else k,
                            v.encode() if isinstance(v, str) else v))
        self.send_headers(sid, headers, end_stream=True)
        return sid

    def pump_until(self, sid: int, timeout: float = 20.0):
        """Read frames until stream `sid` completes; returns the Stream."""
        if self.sock is None:
            raise H2Error('no socket attached')
        import time
        st = self._get_stream(sid)
        deadline = time.time() + timeout
        while not st.complete and not st.end_stream:
            if time.time() > deadline:
                raise TimeoutError('stream %d did not complete' % sid)
            self._dispatch(self.recv_frame())
        if st.reset_code is not None:
            raise H2StreamError('stream %d reset by peer: 0x%x' % (sid, st.reset_code))
        return st

    def get(self, authority: str, path: str, scheme: str = 'https',
            extra: list | None = None, timeout: float = 20.0):
        """One-shot GET: returns (status:int, headers:list, body:bytes)."""
        sid = self.request_start(authority, path, scheme, extra)
        st = self.pump_until(sid, timeout)
        if st.reset_code is not None:
            raise H2StreamError('stream reset by peer: %d' % st.reset_code)
        status = 0
        for n, v in st.headers:
            if n == b':status':
                status = int(v)
        return status, st.headers, bytes(st.data)

    def ping(self, opaque: bytes = b'12345678') -> bool:
        self.send_frame(T_PING, 0, 0, opaque)
        import time
        deadline = time.time() + 10
        before = self.pings_acked
        while self.pings_acked == before and time.time() < deadline:
            self._dispatch(self.recv_frame())
        return self.pings_acked > before
