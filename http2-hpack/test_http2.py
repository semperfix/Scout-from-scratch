#!/usr/bin/env python3
"""Validation suite for the from-scratch HTTP/2 + HPACK implementation.
Numbered checks; prints n/n and exits nonzero on failure."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hpack
from hpack import HPACKError
import http2
from http2 import (H2Connection, Frame, FrameReader, PREFACE, build_settings,
                   parse_settings, H2Error, H2StreamError, T_DATA, T_HEADERS,
                   T_SETTINGS, T_PING, T_GOAWAY, T_RST_STREAM, T_WINDOW_UPDATE,
                   T_CONTINUATION, F_ACK)

PASS, TOTAL = [], [0]


def check(name, cond):
    TOTAL[0] += 1
    PASS.append(bool(cond))
    print(('PASS' if cond else 'FAIL'), '-', name)
    if not cond:
        import traceback
        traceback.print_stack(limit=3)


def hx(s):
    return bytes.fromhex(s.replace(' ', ''))

# ---------------------------------------------------------------- HPACK ---
# 1. integer codec (RFC 7541 C.1)
check('int: C.1.2 1337/5 -> 1f9a0a',
      hpack.encode_int(1337, 5) == hx('1f9a0a'))
check('int: C.1.1 10/5 -> 0a', hpack.encode_int(10, 5) == b'\x0a')
check('int: C.1.3 42/8 -> 2a', hpack.encode_int(42, 8) == b'\x2a')
ok = True
for v, p in [(0, 5), (30, 5), (31, 5), (32, 5), (127, 7), (128, 7), (255, 8),
             (16383, 8), (1 << 20, 5), (2**32 - 1, 5)]:
    if hpack.decode_int(hpack.encode_int(v, p), 0, p) != (v, len(hpack.encode_int(v, p))):
        ok = False
check('int: roundtrip incl. prefix boundaries', ok)

# 2. Huffman table structure
from fractions import Fraction
kraft = sum(Fraction(1, 1 << n) for _, (_, n) in hpack.HUFFMAN_TABLE.items())
check('huffman: 257 entries', len(hpack.HUFFMAN_TABLE) == 257)
check('huffman: Kraft sum == 1 (complete prefix code)', kraft == 1)
items = sorted(((n, s, c) for s, (c, n) in hpack.HUFFMAN_TABLE.items()))
viol = 0
pn, pc = None, None
for n, s, c in items:
    if pn is not None:
        if c != (pc + 1 if n == pn else (pc + 1) << (n - pn)):
            viol += 1
    pn, pc = n, c
check('huffman: canonical sequentiality, 0 violations', viol == 0)
check('huffman: EOS is 30 one-bits', hpack.HUFFMAN_TABLE[256] == (0x3fffffff, 30))

# 3. Huffman codec
check('huffman: C.4.1 www.example.com byte-exact',
      hpack.huffman_encode(b'www.example.com') == hx('f1e3c2e5f23a6ba0ab90f4ff'))
check('huffman: C.6.1 302 -> 6402',
      hpack.huffman_encode(b'302') == hx('6402'))
check('huffman: C.6.3 gzip -> 9bd9ab',
      hpack.huffman_encode(b'gzip') == hx('9bd9ab'))
ok = all(hpack.huffman_decode(hpack.huffman_encode(bytes([b]))) == bytes([b])
         for b in range(256))
check('huffman: roundtrip all 256 symbols', ok)
try:
    hpack.huffman_decode(bytes([0x1e]))  # 00011|110 -> pad bit 0
    ok = False
except HPACKError:
    ok = True
check('huffman: non-one padding rejected', ok)
try:
    hpack.huffman_decode(b'\xff\xff\xff\xff')  # 32 ones -> EOS decoded
    ok = False
except HPACKError:
    ok = True
check('huffman: EOS mid-string rejected', ok)
try:
    hpack.huffman_decode(bytes([0x1f, 0xff]))  # 'a' + 8 one-bits pad
    ok = False
except HPACKError:
    ok = True
check('huffman: >7-bit padding rejected', ok)

# 4. static table
check('static: 61 entries', len(hpack.STATIC_TABLE) == 62)
check('static: idx2=(:method,GET) idx8=(:status,200) idx61=www-authenticate',
      hpack.STATIC_TABLE[2] == (b':method', b'GET')
      and hpack.STATIC_TABLE[8] == (b':status', b'200')
      and hpack.STATIC_TABLE[61] == (b'www-authenticate', b''))

# 5. RFC C.2 representation examples
d = hpack.Decoder()
check('C.2.1 literal indexed', d.decode(hx('400a637573746f6d2d6b65790d637573746f6d2d686561646572'))
      == [(b'custom-key', b'custom-header')] and d.table.size == 55)
d = hpack.Decoder()
check('C.2.2 literal no-index', d.decode(hx('040c2f73616d706c652f70617468'))
      == [(b':path', b'/sample/path')] and d.table.size == 0)
d = hpack.Decoder()
check('C.2.3 literal never-indexed', d.decode(hx('100870617373776f726406736563726574'))
      == [(b'password', b'secret')] and d.table.size == 0)
check('C.2.4 indexed', hpack.Decoder().decode(hx('82')) == [(b':method', b'GET')])

# 6. RFC C.3 request sequence without Huffman (dynamic table evolution)
d = hpack.Decoder()
h1 = d.decode(hx('828684410f7777772e6578616d706c652e636f6d'))
check('C.3.1 decodes', [x[0] for x in h1] == [b':method', b':scheme', b':path', b':authority']
      and h1[3][1] == b'www.example.com')
check('C.3.1 table: [:authority] size 57',
      [(n, v) for n, v in d.table.entries] == [(b':authority', b'www.example.com')]
      and d.table.size == 57)
h2 = d.decode(hx('828684be58086e6f2d6361636865'))
check('C.3.2 decodes + idx62 dynamic ref',
      h2[3] == (b':authority', b'www.example.com') and h2[4] == (b'cache-control', b'no-cache'))
check('C.3.2 table: [cc:no-cache, :authority] size 110',
      [n for n, v in d.table.entries] == [b'cache-control', b':authority'] and d.table.size == 110)
h3 = d.decode(hx('828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565'))
check('C.3.3 decodes', h3[1] == (b':scheme', b'https') and h3[2] == (b':path', b'/index.html')
      and h3[4] == (b'custom-key', b'custom-value'))
check('C.3.3 table size 164', d.table.size == 164
      and [n for n, v in d.table.entries] == [b'custom-key', b'cache-control', b':authority'])

# 7. RFC C.4 with Huffman -> same headers
d = hpack.Decoder()
check('C.4.1 == C.3.1 headers',
      d.decode(hx('828684418cf1e3c2e5f23a6ba0ab90f4ff')) == h1)
check('C.4.2 == C.3.2 headers',
      d.decode(hx('828684be5886a8eb10649cbf')) == h2)
check('C.4.3 == C.3.3 headers',
      d.decode(hx('828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf')) == h3)

# 8. RFC C.5 responses with table size 256 (evictions)
d = hpack.Decoder(max_size=256, max_allowed=256)
r1 = d.decode(hx('4803333032580770726976617465611d4d6f6e2c203231204f63742032303133'
                 '2032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d'))
check('C.5.1 decodes', r1[0] == (b':status', b'302') and r1[3] == (b'location', b'https://www.example.com'))
check('C.5.1 table size 222', d.table.size == 222)
r2 = d.decode(hx('4803333037c1c0bf'))
check('C.5.2 decodes (307, evict 302)', r2[0] == (b':status', b'307')
      and r2[1] == (b'cache-control', b'private'))
check('C.5.2 table: 307 evicted 302', d.table.entries[0] == (b':status', b'307')
      and all(v != b'302' for _, v in d.table.entries))
r3 = d.decode(hx('88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54'
                 'c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f5049554158'
                 '5157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31'))
check('C.5.3 decodes', r3[0] == (b':status', b'200') and r3[5][0] == b'set-cookie')
check('C.5.3 table: [set-cookie, content-encoding, date] size 215',
      [n for n, v in d.table.entries] == [b'set-cookie', b'content-encoding', b'date']
      and d.table.size == 215)

# 9. RFC C.6 with Huffman -> same headers
d = hpack.Decoder(max_size=256, max_allowed=256)
check('C.6.1 == C.5.1',
      d.decode(hx('488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1b'
                  'ff6e919d29ad171863c78f0b97c8e9ae82ae43d3')) == r1)
check('C.6.2 == C.5.2', d.decode(hx('4883640effc1c0bf')) == r2)
check('C.6.3 == C.5.3',
      d.decode(hx('88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab'
                  '77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f'
                  '9587316065c003ed4ee5b1063d5007')) == r3)

# 10. encoder behavior
e = hpack.Encoder()
b1 = e.encode([(b':method', b'GET'), (b':scheme', b'http'), (b':path', b'/'),
               (b':authority', b'www.example.com')])
b2 = e.encode([(b':method', b'GET'), (b':scheme', b'http'), (b':path', b'/'),
               (b':authority', b'www.example.com')])
check('encoder: 2nd block uses indexed refs (82 86 84 be)',
      b2[:4] == hx('828684be'))
check('encoder: roundtrip', hpack.Decoder().decode(b1) ==
      [(b':method', b'GET'), (b':scheme', b'http'), (b':path', b'/'),
       (b':authority', b'www.example.com')])
e = hpack.Encoder(use_huffman=False)
check('encoder: no-huffman C.3.1-shaped output starts 82 86 84 41',
      e.encode([(b':method', b'GET'), (b':scheme', b'http'), (b':path', b'/'),
                (b':authority', b'www.example.com')])[:4] == hx('82868441'))

# 11. never-indexed sensitive field
e = hpack.Encoder()
enc = e.encode([(b'authorization', b'secret')])
check('encoder: authorization never-indexed (0x1_ pattern)',
      enc[0] & 0xf0 == 0x10)
d = hpack.Decoder()
check('decoder: never-indexed not added to table',
      d.decode(enc) == [(b'authorization', b'secret')] and d.table.size == 0)

# 12. literal without indexing
e = hpack.Encoder()
enc = e.encode_noindex([(b'x-a', b'1')])
check('noindex: pattern 0x0_ and table untouched',
      enc[0] & 0xf0 == 0x00 and hpack.Decoder().decode(enc) == [(b'x-a', b'1')])

# 13. dynamic table eviction
t = hpack.DynamicTable(max_size=100)
t.insert(b'aa', b'11')   # 32+2+2=36
t.insert(b'bb', b'22')   # 36 -> 72
t.insert(b'cc', b'33')   # 36 -> 108 > 100, evict oldest (aa)
check('dyntab: FIFO eviction', [n for n, v in t.entries] == [b'cc', b'bb']
      and t.size == 72)
t.insert(b'big', b'x' * 200)  # larger than max -> table cleared
check('dyntab: oversize entry clears table', t.entries == [] and t.size == 0)

# 14. table size update
e = hpack.Encoder()
e.set_max_size(256)
blk = e.encode([(b':status', b'200')])
check('encoder: size update emitted first (3f e1 01)',
      blk[:3] == hx('3fe101'))
d = hpack.Decoder()
d.decode(blk)
check('decoder: size update applied', d.table.max_size == 256)
try:
    hpack.Decoder(max_allowed=128).decode(hx('3fe101'))
    ok = False
except HPACKError:
    ok = True
check('decoder: size update above max_allowed rejected', ok)

# 15. decoder errors
for bad, name in [(hx('80'), 'index 0'), (hx('ff9a0a'), 'index out of range'),
                  (hx('41'), 'truncated literal'), (hx(''), 'empty ok')]:
    try:
        r = hpack.Decoder().decode(bad)
        ok = (name == 'empty ok' and r == [])
    except HPACKError:
        ok = name != 'empty ok'
    check('decoder error: ' + name, ok)
try:
    hpack.Decoder(max_list_size=10).decode(hx('400a637573746f6d2d6b65790d637573746f6d2d686561646572'))
    ok = False
except HPACKError:
    ok = True
check('decoder: header list size limit enforced', ok)

# 16. encoder/decoder roundtrip fuzz (self-consistent)
import random
random.seed(7)
names = [b':method', b':path', b':authority', b'cookie', b'x-n-%d', b'etag']
vals = [b'GET', b'/', b'h', b'v-%d', b'"xyz"']
ok = True
for _ in range(100):
    hdrs = []
    for _ in range(random.randint(1, 6)):
        n = random.choice(names); v = random.choice(vals)
        n = n % random.randrange(9) if b'%d' in n else n
        v = v % random.randrange(9) if b'%d' in v else v
        hdrs.append((n, v))
    e, d = hpack.Encoder(), hpack.Decoder()
    if d.decode(e.encode(hdrs)) != hdrs:
        ok = False
check('codec: 100 random roundtrips', ok)

# ------------------------------------------------------------- HTTP/2 ---
# 17. frame encode/decode roundtrip, all types + R-bit masking
ok = True
for t in range(10):
    f = Frame(t, 0xab, 0x80000001 | 5, b'payload-%d' % t)
    raw = f.encode()
    fr = FrameReader()
    g = fr.feed(raw)
    if not (len(g) == 1 and g[0].type == t and g[0].flags == 0xab
            and g[0].stream == 5 and g[0].payload == b'payload-%d' % t):
        ok = False
check('frames: roundtrip all 10 types, R-bit masked', ok)
fr = FrameReader()
check('frames: incremental split delivery',
      fr.feed(Frame(T_DATA, 0, 1, b'hi').encode()[:5]) == []
      and len(fr.feed(Frame(T_DATA, 0, 1, b'hi').encode()[5:])) == 1)

# 18. preface
check('preface: exact magic', PREFACE == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

# 19. settings build/parse
params = {1: 4096, 2: 0, 3: 100, 4: 65535, 5: 16384}
check('settings: build/parse roundtrip', parse_settings(build_settings(params)) == params)


class FakeSock:
    """Synchronous in-memory socket stand-in."""
    def __init__(self):
        self.sent = bytearray()
        self.incoming = bytearray()

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if not self.incoming:
            raise ConnectionError('no more server bytes')
        out, self.incoming = self.incoming[:n], self.incoming[n:]
        return bytes(out)


def server_bytes(*frames):
    return b''.join(f.encode() for f in frames)


def fresh_conn():
    return H2Connection(sock=FakeSock())


# 20. client preface + SETTINGS ack + PING
c = fresh_conn()
c.send_preface()
sent = bytes(c.sock.sent)
check('client: preface then SETTINGS frame',
      sent.startswith(PREFACE) and sent[len(PREFACE) + 3:len(PREFACE) + 5] == b'\x04\x00'
      and parse_settings(sent[len(PREFACE) + 9:len(PREFACE) + 9 + 30])[2] == 0)
# server: SETTINGS + PING
c.sock.incoming += server_bytes(
    Frame(T_SETTINGS, 0, 0, build_settings({1: 1024, 4: 32768})),
    Frame(T_PING, 0, 0, b'abcdefgh'))
c._dispatch(c.recv_frame())
c._dispatch(c.recv_frame())
sent = bytes(c.sock.sent)
check('client: ACKs server SETTINGS (empty, ACK flag)',
      Frame(T_SETTINGS, 0x1, 0, b'').encode() in sent)
check('client: PING ACK echoes opaque data',
      Frame(T_PING, 0x1, 0, b'abcdefgh').encode() in sent)
check('client: peer settings applied', c.peer_settings[1] == 1024
      and c.peer_settings[4] == 32768 and c.decoder.table.max_allowed == 1024)

# 21. simple GET response
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200'), (b'content-type', b'text/plain')])
c.sock.incoming += server_bytes(Frame(T_SETTINGS, 0, 0, b''))
c._dispatch(c.recv_frame())
sid = c.request_start('x.test', '/')
c.sock.incoming += server_bytes(
    Frame(T_HEADERS, 0x4, sid, block),
    Frame(T_DATA, 0x1, sid, b'hello world'))
st = c.pump_until(sid)
check('GET: status/headers/body', st.headers[0] == (b':status', b'200')
      and bytes(st.data) == b'hello world' and st.end_stream)

# 22. CONTINUATION reassembly
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200')] + [(b'x-h-%d' % i, b'v' * 40) for i in range(30)])
sid = c.request_start('x.test', '/big')
c.sock.incoming += server_bytes(
    Frame(T_HEADERS, 0x0, sid, block[:100]),
    Frame(T_CONTINUATION, 0x0, sid, block[100:300]),
    Frame(T_CONTINUATION, 0x4, sid, block[300:]),
    Frame(T_DATA, 0x1, sid, b'done'))
st = c.pump_until(sid)
check('CONTINUATION: fragmented header block reassembled',
      len(st.headers) == 31 and bytes(st.data) == b'done')

# 23. flow control accounting
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200')])
sid = c.request_start('x.test', '/big')
c.sock.incoming += server_bytes(Frame(T_HEADERS, 0x4, sid, block))
for i in range(3):
    c.sock.incoming += Frame(T_DATA, 0x0, sid, b'z' * 16384).encode()
c.sock.incoming += Frame(T_DATA, 0x1, sid, b'z' * 1000).encode()
st = c.pump_until(sid)
sent = bytes(c.sock.sent)
n_wu_stream = sent.count(Frame(T_WINDOW_UPDATE, 0, sid, (0).to_bytes(4, 'big')).encode()[:9])
check('flow: 50152-byte body reassembled', len(st.data) == 3 * 16384 + 1000)
check('flow: WINDOW_UPDATEs emitted (stream+conn)',
      b'\x00\x00\x04\x08\x00' in sent and n_wu_stream >= 1)
# exact increment math: 16384 + 16384 + 7232 = 40000 bytes in legal frames
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200')])
sid = c.request_start('x.test', '/exact')
c.sock.incoming += server_bytes(
    Frame(T_HEADERS, 0x4, sid, block),
    Frame(T_DATA, 0x0, sid, b'q' * 16384),
    Frame(T_DATA, 0x0, sid, b'q' * 16384),
    Frame(T_DATA, 0x1, sid, b'q' * 7232))
st = c.pump_until(sid)
sent = bytes(c.sock.sent)
# stream window: 65535 -> 49151 -> 32767 (top-up +32768) -> 49151... wait:
# 65535-16384=49151; -16384=32767 <=32768 -> WU(32768) -> 65535; -7232=58303
wu_stream = Frame(T_WINDOW_UPDATE, 0, sid, (32768).to_bytes(4, 'big')).encode()
check('flow: exact stream WINDOW_UPDATE increment (32768)',
      wu_stream in sent and c.streams[sid].recv_window == 58303
      and c.conn_recv_window == 65535 + 2**20 - 40000
      and len(st.data) == 40000)

# 24. RST_STREAM
c = fresh_conn()
c.send_preface()
sid = c.request_start('x.test', '/')
c.sock.incoming += server_bytes(Frame(T_RST_STREAM, 0, sid, (0x8).to_bytes(4, 'big')))
c._dispatch(c.recv_frame())
try:
    c.pump_until(sid)
    ok = False
except H2StreamError:
    ok = True
check('RST_STREAM: stream error surfaces', ok and c.streams[sid].reset_code == 0x8)

# 25. GOAWAY blocks new streams
c = fresh_conn()
c.send_preface()
c.sock.incoming += server_bytes(Frame(T_GOAWAY, 0, 0, (0).to_bytes(4, 'big') * 2))
c._dispatch(c.recv_frame())
try:
    c.request_start('x.test', '/')
    ok = False
except H2Error:
    ok = True
check('GOAWAY: new streams refused', ok and c.goaway == (0, 0))

# 26-27. protocol errors
c = fresh_conn()
c.send_preface()
for bad, name in [
        (Frame(T_WINDOW_UPDATE, 0, 0, (0).to_bytes(4, 'big')), 'zero WINDOW_UPDATE increment'),
        (Frame(T_DATA, 0, 0, b'x'), 'DATA on stream 0'),
        (Frame(T_SETTINGS, 0, 1, b''), 'SETTINGS on stream 1'),
        (Frame(T_PING, 0, 0, b'short'), 'PING length != 8'),
        (Frame(T_CONTINUATION, 0x4, 99, b'x'), 'CONTINUATION without HEADERS')]:
    c.sock.incoming += bad.encode()
    try:
        c._dispatch(c.recv_frame())
        ok = False
    except (H2Error, H2StreamError, KeyError):
        ok = True
    check('protocol error: ' + name, ok)

# 28. trailers
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
h1, h2b = enc.encode([(b':status', b'200')]), enc.encode([(b'grpc-status', b'0')])
sid = c.request_start('x.test', '/')
c.sock.incoming += server_bytes(
    Frame(T_HEADERS, 0x4, sid, h1),
    Frame(T_DATA, 0x0, sid, b'body'),
    Frame(T_HEADERS, 0x4 | 0x1, sid, h2b))
st = c.pump_until(sid)
check('trailers: captured separately', st.trailers == [(b'grpc-status', b'0')]
      and bytes(st.data) == b'body')

# 29. padded DATA
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200')])
sid = c.request_start('x.test', '/')
pad_payload = bytes([5]) + b'hello' + b'\x00' * 5
c.sock.incoming += server_bytes(
    Frame(T_HEADERS, 0x4, sid, block),
    Frame(T_DATA, 0x8 | 0x1, sid, pad_payload))
st = c.pump_until(sid)
check('PADDED DATA: padding stripped', bytes(st.data) == b'hello')

# 30. unknown frame type ignored
c = fresh_conn()
c.send_preface()
c.sock.incoming += Frame(99, 0, 0, b'???').encode()
try:
    c._dispatch(c.recv_frame())
    ok = True
except Exception:
    ok = False
check('unknown frame type ignored', ok)

# 31. INITIAL_WINDOW_SIZE change adjusts stream windows
c = fresh_conn()
c.send_preface()
sid = c.request_start('x.test', '/')
before = c.streams[sid].send_window
c.sock.incoming += server_bytes(
    Frame(T_SETTINGS, 0, 0, build_settings({4: 131070})))
c._dispatch(c.recv_frame())
check('SETTINGS INITIAL_WINDOW_SIZE: stream window adjusted by delta',
      c.streams[sid].send_window == before + (131070 - 65535))

# 32. HEADERS with PADDED|PRIORITY flags
c = fresh_conn()
c.send_preface()
enc = hpack.Encoder()
block = enc.encode([(b':status', b'200')])
sid = c.request_start('x.test', '/')
payload = bytes([3]) + b'\x00' * 5 + block + b'\x00' * 3  # padlen + priority + block + pad
c.sock.incoming += server_bytes(Frame(T_HEADERS, 0x4 | 0x8 | 0x20, sid, payload))
c._dispatch(c.recv_frame())
check('HEADERS PADDED|PRIORITY: parsed', c.streams[sid].headers == [(b':status', b'200')])

# 33. client fragments large header blocks at peer max frame size
c = fresh_conn()
c.send_preface()
c.peer_settings[5] = 100
c.peer_max_frame = 100
sid = c._new_stream_id()
c.streams[sid] = http2.Stream(sid, 65535)
big = [(b'x-k-%d' % i, b'v' * 50) for i in range(20)]
c.send_headers(sid, big)
sent = bytes(c.sock.sent)
n_hdr = sent.count(b'\x00\x00\x64\x01')  # len=100 HEADERS frames
n_cont = sent.count(b'\x09')  # crude; verify via parse instead
fr = FrameReader()
frames = fr.feed(sent[len(PREFACE):])
types = [f.type for f in frames if f.type in (1, 9)]
check('client: header block fragmented into HEADERS+CONTINUATIONs',
      types[0] == 1 and set(types[1:]) == {9} and len(types) > 2
      and frames[0].flags & 0x4 == 0 and frames[-1].flags & 0x4 != 0)

# ------------------------------------------------------------------ report ---
n = len(PASS)
okc = sum(PASS)
print('\n%d/%d checks passed' % (okc, n))
sys.exit(0 if okc == n else 1)
