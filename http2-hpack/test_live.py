#!/usr/bin/env python3
"""Live validation: real HTTP/2 over the hand-rolled TLS 1.3 stack
against nghttp2.org (the reference implementation's server)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2tls
import http2

PASS, TOTAL = [], [0]


def check(name, cond):
    TOTAL[0] += 1
    PASS.append(bool(cond))
    print(('PASS' if cond else 'FAIL'), '-', name)


HOST = 'nghttp2.org'

# L1: ALPN negotiates h2
conn, info = h2tls.connect_h2(HOST)
check('L1: ALPN negotiated h2', info['alpn'] == b'h2')
print('     cert CN=%r suite=0x%04x' % (info['cn'], info['suite']))

# L2: GET / byte-identical to curl
ref = subprocess.run(['curl', '-s', '--http2', 'https://%s/' % HOST],
                     capture_output=True, timeout=60).stdout
status, headers, body = conn.get(HOST, '/')
check('L2: GET / -> 200', status == 200)
check('L2: body byte-identical to curl (%d bytes)' % len(ref), body == ref)
ctype = next((v for n, v in headers if n == b'content-type'), b'')
print('     content-type:', ctype.decode('latin-1'),
      '| server:', next((v.decode('latin-1') for n, v in headers if n == b'server'), '?'))

# L3: multiplexing - two concurrent streams, one connection
# (L2 already consumed stream 1, so these are 3 and 5)
s1 = conn.request_start(HOST, '/')
s2 = conn.request_start(HOST, '/httpbin/get')
st1 = conn.pump_until(s1)
st2 = conn.pump_until(s2)
b1, b2 = bytes(st1.data), bytes(st2.data)
check('L3: stream ids are client-initiated odd (3,5)', s1 == 3 and s2 == 5)
check('L3: stream 3 complete (%d bytes)' % len(b1), st1.end_stream and len(b1) > 1000)
# /httpbin/get echoes request headers, so compare structure not bytes
import json
j2 = json.loads(b2)
check('L3: stream 5 complete, JSON intact on the right stream',
      st2.end_stream and j2.get('url') == 'https://nghttp2.org/httpbin/get')

# L4: dynamic table - :authority must be an indexed ref on repeat requests
# fresh connection: capture raw HEADERS bytes of request 1 and 2
conn2, _ = h2tls.connect_h2(HOST)
sent_log = []
orig_send = conn2.send_frame
def spy(ftype, flags, stream, payload=b''):
    if ftype == http2.T_HEADERS:
        sent_log.append(bytes(payload))
    return orig_send(ftype, flags, stream, payload)
conn2.send_frame = spy
conn2.get(HOST, '/')
conn2.get(HOST, '/')
first, second = sent_log
check('L4: 1st request literal :authority (0x41 present)', b'\x41' in first)
check('L4: 2nd request fully indexed (82 87 be 84)',
      second[:4] == bytes.fromhex('8287be84'))
print('     1st head:', first[:8].hex(), '| 2nd head:', second[:8].hex())

# L5: PING roundtrip
check('L5: PING/PONG roundtrip', conn.ping(b'\xde\xad\xbe\xef\x00\x11\x22\x33'))

# L6: server SETTINGS were parsed (header table size etc.)
check('L6: peer SETTINGS seen (max frame size sane)',
      16384 <= conn.peer_settings[http2.S_MAX_FRAME_SIZE] <= 16777215)
print('     peer max_frame_size:', conn.peer_settings[http2.S_MAX_FRAME_SIZE],
      '| init window:', conn.peer_settings[http2.S_INITIAL_WINDOW_SIZE])

n = len(PASS)
print('\n%d/%d live checks passed' % (sum(PASS), n))
sys.exit(0 if sum(PASS) == n else 1)
