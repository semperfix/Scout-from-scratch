#!/usr/bin/env python3
"""h2fetch: HTTP/2 client and forensic frame dumper, from scratch.

Usage:
  h2fetch.py get <https-url> [-o outfile]     single GET over HTTP/2
  h2fetch.py multi <url>...                   concurrent GETs, multiplexed
  h2fetch.py frames <raw-bytes-file>          forensic dump of captured frames

The TLS layer is the hand-rolled #42 stack with ALPN(h2) negotiation;
every frame above it is parsed by http2.py and every header block by
hpack.py. No third-party HTTP code is involved.
"""
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2tls
import http2
import hpack


def _split(url):
    p = urlparse(url)
    assert p.scheme == 'https', 'only https supported'
    return p.hostname, p.path or '/', p


def cmd_get(url, outfile=None):
    host, path, _ = _split(url)
    conn, info = h2tls.connect_h2(host)
    print('ALPN:', info['alpn'], '| cert CN:', info['cn'],
          '| suite: 0x%04x' % info['suite'])
    status, headers, body = conn.get(host, path)
    print('status:', status)
    for n, v in headers:
        print('  %s: %s' % (n.decode('latin-1'), v.decode('latin-1')))
    print('body bytes:', len(body))
    if outfile:
        open(outfile, 'wb').write(body)
        print('saved to', outfile)
    return status, body


def cmd_multi(urls):
    by_host = {}
    for u in urls:
        host, path, _ = _split(u)
        by_host.setdefault(host, []).append((u, path))
    for host, items in by_host.items():
        conn, info = h2tls.connect_h2(host)
        print('== %s (ALPN %s)' % (host, info['alpn']))
        sids = [(u, conn.request_start(host, path)) for u, path in items]
        for u, sid in sids:
            st = conn.pump_until(sid)
            status = next(int(v) for n, v in st.headers if n == b':status')
            print('  [%d] %s -> %d, %d bytes' % (sid, u, status, len(st.data)))


def cmd_frames(path):
    """Forensic dump: parse raw captured bytes into frames, HPACK-decode
    any header blocks (e.g. bytes carved from a pcap with #16's carver)."""
    data = open(path, 'rb').read()
    # strip a client preface if present
    if data.startswith(http2.PREFACE):
        print('(client connection preface stripped)')
        data = data[len(http2.PREFACE):]
    dec = hpack.Decoder()
    rdr = http2.FrameReader()
    frag = {}
    for f in rdr.feed(data):
        line = '%-12s stream=%-5d flags=0x%02x len=%d' % (
            f.name, f.stream, f.flags, len(f.payload))
        if f.type == http2.T_SETTINGS and not f.flags & http2.F_ACK and f.stream == 0:
            try:
                params = http2.parse_settings(f.payload)
                line += ' ' + str({k: v for k, v in params.items()})
            except http2.H2Error as e:
                line += ' (parse error: %s)' % e
        elif f.type in (http2.T_HEADERS, http2.T_CONTINUATION):
            frag.setdefault(f.stream, bytearray())
            frag[f.stream] += f.payload
            if f.flags & http2.F_END_HEADERS:
                try:
                    hdrs = dec.decode(bytes(frag.pop(f.stream)))
                    line += '\n' + '\n'.join(
                        '      %s: %s' % (n.decode('latin-1'), v.decode('latin-1'))
                        for n, v in hdrs)
                except hpack.HPACKError as e:
                    line += ' (HPACK error: %s)' % e
        elif f.type == http2.T_DATA:
            line += ' %r...' % (f.payload[:32],)
        elif f.type == http2.T_GOAWAY and len(f.payload) >= 8:
            line += ' last=%d err=%d' % (
                int.from_bytes(f.payload[:4], 'big') & 0x7fffffff,
                int.from_bytes(f.payload[4:8], 'big'))
        elif f.type == http2.T_WINDOW_UPDATE and len(f.payload) == 4:
            line += ' increment=%d' % (int.from_bytes(f.payload, 'big') & 0x7fffffff)
        elif f.type == http2.T_RST_STREAM and len(f.payload) == 4:
            line += ' code=%d' % int.from_bytes(f.payload, 'big')
        print(line)
    if rdr.buf:
        print('(%d trailing bytes: incomplete frame)' % len(rdr.buf))


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == 'get' and len(argv) >= 3:
        out = None
        if '-o' in argv:
            out = argv[argv.index('-o') + 1]
        cmd_get(argv[2], out)
    elif cmd == 'multi' and len(argv) >= 3:
        cmd_multi(argv[2:])
    elif cmd == 'frames' and len(argv) >= 3:
        cmd_frames(argv[2])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
