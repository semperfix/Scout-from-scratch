#!/usr/bin/env python3
"""Pass 2: buckets -> per-prefix aggregates -> anomaly findings.

Phase A: sort each bucket, sweep into per-prefix aggregates, write .agg files.
Phase B: sweep each .agg file with the global tiny-prefix list (plen<8,
which can span buckets) and run detectors. RAM stays flat throughout.

Detectors:
  MOAS, BOGON_ORIGIN, DEAGG_ORIGIN_CHANGE, LONG_PATH, AS_SET, AS_TRANS_LEAK
"""
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from rib import V4REC, V6REC, NO_ORIGIN

LONG_PATH_THRESHOLD = 30

BOGON_RANGES = [
    (0, 0, 'AS0'),
    (23456, 23456, 'AS_TRANS'),
    (64512, 65534, 'private'),
    (65535, 65535, 'reserved'),
    (4200000000, 4294967294, 'private'),
    (4294967295, 4294967295, 'reserved'),
    (NO_ORIGIN, NO_ORIGIN, 'no-path'),
]


def bogon_label(asn):
    for lo, hi, label in BOGON_RANGES:
        if lo <= asn <= hi:
            return label
    return None


def fmt_prefix(addr, plen, v6):
    import ipaddress
    if v6:
        return f'{ipaddress.IPv6Address(addr)}/{plen}'
    return f'{ipaddress.IPv4Address(addr)}/{plen}'


def addr_int(a, v6):
    return int.from_bytes(a, 'big') if v6 else a


def broadcast_int(a, plen, v6):
    bits = 128 if v6 else 32
    if plen == 0:
        return (1 << bits) - 1
    return addr_int(a, v6) | ((1 << (bits - plen)) - 1)


def cove_rs(tiny_addr, tiny_plen, addr, v6):
    """Does tiny prefix (plen<8) cover addr? addr is bytes (4 or 16)."""
    abit = addr
    nbytes = (tiny_plen + 7) // 8
    if tiny_plen % 8:
        mask = 0xFF & (0xFF << (8 - tiny_plen % 8))
        return (abit[:nbytes - 1] == tiny_addr[:nbytes - 1] and
                (abit[nbytes - 1] & mask) == (tiny_addr[nbytes - 1] & mask))
    return abit[:nbytes] == tiny_addr[:nbytes]


# ---------------------------------------------------------------- phase A

class Agg:
    __slots__ = ('addr', 'plen', 'n', 'origins', 'peers', 'minlen', 'maxlen',
                 'has_set', 'has_trans', 'no_path')


def aggregate_bucket(path, v6, agg_path):
    """Sort bucket, collapse to per-prefix aggregates, write .agg text file.

    .agg line: v6|plen|addrhex|n|origins_csv|npeers|minlen|maxlen|hasset|hastrans|nopath
    Returns (stats, tiny_aggs) where tiny_aggs covers plen<8 prefixes.
    """
    rec = V6REC if v6 else V4REC
    size = rec.size
    raw = open(path, 'rb').read()
    n = len(raw) // size
    items = [None] * n
    for i in range(n):
        r = rec.unpack_from(raw, i * size)
        items[i] = (r[1], r[0], r[2], r[3], r[4], r[5])  # addr,plen,origin,pathlen,flags,peer
    del raw
    items.sort(key=lambda t: (t[0], t[1]))

    stats = {'prefixes': 0, 'entries': 0}
    tiny_aggs = []
    cur = None
    with open(agg_path, 'w') as out:
        def flush():
            nonlocal cur
            if cur is None:
                return
            stats['prefixes'] += 1
            stats['entries'] += cur.n
            origins = sorted(cur.origins)
            out.write('|'.join([
                '6' if v6 else '4', str(cur.plen),
                (cur.addr.hex() if v6 else '%08x' % cur.addr),
                str(cur.n), ','.join(map(str, origins)), str(len(cur.peers)),
                str(cur.minlen), str(cur.maxlen),
                '1' if cur.has_set else '0', '1' if cur.has_trans else '0',
                str(cur.no_path)]) + '\n')
            if cur.plen < 8:
                tiny_aggs.append({
                    'v6': v6, 'plen': cur.plen,
                    'addr': cur.addr if v6 else cur.addr.to_bytes(4, 'big'),
                    'origins': origins,
                    'prefix': fmt_prefix(cur.addr if v6 else cur.addr.to_bytes(4, 'big'),
                                         cur.plen, v6)})
            cur = None

        for addr, plen, origin, pathlen, flags, peer_as in items:
            if cur is None or cur.addr != addr or cur.plen != plen:
                flush()
                cur = Agg()
                cur.addr, cur.plen = addr, plen
                cur.n = 0
                cur.origins = set()
                cur.peers = set()
                cur.minlen, cur.maxlen = 255, 0
                cur.has_set = cur.has_trans = False
                cur.no_path = 0
            cur.n += 1
            cur.peers.add(peer_as)
            if origin == NO_ORIGIN:
                cur.no_path += 1
            else:
                cur.origins.add(origin)
            if pathlen < cur.minlen:
                cur.minlen = pathlen
            if pathlen > cur.maxlen:
                cur.maxlen = pathlen
            cur.has_set = cur.has_set or bool(flags & 1)
            cur.has_trans = cur.has_trans or bool(flags & 2)
        flush()
    return stats, tiny_aggs


# ---------------------------------------------------------------- phase B

def detect_bucket(agg_path, v6, tiny_global, out):
    """Sweep .agg file (already in (addr,plen) order), run detectors."""
    stats = {'moas': 0, 'bogon': 0, 'deagg': 0, 'long_path': 0,
             'as_set': 0, 'as_trans': 0}
    stack = []  # (broadcast, plen, origins, prefix_str)
    with open(agg_path) as f:
        for line in f:
            p = line.rstrip('\n').split('|')
            plen = int(p[1])
            addr = bytes.fromhex(p[2])
            asrc = addr if v6 else int.from_bytes(addr, 'big')
            n = int(p[3])
            origins = [int(x) for x in p[4].split(',')] if p[4] else []
            npeers = int(p[5])
            minlen, maxlen = int(p[6]), int(p[7])
            has_set, has_trans = p[8] == '1', p[9] == '1'
            aint = addr_int(asrc, v6)
            while stack and aint > stack[-1][0]:
                stack.pop()
            covering = None
            # Covering-prefix eligibility: 0.0.0.0/0 and ::/0 are default
            # routes (often leaked by many peers with many origins) and say
            # nothing about who holds an address block, so they can never be
            # covering prefixes. Other sub-/8 prefixes (cross-bucket) only
            # count when they have a single unambiguous origin.
            def _usable(plen, origins):
                if plen == 0:
                    return False
                if plen < 8 and len(origins) != 1:
                    return False
                return True
            if stack and stack[-1][1] < plen and \
                    _usable(stack[-1][1], stack[-1][2]):
                covering = (stack[-1][3], stack[-1][2])
            else:
                # cross-bucket tiny covering prefix?
                for t in tiny_global:
                    if t['v6'] == v6 and t['plen'] < plen and \
                            _usable(t['plen'], t['origins']) and \
                            cove_rs(t['addr'], t['plen'], addr, v6):
                        covering = (t['prefix'], t['origins'])
                        break
            pfx = fmt_prefix(addr, plen, v6)
            if len(origins) > 1:
                stats['moas'] += 1
                out.write(json.dumps({'kind': 'MOAS', 'prefix': pfx,
                                      'origins': origins, 'n_entries': n,
                                      'n_peers': npeers}) + '\n')
            for o in origins:
                label = bogon_label(o)
                if label:
                    stats['bogon'] += 1
                    out.write(json.dumps({'kind': 'BOGON_ORIGIN', 'prefix': pfx,
                                          'origin': o, 'label': label,
                                          'n_entries': n}) + '\n')
                    break
            if covering is not None and origins and covering[1]:
                if set(origins).isdisjoint(covering[1]):
                    stats['deagg'] += 1
                    out.write(json.dumps({
                        'kind': 'DEAGG_ORIGIN_CHANGE', 'prefix': pfx,
                        'origins': origins, 'covering': covering[0],
                        'covering_origins': covering[1],
                        'via_tiny': covering[0] not in
                        [s[3] for s in stack]}) + '\n')
            if maxlen >= LONG_PATH_THRESHOLD:
                stats['long_path'] += 1
                out.write(json.dumps({'kind': 'LONG_PATH', 'prefix': pfx,
                                      'origins': origins, 'maxlen': maxlen,
                                      'minlen': minlen}) + '\n')
            if has_set:
                stats['as_set'] += 1
                out.write(json.dumps({'kind': 'AS_SET', 'prefix': pfx,
                                      'origins': origins}) + '\n')
            if has_trans:
                stats['as_trans'] += 1
                out.write(json.dumps({'kind': 'AS_TRANS_LEAK', 'prefix': pfx,
                                      'origins': origins}) + '\n')
            stack.append((broadcast_int(asrc, plen, v6), plen, origins, pfx))
    return stats


def main():
    bucket_dir = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(_HERE, 'buckets')
    phase_a = not (len(sys.argv) > 2 and sys.argv[2] == 'phaseb')
    total = {}
    tiny_global = []
    agg_files = []
    files = sorted(f for f in os.listdir(bucket_dir) if f.endswith('.bin'))
    if phase_a:
        # phase A
        for i, fname in enumerate(files):
            v6 = fname.startswith('bv6_')
            bpath = os.path.join(bucket_dir, fname)
            apath = bpath[:-4] + '.agg'
            stats, tiny = aggregate_bucket(bpath, v6, apath)
            tiny_global.extend(tiny)
            agg_files.append((apath, v6))
            for k, v in stats.items():
                total[k] = total.get(k, 0) + v
            if (i + 1) % 64 == 0:
                print(f'  phase A: {i + 1}/{len(files)}', flush=True)
        print(f'tiny prefixes (plen<8): {len(tiny_global)}')
    else:
        # phase B only: reuse existing .agg files; rebuild tiny list from them
        import glob as _glob
        for apath in sorted(_glob.glob(os.path.join(bucket_dir, '*.agg'))):
            v6 = os.path.basename(apath).startswith('bv6_')
            agg_files.append((apath, v6))
            with open(apath) as f:
                for line in f:
                    p = line.split('|')
                    plen = int(p[1])
                    if plen < 8:
                        addr = bytes.fromhex(p[2])
                        tiny_global.append({
                            'v6': v6, 'plen': plen, 'addr': addr,
                            'origins': [int(x) for x in p[4].split(',')] if p[4] else [],
                            'prefix': fmt_prefix(addr, plen, v6)})
        # stats for prefixes/entries: recompute cheaply from .agg
        total['prefixes'] = sum(1 for a, _ in agg_files for _ in open(a))
        total['entries'] = 0
        for a, _ in agg_files:
            for line in open(a):
                total['entries'] += int(line.split('|')[3])
    # phase B
    with open(os.path.join(bucket_dir, 'findings.jsonl'), 'w') as out:
        for i, (apath, v6) in enumerate(agg_files):
            stats = detect_bucket(apath, v6, tiny_global, out)
            for k, v in stats.items():
                total[k] = total.get(k, 0) + v
            if (i + 1) % 64 == 0:
                print(f'  phase B: {i + 1}/{len(agg_files)}', flush=True)
    with open(os.path.join(bucket_dir, 'stats.json'), 'w') as f:
        json.dump(total, f, indent=1, sort_keys=True)
    print('done.')
    for k in ('prefixes', 'entries', 'moas', 'bogon', 'deagg', 'long_path',
              'as_set', 'as_trans'):
        print(f'  {k}: {total.get(k, 0)}')


if __name__ == '__main__':
    main()
