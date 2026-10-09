#!/usr/bin/env python3
"""End-to-end pipeline test: synthetic bview with planted anomalies."""
import glob
import ipaddress
import io
import json
import os
import shutil
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import test_mrt as T
import mrt
from rib import build_buckets
from aggregate import aggregate_bucket, detect_bucket

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  ok   {name}')
    else:
        FAIL += 1
        print(f'  FAIL {name} {detail}')


def build_bview(path):
    peers = b''
    peers += bytes([0x00]) + ipaddress.IPv4Address('1.1.1.1').packed \
        + ipaddress.IPv4Address('10.0.0.1').packed + struct.pack('>H', 701)
    peers += bytes([0x00]) + ipaddress.IPv4Address('2.2.2.2').packed \
        + ipaddress.IPv4Address('10.0.0.2').packed + struct.pack('>H', 3356)
    pit = (ipaddress.IPv4Address('192.0.2.1').packed + struct.pack('>H', 5) + b'rrc00'
           + struct.pack('>H', 2) + peers)

    def entry(peer_idx, path, as_set=False):
        e = struct.pack('>H', peer_idx) + struct.pack('>I', 1728510000)
        if as_set:
            seg = bytes([1, 2]) + struct.pack('>II', 701, 702)
            seg += bytes([2, 1]) + struct.pack('>I', path[-1])
            a = T.attr(0x40, 1, b'\x00') + T.attr(0x40, 2, seg)
        else:
            a = T.attr(0x40, 1, b'\x00') + T.as_path_attr(path)
        return e + struct.pack('>H', len(a)) + a

    def rib(pfx, plen, entries):
        return (struct.pack('>I', 1) + T.nlri_bytes(pfx, plen)
                + struct.pack('>H', len(entries)) + b''.join(entries))

    recs = [T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.PEER_INDEX_TABLE, pit)]
    # real tiny prefix (plen<8): 10.0.0.0/7 spans buckets 10-11
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('10.0.0.0', 7, [entry(0, [701, 1])])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('10.1.0.0', 16, [entry(0, [701, 1])])))
    # planted hijack in bucket 10, covered by in-bucket /16
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('10.1.2.0', 24, [entry(1, [3356, 666])])))
    # cross-bucket hijack: 11.9.0.0/16 (bucket 11) vs in-bucket 11.0.0.0/8 (MOAS)
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('11.9.0.0', 16, [entry(1, [3356, 99])])))
    # tiny-only coverage: 9.200.0.0/16 has no in-bucket covering prefix;
    # only the tiny 8.0.0.0/7 (buckets 8-9) covers it
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('8.0.0.0', 7, [entry(0, [701, 7])])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('9.200.0.0', 16, [entry(1, [3356, 99])])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('11.0.0.0', 8, [entry(0, [701, 1]), entry(1, [3356, 3])])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('192.168.0.0', 16, [entry(0, [701, 64512])])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('12.0.0.0', 8, [entry(0, [701, 5], as_set=True)])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST,
                             rib('13.0.0.0', 8, [entry(0, list(range(700, 735)))])))
    recs.append(T.mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV6_UNICAST,
                             rib('2001:db8::', 32, [entry(0, [701, 6939])])))
    import gzip
    with gzip.open(path, 'wb') as f:
        f.write(b''.join(recs))


def main():
    d = os.path.join(_HERE, 'testpipe')
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    bv = os.path.join(d, 'synth.gz')
    build_bview(bv)
    bk = os.path.join(d, 'buckets')
    build_buckets(bv, bk)
    # phase A all buckets
    tiny_global = []
    agg_files = []
    for bpath in sorted(glob.glob(os.path.join(bk, '*.bin'))):
        v6 = os.path.basename(bpath).startswith('bv6_')
        apath = bpath[:-4] + '.agg'
        _, tiny = aggregate_bucket(bpath, v6, apath)
        tiny_global.extend(tiny)
        agg_files.append((apath, v6))
    check('tiny captured', len(tiny_global) == 2 and
          all(t['plen'] == 7 for t in tiny_global), tiny_global)
    # phase B all buckets
    out = io.StringIO()
    for apath, v6 in agg_files:
        detect_bucket(apath, v6, tiny_global, out)
    findings = [json.loads(l) for l in out.getvalue().splitlines()]
    kinds = {}
    for fl in findings:
        kinds.setdefault(fl['kind'], []).append(fl['prefix'])
    check('DEAGG in-bucket', '10.1.2.0/24' in kinds.get('DEAGG_ORIGIN_CHANGE', []), kinds)
    check('DEAGG cross-bucket vs in-bucket MOAS', '11.9.0.0/16' in kinds.get('DEAGG_ORIGIN_CHANGE', []), kinds)
    check('DEAGG tiny-only coverage', '9.200.0.0/16' in kinds.get('DEAGG_ORIGIN_CHANGE', []), kinds)
    deagg = [f for f in findings if f['kind'] == 'DEAGG_ORIGIN_CHANGE'
             and f['prefix'] == '10.1.2.0/24'][0]
    check('deagg covering', deagg['covering'] == '10.1.0.0/16'
          and deagg['covering_origins'] == [1] and not deagg['via_tiny'], deagg)
    deagg2 = [f for f in findings if f['kind'] == 'DEAGG_ORIGIN_CHANGE'
              and f['prefix'] == '9.200.0.0/16'][0]
    check('deagg tiny covering', deagg2['covering'] == '8.0.0.0/7'
          and deagg2['covering_origins'] == [7] and deagg2['via_tiny'], deagg2)
    check('MOAS found', kinds.get('MOAS') == ['11.0.0.0/8'], kinds)
    check('BOGON found', kinds.get('BOGON_ORIGIN') == ['192.168.0.0/16'], kinds)
    check('AS_SET found', kinds.get('AS_SET') == ['12.0.0.0/8'], kinds)
    check('LONG_PATH found', kinds.get('LONG_PATH') == ['13.0.0.0/8'], kinds)
    check('no false deagg on 10.1.0.0/16',
          '10.1.0.0/16' not in kinds.get('DEAGG_ORIGIN_CHANGE', []))
    print(f'{PASS} passed, {FAIL} failed')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
