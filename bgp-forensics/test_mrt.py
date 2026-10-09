#!/usr/bin/env python3
"""Tests for mrt.py: synthetic round-trip + differential vs mrtparse on real data."""
import gzip
import io
import struct
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import mrt

PASS = 0
FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  ok   {name}')
    else:
        FAIL += 1
        print(f'  FAIL {name} {detail}')


def nlri_bytes(addr, plen, v6=False):
    import ipaddress
    ip = ipaddress.ip_address(addr)
    raw = ip.packed
    nbytes = (plen + 7) // 8
    return bytes([plen]) + raw[:nbytes]


def attr(flags, atype, val):
    if len(val) > 255:
        return bytes([flags | 0x10, atype]) + struct.pack('>H', len(val)) + val
    return bytes([flags, atype, len(val)]) + val


def as_path_attr(path, asn4=True):
    # single AS_SEQUENCE segment
    w = 4 if asn4 else 2
    seg = bytes([2, len(path)]) + b''.join(a.to_bytes(w, 'big') for a in path)
    return attr(0x40, 2, seg)


def bgp_update_msg(withdrawn, announced, attrs):
    w = b''.join(nlri_bytes(a, p) for a, p in withdrawn)
    n = b''.join(nlri_bytes(a, p) for a, p in announced)
    body = struct.pack('>H', len(w)) + w + struct.pack('>H', len(attrs)) + attrs + n
    blen = 19 + len(body)
    return b'\xff' * 16 + struct.pack('>H', blen) + bytes([2]) + body


def bgp4mp_record(peer_as, local_as, peer_ip, local_ip, bgp_msg, asn4=True):
    import ipaddress
    w = 4 if asn4 else 2
    p = ipaddress.ip_address(peer_ip).packed
    l = ipaddress.ip_address(local_ip).packed
    afi = 2 if len(p) == 16 else 1
    return (peer_as.to_bytes(w, 'big') + local_as.to_bytes(w, 'big') +
            struct.pack('>HH', 0, afi) + p + l + bgp_msg)


def mrt_record(ts, typ, sub, payload):
    return struct.pack('>IHHI', ts, typ, sub, len(payload)) + payload


def test_bgp4mp_roundtrip():
    print('synthetic BGP4MP round-trip')
    attrs = (attr(0x40, 1, b'\x00') +                      # ORIGIN IGP
             as_path_attr([701, 3356, 15169]) +            # AS_PATH
             attr(0x40, 3, bytes([8, 8, 8, 8])) +          # NEXT_HOP
             attr(0xC0, 8, struct.pack('>II', 0xFFFF029A, 15169 << 16 | 100)))  # community 65535:666? no: 666:100
    msg = bgp_update_msg([('4.3.2.0', 24)], [('1.2.3.0', 24), ('2001:db8::', 32)],
                         attrs)
    # note: v6 NLRI in plain UPDATE section is unusual; keep v4 only for strictness
    msg = bgp_update_msg([('4.3.2.0', 24)], [('1.2.3.0', 24), ('9.9.9.0', 24)], attrs)
    rec = mrt_record(1728510000, mrt.BGP4MP, mrt.BGP4MP_MESSAGE_AS4,
                     bgp4mp_record(3356, 1103, '4.69.0.1', '193.0.0.1', msg))
    (ts, typ, sub, payload), = list(mrt.iter_mrt_records(io.BytesIO(rec)))
    check('mrt header', (ts, typ, sub) == (1728510000, 16, 4), f'{ts},{typ},{sub}')
    info = mrt.parse_bgp_message(payload, asn4=True)
    check('peer_as', info['peer_as'] == 3356)
    check('peer_ip', info['peer_ip'] == '4.69.0.1')
    check('bgp_type UPDATE', info['bgp_type'] == 2)
    upd = info['update']
    check('withdrawn', upd['withdrawn'] == [('4.3.2.0', 24)], upd['withdrawn'])
    check('announced', upd['announced'] == [('1.2.3.0', 24), ('9.9.9.0', 24)], upd['announced'])
    a = mrt.parse_path_attributes(upd['attr_raw'], asn4=True)
    check('origin', a['origin'] == 'IGP', a.get('origin'))
    check('as_path', a['as_path'] == [(2, [701, 3356, 15169])], a.get('as_path'))
    check('origin_as', mrt.origin_as(a) == 15169)
    check('next_hop', a['next_hop'] == '8.8.8.8')
    check('communities', a['communities'] == ['65535:666', '15169:100'], a.get('communities'))


def test_as4_merge():
    print('RFC 6793 AS4_PATH merge')
    # 2-byte AS_PATH with AS_TRANS placeholders + AS4_PATH with real ASNs
    p2 = bytes([2, 4]) + struct.pack('>HHHH', 701, 3356, mrt.AS_TRANS, mrt.AS_TRANS)
    p4 = bytes([2, 2]) + struct.pack('>II', 15169, 36040)
    attrs = attr(0x40, 2, p2) + attr(0x40, 17, p4)
    a = mrt.parse_path_attributes(attrs, asn4=False)
    check('merged path', a['as_path'] == [(2, [701, 3356, 15169, 36040])], a.get('as_path'))
    check('merged origin', mrt.origin_as(a) == 36040)


def test_table_dump_v2_roundtrip():
    print('synthetic TABLE_DUMP_V2 round-trip')
    import ipaddress
    # peer index table: 2 peers (v4/2-byte AS, v6/4-byte AS)
    peers = b''
    peers += bytes([0]) + ipaddress.IPv4Address('10.0.0.1').packed + b'\xc0\x00'  # wait: bgp_id then ip then as
    # correct order: type, bgp_id(4), ip, as
    peers = b''
    peers += bytes([0x00]) + ipaddress.IPv4Address('1.1.1.1').packed + ipaddress.IPv4Address('10.0.0.1').packed + struct.pack('>H', 701)
    peers += bytes([0x03]) + ipaddress.IPv4Address('2.2.2.2').packed + ipaddress.IPv6Address('2001:db8::1').packed + struct.pack('>I', 3356)
    pit = (ipaddress.IPv4Address('192.0.2.1').packed + struct.pack('>H', 5) + b'rrc00' +
           struct.pack('>H', 2) + peers)
    recs = [mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.PEER_INDEX_TABLE, pit)]
    # RIB v4 entry: 8.8.8.0/24 with 2 entries
    e1 = struct.pack('>H', 0) + struct.pack('>I', 1728510001)
    a1 = attr(0x40, 1, b'\x00') + as_path_attr([701, 15169])
    e1 += struct.pack('>H', len(a1)) + a1
    e2 = struct.pack('>H', 1) + struct.pack('>I', 1728510002)
    a2 = attr(0x40, 1, b'\x00') + as_path_attr([3356, 701, 15169])
    e2 += struct.pack('>H', len(a2)) + a2
    rib = struct.pack('>I', 99) + nlri_bytes('8.8.8.0', 24) + struct.pack('>H', 2) + e1 + e2
    recs.append(mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV4_UNICAST, rib))
    # RIB v6 entry
    e3 = struct.pack('>H', 1) + struct.pack('>I', 1728510003)
    a3 = attr(0x40, 1, b'\x00') + as_path_attr([3356, 6939])
    e3 += struct.pack('>H', len(a3)) + a3
    rib6 = struct.pack('>I', 100) + nlri_bytes('2001:4860::', 32, v6=True) + struct.pack('>H', 1) + e3
    recs.append(mrt_record(1728510000, mrt.TABLE_DUMP_V2, mrt.RIB_IPV6_UNICAST, rib6))
    stream = io.BytesIO(b''.join(recs))
    got = list(mrt.iter_mrt_records(stream))
    check('3 records', len(got) == 3, len(got))
    pit_info = mrt.parse_peer_index_table(got[0][3])
    check('view', pit_info['view_name'] == 'rrc00')
    check('peer0', pit_info['peers'][0]['as'] == 701 and pit_info['peers'][0]['ip'] == '10.0.0.1', pit_info['peers'][0])
    check('peer1 v6', pit_info['peers'][1]['ip'] == '2001:db8::1' and pit_info['peers'][1]['as'] == 3356, pit_info['peers'][1])
    (addr, plen, entries), off = mrt.parse_rib_entry(got[1][3], 0, v6=False)
    check('rib v4 prefix', (addr, plen) == ('8.8.8.0', 24), (addr, plen))
    check('rib v4 entries', len(entries) == 2)
    check('fast_origin e1', mrt.fast_origin(entries[0][2]) == 15169)
    check('fast_origin e2', mrt.fast_origin(entries[1][2]) == 15169)
    a = mrt.parse_path_attributes(entries[1][2], asn4=True)
    check('full path e2', mrt.as_path_flat(a) == [3356, 701, 15169])
    (addr6, plen6, entries6), off6 = mrt.parse_rib_entry(got[2][3], 0, v6=True)
    check('rib v6 prefix', (addr6, plen6) == ('2001:4860::', 32), (addr6, plen6))
    check('fast_origin v6', mrt.fast_origin(entries6[0][2]) == 6939)


def test_differential_updates():
    print('differential vs mrtparse on real updates file')
    from mrtparse import Reader
    path = os.environ.get('BGP_UPDATES', os.path.join(_HERE, 'data', 'updates.mrt.gz'))
    if not os.path.exists(path):
        print(f'skipped (no updates dump; set BGP_UPDATES to a fetched updates.mrt.gz)')
        return
    # my parser
    mine_recs = mine_updates = mine_ann = mine_wd = 0
    sample = []
    with gzip.open(path, 'rb') as f:
        for ts, typ, sub, payload in mrt.iter_mrt_records(f):
            mine_recs += 1
            if typ == mrt.BGP4MP and sub in (mrt.BGP4MP_MESSAGE, mrt.BGP4MP_MESSAGE_AS4):
                try:
                    info = mrt.parse_bgp_message(payload, asn4=(sub == mrt.BGP4MP_MESSAGE_AS4))
                except mrt.MRTError as e:
                    print('   my parse error:', e)
                    continue
                if info['bgp_type'] == mrt.BGP_UPDATE:
                    mine_updates += 1
                    u = info['update']
                    mine_ann += len(u['announced'])
                    mine_wd += len(u['withdrawn'])
                    if len(sample) < 5 and u['announced']:
                        a = mrt.parse_path_attributes(u['attr_raw'], asn4=(sub == mrt.BGP4MP_MESSAGE_AS4))
                        sample.append((u['announced'][0], mrt.origin_as(a)))
    # mrtparse
    theirs_recs = theirs_updates = theirs_ann = theirs_wd = 0
    for entry in Reader(path):
        theirs_recs += 1
        d = entry.data
        m = d.get('bgp_message')
        if d.get('type') == {16: 'BGP4MP'} and isinstance(m, dict) and m.get('type') == {2: 'UPDATE'}:
            theirs_updates += 1
            theirs_ann += len(m.get('nlri') or [])
            theirs_wd += len(m.get('withdrawn_routes') or [])
    check('record count', mine_recs == theirs_recs, f'mine={mine_recs} theirs={theirs_recs}')
    check('update count', mine_updates == theirs_updates, f'mine={mine_updates} theirs={theirs_updates}')
    check('announced nlri', mine_ann == theirs_ann, f'mine={mine_ann} theirs={theirs_ann}')
    check('withdrawn nlri', mine_wd == theirs_wd, f'mine={mine_wd} theirs={theirs_wd}')
    print('   sample origins:', sample)


if __name__ == '__main__':
    test_bgp4mp_roundtrip()
    test_as4_merge()
    test_table_dump_v2_roundtrip()
    test_differential_updates()
    print(f'\n{PASS} passed, {FAIL} failed')
    sys.exit(1 if FAIL else 0)
