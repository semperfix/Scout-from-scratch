#!/usr/bin/env python3
"""Targeted deep-dive: re-scan the RIB dump and fully parse entries only for
a wanted set of prefixes. Everything else is skipped by offset math, so the
pass is fast despite the dump's size.
"""
import gzip
import struct
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import mrt

_U16 = struct.Struct('>H')
_U32 = struct.Struct('>I')


def norm_prefix(addr, plen, v6):
    return f'{addr}/{plen}'


def paths_for_prefixes(bview_path, wanted, v6_wanted=None, limit_per_prefix=8):
    """wanted: set of 'addr/plen' strings (v4). v6_wanted: set for v6.

    Returns {prefix: [(peer_as, as_path, communities, next_hop), ...]}.
    """
    wanted = set(wanted or [])
    v6_wanted = set(v6_wanted or [])
    out = {}
    peers = []
    with gzip.open(bview_path, 'rb') as f:
        for ts, typ, sub, payload in mrt.iter_mrt_records(f):
            if typ != mrt.TABLE_DUMP_V2:
                continue
            if sub == mrt.PEER_INDEX_TABLE:
                peers = mrt.parse_peer_index_table(payload)['peers']
                continue
            v6 = (sub == mrt.RIB_IPV6_UNICAST)
            if sub not in (mrt.RIB_IPV4_UNICAST, mrt.RIB_IPV6_UNICAST):
                continue
            off = 4
            plen = payload[off]; off += 1
            nbytes = (plen + 7) // 8
            praw = payload[off:off + nbytes]; off += nbytes
            width = 16 if v6 else 4
            full = (praw + b'\x00' * (width - nbytes))
            if plen % 8 and nbytes:
                mask = 0xFF & (0xFF << (8 - plen % 8))
                full = full[:nbytes - 1] + bytes([full[nbytes - 1] & mask]) + full[nbytes:]
            import ipaddress
            addr = str(ipaddress.IPv6Address(full) if v6 else ipaddress.IPv4Address(full))
            key = f'{addr}/{plen}'
            want = (key in v6_wanted) if v6 else (key in wanted)
            ecount = _U16.unpack_from(payload, off)[0]; off += 2
            if not want:
                # skip all entries by offset math
                for _ in range(ecount):
                    off += 2 + 4
                    alen = _U16.unpack_from(payload, off)[0]; off += 2
                    off += alen
                continue
            lst = out.setdefault(key, [])
            for _ in range(ecount):
                if len(lst) >= limit_per_prefix:
                    # still must advance offsets
                    off += 2 + 4
                    alen = _U16.unpack_from(payload, off)[0]; off += 2
                    off += alen
                    continue
                peer_idx = _U16.unpack_from(payload, off)[0]; off += 2
                off += 4
                alen = _U16.unpack_from(payload, off)[0]; off += 2
                attr_raw = payload[off:off + alen]; off += alen
                try:
                    attrs = mrt.parse_path_attributes(attr_raw, asn4=True)
                except mrt.MRTError:
                    continue
                peer_as = peers[peer_idx]['as'] if peer_idx < len(peers) else 0
                lst.append((peer_as, mrt.as_path_flat(attrs),
                            attrs.get('communities', []),
                            attrs.get('next_hop')))
    return out


if __name__ == '__main__':
    # smoke: pull Google's 8.8.8.0/24 and check origin AS15169
    r = paths_for_prefixes(
        os.environ.get('BGP_RIB', os.path.join(_HERE, 'data', 'bview.mrt.gz')),
        {'8.8.8.0/24'})
    for pfx, rows in r.items():
        origins = {p[-1] for _, p, _, _ in rows if p}
        print(pfx, 'origins:', origins, 'samples:', len(rows))
        assert origins == {15169}, origins
        print('deepdive smoke OK')
