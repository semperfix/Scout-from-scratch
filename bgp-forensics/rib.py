#!/usr/bin/env python3
"""Streaming RIB builder: bview (TABLE_DUMP_V2) -> per-bucket entry files.

Memory-bounded design: the full table (46M entries here) never sits in RAM.
Pass 1 streams the dump and appends fixed-size per-entry records into 256
bucket files keyed by first address byte (v4 and v6 separately).
Pass 2 (aggregate.py) sorts each bucket in RAM and sweeps it.

Entry record formats (all big-endian):
  v4: >B I I B B I  = plen, addr, origin_as, path_len, flags, peer_as  (15 B)
  v6: >B 16s I B B I = plen, addr16, origin_as, path_len, flags, peer_as (27 B)
flags: bit0 = AS_SET present, bit1 = AS_TRANS present in path
path_len capped at 255; origin_as = 0xFFFFFFFF when no AS_PATH.
"""
import gzip
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import mrt

V4REC = struct.Struct('>BIIBBI')
V6REC = struct.Struct('>B16sIBBI')
NO_ORIGIN = 0xFFFFFFFF
_U16 = struct.Struct('>H')
_U32 = struct.Struct('>I')
PEERS = []  # filled from PEER_INDEX_TABLE; module-level so rib passes are safe


def aspath_scan(attr_raw):
    """Single walk over path attributes.

    Returns (origin_as, path_len, has_set, has_trans). origin_as is
    NO_ORIGIN if no usable AS_PATH. path_len counts ASNs in AS_PATH.
    """
    off = 0
    n = len(attr_raw)
    origin = NO_ORIGIN
    plen = 0
    has_set = False
    has_trans = False
    A = attr_raw
    while off + 3 <= n:
        flags, atype = A[off], A[off + 1]
        if flags & 0x10:
            if off + 4 > n:
                break
            alen = _U16.unpack_from(A, off + 2)[0]
            voff = off + 4
        else:
            alen = A[off + 2]
            voff = off + 3
        if voff + alen > n:
            break
        if atype == 2 and alen >= 2:  # AS_PATH
            so, end = voff, voff + alen
            while so + 2 <= end:
                stype, slen = A[so], A[so + 1]
                aend = so + 2 + slen * 4
                if aend > end:
                    break
                if stype == 1:
                    has_set = True
                plen += slen
                # last ASN of this segment (origin if final segment)
                if aend == end or True:
                    last = A[aend - 4:aend]
                    o = _U32.unpack(last)[0]
                    origin = o
                    if o == 23456:
                        has_trans = True
                so = aend
        off = voff + alen
    return origin, min(plen, 255), has_set, has_trans


def build_buckets(bview_path, bucket_dir, progress_every=200000):
    os.makedirs(bucket_dir, exist_ok=True)
    # lazy-open bucket files with per-bucket bytearray buffers
    bufs = {}
    files = {}

    def emit(bucket, rec):
        b = bufs.get(bucket)
        if b is None:
            b = bufs[bucket] = bytearray()
        b += rec
        if len(b) >= 1 << 20:
            f = files.get(bucket)
            if f is None:
                f = files[bucket] = open(os.path.join(bucket_dir, bucket + '.bin'), 'wb')
            f.write(b)
            bufs[bucket] = bytearray()

    n_recs = n_entries = 0
    tiny = []  # (fam, plen, addr_int_or_bytes, origin info) for plen < 8
    with gzip.open(bview_path, 'rb') as f:
        for ts, typ, sub, payload in mrt.iter_mrt_records(f):
            if typ != mrt.TABLE_DUMP_V2:
                continue
            if sub == mrt.PEER_INDEX_TABLE:
                PEERS[:] = mrt.parse_peer_index_table(payload)['peers']
                continue
            if sub not in (mrt.RIB_IPV4_UNICAST, mrt.RIB_IPV6_UNICAST):
                continue
            v6 = (sub == mrt.RIB_IPV6_UNICAST)
            width = 16 if v6 else 4
            off = 4  # skip sequence number
            plen = payload[off]; off += 1
            nbytes = (plen + 7) // 8
            praw = payload[off:off + nbytes]; off += nbytes
            addr_full = (praw + b'\x00' * (width - nbytes))
            if plen % 8 and nbytes:
                mask = 0xFF & (0xFF << (8 - plen % 8))
                addr_full = (addr_full[:nbytes - 1] + bytes([addr_full[nbytes - 1] & mask]) +
                             addr_full[nbytes:])
            ecount = _U16.unpack_from(payload, off)[0]; off += 2
            n_recs += 1
            first_byte = addr_full[0]
            bucket = ('bv6_%03d' if v6 else 'bv4_%03d') % first_byte
            if plen < 8:
                tiny.append((6 if v6 else 4, plen, addr_full))
            for _ in range(ecount):
                peer_idx = _U16.unpack_from(payload, off)[0]; off += 2
                off += 4  # originated time
                alen = _U16.unpack_from(payload, off)[0]; off += 2
                attr_raw = payload[off:off + alen]; off += alen
                origin, pathlen, has_set, has_trans = aspath_scan(attr_raw)
                flags = (1 if has_set else 0) | (2 if has_trans else 0)
                peer_as = PEERS[peer_idx]['as'] if peer_idx < len(PEERS) else 0
                if v6:
                    rec = V6REC.pack(plen, addr_full, origin, pathlen, flags, peer_as)
                else:
                    rec = V4REC.pack(plen, int.from_bytes(addr_full, 'big'),
                                     origin, pathlen, flags, peer_as)
                emit(bucket, rec)
                n_entries += 1
            if n_recs % progress_every == 0:
                print(f'  ... {n_recs} prefixes, {n_entries} entries', flush=True)
    for bucket, b in bufs.items():
        if b:
            f = files.get(bucket)
            if f is None:
                f = open(os.path.join(bucket_dir, bucket + '.bin'), 'wb')
                files[bucket] = f
            f.write(b)
    for f in files.values():
        f.close()
    print(f'done: {n_recs} prefixes, {n_entries} entries, {len(PEERS)} peers')
    return tiny


if __name__ == '__main__':
    bview = sys.argv[1] if len(sys.argv) > 1 else \
        os.environ.get('BGP_RIB', os.path.join(_HERE, 'data', 'bview.mrt.gz'))
    outdir = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(_HERE, 'buckets')
    tiny = build_buckets(bview, outdir)
    # persist tiny covering prefixes (plen<8) for the aggregate pass
    with open(os.path.join(outdir, 'tiny.txt'), 'w') as f:
        for fam, plen, addr in tiny:
            f.write(f'{fam} {plen} {addr.hex()}\n')
    print(f'tiny prefixes (plen<8): {len(tiny)}')
