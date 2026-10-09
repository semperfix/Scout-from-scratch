#!/usr/bin/env python3
"""MRT (RFC 6396) + BGP UPDATE (RFC 4271) parser, stdlib only.

Supports:
  - MRT common header framing, streaming iteration
  - BGP4MP MESSAGE (subtype 1, 2-byte ASNs) and MESSAGE_AS4 (subtype 4, 4-byte ASNs)
  - TABLE_DUMP_V2: PEER_INDEX_TABLE, RIB_IPV4_UNICAST, RIB_IPV6_UNICAST
  - BGP path attributes: ORIGIN, AS_PATH (+AS4_PATH merge per RFC 6793),
    NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITY,
    MP_REACH_NLRI, MP_UNREACH_NLRI, EXTENDED_COMMUNITY (raw)
"""
import struct
import ipaddress

# ---- MRT types/subtypes (RFC 6396) ----
TABLE_DUMP_V2 = 13
PEER_INDEX_TABLE = 1
RIB_IPV4_UNICAST = 2
RIB_IPV6_UNICAST = 4
BGP4MP = 16
BGP4MP_MESSAGE = 1
BGP4MP_MESSAGE_AS4 = 4

# ---- BGP message types (RFC 4271) ----
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

# ---- Attribute type codes ----
A_ORIGIN = 1
A_AS_PATH = 2
A_NEXT_HOP = 3
A_MED = 4
A_LOCAL_PREF = 5
A_ATOMIC_AGG = 6
A_AGGREGATOR = 7
A_COMMUNITY = 8
A_MP_REACH = 14
A_MP_UNREACH = 15
A_EXT_COMMUNITY = 16
A_AS4_PATH = 17
A_AS4_AGGREGATOR = 18

AS_TRANS = 23456
ORIGIN_NAMES = {0: 'IGP', 1: 'EGP', 2: 'INCOMPLETE'}

_U16 = struct.Struct('>H')
_U32 = struct.Struct('>I')
_MRT_HDR = struct.Struct('>IHHI')   # ts, type, subtype, length
_BGP_HDR = struct.Struct('>16sHB')  # marker, length, type  (marker checked separately)


class MRTError(Exception):
    pass


def iter_mrt_records(f):
    """Yield (timestamp, type, subtype, payload_bytes) from a binary stream."""
    hdr = _MRT_HDR
    while True:
        raw = f.read(hdr.size)
        if not raw:
            return
        if len(raw) < hdr.size:
            raise MRTError(f'truncated MRT header: {len(raw)} bytes')
        ts, typ, sub, length = hdr.unpack(raw)
        payload = f.read(length)
        if len(payload) < length:
            raise MRTError(f'truncated MRT record: want {length}, got {len(payload)}')
        yield ts, typ, sub, payload


# ---------------------------------------------------------------- prefixes

def decode_prefix(buf, off, v6=False):
    """Decode one NLRI prefix at buf[off:]. Returns (addr_str, plen, new_off)."""
    plen = buf[off]
    nbytes = (plen + 7) // 8
    raw = buf[off + 1:off + 1 + nbytes]
    if len(raw) < nbytes:
        raise MRTError('truncated prefix')
    width = 16 if v6 else 4
    full = raw + b'\x00' * (width - nbytes)
    # canonicalize: mask off trailing bits past plen
    if plen % 8 and nbytes:
        mask = 0xFF & (0xFF << (8 - plen % 8))
        full = full[:nbytes - 1] + bytes([full[nbytes - 1] & mask]) + full[nbytes:]
    fam = 6 if v6 else 4
    addr = str(ipaddress.ip_address(int.from_bytes(full, 'big')) if False else
               ipaddress.IPv6Address(full) if v6 else ipaddress.IPv4Address(full))
    return addr, plen, off + 1 + nbytes


def prefix_key(addr, plen):
    """Compact canonical key 'addr/plen'."""
    return f'{addr}/{plen}'


def decode_nlri(buf, v6=False):
    out = []
    off = 0
    while off < len(buf):
        addr, plen, off = decode_prefix(buf, off, v6)
        out.append((addr, plen))
    return out


# ---------------------------------------------------------------- attributes

def _parse_as_path(buf, asn4):
    """Parse AS_PATH value -> list of (seg_type, [asns])."""
    segs = []
    off = 0
    w = 4 if asn4 else 2
    while off < len(buf):
        if off + 2 > len(buf):
            raise MRTError('truncated AS_PATH segment header')
        stype, slen = buf[off], buf[off + 1]
        off += 2
        asns = []
        for _ in range(slen):
            if off + w > len(buf):
                raise MRTError('truncated AS_PATH segment')
            asns.append(int.from_bytes(buf[off:off + w], 'big'))
            off += w
        segs.append((stype, asns))
    return segs


def _merge_as4_path(as_path, as4_path):
    """RFC 6793: replace AS_TRANS placeholders with real 4-byte ASNs.

    as_path: segments with 2-byte ASNs; as4_path: segments with 4-byte ASNs.
    The AS4_PATH holds the trailing part of the true path; leading segments
    (up to the AS_TRANS run) come from AS_PATH.
    """
    # flatten trailing AS_TRANS count in as_path
    flat = []
    for stype, asns in as_path:
        flat.append((stype, list(asns)))
    # count trailing AS_TRANS ASNs (only meaningful in SEQUENCE tail)
    n_trans = 0
    for stype, asns in reversed(flat):
        if stype != 2:  # AS_SEQUENCE
            break
        for a in reversed(asns):
            if a == AS_TRANS:
                n_trans += 1
            else:
                break
        else:
            continue
        break
    flat4 = []
    for stype, asns in as4_path:
        flat4.extend(asns if stype == 2 else [])
    # replacement: drop n_trans trailing AS_TRANS, append as4 tail
    seq = []
    for stype, asns in flat:
        if stype == 2:
            seq.extend(asns)
    # remove trailing AS_TRANS
    while seq and seq[-1] == AS_TRANS and n_trans > 0:
        seq.pop()
        n_trans -= 1
    seq.extend(flat4)
    # rebuild: keep original segments, but replace the SEQUENCE tail
    out = []
    for stype, asns in flat:
        if stype == 2:
            continue  # replaced below
        out.append((stype, asns))
    if seq:
        out.append((2, seq))
    return out


def parse_path_attributes(buf, asn4):
    """Parse BGP path attributes. Returns dict of decoded attributes.

    asn4: True if ASNs are 4 bytes (TABLE_DUMP_V2, BGP4MP AS4).
    Unknown/optional attributes are kept raw under ('raw', type).
    """
    attrs = {}
    raw = {}
    off = 0
    n = len(buf)
    while off < n:
        if off + 3 > n:
            raise MRTError('truncated attribute header')
        flags, atype = buf[off], buf[off + 1]
        off += 2
        if flags & 0x10:  # extended length
            if off + 2 > n:
                raise MRTError('truncated extended attribute length')
            alen = _U16.unpack_from(buf, off)[0]
            off += 2
        else:
            alen = buf[off]
            off += 1
        if off + alen > n:
            raise MRTError(f'truncated attribute value: type={atype} len={alen}')
        val = buf[off:off + alen]
        off += alen
        partial = bool(flags & 0x20)

        if atype == A_ORIGIN and alen == 1:
            attrs['origin'] = ORIGIN_NAMES.get(val[0], f'UNKNOWN({val[0]})')
        elif atype == A_AS_PATH:
            attrs['as_path'] = _parse_as_path(val, asn4)
        elif atype == A_AS4_PATH:
            attrs['as4_path'] = _parse_as_path(val, True)
        elif atype == A_NEXT_HOP and alen == 4:
            attrs['next_hop'] = str(ipaddress.IPv4Address(val))
        elif atype == A_MED and alen == 4:
            attrs['med'] = _U32.unpack(val)[0]
        elif atype == A_LOCAL_PREF and alen == 4:
            attrs['local_pref'] = _U32.unpack(val)[0]
        elif atype == A_ATOMIC_AGG:
            attrs['atomic_aggregate'] = True
        elif atype == A_AGGREGATOR and alen in (6, 8):
            w = 4 if alen == 8 else 2
            attrs['aggregator'] = (int.from_bytes(val[:w], 'big'),
                                   str(ipaddress.IPv4Address(val[w:w + 4])))
        elif atype == A_COMMUNITY and alen % 4 == 0:
            attrs['communities'] = [f'{_U16.unpack(val[i:i+2])[0]}:{_U16.unpack(val[i+2:i+4])[0]}'
                                    for i in range(0, alen, 4)]
        elif atype == A_MP_REACH and alen >= 5:
            afi = _U16.unpack(val[:2])[0]
            safi = val[2]
            nh_len = val[3]
            nh = val[4:4 + nh_len]
            nlri = val[4 + nh_len + 1:]
            v6 = (afi == 2)
            try:
                nh_str = str(ipaddress.IPv6Address(nh) if v6 and len(nh) == 16
                             else ipaddress.IPv4Address(nh) if len(nh) == 4
                             else nh.hex())
            except Exception:
                nh_str = nh.hex()
            attrs['mp_reach'] = {
                'afi': afi, 'safi': safi, 'next_hop': nh_str,
                'nlri': [(a, p) for a, p in decode_nlri(nlri, v6)],
            }
        elif atype == A_MP_UNREACH and alen >= 3:
            afi = _U16.unpack(val[:2])[0]
            safi = val[2]
            v6 = (afi == 2)
            attrs['mp_unreach'] = {
                'afi': afi, 'safi': safi,
                'withdrawn': [(a, p) for a, p in decode_nlri(val[3:], v6)],
            }
        else:
            raw[atype] = bytes(val)
        if partial:
            attrs.setdefault('partial_attrs', []).append(atype)
    if 'as4_path' in attrs and 'as_path' in attrs and not asn4:
        attrs['as_path'] = _merge_as4_path(attrs['as_path'], attrs.pop('as4_path'))
    elif 'as4_path' in attrs:
        attrs['as_path'] = attrs.pop('as4_path')
    if raw:
        attrs['raw_attrs'] = raw
    return attrs


def as_path_flat(attrs):
    """Flatten as_path segments to a plain ASN list (SETs expanded inline)."""
    out = []
    for stype, asns in attrs.get('as_path', []):
        out.extend(asns)
    return out


def origin_as(attrs):
    """Origin AS = last ASN of the flattened AS_PATH, or None."""
    p = as_path_flat(attrs)
    return p[-1] if p else None


# ---------------------------------------------------------------- BGP UPDATE

def parse_bgp_update(msg):
    """Parse a BGP UPDATE message (after the 19-byte header).

    Returns dict: withdrawn [(addr,plen)], announced [(addr,plen)], attrs.
    """
    if len(msg) < 4:
        raise MRTError('truncated UPDATE')
    wlen = _U16.unpack_from(msg, 0)[0]
    off = 2
    if off + wlen + 2 > len(msg):
        raise MRTError('truncated UPDATE withdrawn section')
    withdrawn = decode_nlri(msg[off:off + wlen])
    off += wlen
    alen = _U16.unpack_from(msg, off)[0]
    off += 2
    if off + alen > len(msg):
        raise MRTError('truncated UPDATE attributes')
    attr_raw = msg[off:off + alen]
    off += alen
    announced = decode_nlri(msg[off:])
    return {'withdrawn': withdrawn, 'announced': announced,
            'attr_raw': attr_raw}


def parse_bgp_message(payload, asn4):
    """Parse one BGP4MP record payload.

    Returns dict with peer/local info and, for UPDATEs, the parsed update
    (attributes parsed lazily via attr_raw unless parse_attrs=True).
    """
    w = 4 if asn4 else 2
    off = 0
    peer_as = int.from_bytes(payload[off:off + w], 'big'); off += w
    local_as = int.from_bytes(payload[off:off + w], 'big'); off += w
    ifindex = _U16.unpack_from(payload, off)[0]; off += 2
    # RFC 6396 s7: Address Family follows Interface Index (1 = IPv4, 2 = IPv6)
    afi = _U16.unpack_from(payload, off)[0]; off += 2
    addrlen = 4 if afi == 1 else 16 if afi == 2 else None
    if addrlen is None:
        raise MRTError(f'BGP4MP: unknown address family {afi}')
    info = {'peer_as': peer_as, 'local_as': local_as, 'ifindex': ifindex,
            'asn4': asn4}
    peer_ip = payload[off:off + addrlen]; off += addrlen
    local_ip = payload[off:off + addrlen]; off += addrlen
    info['peer_ip'] = str(ipaddress.IPv4Address(peer_ip) if addrlen == 4
                          else ipaddress.IPv6Address(peer_ip))
    info['local_ip'] = str(ipaddress.IPv4Address(local_ip) if addrlen == 4
                           else ipaddress.IPv6Address(local_ip))
    if payload[off:off + 16] != b'\xff' * 16:
        raise MRTError('BGP4MP: missing BGP marker after addresses')
    bgp = payload[off:]
    if len(bgp) < 19:
        raise MRTError('truncated BGP message')
    blen = _U16.unpack_from(bgp, 16)[0]
    btype = bgp[18]
    info['bgp_type'] = btype
    body = bgp[19:blen] if blen >= 19 else bgp[19:]
    if btype == BGP_UPDATE:
        info['update'] = parse_bgp_update(body)
    return info


# ---------------------------------------------------------------- TABLE_DUMP_V2

def parse_peer_index_table(payload):
    off = 0
    collector_bgp_id = str(ipaddress.IPv4Address(payload[off:off + 4])); off += 4
    vlen = _U16.unpack_from(payload, off)[0]; off += 2
    view_name = payload[off:off + vlen].decode('ascii', 'replace'); off += vlen
    peer_count = _U16.unpack_from(payload, off)[0]; off += 2
    peers = []
    for _ in range(peer_count):
        ptype = payload[off]; off += 1
        v6 = bool(ptype & 0x01)
        as4 = bool(ptype & 0x02)
        bgp_id = str(ipaddress.IPv4Address(payload[off:off + 4])); off += 4
        alen = 16 if v6 else 4
        ip = payload[off:off + alen]; off += alen
        w = 4 if as4 else 2
        asn = int.from_bytes(payload[off:off + w], 'big'); off += w
        peers.append({'bgp_id': bgp_id,
                      'ip': str(ipaddress.IPv6Address(ip) if v6 else ipaddress.IPv4Address(ip)),
                      'as': asn, 'v6': v6})
    return {'collector_bgp_id': collector_bgp_id, 'view_name': view_name,
            'peers': peers}


def parse_rib_entry(payload, off, v6=False):
    """Parse one RIB_*_UNICAST record. Returns (prefixes_info, new_off).

    prefixes_info: list of (addr, plen, entries) where entries is a list of
    (peer_index, originated_ts, attr_raw).
    """
    seq = _U32.unpack_from(payload, off)[0]; off += 4
    plen = payload[off]; off += 1
    nbytes = (plen + 7) // 8
    praw = payload[off:off + nbytes]; off += nbytes
    width = 16 if v6 else 4
    full = (praw + b'\x00' * (width - nbytes))
    if plen % 8 and nbytes:
        mask = 0xFF & (0xFF << (8 - plen % 8))
        full = full[:nbytes - 1] + bytes([full[nbytes - 1] & mask]) + full[nbytes:]
    addr = str(ipaddress.IPv6Address(full) if v6 else ipaddress.IPv4Address(full))
    ecount = _U16.unpack_from(payload, off)[0]; off += 2
    entries = []
    for _ in range(ecount):
        peer_idx = _U16.unpack_from(payload, off)[0]; off += 2
        orig_ts = _U32.unpack_from(payload, off)[0]; off += 4
        alen = _U16.unpack_from(payload, off)[0]; off += 2
        attr_raw = payload[off:off + alen]; off += alen
        entries.append((peer_idx, orig_ts, attr_raw))
    return (addr, plen, entries), off


def fast_origin(attr_raw):
    """Extract origin ASN from raw path attributes without full decode.

    Walks attributes to find AS_PATH (type 2), then takes the last ASN of
    the last segment. Assumes 4-byte ASNs (TABLE_DUMP_V2 / AS4).
    Returns None if no usable AS_PATH.
    """
    off = 0
    n = len(attr_raw)
    origin = None
    while off + 3 <= n:
        flags, atype = attr_raw[off], attr_raw[off + 1]
        if flags & 0x10:
            if off + 4 > n:
                return origin
            alen = _U16.unpack_from(attr_raw, off + 2)[0]
            voff = off + 4
        else:
            alen = attr_raw[off + 2]
            voff = off + 3
        if voff + alen > n:
            return origin
        if atype == A_AS_PATH and alen >= 2:
            # last segment: walk to end, take last ASN of final segment
            so = voff
            end = voff + alen
            last_seg_asns = None
            while so + 2 <= end:
                slen = attr_raw[so + 1]
                astart = so + 2
                aend = astart + slen * 4
                if aend > end:
                    break
                last_seg_asns = attr_raw[astart:aend]
                so = aend
            if last_seg_asns:
                origin = _U32.unpack(last_seg_asns[-4:])[0]
        off = voff + alen
    return origin
