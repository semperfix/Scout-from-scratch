#!/usr/bin/env python3
"""pcapcheck.py - Hand-rolled packet forensics. Zero Wireshark/tshark.

Reads libpcap and pcapng captures byte-by-byte (stdlib only):

  * libpcap: global header, magic-driven endianness, per-packet headers
  * pcapng: section header blocks (endianness per section), interface
    description blocks, enhanced packet blocks, timestamp resolutions
  * dissectors: Ethernet -> IPv4 / IPv6 -> TCP / UDP (ARP/ICMP noted, skipped)
  * full TCP stream reassembly: sequence ordering, overlap trimming,
    retransmit counting, SYN/FIN sequence accounting
  * app layer: HTTP requests/responses (Content-Length + chunked),
    TLS ClientHello SNI extraction, DNS queries/answers over UDP
  * triage: port scans, beaconing (periodicity test), large transfers,
    top talkers, TLS SNI list, DNS query list; --carve dumps every
    reassembled stream to disk

Usage:
    python3 pcapcheck.py capture.pcap
    python3 pcapcheck.py capture.pcapng --carve out/
    python3 pcapcheck.py --help

Exit 0 always; the VERDICT: line is the machine-readable result
(CLEAN / WORTH-A-LOOK / SUSPICIOUS).

Honest subset / limitations:
  * Link types: Ethernet (1) and raw IP only. 802.11, PPP, loopback not parsed.
  * TCP reassembly groups by 4-tuple (both directions in one stream);
    selective ACKs and window scaling are ignored (we only need the bytes).
  * TLS: only ClientHello SNI is parsed; no decryption, no other handshakes.
  * DNS: UDP only, standard queries; TCP DNS and EDNS options are skipped.
  * Beaconing is a periodicity heuristic (CV of inter-arrival times), not proof.
"""

import argparse
import os
import struct
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# Capture file readers
# ---------------------------------------------------------------------------

class PcapError(Exception):
    pass

def _read_libpcap(data):
    """Yield (ts, linktype, packet_bytes)."""
    if len(data) < 24:
        raise PcapError("too short for libpcap global header")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == 0xA1B2C3D4:
        endian, ts_scale = ">", 1_000_000
    elif magic == 0xD4C3B2A1:
        endian, ts_scale = "<", 1_000_000
    elif magic == 0xA1B23C4D:
        endian, ts_scale = ">", 1_000_000_000
    elif magic == 0x4D3CB2A1:
        endian, ts_scale = "<", 1_000_000_000
    else:
        raise PcapError(f"unknown libpcap magic 0x{magic:08x}")
    ver_maj, ver_min, _tz, _sig, _snaplen, linktype = struct.unpack_from(
        endian + "HHIIII", data, 4)
    if (ver_maj, ver_min) != (2, 4):
        raise PcapError(f"unexpected libpcap version {ver_maj}.{ver_min}")
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_frac, caplen, _len = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        pkt = data[pos:pos + caplen]
        if len(pkt) < caplen:
            break
        pos += caplen
        yield (ts_sec + ts_frac / ts_scale, linktype, pkt)

def _read_pcapng(data):
    """Yield (ts, linktype, packet_bytes) from pcapng sections."""
    pos = 0
    endian = None
    ifbs = []          # per-section interfaces: (linktype, ts_resolution)
    while pos + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, pos)
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 0x0A0D0D0A:                       # Section Header Block
            bom = struct.unpack_from("<I", body, 0)[0]
            if bom == 0x1A2B3C4D:
                endian = "<"
            elif bom == 0x4D3C2B1A:
                endian = ">"
            else:
                raise PcapError("bad pcapng byte-order magic")
            ifbs = []
        elif btype == 0x00000001 and endian:          # Interface Description Block
            linktype, _res, _snaplen = struct.unpack_from(endian + "HHI", body, 0)
            ts_resol = 1_000_000                      # default: microseconds
            opts = body[8:]
            while len(opts) >= 4:
                ocode, olen = struct.unpack_from(endian + "HH", opts, 0)
                oval = opts[4:4 + olen]
                if ocode == 9 and olen >= 1:          # if_tsresol
                    b = oval[0]
                    if b & 0x80:
                        ts_resol = 2 ** (b & 0x7F)
                    else:
                        ts_resol = 10 ** b
                if ocode == 0:
                    break
                opts = opts[4 + olen + ((4 - olen % 4) % 4):]
            ifbs.append((linktype, ts_resol))
        elif btype == 0x00000006 and endian:          # Enhanced Packet Block
            if_id, ts_hi, ts_lo, caplen, _len = struct.unpack_from(
                endian + "IIIII", body, 0)
            if if_id < len(ifbs):
                linktype, ts_resol = ifbs[if_id]
                ts = ((ts_hi << 32) | ts_lo) / ts_resol
                pkt = body[20:20 + caplen]
                yield (ts, linktype, pkt)
        # other blocks (SPB, NRB, ISB...) skipped
        pos += blen
    if endian is None:
        raise PcapError("no section header block found")

def read_packets(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return list(_read_pcapng(data)), "pcapng"
    return list(_read_libpcap(data)), "libpcap"

# ---------------------------------------------------------------------------
# Dissectors: Ethernet -> IP -> TCP/UDP
# ---------------------------------------------------------------------------

def ip4(b):
    return ".".join(str(x) for x in b)

def ip6(b):
    return ":".join(f"{int.from_bytes(b[i:i+2], 'big'):x}" for i in range(0, 16, 2))

class Packet:
    __slots__ = ("ts", "src", "dst", "proto", "sport", "dport",
                 "seq", "ack", "flags", "payload", "length")
    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

TCP_FLAGS = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
             0x10: "ACK", 0x20: "URG"}

def dissect(ts, linktype, frame):
    """Return a Packet or None (non-IP / unparsable)."""
    pkt = frame
    if linktype == 1:                       # Ethernet
        if len(pkt) < 14:
            return None
        etype = struct.unpack_from(">H", pkt, 12)[0]
        pkt = pkt[14:]
        if etype == 0x8100 and len(pkt) >= 4:    # single VLAN tag
            etype = struct.unpack_from(">H", pkt, 2)[0]
            pkt = pkt[4:]
        if etype == 0x0800:
            ver = 4
        elif etype == 0x86DD:
            ver = 6
        else:
            return None                     # ARP etc.
    elif linktype in (12, 101):             # raw IP
        ver = pkt[0] >> 4 if pkt else 0
    else:
        return None
    try:
        if ver == 4:
            return _dissect_ipv4(ts, pkt)
        if ver == 6:
            return _dissect_ipv6(ts, pkt)
    except (struct.error, IndexError):
        return None
    return None

def _dissect_ipv4(ts, pkt):
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl:
        return None
    proto = pkt[9]
    src, dst = ip4(pkt[12:16]), ip4(pkt[16:20])
    return _dissect_transport(ts, src, dst, proto, pkt[ihl:])

def _dissect_ipv6(ts, pkt):
    if len(pkt) < 40:
        return None
    nxt = pkt[6]
    src, dst = ip6(pkt[8:24]), ip6(pkt[24:40])
    off = 40
    while nxt not in (6, 17, 59):            # walk extension headers
        if off + 2 > len(pkt):
            return None
        nxt = pkt[off]
        hlen = (pkt[off + 1] + 1) * 8
        off += hlen
    if nxt == 59:
        return None
    return _dissect_transport(ts, src, dst, nxt, pkt[off:])

def _dissect_transport(ts, src, dst, proto, seg):
    if proto == 6 and len(seg) >= 20:        # TCP
        (sport, dport, seq, ack, off_flags, _win,
         _sum, _urg) = struct.unpack_from(">HHIIHHHH", seg, 0)
        hlen = ((off_flags >> 12) & 0xF) * 4
        flags = off_flags & 0x3F
        return Packet(ts=ts, src=src, dst=dst, proto="TCP",
                      sport=sport, dport=dport, seq=seq, ack=ack,
                      flags=flags, payload=seg[hlen:], length=len(seg))
    if proto == 17 and len(seg) >= 8:        # UDP
        sport, dport, _len, _sum = struct.unpack_from(">HHHH", seg, 0)
        return Packet(ts=ts, src=src, dst=dst, proto="UDP",
                      sport=sport, dport=dport, seq=0, ack=0,
                      flags=0, payload=seg[8:], length=len(seg))
    return None

def flag_str(flags):
    return ",".join(n for b, n in TCP_FLAGS.items() if flags & b) or "-"

# ---------------------------------------------------------------------------
# TCP stream reassembly (per direction - TCP is full-duplex, each side has
# its own sequence space; merging them into one seq space is wrong)
# ---------------------------------------------------------------------------

def _reassemble_dir(segments):
    segs = sorted(segments)
    out = bytearray()
    pos = None
    for seq, b in segs:
        if pos is None:
            out += b
            pos = seq + len(b)
        elif seq < pos:
            trim = pos - seq
            if trim < len(b):
                out += b[trim:]
                pos = seq + len(b)
        elif seq == pos:
            out += b
            pos += len(b)
        else:
            out += b"\x00" * (seq - pos)  # gap: pad with NULs (documented)
            out += b
            pos = seq + len(b)
    return bytes(out)

class Stream:
    def __init__(self, key):
        self.key = key                        # sorted ((ip,port),(ip,port))
        self.dirs = [[], []]                  # segments per direction
        self.retransmits = 0
        self.packets = 0
        self.bytes = 0
        self.start_ts = None
        self.end_ts = None
        self.data = {}                        # dir -> reassembled bytes
        self.syn_seen = False
        self.fin_seen = False

    def _dir(self, p):
        return 0 if (p.src, p.sport) == self.key[0] else 1

    def add(self, p):
        self.packets += 1
        if self.start_ts is None:
            self.start_ts = p.ts
        self.end_ts = p.ts
        if p.flags & 0x02:
            self.syn_seen = True
        if p.flags & 0x01:
            self.fin_seen = True
        if not p.payload:
            return
        d = self._dir(p)
        seq = p.seq + (1 if p.flags & 0x02 else 0)   # SYN consumes a seq number
        for (s, b) in self.dirs[d]:
            if s <= seq < s + len(b):
                self.retransmits += 1
                return
        self.dirs[d].append((seq, p.payload))
        self.bytes += len(p.payload)

    def reassemble(self):
        for d in (0, 1):
            self.data[d] = _reassemble_dir(self.dirs[d])
        return self.data

    def endpoint(self, d):
        return self.key[d]

def stream_key(p):
    return tuple(sorted(((p.src, p.sport), (p.dst, p.dport))))

# ---------------------------------------------------------------------------
# App-layer extraction
# ---------------------------------------------------------------------------

def _dechunk(data):
    """Decode chunked transfer encoding. Returns (body, next_pos)."""
    body = bytearray()
    pos = 0
    while True:
        eol = data.find(b"\r\n", pos)
        if eol == -1:
            break
        line = data[pos:eol].split(b";")[0].strip()
        try:
            size = int(line, 16)
        except ValueError:
            break
        pos = eol + 2
        if size == 0:
            # skip trailers to final CRLF
            end = data.find(b"\r\n\r\n", pos)
            pos = (end + 4) if end != -1 else len(data)
            break
        body += data[pos:pos + size]
        pos += size + 2
    return bytes(body), pos

def parse_http(data):
    """Parse HTTP messages from a byte stream.

    Returns list of (kind, first_line, headers, body) where kind is
    'request' or 'response'.
    """
    out = []
    pos = 0
    while True:
        hend = data.find(b"\r\n\r\n", pos)
        if hend == -1:
            break
        head = data[pos:hend].decode("latin-1", "replace")
        lines = head.split("\r\n")
        first = lines[0] if lines else ""
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                             "OPTIONS ", "PATCH ")):
            kind = "request"
        elif first.startswith("HTTP/"):
            kind = "response"
        else:
            pos = hend + 4
            continue
        body_start = hend + 4
        body = b""
        if "chunked" in hdrs.get("transfer-encoding", ""):
            body, consumed = _dechunk(data[body_start:])
            body_start += consumed
        elif hdrs.get("content-length", "").isdigit():
            n = int(hdrs["content-length"])
            body = data[body_start:body_start + n]
            body_start += n
        out.append((kind, first, hdrs, body))
        pos = body_start
    return out

def tls_clienthello_sni(data):
    """Extract SNI hostnames from TLS ClientHello records in a stream."""
    snis = []
    pos = 0
    while pos + 5 <= len(data):
        ctype, ver, reclen = struct.unpack_from(">BHH", data, pos)
        if ctype != 0x16 or pos + 5 + reclen > len(data):
            # not TLS record: slide one byte (handles streams with preamble)
            pos += 1
            continue
        frag = data[pos + 5:pos + 5 + reclen]
        pos += 5 + reclen
        if len(frag) < 4 or frag[0] != 0x01:      # handshake type ClientHello
            continue
        try:
            p = 4 + 2 + 32                        # hs header + version + random
            if p + 1 > len(frag):
                continue
            sid_len = frag[p]; p += 1 + sid_len
            if p + 2 > len(frag):
                continue
            cs_len = struct.unpack_from(">H", frag, p)[0]; p += 2 + cs_len
            if p + 1 > len(frag):
                continue
            cm_len = frag[p]; p += 1 + cm_len
            if p + 2 > len(frag):
                continue
            ext_len = struct.unpack_from(">H", frag, p)[0]; p += 2
            end = p + ext_len
            while p + 4 <= end and p + 4 <= len(frag):
                etype, elen = struct.unpack_from(">HH", frag, p)
                p += 4
                if etype == 0 and p + elen <= len(frag):   # server_name
                    q = p + 2
                    while q + 3 <= p + elen:
                        ntype = frag[q]
                        nlen = struct.unpack_from(">H", frag, q + 1)[0]
                        if ntype == 0:
                            snis.append(frag[q + 3:q + 3 + nlen].decode("latin-1", "replace"))
                        q += 3 + nlen
                p += elen
        except (struct.error, IndexError):
            continue
    return snis

def _dns_name(data, off):
    labels = []
    jumped = False
    end = off
    for _ in range(64):                           # loop guard
        if off >= len(data):
            return None, off
        ln = data[off]
        if ln & 0xC0 == 0xC0:                     # compression pointer
            if off + 1 >= len(data):
                return None, off
            ptr = struct.unpack_from(">H", data, off)[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
        elif ln == 0:
            if not jumped:
                end = off + 1
            break
        else:
            off += 1
            labels.append(data[off:off + ln].decode("latin-1", "replace"))
            off += ln
    return ".".join(labels), end

def parse_dns(data):
    """Parse a DNS message. Returns (queries, answers) as name lists."""
    if len(data) < 12:
        return [], []
    _id, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
    off = 12
    queries, answers = [], []
    for _ in range(qd):
        name, off = _dns_name(data, off)
        if name is None or off + 4 > len(data):
            break
        queries.append(name)
        off += 4
    for _ in range(an):
        name, off = _dns_name(data, off)
        if name is None or off + 10 > len(data):
            break
        rdlen = struct.unpack_from(">H", data, off + 8)[0]
        answers.append(name)
        off += 10 + rdlen
    return queries, answers

# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

BEACON_MIN_SAMPLES = 6

def triage(packets, streams):
    findings = []
    by_src_ports = defaultdict(set)      # (src, dst) -> set(dport)
    conns = defaultdict(list)           # (src, dst) -> [ts]
    talkers = defaultdict(int)          # ip -> bytes
    udp_dns_queries = []
    snis = []
    http_items = []

    for p in packets:
        talkers[p.src] += p.length
        talkers[p.dst] += p.length
        if p.proto == "TCP" and p.flags & 0x02 and not p.flags & 0x10:
            by_src_ports[(p.src, p.dst)].add(p.dport)
        if p.proto == "TCP":
            conns[(p.src, p.dst)].append(p.ts)
        if p.proto == "UDP" and (p.sport == 53 or p.dport == 53):
            q, _a = parse_dns(p.payload)
            udp_dns_queries.extend(q)

    for s in streams.values():
        s.reassemble()
        for d in (0, 1):
            data = s.data[d]
            if not data:
                continue
            if data.startswith(b"\x16\x03"):
                snis.extend(tls_clienthello_sni(data))
            for kind, first, hdrs, body in parse_http(data):
                http_items.append((s.key, d, kind, first, len(body)))

    # port scan: one source touching many ports on one host
    for (src, dst), ports in by_src_ports.items():
        if len(ports) >= 10:
            findings.append(("high",
                f"possible port scan: {src} -> {dst} probed {len(ports)} ports"))

    # beaconing: periodic connections between a pair
    for (src, dst), times in conns.items():
        times = sorted(times)
        if len(times) >= BEACON_MIN_SAMPLES:
            gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
            if len(gaps) >= BEACON_MIN_SAMPLES - 1:
                mean = sum(gaps) / len(gaps)
                var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
                cv = (var ** 0.5) / mean if mean else 999
                if cv < 0.25 and mean > 1.0:
                    findings.append(("medium",
                        f"possible beaconing: {src} -> {dst} every ~{mean:.1f}s "
                        f"(CV={cv:.2f}, {len(times)} conns)"))

    # large transfers
    for s in streams.values():
        if s.bytes >= 1_000_000:
            (a, b) = s.key
            findings.append(("medium",
                f"large transfer: {a[0]}:{a[1]} <-> {b[0]}:{b[1]} "
                f"{s.bytes} bytes in {s.packets} packets"))

    top = sorted(talkers.items(), key=lambda kv: -kv[1])[:5]
    return findings, {"top_talkers": top, "snis": sorted(set(snis)),
                      "dns_queries": sorted(set(udp_dns_queries)),
                      "http": http_items}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hand-rolled pcap forensics: libpcap/pcapng, TCP "
                    "reassembly, HTTP/TLS-SNI/DNS extraction, triage. Stdlib only.")
    ap.add_argument("pcap", help="capture file (.pcap / .pcapng)")
    ap.add_argument("--carve", metavar="DIR",
                    help="dump every reassembled TCP stream to DIR")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of the report")
    args = ap.parse_args(argv)

    try:
        raw, fmt = read_packets(args.pcap)
    except PcapError as e:
        print(f"error: {e}", file=sys.stderr)
        print("VERDICT: WORTH-A-LOOK -- unreadable capture")
        return 0

    packets = []
    skipped = 0
    for ts, linktype, frame in raw:
        p = dissect(ts, linktype, frame)
        if p is None:
            skipped += 1
        else:
            packets.append(p)

    streams = {}
    for p in packets:
        if p.proto != "TCP":
            continue
        k = stream_key(p)
        streams.setdefault(k, Stream(k)).add(p)

    findings, info = triage(packets, streams)

    if args.carve:
        os.makedirs(args.carve, exist_ok=True)
        for i, s in enumerate(streams.values()):
            for d in (0, 1):
                (a, b) = (s.key[d], s.key[1 - d])
                fn = f"stream{i:03d}_{a[0]}_{a[1]}-to-{b[0]}_{b[1]}.bin"
                with open(os.path.join(args.carve, fn), "wb") as f:
                    f.write(s.data[d])

    n_high = sum(1 for sev, _ in findings if sev == "high")
    verdict = "SUSPICIOUS" if n_high else ("WORTH-A-LOOK" if findings else "CLEAN")
    why = ("high-severity indicators" if n_high
           else ("triage notes" if findings else "no indicators"))

    if args.json:
        import json
        print(json.dumps({
            "file": args.pcap, "format": fmt,
            "packets": len(packets), "skipped": skipped,
            "streams": len(streams),
            "findings": [{"severity": s, "text": t} for s, t in findings],
            "snis": info["snis"], "dns_queries": info["dns_queries"],
            "verdict": verdict,
        }, indent=2))
        return 0

    print(f"file: {args.pcap}  ({fmt}, {len(packets)} packets, {skipped} skipped)")
    print(f"tcp streams: {len(streams)}")
    for s in streams.values():
        (a, b) = s.key
        d0, d1 = len(s.data[0]), len(s.data[1])
        print(f"  {a[0]}:{a[1]} <-> {b[0]}:{b[1]}  "
              f"pkts={s.packets} bytes={s.bytes} retrans={s.retransmits} "
              f"syn={s.syn_seen} fin={s.fin_seen} dir0={d0}B dir1={d1}B")
    if info["http"]:
        print("http:")
        for key, d, kind, first, blen in info["http"]:
            ep = key[d]
            print(f"  [{kind}] {ep[0]}:{ep[1]}: {first}  (body {blen}B)")
    if info["snis"]:
        print("tls sni: " + ", ".join(info["snis"]))
    if info["dns_queries"]:
        print("dns queries: " + ", ".join(info["dns_queries"]))
    if info["top_talkers"]:
        print("top talkers:")
        for ip, n in info["top_talkers"]:
            print(f"  {ip}: {n} bytes")
    if findings:
        print("findings:")
        for sev, text in findings:
            print(f"  {'[!!]' if sev == 'high' else '[!]'} {text}")
    print(f"VERDICT: {verdict} -- {why}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
