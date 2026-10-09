#!/usr/bin/env python3
"""make_fixtures.py - Craft forensic pcap fixtures with struct (no scapy).

  fixtures/http.pcap  - libpcap LE: TCP handshake (SYN/SYN-ACK/ACK) +
                        HTTP GET + HTTP/1.1 200 response, then a UDP DNS
                        query for example.com
  fixtures/dns.pcapng  - pcapng: a single DNS query (exercises the
                        section-header/IDB/EPB path)

All checksums are zeroed (we don't validate them); sequence numbers are
realistic so reassembly can be verified.
"""
import os
import struct

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

CLIENT_MAC = bytes.fromhex("001122334455")
SERVER_MAC = bytes.fromhex("66778899aabb")
CLIENT_IP = bytes([192, 168, 1, 10])
SERVER_IP = bytes([93, 184, 216, 34])      # example.com
DNS_IP = bytes([8, 8, 8, 8])

def eth(src_mac, dst_mac, payload, etype=0x0800):
    return dst_mac + src_mac + struct.pack(">H", etype) + payload

def ip4(src, dst, proto, payload):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234,
                    0x4000, 64, proto, 0, src, dst)
    return h + payload

def tcp(sport, dport, seq, ack, flags, payload=b""):
    h = struct.pack(">HHIIHHHH", sport, dport, seq, ack,
                    (5 << 12) | flags, 64240, 0, 0)
    return h + payload

SYN, ACK, PSH = 0x02, 0x10, 0x08

def dns_query(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    hdr = struct.pack(">HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
    return hdr + q + struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN

def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload

HTTP_REQ = (b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: pcapcheck-fixture\r\n"
            b"\r\n")
HTTP_RESP = (b"HTTP/1.1 200 OK\r\n"
             b"Content-Type: text/plain\r\n"
             b"Content-Length: 13\r\n"
             b"\r\n"
             b"Hello, world!")

def pcap_packet(ts_sec, ts_usec, frame):
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame

def main():
    os.makedirs(FIX, exist_ok=True)

    pkts = []
    t = 1_700_000_000
    c_seq, s_seq = 1000, 5000
    # 1. SYN
    pkts.append((t, 0, eth(CLIENT_MAC, SERVER_MAC,
        ip4(CLIENT_IP, SERVER_IP, 6, tcp(43210, 80, c_seq, 0, SYN)))))
    # 2. SYN-ACK
    pkts.append((t, 1000, eth(SERVER_MAC, CLIENT_MAC,
        ip4(SERVER_IP, CLIENT_IP, 6, tcp(80, 43210, s_seq, c_seq + 1, SYN | ACK)))))
    # 3. ACK
    pkts.append((t, 2000, eth(CLIENT_MAC, SERVER_MAC,
        ip4(CLIENT_IP, SERVER_IP, 6, tcp(43210, 80, c_seq + 1, s_seq + 1, ACK)))))
    # 4. HTTP GET (split across 2 segments to exercise reassembly)
    half = len(HTTP_REQ) // 2
    pkts.append((t, 3000, eth(CLIENT_MAC, SERVER_MAC,
        ip4(CLIENT_IP, SERVER_IP, 6,
            tcp(43210, 80, c_seq + 1, s_seq + 1, PSH | ACK, HTTP_REQ[:half])))))
    pkts.append((t, 3100, eth(CLIENT_MAC, SERVER_MAC,
        ip4(CLIENT_IP, SERVER_IP, 6,
            tcp(43210, 80, c_seq + 1 + half, s_seq + 1, PSH | ACK, HTTP_REQ[half:])))))
    # 5. HTTP response
    pkts.append((t, 4000, eth(SERVER_MAC, CLIENT_MAC,
        ip4(SERVER_IP, CLIENT_IP, 6,
            tcp(80, 43210, s_seq + 1, c_seq + 1 + len(HTTP_REQ), PSH | ACK, HTTP_RESP)))))
    # 6. DNS query over UDP
    dq = dns_query("example.com")
    pkts.append((t, 5000, eth(CLIENT_MAC, SERVER_MAC,
        ip4(CLIENT_IP, DNS_IP, 17, udp(53531, 53, dq)))))

    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(os.path.join(FIX, "http.pcap"), "wb") as f:
        f.write(global_hdr)
        for ts_s, ts_u, frame in pkts:
            f.write(pcap_packet(ts_s, ts_u, frame))

    # --- pcapng: one DNS query ---
    dq = dns_query("beacon.evil.example")
    frame = eth(CLIENT_MAC, SERVER_MAC, ip4(CLIENT_IP, DNS_IP, 17, udp(53532, 53, dq)))
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)   # magic + ver + section len (-1 = unspec)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 1, 0, 0)                # linktype=eth, reserved, snaplen
    idb = struct.pack("<II", 0x00000001, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    epb_body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame
    epb_body += b"\x00" * ((4 - len(frame) % 4) % 4)
    epb = struct.pack("<II", 0x00000006, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
    with open(os.path.join(FIX, "dns.pcapng"), "wb") as f:
        f.write(shb + idb + epb)
    print("wrote fixtures/http.pcap, dns.pcapng")

if __name__ == "__main__":
    main()
