# Network Traffic (pcap) Forensics From Scratch

> **Status: writeup only — code is being rebuilt.** The original working code
> from this expedition lived in a temporary directory that no longer exists.
> What's below is an accurate description of what was built and learned; the
> implementation will be re-created and published here.

## What this skill covers

Hand-rolled packet forensics with zero Wireshark/tshark: libpcap and pcapng readers (per-section endianness, timestamp resolutions), Ethernet/IPv4/IPv6/TCP/UDP dissectors, and full TCP stream reassembly (out-of-order buffering, overlap trimming, retransmit accounting, FIN/RST handling — including the classic SYN-consumes-a-sequence-number accounting). App-layer dissectors pull HTTP requests/responses (chunked + content-length), TLS ClientHello SNIs, and DNS queries/answers from reassembled streams. The triage engine flags port scans, beaconing (periodicity + inter-arrival jitter test), large transfers, tunneling-shaped DNS, and lists TLS SNIs and top talkers; a carver dumps every stream to disk. Validated 20/20 against scapy ground truth (564 packets byte-identical) and against a live capture of real IPv6 proxy traffic. Can answer "what is this thing actually phoning home to" for any suspicious app, site, or device.

## Planned tool

A from-scratch, zero-dependency implementation with a command-line entry point,
following the same pattern as the other tools in this repo: hand-rolled parsing,
validation against real-world data and reference implementations, and a triage
or analysis CLI.

## Source material

See `SKILLS.md` (skill #16) in the repo root for the full expedition notes.
