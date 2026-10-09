#!/usr/bin/env python3
"""fzip -- the compression workbench CLI.

  fzip analyze FILE        entropy + head-to-head codec bench
  fzip gzdecode FILE.gz    decode a gzip file with the hand-rolled DEFLATE
  fzip gzencode FILE       encode with my fixed-Huffman DEFLATE -> real .gz
  fzip roundtrip FILE      all-codec roundtrip integrity check
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from entropy import bench, report, shannon_entropy
from deflate import decompress_gzip, decompress_raw, compress_fixed, gzip_wrap
from lzw import compress as lzw_c, decompress as lzw_d
from huffman import HuffmanEncoder
from bits import BitWriter, BitReader
from lz77 import tokenize, detokenize


def cmd_analyze(path):
    with open(path, 'rb') as f:
        data = f.read()
    print(report(bench(data, label=path)))


def cmd_gzdecode(path):
    with open(path, 'rb') as f:
        raw = f.read()
    out = decompress_gzip(raw)
    sys.stdout.buffer.write(out)
    print(f"\n# decoded {len(out)} bytes OK (CRC+ISIZE verified)",
          file=sys.stderr)


def cmd_gzencode(path):
    with open(path, 'rb') as f:
        data = f.read()
    raw = compress_fixed(data)
    import binascii
    gz = gzip_wrap(raw, fname=os.path.basename(path))
    # trailer: CRC32 + ISIZE
    gz += (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
    gz += (len(data) & 0xFFFFFFFF).to_bytes(4, 'little')
    sys.stdout.buffer.write(gz)
    print(f"# encoded {len(data)} -> {len(gz)} bytes", file=sys.stderr)


def cmd_roundtrip(path):
    with open(path, 'rb') as f:
        data = f.read()
    ok = True

    def check(name, dec, enc_bytes):
        global_ok = True
        try:
            rt = dec(enc_bytes)
        except Exception as e:  # noqa: BLE001
            print(f"  {name:18s} FAIL ({e})")
            return False
        good = rt == data
        print(f"  {name:18s} {'OK' if good else 'MISMATCH'}")
        return good

    # Huffman
    enc = HuffmanEncoder(data)
    w = BitWriter()
    enc.encode(data, w)
    from huffman import HuffmanDecoder
    dec = HuffmanDecoder(enc.codes)
    r = BitReader(w.bytes())
    rt = bytes(dec.decode_symbol(r) for _ in range(len(data)))
    print(f"  {'huffman':18s} {'OK' if rt == data else 'MISMATCH'}")
    ok &= (rt == data)

    # LZW
    ok &= check('lzw', lzw_d, lzw_c(data))

    # LZ77
    ok &= check('lz77', detokenize, tokenize(data))

    # my DEFLATE (raw), verified by *my* decoder
    ok &= check('deflate-fixed', decompress_raw, compress_fixed(data))

    # my DEFLATE, verified by *system* zlib -- the real test
    import zlib
    try:
        rt = zlib.decompress(compress_fixed(data), -15)
        good = rt == data
    except Exception as e:  # noqa: BLE001
        good = False
        print(f"  zlib-of-mine      FAIL ({e})")
    if good:
        print(f"  {'zlib-of-mine':18s} OK")
    ok &= good

    print("ALL OK" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, path = argv[1], argv[2]
    if cmd == 'analyze':
        cmd_analyze(path)
    elif cmd == 'gzdecode':
        cmd_gzdecode(path)
    elif cmd == 'gzencode':
        cmd_gzencode(path)
    elif cmd == 'roundtrip':
        return cmd_roundtrip(path)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
