#!/usr/bin/env python3
"""Fuzzing harnesses: thin adapters from raw bytes to my parser entry points."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXP29 = os.path.expanduser("~/workspace/learning/expedition-29-certforensics")
EXP19 = os.path.expanduser("~/workspace/learning/expedition-19-peforensics")
sys.path.insert(0, EXP29)
sys.path.insert(0, EXP19)

import der  # noqa: E402
from der import DERError  # noqa: E402
import peparse  # noqa: E402
from peparse import PEError  # noqa: E402


def target_der(data: bytes):
    der.parse_der(bytes(data))


def target_pe(data: bytes):
    # PE takes a path; give each forked child its own temp file
    path = f"/tmp/minifuzz_pe_{os.getpid()}.bin"
    with open(path, "wb") as f:
        f.write(data)
    try:
        peparse.PE(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


DER_DICT = [
    b"\x30", b"\x31", b"\x02", b"\x06", b"\x05\x00", b"\x0c", b"\x13",
    b"\x17", b"\x18", b"\x03", b"\x04", b"\x81", b"\x82", b"\x83",
    b"\xa0", b"\xa1", b"\xa2", b"\xa3",
    bytes.fromhex("2a864886f70d"),  # rsaEncryption OID prefix
    bytes.fromhex("2b06010401"),     # enterprises arc
]

PE_DICT = [
    b"MZ", b"PE\x00\x00", b"\x0b\x01", b"\x0b\x02",
    b".text\x00\x00\x00", b".rsrc\x00\x00\x00",
    b"\x4c\x01",  # i386
    b"\x64\x86",  # amd64
]
