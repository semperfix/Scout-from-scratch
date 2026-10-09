"""Hand-rolled tar parser. Zero dependencies beyond stdlib (struct only).

Handles: v7, USTAR, GNU ('L'/'K' longname/longlink), pax extended headers ('x'),
pax global headers ('g'), base-256 (GNU binary) numeric fields, ustar prefix
joining, checksum verification, symlink/hardlink/dir members.

Checksum is verified per header: tampered headers raise TarError.
Data offsets point into the original buffer so big blobs are never copied.
"""

import struct

BLOCK = 512


class TarError(Exception):
    pass


def _octal(buf: bytes, field: str) -> int:
    """Parse a tar numeric field: octal ASCII, or GNU base-256 if high bit set."""
    b = buf.rstrip(b"\x00").rstrip(b" ")
    if not b:
        return 0
    if b[0] & 0x80:
        # base-256 big-endian. 0x80 in the top byte is just the marker bit
        # (clear it); 0xFF means a negative two's-complement value.
        v = int.from_bytes(b, "big")
        if b[0] == 0xFF:
            v -= 1 << (8 * len(b))
        else:
            v &= (1 << (8 * len(b) - 1)) - 1
        return v
    try:
        return int(b.decode("ascii").strip("\x00 "), 8)
    except ValueError:
        raise TarError(f"bad octal in {field}: {b!r}")


def _str(buf: bytes) -> str:
    return buf.split(b"\x00", 1)[0].decode("utf-8", "replace")


class TarMember:
    __slots__ = ("name", "size", "mtime", "mode", "uid", "gid", "uname",
                 "gname", "typeflag", "linkname", "data_off", "pax")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))
        self.pax = kw.get("pax") or {}

    @property
    def isreg(self):
        return self.typeflag in ("0", "\x00")

    @property
    def isdir(self):
        return self.typeflag == "5"

    @property
    def issym(self):
        return self.typeflag == "2"

    @property
    def ishard(self):
        return self.typeflag == "1"


def _parse_pax(data: bytes) -> dict:
    """Parse pax extended-header records: '<len> <key>=<value>\\n' *."""
    out = {}
    i = 0
    while i < len(data):
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        line = data[i:nl]
        i = nl + 1
        if not line:
            continue
        sp = line.find(b" ")
        eq = line.find(b"=", sp + 1)
        if sp < 0 or eq < 0:
            continue
        try:
            decl = int(line[:sp])
        except ValueError:
            continue
        if decl != len(line) + 1:  # declared length covers the trailing \n
            continue
        out[line[sp + 1:eq].decode("utf-8", "replace")] = \
            line[eq + 1:].decode("utf-8", "replace")
    return out


def parse(data: bytes, *, verify_checksum: bool = True) -> list:
    """Parse a tar archive; return list[TarMember] with data_off into `data`."""
    members = []
    n = len(data)
    off = 0
    pending_longname = None
    pending_longlink = None
    pending_pax = {}
    global_pax = {}
    saw_end = False  # at least one zero block = proper end-of-archive marker

    while off + BLOCK <= n:
        hdr = data[off:off + BLOCK]
        if hdr == b"\x00" * BLOCK:
            saw_end = True
            break

        if verify_checksum:
            stored = hdr[148:156]
            try:
                want = _octal(stored, "chksum")
            except TarError:
                raise TarError(f"bad checksum field at offset {off}")
            calc = sum(hdr[:148]) + 8 * 0x20 + sum(hdr[156:])
            if calc != want:
                raise TarError(
                    f"checksum mismatch at offset {off}: stored {want:o}, computed {calc:o}")

        name = _str(hdr[0:100])
        mode = _octal(hdr[100:108], "mode")
        uid = _octal(hdr[108:116], "uid")
        gid = _octal(hdr[116:124], "gid")
        size = _octal(hdr[124:136], "size")
        mtime = _octal(hdr[136:148], "mtime")
        typeflag = chr(hdr[156])
        linkname = _str(hdr[157:257])
        magic = hdr[257:263]
        uname = _str(hdr[265:297])
        gname = _str(hdr[297:329])
        prefix = _str(hdr[345:500])

        if magic.startswith(b"ustar") and prefix:
            name = prefix + "/" + name

        data_off = off + BLOCK
        data_end = data_off + size
        if data_end > n:
            raise TarError(f"truncated data for {name!r} at offset {off}")
        raw = data[data_off:data_end]

        # pax path/linkpath/size overrides win over the header fields
        eff_pax = dict(global_pax)
        eff_pax.update(pending_pax)
        if "path" in eff_pax:
            name = eff_pax["path"]
        if "linkpath" in eff_pax:
            linkname = eff_pax["linkpath"]
        if "size" in eff_pax:
            try:
                size = int(eff_pax["size"])
                raw = raw[:size]
            except ValueError:
                pass
        if "mtime" in eff_pax:
            try:
                mtime = int(float(eff_pax["mtime"]))
            except ValueError:
                pass
        if "uname" in eff_pax:
            uname = eff_pax["uname"]
        if "gname" in eff_pax:
            gname = eff_pax["gname"]

        if pending_longname is not None:
            name = pending_longname
            pending_longname = None
        if pending_longlink is not None:
            linkname = pending_longlink
            pending_longlink = None

        if typeflag == "L":          # GNU longname: data is next member's name
            pending_longname = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        elif typeflag == "K":       # GNU longlink
            pending_longlink = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        elif typeflag == "x":       # pax extended header for next member
            pending_pax = _parse_pax(raw)
        elif typeflag == "g":       # pax global header
            global_pax.update(_parse_pax(raw))
        else:
            members.append(TarMember(
                name=name, size=size, mtime=mtime, mode=mode, uid=uid,
                gid=gid, uname=uname, gname=gname, typeflag=typeflag,
                linkname=linkname, data_off=data_off, pax=eff_pax))

        pending_pax = {} if typeflag != "x" else pending_pax
        off = data_off + ((size + BLOCK - 1) // BLOCK) * BLOCK

    if not saw_end:
        raise TarError("unexpected EOF: no end-of-archive marker "
                       "(truncated download?)")
    return members


def read_data(data: bytes, m: TarMember) -> bytes:
    return data[m.data_off:m.data_off + m.size]
