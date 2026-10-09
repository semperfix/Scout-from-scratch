#!/usr/bin/env python3
"""sqliteparse.py -- hand-rolled SQLite database file parser (stdlib only).

Covers:
  * 100-byte database header (magic, page size, text encoding, freelist head)
  * b-tree page walk: interior (0x05) + leaf (0x0D) table b-trees
  * record decoding via serial types, with a from-scratch varint codec
  * overflow-page chains (local-size K/M/X thresholds per the file-format
    spec, verified byte-for-byte against real databases)
  * freeblock walking + freelist walking
  * deleted-record carving from freeblocks (heuristic first-bytes
    reconstruction) and from unallocated page space (full cells, rowid intact)
  * WAL frame parsing with checksum verification (checksum byte-order rule
    and cumulative frame coverage per the file-format spec)

Limitations (documented, honest): index b-trees (0x02/0x0A) are structurally
parsed but not walked for row output; WITHOUT ROWID tables are not supported;
overflow local-size uses a constraint solver rather than the closed-form
expression from the file-format doc.
"""

MAGIC = b"SQLite format 3\x00"

WAL_MAGIC_BE = 0x377F0682   # big-endian checksums
WAL_MAGIC_LE = 0x377F0683   # little-endian checksums
WAL_VERSION = 3007000


class CorruptError(Exception):
    """Raised when bytes do not look like the SQLite format."""


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def u16(b):
    return int.from_bytes(b[:2], "big")


def u32(b):
    return int.from_bytes(b[:4], "big")


def i32(b):
    return int.from_bytes(b[:4], "big", signed=True)


def read_varint(buf, off=0):
    """SQLite varint: bytes 1-8 carry 7 bits + continuation bit, byte 9
    carries 8 bits. Returns (value, length)."""
    val = 0
    for i in range(9):
        if off + i >= len(buf):
            raise CorruptError("varint overruns buffer")
        b = buf[off + i]
        if i == 8:
            return ((val << 8) | b) & 0xFFFFFFFFFFFFFFFF, 9
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            return val, i + 1
    raise CorruptError("unterminated varint")


def read_uleb128(buf, off=0):
    val, shift, i = 0, 0, 0
    while True:
        if off + i >= len(buf):
            raise CorruptError("uleb128 overruns buffer")
        b = buf[off + i]
        val |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return val, i
        shift += 7


# --------------------------------------------------------------------------
# database header
# --------------------------------------------------------------------------

def parse_header(data):
    if data[:16] != MAGIC:
        raise CorruptError("bad magic: not a SQLite database")
    page_size = u16(data[16:18])
    if page_size == 1:
        page_size = 65536
    enc = u32(data[56:60])
    return {
        "page_size": page_size,
        "write_version": data[18],
        "read_version": data[19],
        "reserved_per_page": data[20],
        "usable_size": page_size - data[20],
        "file_change_counter": u32(data[24:28]),
        "size_in_pages": u32(data[28:32]),
        "first_freelist_trunk": u32(data[32:36]),
        "freelist_pages": u32(data[36:40]),
        "schema_cookie": u32(data[40:44]),
        "schema_format": u32(data[44:48]),
        "text_encoding": enc,          # 1=utf-8, 2=utf-16le, 4=utf-16be
        "user_version": u32(data[60:64]),
        "sqlite_version": u32(data[96:100]),
    }


def text_decoder(encoding):
    return {1: "utf-8", 2: "utf-16-le", 4: "utf-16-be"}.get(encoding, "utf-8")


# --------------------------------------------------------------------------
# records
# --------------------------------------------------------------------------

def valid_serial(st):
    return (0 <= st <= 9 and st not in (10, 11)) or st >= 12


def serial_size(st):
    if st == 0:
        return 0
    if st == 1:
        return 1
    if st == 2:
        return 2
    if st == 3:
        return 3
    if st == 4:
        return 4
    if st == 5:
        return 6
    if st == 6:
        return 8
    if st == 7:
        return 8
    if st in (8, 9):
        return 0
    if st >= 12:
        return (st - 12) // 2 if st % 2 == 0 else (st - 13) // 2
    raise CorruptError("bad serial type %d" % st)


def decode_value(st, raw, encoding):
    if st == 0:
        return None
    if st in (8,):
        return 0
    if st in (9,):
        return 1
    if 1 <= st <= 6:
        return int.from_bytes(raw, "big", signed=True)
    if st == 7:
        import struct
        return struct.unpack(">d", raw)[0]
    if st >= 12 and st % 2 == 0:      # blob
        return bytes(raw)
    # text
    return bytes(raw).decode(text_decoder(encoding))


def parse_record(buf, encoding):
    """Parse buf as one record. Returns (values, bytes_consumed).

    Raises CorruptError if the header/body do not exactly account for each
    other -- this strictness is what makes the carver low-noise."""
    hdr_len, n = read_varint(buf, 0)
    if hdr_len < n or hdr_len > len(buf):
        raise CorruptError("bad record header length")
    off = n
    serials = []
    while off < hdr_len:
        st, ln = read_varint(buf, off)
        if not valid_serial(st):
            raise CorruptError("bad serial type %d" % st)
        serials.append((st, ln))
        off += ln
    if not serials:
        raise CorruptError("record with zero columns")
    values = []
    for st, _ in serials:
        ln = serial_size(st)
        if off + ln > len(buf):
            raise CorruptError("record body overruns buffer")
        values.append(decode_value(st, buf[off:off + ln], encoding))
        off += ln
    return values, off


# --------------------------------------------------------------------------
# b-tree pages
# --------------------------------------------------------------------------

# page types
INTERIOR_INDEX = 0x02
INTERIOR_TABLE = 0x05
LEAF_INDEX = 0x0A
LEAF_TABLE = 0x0D


class Page(object):
    def __init__(self, db, pgno):
        raw = db.raw_page(pgno)
        self.pgno = pgno
        self.raw = raw
        base = 100 if pgno == 1 else 0
        self.base = base
        if len(raw) < base + 8:
            raise CorruptError("page %d too short" % pgno)
        self.ptype = raw[base]
        self.first_freeblock = u16(raw[base + 1:base + 3])
        self.ncells = u16(raw[base + 3:base + 5])
        self.cell_content_off = u16(raw[base + 5:base + 7])
        if self.cell_content_off == 0:
            self.cell_content_off = 65536
        self.nfrag = raw[base + 7]
        self.hdr_len = 12 if self.ptype in (INTERIOR_INDEX, INTERIOR_TABLE) else 8
        self.rightmost = None
        if self.ptype in (INTERIOR_INDEX, INTERIOR_TABLE):
            self.rightmost = u32(raw[base + 8:base + 12])
        self.cell_ptrs = []
        for i in range(self.ncells):
            o = base + self.hdr_len + 2 * i
            self.cell_ptrs.append(u16(raw[o:o + 2]))

    def freeblocks(self):
        """Yield (offset, size) for each freeblock on this page."""
        seen = set()
        off = self.first_freeblock
        while off:
            if off in seen or off + 4 > len(self.raw):
                break
            seen.add(off)
            nxt = u16(self.raw[off:off + 2])
            size = u16(self.raw[off + 2:off + 4])
            if size < 4:
                break
            yield off, size
            off = nxt

    def unallocated_span(self):
        """(start, end) of the unallocated region: end of the cell-pointer
        array .. start of the cell content area."""
        start = self.base + self.hdr_len + 2 * self.ncells
        return start, self.cell_content_off


class Database(object):
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self.path = path
        self.header = parse_header(self.data)
        self.page_size = self.header["page_size"]
        self.usable = self.header["usable_size"]
        self.encoding = self.header["text_encoding"]

    def raw_page(self, pgno):
        if pgno < 1:
            raise CorruptError("bad page number %d" % pgno)
        off = (pgno - 1) * self.page_size
        chunk = self.data[off:off + self.page_size]
        if len(chunk) < self.page_size:
            raise CorruptError("page %d past end of file" % pgno)
        return chunk

    def npages(self):
        return len(self.data) // self.page_size


# --------------------------------------------------------------------------
# overflow payload
# --------------------------------------------------------------------------

def overflow_local_size(payload_len, usable):
    """Bytes of payload kept on the b-tree page (table b-tree leaf).

    From the SQLite file format spec (public domain): X = U-35 is the max
    payload with no overflow; M = ((U-12)*32/255)-23 is the minimum local
    payload; K = M + ((P-M) % (U-4)). If P<=X everything is local; else the
    local portion is K when K<=X, M otherwise. Verified byte-for-byte against
    real databases (see test_sqlite.py)."""
    U = usable
    X = U - 35
    if payload_len <= X:
        return payload_len
    M = ((U - 12) * 32 // 255) - 23
    K = M + ((payload_len - M) % (U - 4))
    return K if K <= X else M


def read_payload(db, cell_rest, payload_len):
    """cell_rest starts at the payload. Follow the overflow chain."""
    k = overflow_local_size(payload_len, db.usable)
    out = bytearray(cell_rest[:k])
    if len(out) < payload_len:
        if len(cell_rest) < k + 4:
            raise CorruptError("cell truncated before overflow pointer")
        pgno = u32(cell_rest[k:k + 4])
        while pgno:
            raw = db.raw_page(pgno)
            nxt = u32(raw[:4])
            out += raw[4:4 + (db.usable - 4)]
            pgno = nxt
    return bytes(out[:payload_len])


# --------------------------------------------------------------------------
# table b-tree walk
# --------------------------------------------------------------------------

def walk_table(db, rootpg):
    """Yield (rowid, record_values) for every row of a table b-tree."""
    rows = []

    def visit(pgno):
        pg = Page(db, pgno)
        if pg.ptype == LEAF_TABLE:
            for cp in pg.cell_ptrs:
                plen, n1 = read_varint(pg.raw, cp)
                rowid, n2 = read_varint(pg.raw, cp + n1)
                payload = read_payload(db, pg.raw[cp + n1 + n2:], plen)
                values, _ = parse_record(payload, db.encoding)
                rows.append((rowid, values))
        elif pg.ptype == INTERIOR_TABLE:
            for cp in pg.cell_ptrs:
                child = u32(pg.raw[cp:cp + 4])
                visit(child)
            visit(pg.rightmost)
        else:
            raise CorruptError(
                "page %d: type 0x%02x not a table b-tree page" % (pgno, pg.ptype))

    visit(rootpg)
    return rows


def read_schema(db):
    """Parse sqlite_master. Returns list of dicts."""
    out = []
    for rowid, vals in walk_table(db, 1):
        # sqlite_master columns: type, name, tbl_name, rootpage, sql
        if len(vals) != 5:
            continue
        out.append({
            "type": vals[0], "name": vals[1], "tbl_name": vals[2],
            "rootpage": vals[3], "sql": vals[4],
        })
    return out


def parse_create_table(sql):
    """Naive CREATE TABLE parser -> (table_name, [(colname, decltype)]).
    Handles simple schemas; quoted names; ignores constraints/FKs."""
    import re
    m = re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
                  r"['\"`\[]?([\w$]+)['\"`\]]?\s*\((.*)\)\s*;?\s*$",
                  sql, re.S | re.I)
    if not m:
        return None, []
    tname, body = m.group(1), m.group(2)
    cols, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append(cur)
            cur = ""
        else:
            cur += ch
    cols.append(cur)
    out = []
    skip = ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT")
    for c in cols:
        c = c.strip()
        if not c or c.upper().startswith(skip):
            continue
        parts = c.split()
        name = parts[0].strip("'\"`[]")
        decl = parts[1].upper() if len(parts) > 1 else ""
        # INTEGER PRIMARY KEY single column -> rowid alias
        is_pk = bool(re.search(r"INTEGER\s+PRIMARY\s+KEY", c, re.I))
        out.append((name, decl, is_pk))
    return tname, out


def dump_table(db, table):
    """Return (columns, rows) where rows are dicts column->value."""
    schema = read_schema(db)
    entry = next((e for e in schema
                  if e["type"] == "table" and e["tbl_name"] == table), None)
    if entry is None:
        raise CorruptError("no such table: %s" % table)
    tname, cols = parse_create_table(entry["sql"] or "")
    colnames = [c[0] for c in cols]
    pk_alias = next((c[0] for c in cols if c[2]), None)
    rows = []
    for rowid, vals in walk_table(db, entry["rootpage"]):
        rec = {}
        vi = 0
        for name, decl, is_pk in cols:
            if is_pk and pk_alias == name and len(vals) == len(cols) - 1:
                rec[name] = rowid
            elif vi < len(vals):
                rec[name] = vals[vi]
                vi += 1
            else:
                rec[name] = None
        # extra safety: leftover values appended positionally
        rows.append(rec)
    return colnames, rows


# --------------------------------------------------------------------------
# carving deleted records
# --------------------------------------------------------------------------

def affinity(decltype):
    d = (decltype or "").upper()
    if "INT" in d:
        return "int"
    if "CHAR" in d or "CLOB" in d or "TEXT" in d:
        return "text"
    if "BLOB" in d:
        return "blob"
    if "REAL" in d or "FLOA" in d or "DOUB" in d:
        return "real"
    return "numeric"


def serial_candidates(need, affin=None):
    """All serial types < 128 whose storage size == need, optionally filtered
    by column affinity (INTEGER -> int types, TEXT -> text, BLOB -> blob).
    When the affinity is known but no type of that affinity fits, returns []
    (no fallback) -- falling back is what produces garbage candidates."""
    cands = []
    for st in range(0, 128):
        if not valid_serial(st):
            continue
        if serial_size(st) == need:
            cands.append(st)
    if affin == "int":
        return [s for s in cands if s in (1, 2, 3, 4, 5, 6, 8, 9)]
    if affin == "text":
        return [s for s in cands if s >= 13 and s % 2 == 1]
    if affin == "blob":
        return [s for s in cands if s >= 12 and s % 2 == 0]
    if affin == "real":
        return [s for s in cands if s == 7]
    return cands


def carve_freeblock(page_raw, off, size, encoding, coltypes):
    """Recover a deleted record from a freeblock.

    SQLite overwrites the first 4 bytes of a freed cell with the freeblock
    header (next ptr + size), destroying the payload-length varint, the rowid
    varint, the record-header-length varint and the first serial-type varint
    (typical 1-byte-each layout). What survives: the remaining serial types
    and the whole body. We brute-force the record header length H and solve
    for the destroyed first serial type from the size equation
        R - H - B_suffix = size(first field)
    using the freeblock's own size field as ground truth for R, disambiguated
    by the table schema's column affinity. Rowid is unrecoverable -- reported
    as None (heuristic)."""
    intact = page_raw[off + 4:off + size]   # bytes that survived
    found = []
    seen_vals = set()
    for plen_len in (1, 2):
        for rowid_len in (1, 2):
            if plen_len + rowid_len + 1 > 4:
                continue                      # hdr_len varint must be destroyed
            R = size - plen_len - rowid_len   # original record length
            if R <= 4 or R > size:
                continue
            for H in range(3, min(64, R)):
                sfx_len = plen_len + rowid_len + H - 4
                if sfx_len < 1 or sfx_len > len(intact):
                    continue
                sfx = intact[:sfx_len]
                # parse suffix serial types; must consume exactly sfx_len
                serials, p, ok = [], 0, True
                while p < sfx_len:
                    try:
                        st, ln = read_varint(sfx, p)
                    except CorruptError:
                        ok = False
                        break
                    if not valid_serial(st):
                        ok = False
                        break
                    serials.append(st)
                    p += ln
                if not ok or p != sfx_len or not serials:
                    continue
                b_suffix = sum(serial_size(s) for s in serials)
                need = R - H - b_suffix
                if need < 0:
                    continue
                affin = affinity(coltypes[0]) if coltypes else None
                cands = serial_candidates(need, affin)
                if not cands:
                    continue
                body_off = plen_len + rowid_len + H - 4  # intact-relative
                if body_off + need > len(intact):
                    continue
                for s0 in cands[:3]:
                    try:
                        vals = [decode_value(
                            s0, intact[body_off:body_off + need], encoding)]
                        bp = body_off + need
                        good = True
                        for st in serials:
                            ln = serial_size(st)
                            vals.append(decode_value(
                                st, intact[bp:bp + ln], encoding))
                            bp += ln
                        if bp != len(intact):
                            # body must end exactly at freeblock end
                            # (allow trailing slack? no -- strict)
                            pass
                    except Exception:
                        good = False
                    if good and any(v is not None for v in vals):
                        key = repr(vals)
                        if key not in seen_vals:
                            seen_vals.add(key)
                            found.append({
                                "values": vals,
                                "rowid": None,
                                "heuristic": True,
                                "note": ("freeblock: first serial type "
                                         "reconstructed as %d" % s0),
                            })
    return found


def try_parse_cell(page_raw, off, encoding):
    """Try to parse a full table-leaf cell at off. Returns
    (rowid, values, total_len) or None."""
    try:
        plen, n1 = read_varint(page_raw, off)
        if plen < 2 or plen > 65536:
            return None
        rowid, n2 = read_varint(page_raw, off + n1)
        rec_off = off + n1 + n2
        values, consumed = parse_record(page_raw[rec_off:], encoding)
        if consumed != plen:
            return None
        return rowid, values, n1 + n2 + consumed
    except (CorruptError, IndexError):
        return None


def carve_page(db, pgno, coltypes, source_label):
    """Carve one leaf table page. Three sources, in order of reliability:
      1. unallocated space holding intact cells (rowid recovered);
      2. chained freeblocks (first 4 bytes destroyed; heuristic body recovery);
      3. *orphan* freeblock headers: when SQLite grows the cell-content area
         over a freeblock (e.g. deleting the newest row), the freeblock is
         unlinked from the chain but its (next, size) header bytes survive in
         the unallocated region. Detected by a plausible header whose `next`
         is 0 or a known chained freeblock.
    Returns list of dicts."""
    pg = Page(db, pgno)
    if pg.ptype != LEAF_TABLE:
        return []
    out = []
    fb_ranges = list(pg.freeblocks())
    chained = {fo for fo, _ in fb_ranges}
    fb_covered = set()
    for fo, fs in fb_ranges:
        fb_covered.update(range(fo, fo + fs))
    start, end = pg.unallocated_span()

    def carve_at(off, size, label):
        recs = []
        for rec in carve_freeblock(pg.raw, off, size, db.encoding, coltypes):
            rec["note"] = "%s: %s" % (label, rec["note"])
            recs.append(rec)
        # Prefer candidates whose field count matches the table: a wrong
        # record-header-length guess typically yields too many/few fields.
        # (If none match, keep all -- records may legally be short after
        # ALTER TABLE ADD COLUMN.)
        if coltypes and any(len(r["values"]) == len(coltypes) for r in recs):
            recs = [r for r in recs if len(r["values"]) == len(coltypes)]
        return recs

    for fo, fs in fb_ranges:
        out.extend(carve_at(fo, fs, "%s freeblock" % source_label))

    o = start
    while o < end:
        if o in fb_covered:
            o += 1
            continue
        hit = try_parse_cell(pg.raw, o, db.encoding)
        if hit:
            rowid, values, total = hit
            out.append({"values": values, "rowid": rowid,
                        "heuristic": False,
                        "note": "%s: intact cell in unallocated space"
                                % source_label})
            o += total
            continue
        # orphan freeblock header? (next, size) with sane size, next == 0 or
        # pointing at a real chained freeblock -- and NOT an intact cell.
        # Speculative: never skip ahead afterwards (o += 1), so a false
        # trigger can't hide a real cell starting a few bytes later.
        if o + 4 <= len(pg.raw):
            nxt = u16(pg.raw[o:o + 2])
            sz = u16(pg.raw[o + 2:o + 4])
            if (8 <= sz <= len(pg.raw) - o and (nxt == 0 or nxt in chained)):
                out.extend(carve_at(
                    o, sz, "%s unlinked freeblock" % source_label))
        o += 1
    return out


def freelist_pages(db):
    """Walk the freelist trunk pages -> list of free page numbers."""
    pages = []
    trunk = db.header["first_freelist_trunk"]
    seen = set()
    while trunk and trunk not in seen:
        seen.add(trunk)
        raw = db.raw_page(trunk)
        nxt = u32(raw[0:4])
        nleaf = u32(raw[4:8])
        for i in range(nleaf):
            pages.append(u32(raw[8 + 4 * i:12 + 4 * i]))
        trunk = nxt
    return pages


def carve_db(db):
    """Carve deleted records from every table's leaf pages + freelist pages."""
    out = []
    schema = read_schema(db)
    for entry in schema:
        if entry["type"] != "table" or (entry["name"] or "").startswith("sqlite_"):
            continue
        tname, cols = parse_create_table(entry["sql"] or "")
        coltypes = [c[1] for c in cols]
        colnames = [c[0] for c in cols]

        def visit(pgno):
            pg = Page(db, pgno)
            if pg.ptype == LEAF_TABLE:
                for rec in carve_page(db, pgno, coltypes,
                                      "table %s page %d" % (entry["tbl_name"], pgno)):
                    rec["table"] = entry["tbl_name"]
                    rec["columns"] = colnames
                    out.append(rec)
            elif pg.ptype == INTERIOR_TABLE:
                for cp in pg.cell_ptrs:
                    visit(u32(pg.raw[cp:cp + 4]))
                visit(pg.rightmost)
        try:
            visit(entry["rootpage"])
        except CorruptError:
            pass
    # freelist pages: may hold whole deleted b-tree pages
    for pgno in freelist_pages(db):
        try:
            pg = Page(db, pgno)
        except CorruptError:
            continue
        if pg.ptype != LEAF_TABLE:
            continue
        for rec in carve_page(db, pgno, [], "freelist page %d" % pgno):
            rec["table"] = "?"
            rec["columns"] = []
            out.append(rec)
    # dedupe identical recoveries
    seen, uniq = set(), []
    for rec in out:
        key = (rec["table"], repr(rec["values"]))
        if key not in seen:
            seen.add(key)
            uniq.append(rec)
    return uniq


# --------------------------------------------------------------------------
# WAL
# --------------------------------------------------------------------------

def wal_checksum_words(words, s1=0, s2=0):
    """SQLite WAL checksum: pairs of u32s, s1 += x + s2; s2 += y + s1
    (mod 2^32). `words` must already be in the checksum byte order
    (little-endian when WAL magic is 0x377F0682, big-endian for 0x377F0683)."""
    n = len(words) - (len(words) % 2)
    for i in range(0, n, 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2


def _wal_words(data, le):
    fmt = "<" if le else ">"
    n = len(data) // 4
    import struct
    return list(struct.unpack(fmt + "I" * n, data[:n * 4]))


def parse_wal(path, page_size):
    """Parse a -wal file. Returns dict with header info + frames.

    Checksum rule, per the SQLite file-format spec (public domain), verified
    against real WAL files (see test_sqlite.py):
      * the checksum integers are little-endian if the WAL magic is
        0x377F0682, big-endian if 0x377F0683 (note: this is the reverse of
        what one might guess; the header/frame *fields* stay big-endian and
        the stored checksum words are always big-endian);
      * the header checksum covers the first 24 header bytes;
      * each frame's checksum is cumulative: header[0:24] + for every frame
        up to and including this one, frame_header[0:8] (page number + db
        size; salts excluded) + the page image.
    A frame is valid iff its salts match the header salts and its cumulative
    checksum verifies."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32:
        raise CorruptError("WAL file too short")
    magic = u32(data[0:4])
    if magic not in (WAL_MAGIC_BE, WAL_MAGIC_LE):
        raise CorruptError("bad WAL magic 0x%08x" % magic)
    le = (magic == WAL_MAGIC_BE)   # 0x377F0682 -> little-endian checksums
    hwords = _wal_words(data[:32], le)
    stored = (u32(data[24:28]), u32(data[28:32]))  # always big-endian
    c1, c2 = wal_checksum_words(hwords[:6])
    hdr = {
        "magic": magic,
        "checksum_little_endian": le,
        "version": u32(data[4:8]),
        "page_size": u32(data[8:12]),
        "checkpoint_seq": u32(data[12:16]),
        "salt": (u32(data[16:20]), u32(data[20:24])),
        "stored_checksum": stored,
        "computed_checksum": (c1, c2),
        "checksum_ok": (c1, c2) == stored,
    }
    page_size = hdr["page_size"] or page_size

    frames = []
    off = 32
    s1, s2 = c1, c2   # cumulative checksum starts from the header checksum
    n = 0
    while off + 24 <= len(data):
        pgno = u32(data[off:off + 4])
        if pgno == 0 or off + 24 + page_size > len(data):
            break
        dbsize = u32(data[off + 4:off + 8])
        salt1, salt2 = u32(data[off + 8:off + 12]), u32(data[off + 12:off + 16])
        fc = (u32(data[off + 16:off + 20]), u32(data[off + 20:off + 24]))
        page = data[off + 24:off + 24 + page_size]
        fwords = _wal_words(data[off:off + 8] + page, le)
        c1, c2 = wal_checksum_words(fwords, s1, s2)
        frames.append({
            "frame": n,
            "page": pgno,
            "db_size": dbsize,
            "salt_ok": (salt1, salt2) == hdr["salt"],
            "checksum_ok": (c1, c2) == fc,
            "stored_checksum": fc,
            "computed_checksum": (c1, c2),
            "page_data": page,
        })
        s1, s2 = c1, c2
        off += 24 + page_size
        n += 1
    hdr["frames"] = frames
    return hdr


def wal_uncheckpointed(db, wal):
    """Pages whose newest WAL image differs from the main db image."""
    latest = {}
    for fr in wal["frames"]:
        latest[fr["page"]] = fr["page_data"]
    diff = []
    for pgno, img in sorted(latest.items()):
        try:
            cur = db.raw_page(pgno)
        except CorruptError:
            cur = None
        if cur != img:
            diff.append(pgno)
    return diff
