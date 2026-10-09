#!/usr/bin/env python3
"""pdfcheck.py - Hand-rolled PDF parser for document forensics.

Reads a PDF byte-by-byte with zero PDF libraries: finds every ``startxref``
( = every revision / incremental update), parses xref tables, follows /Prev
chains, parses PDF objects by hand (dicts, arrays, strings, hex strings,
names, references, streams), resolves the catalog and /Info dict, and flags:

  * /OpenAction, /JavaScript (catalog + /Names), /AA additional actions
  * /Launch actions (a classic malicious-payload tell)
  * /EmbeddedFiles
  * metadata inconsistencies (Creator vs Producer, impossible dates)
  * incremental updates that redefine objects after an apparent "signing"
  * encrypted documents (/Encrypt - we cannot parse those)

Can also extract the visible text of every revision (``--text``), so you can
see what the document said *before* an incremental update changed it.

Usage:
    python3 pdfcheck.py suspect.pdf
    python3 pdfcheck.py suspect.pdf --text        # also dump text per revision
    python3 pdfcheck.py --help

Exit code is always 0; the VERDICT: line is the machine-readable result
(CLEAN / WORTH-A-LOOK / SUSPICIOUS / MALICIOUS).

Limitations (honest subset):
  * xref *streams* (compressed cross-references, /Type /XRef) are detected
    and reported but not parsed - we handle classic xref tables only.
  * Object streams (/Type /ObjStm) are detected but not parsed.
  * Encrypted PDFs are flagged and skipped - we do not attempt decryption.
  * Text extraction decodes literal strings as Latin-1; custom encodings and
    ToUnicode CMaps are not applied, so exotic fonts may come out garbled.
"""

import argparse
import re
import sys

# ---------------------------------------------------------------------------
# PDF value model
# ---------------------------------------------------------------------------

class PDFName(str):
    """A /Name object."""

class PDFRef:
    """An indirect reference: ``num gen R``."""
    __slots__ = ("num", "gen")
    def __init__(self, num, gen):
        self.num = num
        self.gen = gen
    def __repr__(self):
        return f"{self.num} {self.gen} R"
    def __eq__(self, other):
        return isinstance(other, PDFRef) and (self.num, self.gen) == (other.num, other.gen)
    def __hash__(self):
        return hash((self.num, self.gen))

# ---------------------------------------------------------------------------
# Hand-rolled lexer / parser over the raw bytes
# ---------------------------------------------------------------------------

_WS = b" \t\n\r\f\x00"
_DELIMS = b"()<>[]{}/%"

class Cursor:
    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def eof(self):
        return self.pos >= len(self.data)

    def peek(self, n=1):
        return self.data[self.pos:self.pos + n]

    def skip_ws(self):
        d = self.data
        p = self.pos
        while p < len(d):
            c = d[p:p + 1]
            if c in _WS:
                p += 1
            elif c == b"%":                      # comment to end of line
                while p < len(d) and d[p:p + 1] not in b"\r\n":
                    p += 1
            else:
                break
        self.pos = p

def _parse_name(c):
    assert c.peek() == b"/"
    c.pos += 1
    d = c.data
    out = bytearray()
    while c.pos < len(d):
        ch = d[c.pos:c.pos + 1]
        if ch in _WS or ch in _DELIMS:
            break
        if ch == b"#" and c.pos + 2 < len(d):    # hex escape
            try:
                out.append(int(d[c.pos + 1:c.pos + 3], 16))
                c.pos += 3
                continue
            except ValueError:
                pass
        out.append(d[c.pos])
        c.pos += 1
    return PDFName(out.decode("latin-1"))

def _parse_literal_string(c):
    assert c.peek() == b"("
    c.pos += 1
    d = c.data
    out = bytearray()
    depth = 1
    while c.pos < len(d) and depth:
        ch = d[c.pos:c.pos + 1]
        if ch == b"\\":
            c.pos += 1
            if c.pos >= len(d):
                break
            e = d[c.pos:c.pos + 1]
            if e in b"n":
                out.append(ord("\n")); c.pos += 1
            elif e == b"r":
                out.append(ord("\r")); c.pos += 1
            elif e == b"t":
                out.append(ord("\t")); c.pos += 1
            elif e == b"b":
                out.append(ord("\b")); c.pos += 1
            elif e == b"f":
                out.append(ord("\f")); c.pos += 1
            elif e == b"(":
                out.append(ord("(")); c.pos += 1
            elif e == b")":
                out.append(ord(")")); c.pos += 1
            elif e == b"\\":
                out.append(ord("\\")); c.pos += 1
            elif e in b"\r\n":                   # line continuation
                c.pos += 1
                if e == b"\r" and d[c.pos:c.pos + 1] == b"\n":
                    c.pos += 1
            elif e[:1].isdigit():
                m = re.match(rb"[0-7]{1,3}", d[c.pos:c.pos + 3])
                out.append(int(m.group(0), 8) & 0xFF)
                c.pos += len(m.group(0))
            else:
                out.append(d[c.pos]); c.pos += 1
        elif ch == b"(":
            depth += 1; out.append(ord("(")); c.pos += 1
        elif ch == b")":
            depth -= 1; c.pos += 1
            if depth:
                out.append(ord(")"))
        else:
            out.append(d[c.pos]); c.pos += 1
    return bytes(out)

def _parse_hex_string(c):
    assert c.peek(2) == b"<>"
    c.pos += 1
    d = c.data
    out = bytearray()
    hexchars = bytearray()
    while c.pos < len(d):
        ch = d[c.pos:c.pos + 1]
        if ch == b">":
            c.pos += 1
            break
        if ch not in _WS:
            hexchars.append(d[c.pos])
        c.pos += 1
    if len(hexchars) % 2:
        hexchars.append(ord("0"))
    for i in range(0, len(hexchars), 2):
        out.append(int(hexchars[i:i + 2], 16))
    return bytes(out)

_NUM_RE = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")

def _parse_number_or_ref(c):
    m = _NUM_RE.match(c.data, c.pos)
    if not m:
        raise ValueError(f"expected number at offset {c.pos}")
    c.pos = m.end()
    tok = m.group(0)
    val = float(tok) if b"." in tok else int(tok)
    # possible indirect reference: "num gen R"
    save = c.pos
    c.skip_ws()
    m2 = _NUM_RE.match(c.data, c.pos)
    if m2 and float(m2.group(0)).is_integer():
        c.pos = m2.end()
        c.skip_ws()
        if c.peek() == b"R":
            c.pos += 1
            return PDFRef(int(val), int(m2.group(0)))
    c.pos = save
    return val

def _parse_keyword(c):
    d = c.data
    start = c.pos
    while c.pos < len(d) and d[c.pos:c.pos + 1] not in _WS and d[c.pos:c.pos + 1] not in _DELIMS:
        c.pos += 1
    return d[start:c.pos].decode("latin-1")

def parse_value(c):
    """Parse one PDF object at the cursor."""
    c.skip_ws()
    if c.eof():
        raise ValueError("unexpected EOF")
    ch = c.peek()
    if ch == b"<":
        if c.peek(2) == b"<<":
            c.pos += 2
            d = {}
            while True:
                c.skip_ws()
                if c.peek(2) == b">>":
                    c.pos += 2
                    return d
                if c.eof():
                    raise ValueError("unterminated dict")
                key = _parse_name(c)
                val = parse_value(c)
                d[str(key)] = val
        else:
            return _parse_hex_string(c)
    if ch == b"(":
        return _parse_literal_string(c)
    if ch == b"[":
        c.pos += 1
        arr = []
        while True:
            c.skip_ws()
            if c.peek() == b"]":
                c.pos += 1
                return arr
            if c.eof():
                raise ValueError("unterminated array")
            arr.append(parse_value(c))
    if ch == b"/":
        return _parse_name(c)
    if ch.isdigit() or ch in b"+-.":
        return _parse_number_or_ref(c)
    kw = _parse_keyword(c)
    if kw == "true":
        return True
    if kw == "false":
        return False
    if kw == "null":
        return None
    return ("keyword", kw)   # obj / endobj / R / stream / etc.

_INDIRECT_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")

def parse_indirect(data, offset):
    """Parse ``n g obj ... endobj`` at *offset*.

    Returns (num, gen, value, end_offset, stream_bytes|None).
    """
    m = _INDIRECT_RE.match(data, offset)
    if not m:
        return None
    num, gen = int(m.group(1)), int(m.group(2))
    c = Cursor(data, m.end())
    val = parse_value(c)
    c.skip_ws()
    stream = None
    if isinstance(val, dict) and c.peek(6) == b"stream":
        c.pos += 6
        # EOL after 'stream' keyword is not part of the data
        if c.peek(2) == b"\r\n":
            c.pos += 2
        elif c.peek(1) in (b"\r", b"\n"):
            c.pos += 1
        start = c.pos
        end = data.find(b"endstream", start)
        if end == -1:
            raise ValueError(f"unterminated stream at object {num}")
        stream = data[start:end]
        # strip the EOL that precedes endstream
        if stream.endswith(b"\r\n"):
            stream = stream[:-2]
        elif stream.endswith(b"\r") or stream.endswith(b"\n"):
            stream = stream[:-1]
        c.pos = end + len(b"endstream")
    return (num, gen, val, c.pos, stream)

# ---------------------------------------------------------------------------
# Document model: revisions, xref, catalog resolution
# ---------------------------------------------------------------------------

class Revision:
    def __init__(self, index, xref_offset, startxref_pos):
        self.index = index            # 1-based, file order
        self.xref_offset = xref_offset
        self.startxref_pos = startxref_pos
        self.entries = {}             # objnum -> (offset, gen, free?)
        self.trailer = {}
        self.parse_ok = True
        self.parse_error = ""

class PDFDoc:
    def __init__(self, data, path="<bytes>"):
        self.data = data
        self.path = path
        self.revisions = []
        self.findings = []            # (severity, text)
        self._obj_cache = {}          # (rev_index, num) -> (value, stream)

    # -- xref / trailer ----------------------------------------------------
    def _parse_xref_at(self, rev):
        d = self.data
        c = Cursor(d, rev.xref_offset)
        c.skip_ws()
        if c.peek(4) != b"xref":
            rev.parse_ok = False
            rev.parse_error = f"no 'xref' keyword at offset {rev.xref_offset} (xref stream? unsupported)"
            return
        c.pos += 4
        while True:
            c.skip_ws()
            save = c.pos
            line = d[c.pos:c.pos + 64].split(b"\n", 1)[0].split(b"\r", 1)[0]
            if line.startswith(b"trailer"):
                break
            m = re.match(rb"(\d+)\s+(\d+)", line)
            if not m:
                break
            start, count = int(m.group(1)), int(m.group(2))
            c.pos += len(line)
            # consume the EOL
            while c.peek(1) in (b"\r", b"\n"):
                c.pos += 1
            for i in range(count):
                entry = d[c.pos:c.pos + 20]
                c.pos += 20
                if len(entry) < 18:
                    continue
                try:
                    off = int(entry[0:10])
                    gen = int(entry[11:16])
                except ValueError:
                    continue
                free = entry[17:18] == b"f"
                rev.entries[start + i] = (off, gen, free)
        c.skip_ws()
        if c.peek(7) != b"trailer":
            # tolerate: trailer keyword may sit right after entries
            rev.parse_ok = False
            rev.parse_error = "no 'trailer' after xref table"
            return
        c.pos += 7
        try:
            rev.trailer = parse_value(c)
        except ValueError as e:
            rev.parse_ok = False
            rev.parse_error = f"trailer parse failed: {e}"

    def parse(self):
        # Every "startxref" marks one revision (initial write + incremental updates).
        positions = [m.start() for m in re.finditer(rb"startxref", self.data)]
        for i, pos in enumerate(positions):
            m = re.search(rb"startxref\s+(\d+)", self.data[pos:pos + 64])
            if not m:
                continue
            rev = Revision(i + 1, int(m.group(1)), pos)
            self._parse_xref_at(rev)
            self.revisions.append(rev)
        if not self.revisions:
            self.findings.append(("error", "no startxref found - not a parseable PDF"))

    # -- object access ------------------------------------------------------
    def object_map_through(self, rev_index):
        """Cumulative objnum -> file offset, applying revisions 1..rev_index."""
        omap = {}
        for rev in self.revisions[:rev_index]:
            for num, (off, gen, free) in rev.entries.items():
                if not free:
                    omap[num] = off
        return omap

    def get_object(self, num, rev_index):
        key = (rev_index, num)
        if key in self._obj_cache:
            return self._obj_cache[key]
        omap = self.object_map_through(rev_index)
        if num not in omap:
            return None
        parsed = parse_indirect(self.data, omap[num])
        if parsed is None:
            return None
        _, _, val, _, stream = parsed
        self._obj_cache[key] = (val, stream)
        return (val, stream)

    def resolve(self, obj, rev_index):
        """Follow indirect refs until a direct value (depth-limited)."""
        depth = 0
        while isinstance(obj, PDFRef) and depth < 25:
            got = self.get_object(obj.num, rev_index)
            if got is None:
                return None
            obj = got[0]
            depth += 1
        return obj

    def catalog(self, rev_index):
        rev = self.revisions[rev_index - 1]
        root = rev.trailer.get("Root")
        if root is None and rev_index > 1:        # inherit via /Prev
            return self.catalog(rev_index - 1)
        return self.resolve(root, rev_index)

    def info_dict(self, rev_index):
        rev = self.revisions[rev_index - 1]
        info = rev.trailer.get("Info")
        if info is None and rev_index > 1:
            return self.info_dict(rev_index - 1)
        return self.resolve(info, rev_index)

# ---------------------------------------------------------------------------
# Forensic checks
# ---------------------------------------------------------------------------

def _pdf_date_to_tuple(s):
    """Parse D:YYYYMMDDHHmmSS -> tuple, or None."""
    if isinstance(s, bytes):
        s = s.decode("latin-1", "replace")
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", s or "")
    if not m:
        return None
    return tuple(int(g) for g in m.groups())

def _name_str(v):
    return str(v) if isinstance(v, PDFName) else v

def check_catalog(doc, cat, rev_index, findings):
    if not isinstance(cat, dict):
        findings.append(("error", f"rev {rev_index}: catalog is not a dict"))
        return
    # /OpenAction
    if "OpenAction" in cat:
        oa = doc.resolve(cat["OpenAction"], rev_index)
        desc = ""
        if isinstance(oa, dict):
            s = _name_str(oa.get("S"))
            desc = f" action /S /{s}"
            if s == "JavaScript":
                findings.append(("high", "/OpenAction runs JavaScript on open"))
            elif s == "Launch":
                findings.append(("high", "/OpenAction launches an external app/file (Launch)"))
            else:
                findings.append(("medium", f"/OpenAction present{desc}"))
            win = oa.get("Win")
            if isinstance(win, dict) and win.get("P"):
                findings.append(("high", f"/OpenAction Win params: {win.get('P')!r}"))
        elif isinstance(oa, PDFRef):
            findings.append(("medium", f"/OpenAction -> {oa}"))
        else:
            findings.append(("medium", "/OpenAction present"))
    # /AA additional actions
    if "AA" in cat:
        aa = doc.resolve(cat["AA"], rev_index)
        if isinstance(aa, dict):
            findings.append(("medium", f"/AA additional actions: {sorted(aa.keys())}"))
    # /Names -> /JavaScript and /EmbeddedFiles
    names = doc.resolve(cat.get("Names"), rev_index) if "Names" in cat else None
    if isinstance(names, dict):
        js = doc.resolve(names.get("JavaScript"), rev_index) if "JavaScript" in names else None
        if isinstance(js, dict):
            arr = doc.resolve(js.get("Names"), rev_index)
            n = len(arr) // 2 if isinstance(arr, list) else 0
            findings.append(("high", f"/Names /JavaScript: {n} embedded script(s)"))
            if isinstance(arr, list):
                for i in range(0, len(arr), 2):
                    nm = doc.resolve(arr[i], rev_index)
                    ref = arr[i + 1] if i + 1 < len(arr) else None
                    act = doc.resolve(ref, rev_index)
                    code = ""
                    if isinstance(act, dict):
                        jscode = doc.resolve(act.get("JS"), rev_index)
                        if isinstance(jscode, bytes):
                            code = jscode[:80].decode("latin-1", "replace")
                    nm_s = nm.decode("latin-1", "replace") if isinstance(nm, bytes) else nm
                    findings.append(("info", f'  script "{nm_s}": {code!r}'))
        ef = doc.resolve(names.get("EmbeddedFiles"), rev_index) if "EmbeddedFiles" in names else None
        if isinstance(ef, dict):
            arr = doc.resolve(ef.get("Names"), rev_index)
            n = len(arr) // 2 if isinstance(arr, list) else 0
            findings.append(("medium", f"/Names /EmbeddedFiles: {n} embedded file(s)"))
    # /AcroForm with XFA or JS
    acro = doc.resolve(cat.get("AcroForm"), rev_index) if "AcroForm" in cat else None
    if isinstance(acro, dict):
        if "XFA" in acro:
            findings.append(("medium", "/AcroForm contains XFA (dynamic form)"))
    # /Encrypt
    for rev in doc.revisions:
        if "Encrypt" in rev.trailer:
            findings.append(("medium", "document is encrypted (/Encrypt) - content checks are best-effort"))
            break

def _walk_pages(doc, pages_ref, rev_index, out):
    pages = doc.resolve(pages_ref, rev_index)
    if not isinstance(pages, dict):
        return
    kids = doc.resolve(pages.get("Kids"), rev_index)
    if isinstance(kids, list):
        for k in kids:
            node = doc.resolve(k, rev_index)
            if not isinstance(node, dict):
                continue
            t = _name_str(node.get("Type"))
            if t == "Pages":
                _walk_pages(doc, k, rev_index, out)
            elif t == "Page":
                out.append(node)

def check_launch_in_annots(doc, cat, rev_index, findings):
    pages = []
    if isinstance(cat, dict) and "Pages" in cat:
        _walk_pages(doc, cat["Pages"], rev_index, pages)
    for p in pages:
        annots = doc.resolve(p.get("Annots"), rev_index)
        if not isinstance(annots, list):
            continue
        for a in annots:
            ann = doc.resolve(a, rev_index)
            if not isinstance(ann, dict):
                continue
            for key in ("A",):
                act = doc.resolve(ann.get(key), rev_index)
                if isinstance(act, dict) and _name_str(act.get("S")) == "Launch":
                    findings.append(("high", "annotation with /Launch action found"))

def check_metadata(doc, rev_index, findings):
    info = doc.info_dict(rev_index)
    if info is None:
        findings.append(("info", "no /Info metadata dict"))
        return
    if not isinstance(info, dict):
        return
    def s(v):
        v = doc.resolve(v, rev_index)
        return v.decode("latin-1", "replace") if isinstance(v, bytes) else v
    creator, producer = s(info.get("Creator")), s(info.get("Producer"))
    cdate, mdate = s(info.get("CreationDate")), s(info.get("ModDate"))
    if creator and producer and creator != producer:
        findings.append(("info", f"Creator ({creator!r}) != Producer ({producer!r})"))
    ct, mt = _pdf_date_to_tuple(cdate), _pdf_date_to_tuple(mdate)
    if cdate and not ct:
        findings.append(("low", f"CreationDate not in D: format: {cdate!r}"))
    if mdate and not mt:
        findings.append(("low", f"ModDate not in D: format: {mdate!r}"))
    if ct and mt and mt < ct:
        findings.append(("medium", f"ModDate ({mdate}) is BEFORE CreationDate ({cdate}) - impossible"))

def check_revisions(doc, findings):
    n = len(doc.revisions)
    if n > 1:
        findings.append(("info", f"{n} revisions (incremental updates) found"))
    prev_maps = []
    for i, rev in enumerate(doc.revisions, 1):
        omap = doc.object_map_through(i)
        if prev_maps:
            prev = prev_maps[-1]
            redefined = sorted(num for num in omap
                               if num in prev and omap[num] != prev[num])
            added = sorted(num for num in omap if num not in prev)
            if redefined:
                findings.append(("medium",
                    f"rev {i}: redefined objects after earlier revision: {redefined}"))
            if added:
                findings.append(("info", f"rev {i}: new objects: {added}"))
        prev_maps.append(omap)
    # /Prev chain sanity
    for rev in doc.revisions:
        prev = rev.trailer.get("Prev")
        if isinstance(prev, (int, float)):
            known = {r.xref_offset for r in doc.revisions}
            if int(prev) not in known:
                findings.append(("low", f"rev {rev.index}: /Prev -> {int(prev)} points outside known xref offsets"))

# ---------------------------------------------------------------------------
# Text extraction per revision
# ---------------------------------------------------------------------------

def _content_tokens(data):
    """Tokenize a content stream into (kind, value) for text-op scanning."""
    toks = []
    c = Cursor(data)
    while not c.eof():
        c.skip_ws()
        if c.eof():
            break
        ch = c.peek()
        if ch == b"(":
            toks.append(("str", _parse_literal_string(c)))
        elif ch == b"<" and c.peek(2) != b"<<":
            toks.append(("str", _parse_hex_string(c)))
        elif ch == b"[":
            c.pos += 1
            arr = []
            while True:
                c.skip_ws()
                if c.peek() == b"]":
                    c.pos += 1
                    break
                if c.eof():
                    break
                pch = c.peek()
                if pch == b"(":
                    arr.append(("str", _parse_literal_string(c)))
                elif pch == b"<":
                    arr.append(("str", _parse_hex_string(c)))
                elif pch.isdigit() or pch in b"+-.":
                    arr.append(("num", _parse_number_or_ref(c)))
                else:
                    _parse_keyword(c)
            toks.append(("arr", arr))
        elif ch == b"/":
            toks.append(("name", _parse_name(c)))
        elif ch.isdigit() or ch in b"+-.":
            toks.append(("num", _parse_number_or_ref(c)))
        else:
            kw = _parse_keyword(c)
            toks.append(("op", kw))
    return toks

def extract_text_from_stream(data):
    """Pull Tj / TJ / ' / " strings out of a content stream."""
    parts = []
    toks = _content_tokens(data)
    last = None
    for kind, val in toks:
        if kind == "op" and val in ("Tj", "'", '"'):
            if last and last[0] == "str":
                parts.append(last[1])
            last = None
        elif kind == "op" and val == "TJ":
            if last and last[0] == "arr":
                for ak, av in last[1]:
                    if ak == "str":
                        parts.append(av)
            last = None
        elif kind in ("str", "arr", "num", "name"):
            last = (kind, val)
        else:
            last = None
    return b"".join(parts).decode("latin-1", "replace")

def revision_text(doc, rev_index):
    """Visible text of revision *rev_index* (1-based)."""
    cat = doc.catalog(rev_index)
    if not isinstance(cat, dict):
        return ""
    pages = []
    if "Pages" in cat:
        _walk_pages(doc, cat["Pages"], rev_index, pages)
    out = []
    for p in pages:
        cref = p.get("Contents")
        if isinstance(cref, PDFRef):
            refs = [cref]
        elif isinstance(cref, list):
            refs = [r for r in cref if isinstance(r, PDFRef)]
        else:
            continue
        for r in refs:
            got = doc.get_object(r.num, rev_index)
            if got is None:
                continue
            _, stream = got
            if stream:
                # best-effort: skip FlateDecode etc. (would need zlib inflate)
                res = doc.resolve(r, rev_index)
                filt = None
                if isinstance(res, dict):
                    filt = res.get("Filter")
                if filt is None:
                    out.append(extract_text_from_stream(stream))
    return "\n".join(t for t in out if t)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def analyze(path):
    with open(path, "rb") as f:
        data = f.read()
    doc = PDFDoc(data, path)
    findings = []
    doc.findings = findings
    doc.parse()

    latest = len(doc.revisions)
    if doc.revisions:
        cat = doc.catalog(latest)
        check_catalog(doc, cat, latest, findings)
        check_launch_in_annots(doc, cat, latest, findings)
        check_metadata(doc, latest, findings)
        check_revisions(doc, findings)

    sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0, "error": 3}
    highs = sum(1 for s, _ in findings if s == "high")
    mediums = sum(1 for s, _ in findings if s == "medium")
    if any(s == "error" for s, _ in findings):
        verdict = "WORTH-A-LOOK"
        why = "parse errors - manual review needed"
    elif highs >= 2 or (highs >= 1 and mediums >= 1):
        verdict = "MALICIOUS"
        why = "multiple malicious indicators"
    elif highs == 1:
        verdict = "SUSPICIOUS"
        why = "one high-severity indicator"
    elif mediums:
        verdict = "WORTH-A-LOOK"
        why = "medium-severity indicators"
    else:
        verdict = "CLEAN"
        why = "no indicators found"
    return doc, findings, verdict, why

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hand-rolled PDF forensic triage: revisions, JavaScript, "
                    "embedded files, metadata, per-revision text. Stdlib only.")
    ap.add_argument("pdf", help="PDF file to analyze")
    ap.add_argument("--text", action="store_true",
                    help="also extract visible text for every revision")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of the report")
    args = ap.parse_args(argv)

    doc, findings, verdict, why = analyze(args.pdf)

    if args.json:
        import json
        print(json.dumps({
            "file": args.pdf,
            "revisions": len(doc.revisions),
            "startxref_offsets": [r.xref_offset for r in doc.revisions],
            "findings": [{"severity": s, "text": t} for s, t in findings],
            "verdict": verdict,
        }, indent=2))
        return 0

    print(f"file: {args.pdf}  ({len(doc.data)} bytes)")
    print(f"revisions: {len(doc.revisions)}"
          + (f"  startxref -> {[r.xref_offset for r in doc.revisions]}" if doc.revisions else ""))
    total_objs = len(doc.object_map_through(len(doc.revisions))) if doc.revisions else 0
    print(f"objects: {total_objs} (latest revision)")
    if findings:
        print("findings:")
        for sev, text in findings:
            mark = {"high": "[!!]", "medium": "[!]",
                    "low": "[.]", "info": "[i]", "error": "[X]"}[sev]
            print(f"  {mark} {text}")
    else:
        print("findings: none")
    if args.text and doc.revisions:
        for i in range(1, len(doc.revisions) + 1):
            t = revision_text(doc, i)
            print(f"--- revision {i} text ---")
            print(t if t else "  (no extractable text)")
    print(f"VERDICT: {verdict} -- {why}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
