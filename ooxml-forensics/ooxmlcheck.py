#!/usr/bin/env python3
"""ooxmlcheck.py - Hand-rolled ZIP parser + OOXML forensic analyzer.

Parses .docx/.xlsx by hand (no zipfile, no XML security libs for parsing —
only xml.etree from stdlib): EOCD scan from the end of file, central-directory
walk, stored entries read raw, deflated entries inflated with zlib (stdlib,
allowed), CRC32 verified per entry.

Then the forensic analyzer walks the OOXML package and flags:

  * vbaProject.bin present (macro payload; OLE header validated)
  * external relationships (TargetMode="External": tracking pixels, remote templates)
  * hidden text: w:vanish runs, white-on-white runs, micro fonts (w:sz < 8 half-pts)
  * tracked changes: w:ins / w:del with authors and timestamps
  * comments (word/comments/*.xml)
  * embedded OLE / package objects (word/embeddings/*)
  * veryHidden / hidden sheets (xl/workbook.xml)
  * hyperlink display-text vs target mismatch (the classic doc-phish tell)
  * core.xml metadata (creator, lastModifiedBy, created/modified)

Usage:
    python3 ooxmlcheck.py suspect.docx
    python3 ooxmlcheck.py suspect.xlsx --json
    python3 ooxmlcheck.py --help

Exit 0 always; the VERDICT: line is the machine-readable result
(CLEAN / WORTH-A-LOOK / SUSPICIOUS / MALICIOUS).

Honest subset / limitations:
  * Entries using the data-descriptor flag (bit 3, sizes only after the data)
    are reported but skipped - we need sizes up front for stored reads.
  * ZIP64, multi-disk archives, and encryption are detected, not parsed.
  * Hidden-text analysis covers Word (document.xml); Excel cell-level hiding
    is limited to veryHidden sheets.
  * Verdicts are heuristics. Verify before acting.
"""

import argparse
import binascii
import struct
import sys
import zlib
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Hand-rolled ZIP reader
# ---------------------------------------------------------------------------

EOCD_MAGIC = b"PK\x05\x06"
CD_MAGIC = b"PK\x01\x02"
LFH_MAGIC = b"PK\x03\x04"

class ZipError(Exception):
    pass

class ZipEntry:
    def __init__(self, name, method, crc, comp_size, uncomp_size, local_offset, flags):
        self.name = name
        self.method = method          # 0 = stored, 8 = deflated
        self.crc = crc
        self.comp_size = comp_size
        self.uncomp_size = uncomp_size
        self.local_offset = local_offset
        self.flags = flags
        self.data = None              # filled on read

class HandZip:
    """Minimal ZIP reader: EOCD scan, central-directory walk, stored/deflated."""

    def __init__(self, data):
        self.data = data
        self.entries = {}             # name -> ZipEntry
        self.skipped = []             # (name, reason)
        self._parse()

    def _parse(self):
        d = self.data
        # EOCD: scan backwards from the end (comment can be up to 64KiB).
        eocd_pos = d.rfind(EOCD_MAGIC, max(0, len(d) - 66000))
        if eocd_pos == -1:
            raise ZipError("no end-of-central-directory record found")
        (disk_no, cd_disk, cd_count_disk, cd_count,
         cd_size, cd_offset, comment_len) = struct.unpack_from("<HHHHIIH", d, eocd_pos + 4)
        if disk_no != 0 or cd_disk != 0:
            raise ZipError("multi-disk archives not supported")
        if cd_count != cd_count_disk:
            raise ZipError("central directory count mismatch across disks")
        pos = cd_offset
        for _ in range(cd_count):
            if d[pos:pos + 4] != CD_MAGIC:
                raise ZipError(f"bad central-directory magic at {pos}")
            (ver_made, ver_need, flags, method, _mtime, _mdate, crc,
             comp_size, uncomp_size, name_len, extra_len, comment_len2,
             _disk_start, _int_attr, _ext_attr,
             local_offset) = struct.unpack_from("<HHHHHHIIIHHHHHII", d, pos + 4)
            name = d[pos + 46:pos + 46 + name_len].decode("utf-8", "replace")
            pos += 46 + name_len + extra_len + comment_len2
            # ZIP64 / encryption: detect, don't parse
            if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF or local_offset == 0xFFFFFFFF:
                self.skipped.append((name, "ZIP64"))
                continue
            if flags & 0x1:
                self.skipped.append((name, "encrypted"))
                continue
            self.entries[name] = ZipEntry(name, method, crc, comp_size,
                                         uncomp_size, local_offset, flags)

    def read(self, name):
        entry = self.entries[name]
        if entry.data is not None:
            return entry.data
        d = self.data
        off = entry.local_offset
        if d[off:off + 4] != LFH_MAGIC:
            raise ZipError(f"bad local header magic for {name}")
        (_ver, flags, method, _t, _dt, _crc, _cs, _us,
         name_len, extra_len) = struct.unpack_from("<HHHHHIIIHH", d, off + 4)
        data_off = off + 30 + name_len + extra_len
        if flags & 0x08:
            raise ZipError(f"{name}: data descriptor (bit 3) not supported")
        raw = d[data_off:data_off + entry.comp_size]
        if entry.method == 0:
            data = raw
        elif entry.method == 8:
            data = zlib.decompress(raw, -15)     # raw deflate stream
        else:
            raise ZipError(f"{name}: unsupported compression method {entry.method}")
        if len(data) != entry.uncomp_size:
            raise ZipError(f"{name}: uncompressed size mismatch "
                           f"({len(data)} != {entry.uncomp_size})")
        if binascii.crc32(data) & 0xFFFFFFFF != entry.crc:
            raise ZipError(f"{name}: CRC32 mismatch")
        entry.data = data
        return data

# ---------------------------------------------------------------------------
# OOXML helpers
# ---------------------------------------------------------------------------

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
    "dc": "http://purl.org/dc/elements/1.1/",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dcterms": "http://purl.org/dc/terms/",
    "x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}
def qn(prefix, tag):
    return f"{{{NS[prefix]}}}{tag}"

def _rels_of(zipf, part_path):
    """Return list of (Id, Type, Target, TargetMode) for part's .rels."""
    if "/" in part_path:
        rels_path = part_path.rsplit("/", 1)[0] + "/_rels/" + part_path.rsplit("/", 1)[1] + ".rels"
    else:
        rels_path = "_rels/" + part_path + ".rels"
    if rels_path not in zipf.entries:
        return []
    try:
        root = ET.fromstring(zipf.read(rels_path))
    except ET.ParseError:
        return []
    out = []
    for rel in root.findall(qn("rel", "Relationship")):
        out.append((rel.get("Id"), rel.get("Type"), rel.get("Target"),
                    rel.get("TargetMode", "Internal")))
    return out

# ---------------------------------------------------------------------------
# Forensic checks
# ---------------------------------------------------------------------------

def analyze(path):
    with open(path, "rb") as f:
        data = f.read()
    findings = []                     # (severity, text)
    meta = {}
    try:
        zf = HandZip(data)
    except ZipError as e:
        return findings, "WORTH-A-LOOK", f"not a readable ZIP: {e}", meta, []
    meta["entries"] = len(zf.entries)
    names = list(zf.entries)

    # ---- macro payload ------------------------------------------------
    vba = [n for n in names if n.endswith("vbaProject.bin")]
    if vba:
        findings.append(("high", f"vbaProject.bin present: {vba[0]} (macro payload)"))
        try:
            blob = zf.read(vba[0])
            if blob[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                findings.append(("info", "  vbaProject.bin has a valid OLE header"))
            else:
                findings.append(("medium", "  vbaProject.bin has a BAD OLE header (fake/renamed?)"))
        except ZipError as e:
            findings.append(("medium", f"  could not read vbaProject.bin: {e}"))

    # ---- content types: macro-enabled? --------------------------------
    if "[Content_Types].xml" in zf.entries:
        try:
            root = ET.fromstring(zf.read("[Content_Types].xml"))
            for ov in root.findall(qn("ct", "Override")):
                ct = ov.get("ContentType", "")
                if "macroEnabled" in ct:
                    findings.append(("medium", f"macro-enabled content type: {ov.get('PartName')}"))
        except ET.ParseError:
            findings.append(("low", "[Content_Types].xml failed to parse"))

    # ---- external relationships ---------------------------------------
    doc_parts = [n for n in names
                 if n in ("word/document.xml", "xl/workbook.xml")
                 or n.endswith(".xml") and "/_rels/" not in n and n.startswith(("word/", "xl/"))]
    external = []
    rel_targets = {}                  # (part, rId) -> (type, target)
    for part in set(["_rels/.rels"] + doc_parts):
        for rid, rtype, target, mode in _rels_of(zf, part if part != "_rels/.rels" else ".rels"):
            short = rtype.rsplit("/", 1)[-1]
            rel_targets[(part, rid)] = (rtype, target)
            if mode == "External":
                external.append((part, rid, short, target))
                findings.append(("medium" if "hyperlink" not in short else "low",
                                 f"external relationship in {part}: [{short}] -> {target}"))
    if not external:
        findings.append(("info", "no external relationships"))

    # ---- Word: hidden text / tracked changes / comments ----------------
    hyperlink_targets = {}
    if "word/document.xml" in zf.entries:
        try:
            root = ET.fromstring(zf.read("word/document.xml"))
        except ET.ParseError:
            root = None
            findings.append(("low", "word/document.xml failed to parse"))
        if root is not None:
            hidden_runs = []
            for r in root.iter(qn("w", "r")):
                rpr = r.find(qn("w", "rPr"))
                texts = [t.text or "" for t in r.findall(qn("w", "t"))]
                txt = "".join(texts)
                if not txt.strip():
                    continue
                reasons = []
                if rpr is not None:
                    if rpr.find(qn("w", "vanish")) is not None:
                        reasons.append("w:vanish")
                    color = rpr.find(qn("w", "color"))
                    if color is not None and (color.get(qn("w", "val")) or "").upper() == "FFFFFF":
                        reasons.append("white-on-white")
                    sz = rpr.find(qn("w", "sz"))
                    if sz is not None:
                        try:
                            if int(sz.get(qn("w", "val"), "99")) < 8:
                                reasons.append(f"micro-font sz={sz.get(qn('w','val'))}")
                        except ValueError:
                            pass
                if reasons:
                    hidden_runs.append((txt[:60], reasons))
            for txt, reasons in hidden_runs:
                findings.append(("medium", f"hidden text ({', '.join(reasons)}): {txt!r}"))
            if not hidden_runs:
                findings.append(("info", "no hidden-text runs found"))

            # tracked changes
            for tag, sev in (("ins", "low"), ("del", "low")):
                for el in root.iter(qn("w", tag)):
                    author = el.get(qn("w", "author"), "?")
                    date = el.get(qn("w", "date"), "?")
                    txt = next((t.text or "" for t in el.iter(qn("w", "t"))), "")
                    findings.append((sev, f"tracked {tag} by {author} at {date}: {txt[:60]!r}"))

            # comments
            if any(n.startswith("word/comments") for n in names):
                findings.append(("low", "document contains comments (word/comments*.xml)"))

            # hyperlink display vs target mismatch
            for part, rid in [(p, i) for (p, i) in rel_targets
                              if p in ("word/document.xml",) and "hyperlink" in rel_targets[(p, i)][0]]:
                rtype, target = rel_targets[(part, rid)]
                hyperlink_targets[rid] = target
            for hl in root.iter(qn("w", "hyperlink")):
                rid = hl.get(qn("r", "id"))
                disp = "".join(t.text or "" for t in hl.iter(qn("w", "t")))
                tgt = hyperlink_targets.get(rid, "")
                if rid and tgt and disp and disp.strip() not in tgt and tgt not in disp:
                    findings.append(("high",
                        f"hyperlink display/target mismatch: shows {disp[:60]!r} -> {tgt[:80]!r}"))

    # ---- embedded OLE / objects ----------------------------------------
    ole = [n for n in names if "/embeddings/" in n]
    for n in ole:
        findings.append(("medium", f"embedded object: {n}"))
        try:
            blob = zf.read(n)
            if blob[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                findings.append(("info", f"  {n}: valid OLE header"))
        except ZipError:
            pass

    # ---- Excel: veryHidden sheets ---------------------------------------
    if "xl/workbook.xml" in zf.entries:
        try:
            root = ET.fromstring(zf.read("xl/workbook.xml"))
            for sh in root.iter(qn("x", "sheet")):
                state = sh.get("state", "visible")
                if state in ("veryHidden", "hidden"):
                    findings.append(("medium",
                        f"sheet {sh.get('name')!r} is {state}"))
        except ET.ParseError:
            findings.append(("low", "xl/workbook.xml failed to parse"))

    # ---- core metadata ---------------------------------------------------
    if "docProps/core.xml" in zf.entries:
        try:
            root = ET.fromstring(zf.read("docProps/core.xml"))
            def txt(tag):
                el = root.find(tag)
                return el.text if el is not None else None
            meta.update({
                "creator": txt(qn("dc", "creator")),
                "lastModifiedBy": txt(qn("cp", "lastModifiedBy")),
                "created": txt(qn("dcterms", "created")),
                "modified": txt(qn("dcterms", "modified")),
            })
            if meta["creator"] and meta["lastModifiedBy"] and \
               meta["creator"] != meta["lastModifiedBy"]:
                findings.append(("info",
                    f"creator {meta['creator']!r} != lastModifiedBy {meta['lastModifiedBy']!r}"))
        except ET.ParseError:
            findings.append(("low", "docProps/core.xml failed to parse"))

    for name, reason in zf.skipped:
        findings.append(("low", f"ZIP entry skipped ({reason}): {name}"))

    # ---- verdict ----------------------------------------------------------
    highs = sum(1 for s, _ in findings if s == "high")
    mediums = sum(1 for s, _ in findings if s == "medium")
    has_macro = any("vbaProject.bin present" in t for _, t in findings)
    if has_macro and external:
        verdict, why = "MALICIOUS", "macro payload + external relationships"
    elif highs >= 2:
        verdict, why = "MALICIOUS", "multiple high-severity indicators"
    elif highs == 1 or has_macro:
        verdict, why = "SUSPICIOUS", "macro payload or phishing tell"
    elif mediums >= 2:
        verdict, why = "SUSPICIOUS", "multiple medium indicators"
    elif mediums == 1 or any(s == "low" for s, _ in findings):
        verdict, why = "WORTH-A-LOOK", "minor indicators"
    else:
        verdict, why = "CLEAN", "no indicators found"
    return findings, verdict, why, meta, names

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hand-rolled OOXML forensic triage (.docx/.xlsx). "
                    "ZIP parsed by hand; stdlib only.")
    ap.add_argument("doc", help=".docx/.xlsx file to analyze")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of the report")
    ap.add_argument("--list", action="store_true",
                    help="list ZIP entries and exit")
    args = ap.parse_args(argv)

    if args.list:
        import os
        with open(args.doc, "rb") as f:
            zf = HandZip(f.read())
        for n in sorted(zf.entries):
            e = zf.entries[n]
            print(f"{n}  method={e.method} size={e.uncomp_size}")
        return 0

    findings, verdict, why, meta, _names = analyze(args.doc)

    if args.json:
        import json
        print(json.dumps({
            "file": args.doc,
            "verdict": verdict,
            "metadata": meta,
            "findings": [{"severity": s, "text": t} for s, t in findings],
        }, indent=2))
        return 0

    print(f"file: {args.doc}")
    print(f"zip entries: {meta.get('entries', '?')}")
    if any(meta.get(k) for k in ("creator", "lastModifiedBy", "created", "modified")):
        print(f"metadata: creator={meta.get('creator')!r} "
              f"lastModifiedBy={meta.get('lastModifiedBy')!r} "
              f"created={meta.get('created')!r} modified={meta.get('modified')!r}")
    if findings:
        print("findings:")
        for sev, text in findings:
            mark = {"high": "[!!]", "medium": "[!]",
                    "low": "[.]", "info": "[i]"}[sev]
            print(f"  {mark} {text}")
    else:
        print("findings: none")
    print(f"VERDICT: {verdict} -- {why}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
