#!/usr/bin/env python3
"""regtriage.py — forensic triage over a Windows registry hive. Zero deps.

Integrity checks → full key walk → timeline → artifact detectors
(autoruns, services, USBSTOR, UserAssist ROT13, RecentDocs) → deleted-record
recovery → scored CLEAN / WORTH-A-LOOK / SUSPICIOUS / MALICIOUS verdict.
"""
import csv
import re
import struct
import sys
from regparse import Hive, HiveError, NULL, filetime_to_dt

def rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

AUTORUN_KEY = re.compile(r"\\(Run|RunOnce|RunServices|RunServicesOnce)$", re.I)
SUSP_PATH = re.compile(r"(\\Temp\\|\\Temporary|\\AppData\\|http://|https://|\.ps1$)", re.I)

class Triage:
    def __init__(self, hive: Hive):
        self.h = hive
        self.findings = []          # (severity, points, text)
        self.keys = []              # (nk, path)
        self.deleted = []

    def flag(self, sev: str, pts: int, text: str):
        self.findings.append((sev, pts, text))

    # -- phases ----------------------------------------------------
    def integrity(self):
        h = self.h
        if not h.checksum_ok:
            self.flag("ANOMALY", 20, "base-block XOR checksum mismatch (hive may be corrupt/tampered)")
        if h.dirty:
            self.flag("ANOMALY", 10, f"dirty hive: seq1={h.seq1} != seq2={h.seq2} (unclean shutdown, log replay pending)")
        self.flag("INFO", 0, f"hive '{h.fname}': {len(h.bins)} bins, {len(h.cells)} cells, "
                             f"{sum(1 for _,_,a in h.cells if not a)} free cells, "
                             f"v{h.major}.{h.minor}, root lastwrite {h.lastwrite}")

    def walk(self):
        for nk, path in self.h.walk():
            self.keys.append((nk, path))
            subs = self.h.subkey_offsets(nk)
            if nk["nsub"] != len(subs):
                self.flag("ANOMALY", 10,
                          f"count mismatch at {path}: header says {nk['nsub']} subkeys, list holds {len(subs)}")
            vals = self.h.values(nk)
            if nk["nval"] != len(vals):
                self.flag("ANOMALY", 10, f"value-count mismatch at {path}")
            for v in vals:
                self._value_checks(path, v)

    def _value_checks(self, path: str, v: dict):
        data = v["data"]
        s = data if isinstance(data, str) else ""
        if AUTORUN_KEY.search(path) and v["type_id"] in (1, 2):
            self.flag("PERSISTENCE", 10, f"autorun: {path} -> {v['name']} = {s[:120]}")
            if SUSP_PATH.search(s):
                self.flag("SUSPICIOUS", 25, f"autorun points at temp/appdata/net path: {v['name']} = {s[:120]}")
        if re.search(r"\\Services\\[^\\]+$", path) and v["name"] == "ImagePath":
            self.flag("PERSISTENCE", 15, f"service image: {path} ImagePath = {s[:120]}")
            if SUSP_PATH.search(s):
                self.flag("SUSPICIOUS", 30, f"service image in temp/appdata: {s[:120]}")
        if "USBSTOR" in path and v["name"] in ("FriendlyName", "DeviceDesc"):
            self.flag("ARTIFACT", 0, f"USB device: {path} [{v['name']}={s[:80]}]")
        if path.endswith("\\Count") and "UserAssist" in path and v["type"] == "REG_BINARY":
            dec = rot13(v["raw_name"])
            self.flag("ARTIFACT", 0, f"UserAssist executed: {dec} (runs={struct.unpack('<I', v['raw'][4:8])[0] if len(v['raw'])>=8 else '?'})")
        if path.endswith("RecentDocs") and v["name"] not in ("MRUListEx",):
            self.flag("ARTIFACT", 0, f"recent doc: {s[:80]}")

    def deleted_recovery(self):
        self.deleted = self.h.scan_deleted()
        by_cell = {}
        for r in self.deleted:
            by_cell.setdefault(r["cell_off"], []).append(r)
        for r in self.deleted:
            if r["kind"] != "key":
                continue
            try:
                parent = self.h.nk(r["parent"])
                ppath = self.h.path(parent)
            except HiveError:
                ppath = f"<orphan parent @{r['parent']:#x}>"
            vals = self._deleted_values(r)
            vstr = (" values: " + ", ".join(f"{v['name']}={str(v['data'])[:60]}" for v in vals)) if vals else ""
            pts = 40 if AUTORUN_KEY.search(ppath) else 15
            sev = "SUSPICIOUS" if AUTORUN_KEY.search(ppath) else "ARTIFACT"
            self.flag(sev, pts, f"deleted key: {ppath}\\{r['name']} "
                                f"(lastwrite {r['lastwrite']}, {r['nval']} value(s)){vstr}")
        for r in self.deleted:
            if r["kind"] == "value" and not any(k["kind"] == "key" and k["cell_off"] == r["cell_off"]
                                               for k in self.deleted):
                self.flag("ARTIFACT", 5, f"deleted value: {r['name']}={str(r['data'])[:80]} ({r['type']})")

    def _deleted_values(self, nkrec: dict):
        out, vl, n = [], nkrec["vallist"], nkrec["nval"]
        if vl == NULL or not 0 < n <= 1000:
            return out
        try:
            a = self.h._abs(vl) + 4
            for i in range(n):
                vo = struct.unpack_from("<I", self.h.data, a + 4 * i)[0]
                pa, plen, _ = self.h._cell(vo)
                v = self.h._try_vk(self.h.data[pa:pa + plen])
                if v:
                    out.append(v)
        except HiveError:
            pass
        return out

    def timeline(self, csv_path: str):
        rows = sorted(((nk["lastwrite"], path) for nk, path in self.keys if nk["lastwrite"]),
                      key=lambda r: r[0])
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["lastwrite_utc", "path"])
            for ts, path in rows:
                w.writerow([ts.isoformat(), path])
        return rows

    # -- verdict ----------------------------------------------------
    def verdict(self) -> str:
        score = sum(p for _, p, _ in self.findings)
        if score >= 60:
            return "MALICIOUS"
        if score >= 30:
            return "SUSPICIOUS"
        if score >= 10:
            return "WORTH-A-LOOK"
        return "CLEAN"

    def run(self, csv_path="timeline.csv"):
        self.integrity()
        self.walk()
        self.deleted_recovery()
        rows = self.timeline(csv_path)
        return {"verdict": self.verdict(),
                "score": sum(p for _, p, _ in self.findings),
                "keys": len(self.keys),
                "deleted": len(self.deleted),
                "timeline_rows": len(rows),
                "findings": self.findings}


def main(path: str):
    h = Hive(path)
    t = Triage(h)
    rep = t.run()
    print(f"hive: {path}  keys={rep['keys']} deleted_records={rep['deleted']}")
    print(f"verdict: {rep['verdict']} (score {rep['score']})")
    print()
    for sev, pts, text in rep["findings"]:
        print(f"[{sev:11s} +{pts:2d}] {text}")
    print(f"\ntimeline.csv: {rep['timeline_rows']} rows")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fakehive.dat")
