#!/usr/bin/env python3
"""Mailbox forensics triage: point at an mbox file or Maildir, get a report.

Usage:
  python3 mbtriage.py fixtures/inbox.mbox
  python3 mbtriage.py fixtures/maildir
"""
import csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mboxparse import (read_mbox, read_maildir, analyze, thread, triage,
                       walk_mime)

def mbox_unescape(raw):
    """Remove one level of mbox '>' quoting from '>From ' body lines."""
    return "\n".join(l[1:] if l.startswith(">From ") else l
                     for l in raw.split("\n"))

def collect(target):
    msgs, notes = [], []
    uidl = None
    if os.path.isdir(target):
        entries = read_maildir(target)
        for e in entries:
            if e["subdir"] == "tmp":
                notes.append(f"TORN tmp/ file: {os.path.basename(e['path'])} "
                             f"({e['size']} bytes, likely partial delivery)")
                continue
            m = analyze(e["raw"], f"maildir:{e['subdir']}/{os.path.basename(e['path'])}")
            m["flags"] = sorted(e["flags"])
            msgs.append(m)
        uidl_path = os.path.join(target, "uidl.txt")
        if os.path.exists(uidl_path):
            uidl = [int(x[3:]) for x in open(uidl_path).read().split()
                    if x.startswith("UID")]
    else:
        for chunk in read_mbox(target):
            for s in chunk["suspicious"]:
                notes.append(f"mbox line {chunk['offset']+1}: {s}")
            m = analyze(chunk["raw"], f"mbox@{target}:{chunk['offset']+1}")
            m["from_line"] = chunk["from_line"]
            msgs.append(m)
    return msgs, notes, uidl

def report(msgs, notes, uidl, timeline_path=None):
    print(f"== {len(msgs)} messages ==")
    for n in notes:
        print("NOTE:", n)
    print("\n-- timeline --")
    rows = []
    for m in msgs:
        frm = "; ".join(f"{a['name']} <{a['email']}>" if a["name"] else a["email"]
                        for a in m["from"]) or "(none)"
        rows.append((m["date"], m["subject"][:60], frm,
                     ",".join(a["filename"] for a in m["attachments"]),
                     ",".join(m.get("flags", []))))
    rows.sort(key=lambda r: (r[0] is None, r[0]))
    for dt, subj, frm, att, flags in rows:
        print(f"{dt.isoformat() if dt else 'NO-DATE':25} | {subj:40.40} | {frm:35.35} | {att} {flags}")
    print("\n-- threads --")
    for tid, tm in thread(msgs).items():
        if len(tm) > 1:
            print(f"thread {tid[:40]}: {len(tm)} msgs: " +
                  " -> ".join(x["subject"][:25] for x in tm))
    print("\n-- findings --")
    findings = triage(msgs, uidl)
    if not findings:
        print("none")
    for m, code, detail in findings:
        where = m["source"] if m else "(mailbox)"
        print(f"[{code}] {where}: {detail}")
    if timeline_path:
        with open(timeline_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["date", "subject", "from", "to", "attachments", "flags", "source"])
            for dt, subj, frm, att, flags in rows:
                m = next(x for x in msgs if x["subject"][:60] == subj[:60])
                w.writerow([dt.isoformat() if dt else "",
                            m["subject"],
                            "; ".join(a["email"] for a in m["from"]),
                            "; ".join(a["email"] for a in m["to"]),
                            att, flags, m["source"]])
        print(f"\ntimeline -> {timeline_path}")

if __name__ == "__main__":
    target = sys.argv[1]
    tl = sys.argv[2] if len(sys.argv) > 2 else None
    msgs, notes, uidl = collect(target)
    report(msgs, notes, uidl, tl)
