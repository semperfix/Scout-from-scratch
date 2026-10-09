#!/usr/bin/env python3
"""Validation for expedition #21. Ground truth: fixtures/ground_truth.txt.
Cross-validation: Python stdlib `mailbox` module (independent implementation).
"""
import hashlib, mailbox, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mboxparse import (read_mbox, read_maildir, analyze, thread, triage,
                       parse_headers, walk_mime)
from mbtriage import collect, mbox_unescape

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1; print(f"  ok: {name}")
    else:
        failed += 1; print(f"  FAIL: {name} {extra}")

print("== mbox parsing ==")
chunks = read_mbox(os.path.join(FIX, "inbox.mbox"))
check("8 messages in mbox", len(chunks) == 8, f"got {len(chunks)}")
check("no corruption notes on clean mbox",
      not any(c["suspicious"] for c in chunks))
msgs = [analyze(c["raw"], "test") for c in chunks]

print("== header decoding ==")
inv = next(m for m in msgs if "invoice" in m["subject"].lower())
check("encoded-word subject decoded", inv["subject"] == "Your invoice – October is ready for review",
      repr(inv["subject"]))
check("folded Cc parsed", any(a["email"] == "tony.smith@example.com" for a in inv["to"]))
check("X-Gmail-Labels kept", inv["labels"] == "Inbox,Unread", repr(inv["labels"]))

print("== From_ escaping ==")
tony = next(m for m in msgs if m["message_id"] == "tony-shop-21@example.com")
_, body = parse_headers(chunks[2]["raw"])
check("escaped >From line preserved in body", ">From the shop floor" in body)
check("unescape restores original", "From the shop floor, nobody leaves early." in
      mbox_unescape(chunks[2]["raw"]))

print("== EOF edge case ==")
amanda = next(m for m in msgs if m["message_id"] == "amanda-dinner-21@example.com")
check("message without trailing newline parsed", amanda["subject"] == "dinner")

print("== attachments ==")
check("one attachment found", len(inv["attachments"]) == 1)
a = inv["attachments"][0]
check("filename", a["filename"] == "invoice.html", a["filename"])
check("sha256 matches ground truth",
      a["sha256"] == "abe116a5af46a0fc89fa11e7b9e1705a88a9198a210c3dadcf8b9c2864a8d42f")
check("size 76 bytes", a["size"] == 76, str(a["size"]))
leaves = list(walk_mime(chunks[4]["raw"]))
check("M5 multipart leaf count (text+html attach)", len(leaves) == 2, str(len(leaves)))

print("== threading ==")
th = thread(msgs)
big = [t for t in th.values() if len(t) > 1]
check("one 2-message thread", len(big) == 1 and len(big[0]) == 2)
check("thread order parent->reply",
      big[0][0]["message_id"] == "CA+parent21@example.com")

print("== date-skew detection ==")
abe = next(m for m in msgs if m["message_id"] == "abe-money-21@example.com")
findings = triage(msgs)
skew = [f for f in findings if f[1] == "DATE_SKEW" and f[0]["message_id"] == "abe-money-21@example.com"]
check("M4 spoofed Date flagged", len(skew) == 1, str(skew))
check("no other DATE_SKEW", sum(1 for f in findings if f[1] == "DATE_SKEW") == 1)
htmlf = [f for f in findings if f[1] == "HTML_ATTACHMENT"]
check("HTML attachment shape flagged", len(htmlf) == 1)

print("== corrupt.mbox ==")
cc = read_mbox(os.path.join(FIX, "corrupt.mbox"))
check("corrupt file splits into 2", len(cc) == 2, str(len(cc)))
check("unescaped-From note recorded",
      any("NOT preceded by blank line" in s for c in cc for s in c["suspicious"]))
frag = analyze(cc[1]["raw"], "test")
check("fragment has no From: (corruption tell)", frag["from"] == [])

print("== stdlib cross-validation ==")
std = list(mailbox.mbox(os.path.join(FIX, "inbox.mbox")))
check("stdlib agrees: 8 messages", len(std) == 8, str(len(std)))
from mboxparse import decode_words
std_subj = sorted(decode_words(k.get("subject") or "") for k in std)
mine_subj = sorted(m["subject"] for m in msgs)
check("subjects match stdlib", std_subj == mine_subj,
      f"\n std: {std_subj}\n mine: {mine_subj}")

print("== Maildir ==")
entries = read_maildir(os.path.join(FIX, "maildir"))
complete = [e for e in entries if e["subdir"] in ("new", "cur")]
check("5 complete maildir messages", len(complete) == 5, str(len(complete)))
torn = [e for e in entries if e["subdir"] == "tmp"]
check("1 torn tmp file", len(torn) == 1 and torn[0]["size"] == 120)
fs = next(e for e in complete if e["flags"])
check("flags parsed (F=flagged, S=seen)", fs["flags"] == {"flagged", "seen"}, str(fs["flags"]))
msgs2, notes, uidl = collect(os.path.join(FIX, "maildir"))
check("torn tmp noted", any("TORN" in n for n in notes), str(notes))
gaps = [f for f in triage(msgs2, uidl) if f[1] == "UID_GAPS"]
check("UID1005 gap detected", len(gaps) == 1 and "1005" in gaps[0][2], str(gaps))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
