#!/usr/bin/env python3
"""Hand-rolled mailbox forensics parser. Zero deps beyond stdlib (no `mailbox`).

Covers: mbox From_ delimiting (+ corruption detection), Maildir layout + flags,
RFC 5322 header unfolding/decoding, MIME multipart walk, attachment extraction,
JWZ-lite threading, and timeline/triage output.
"""
import base64, binascii, hashlib, os, quopri, re
from datetime import datetime, timezone

class MailboxError(Exception): pass

# ---------------------------------------------------------------- mbox reader
FROM_RE = re.compile(r"^From \S+ \w{3} \w{3} +\d+ \d\d:\d\d:\d\d \d{4}$")

def read_mbox(path):
    """Return list of dicts: {from_line, raw, offset, suspicious}. Splits on
    blank-line + 'From ' lines; a 'From ' NOT preceded by a blank line is a
    corruption indicator (unescaped body line), not a delimiter."""
    with open(path, "rb") as f:
        data = f.read().decode("utf-8", "replace")
    msgs, cur, from_line, start = [], None, None, 0
    suspicious = []
    lines = data.split("\n")
    i = 0
    # mbox must start with a From line
    while i < len(lines) and not lines[i].startswith("From "):
        i += 1
    prev_blank = True
    while i < len(lines):
        line = lines[i]
        if line.startswith("From "):
            # Strict mbox: delimiter is blank-line + From_. A From_ line that
            # directly follows body content means the writer forgot to escape
            # ">From " -- the file is corrupted or hand-tampered. Record it,
            # but still split (that's what every real reader does).
            if not prev_blank and cur:
                suspicious.append(
                    f"From_ delimiter NOT preceded by blank line (mbox line {i+1}): "
                    "unescaped 'From ' in previous body?")
            if cur is not None:
                msgs.append({"from_line": from_line, "raw": "\n".join(cur),
                             "offset": start, "suspicious": list(suspicious)})
                suspicious = []
            from_line, start = line, i
            if not FROM_RE.match(line):
                suspicious.append(f"malformed From_ delimiter: {line[:60]!r}")
            cur = []
        else:
            cur.append(line)
        prev_blank = (line.strip() == "")
        i += 1
    if cur is not None:
        msgs.append({"from_line": from_line, "raw": "\n".join(cur),
                     "offset": start, "suspicious": list(suspicious)})
    return msgs

# ------------------------------------------------------------- Maildir reader
FLAG_MEANINGS = {"D": "draft", "F": "flagged", "P": "passed",
                 "R": "replied", "S": "seen", "T": "trashed"}

def read_maildir(root):
    """Return list of {path, subdir, flags, raw, uid_hint}. tmp/ files are
    delivery-in-progress; a file sitting in tmp/ with message-like content is
    a torn/partial remnant worth flagging."""
    out = []
    for sub in ("new", "cur", "tmp"):
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                raw = f.read()
            flags = set()
            m = re.search(r":2,([A-Z]*)$", name)
            if m:
                flags = {FLAG_MEANINGS.get(c, c) for c in m.group(1)}
            uid = re.search(r"U=(\d+)", name)
            out.append({"path": p, "subdir": sub, "flags": flags,
                        "raw": raw.decode("utf-8", "replace"),
                        "uid": int(uid.group(1)) if uid else None,
                        "size": len(raw)})
    return out

# ------------------------------------------------------- RFC 5322 headers
def unfold(raw_headers):
    out = []
    for line in raw_headers.split("\n"):
        if line[:1] in (" ", "\t") and out:
            out[-1] += " " + line.strip()
        else:
            out.append(line.strip())
    return out

ENC_WORD = re.compile(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=")

def decode_words(s):
    def sub(m):
        charset, enc, text = m.group(1), m.group(2).upper(), m.group(3)
        try:
            if enc == "B":
                b = base64.b64decode(text)
            else:
                b = quopri.decodestring(text.replace("_", " ").encode("latin-1"))
            return b.decode(charset, "replace")
        except Exception:
            return m.group(0)
    # adjacent encoded words separated by whitespace collapse to one
    return re.sub(r"\?=\s+=\?", "?==?", ENC_WORD.sub(sub, s))

def parse_headers(raw):
    """Split raw message into headers dict (lowercased keys, lists) + body."""
    head, sep, body = raw.partition("\n\n")
    if not sep:
        head, body = raw, ""
    hdrs = {}
    for line in unfold(head):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        hdrs.setdefault(k.strip().lower(), []).append(decode_words(v.strip()))
    return hdrs, body

ADDR_RE = re.compile(r'"?([^"<>@,]+)"?\s*<([^<>]+)>|([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)')

def parse_addrs(values):
    out = []
    for v in values:
        for m in ADDR_RE.finditer(v):
            name, email = (m.group(1), m.group(2)) if m.group(2) else ("", m.group(3))
            out.append({"name": (name or "").strip(' "'), "email": email.strip()})
    return out

def parse_date(v):
    """Parse RFC 2822 date -> aware datetime, or None."""
    from email.utils import parsedate_to_datetime
    try:
        dt = parsedate_to_datetime(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

RECEIVED_DATE = re.compile(r";\s*(.+)$")

def received_dates(hdrs):
    out = []
    for r in hdrs.get("received", []):
        m = RECEIVED_DATE.search(r)
        if m:
            dt = parse_date(m.group(1).strip())
            if dt:
                out.append(dt)
    return out

# ---------------------------------------------------------------- MIME walk
def split_multipart(body, boundary):
    parts, cur, in_part = [], [], False
    delim, close = "--" + boundary, "--" + boundary + "--"
    for line in body.split("\n"):
        s = line.strip()
        if s == delim:
            if in_part and cur:
                parts.append("\n".join(cur))
            cur, in_part = [], True
        elif s == close:
            if cur:
                parts.append("\n".join(cur))
            break
        elif in_part:
            cur.append(line)
    return parts

def decode_body(part_hdrs, body):
    cte = (part_hdrs.get("content-transfer-encoding", ["7bit"])[0]).lower()
    b = body.encode("latin-1")
    if cte == "base64":
        try:
            return base64.b64decode(re.sub(r"\s", "", body))
        except binascii.Error:
            return b"<base64 decode failed>".encode()
    if cte in ("quoted-printable", "quotedprintable"):
        return quopri.decodestring(b)
    return b.strip(b"\r\n")

def walk_mime(raw):
    """Yield {headers, content_type, filename, payload_bytes, depth} for each leaf."""
    hdrs, body = parse_headers(raw)
    ct = hdrs.get("content-type", ["text/plain"])[0]
    m = re.search(r'multipart/[^;]+;\s*boundary="?([^";]+)"?', ct, re.I)
    if m:
        for p in split_multipart(body, m.group(1)):
            yield from walk_mime(p)
        return
    filename = None
    for key in ("content-disposition", "content-type"):
        for v in hdrs.get(key, []):
            fm = re.search(r'filename="?([^";]+)"?', v, re.I) or \
                 re.search(r'name="?([^";]+)"?', v, re.I)
            if fm:
                filename = fm.group(1)
    yield {"headers": hdrs, "content_type": ct.split(";")[0].strip().lower(),
           "filename": filename, "payload": decode_body(hdrs, body)}

# ------------------------------------------------------------- message object
def analyze(raw, source):
    hdrs, _ = parse_headers(raw)
    msg = {
        "source": source,
        "message_id": (hdrs.get("message-id", [""])[0]).strip("<> "),
        "subject": hdrs.get("subject", [""])[0],
        "from": parse_addrs(hdrs.get("from", [])),
        "to": parse_addrs(hdrs.get("to", [])) + parse_addrs(hdrs.get("cc", [])),
        "date": parse_date(hdrs.get("date", [""])[0]) if hdrs.get("date") else None,
        "date_raw": hdrs.get("date", [""])[0] if hdrs.get("date") else "",
        "received": received_dates(hdrs),
        "in_reply_to": (hdrs.get("in-reply-to", [""])[0]).strip("<> "),
        "references": re.findall(r"<([^<>]+)>", " ".join(hdrs.get("references", []))),
        "labels": hdrs.get("x-gmail-labels", [""])[0] if hdrs.get("x-gmail-labels") else "",
        "attachments": [],
        "flags": [],
    }
    for leaf in walk_mime(raw):
        if leaf["filename"]:
            msg["attachments"].append({
                "filename": leaf["filename"],
                "content_type": leaf["content_type"],
                "size": len(leaf["payload"]),
                "sha256": hashlib.sha256(leaf["payload"]).hexdigest(),
            })
    return msg

# ------------------------------------------------------------- threading (JWZ-lite)
def thread(msgs):
    """Group by root ancestor via References/In-Reply-To chains."""
    by_id = {m["message_id"]: m for m in msgs if m["message_id"]}
    def root(m):
        seen, cur = set(), m
        while cur["message_id"] not in seen:
            seen.add(cur["message_id"])
            parent = cur["in_reply_to"] or (cur["references"][0] if cur["references"] else "")
            if parent and parent in by_id:
                cur = by_id[parent]
            else:
                break
        return cur["message_id"] or f"unidentified:{id(m)}"
    threads = {}
    for m in msgs:
        threads.setdefault(root(m), []).append(m)
    for tid in threads:
        threads[tid].sort(key=lambda m: (m["date"] is None, m["date"]))
    return threads

# ------------------------------------------------------------------- triage
SUSPICIOUS_EXTS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar",
                   ".msi", ".com", ".pif", ".hta", ".lnk"}

def triage(msgs, uidl=None):
    findings = []
    for m in msgs:
        # Date: header vs Received chain skew
        if m["date"] and m["received"]:
            skew = max(abs((m["date"] - r).total_seconds()) for r in m["received"])
            if skew > 48 * 3600:
                findings.append((m, "DATE_SKEW",
                    f"Date: header {m['date_raw'][:40]} disagrees with Received chain by {skew/86400:.1f} days"))
        if not m["from"]:
            findings.append((m, "NO_FROM", "no parseable From: address"))
        for a in m["attachments"]:
            ext = os.path.splitext(a["filename"])[1].lower()
            if ext in SUSPICIOUS_EXTS:
                findings.append((m, "RISKY_ATTACHMENT", f"{a['filename']} ({ext})"))
            if a["content_type"] == "text/html" and a["filename"]:
                findings.append((m, "HTML_ATTACHMENT", f"{a['filename']} — common phishing lure shape"))
    # UID gap analysis (deleted-message evidence)
    if uidl:
        uids = sorted(uidl)
        gaps = [b for a, b in zip(uids, uids[1:]) if b - a > 1
                for b in range(a + 1, b)]
        if gaps:
            findings.append((None, "UID_GAPS", f"UIDs missing (likely deleted): {gaps}"))
    return findings
