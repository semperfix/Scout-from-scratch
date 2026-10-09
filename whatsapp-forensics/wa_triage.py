"""WhatsApp msgstore.db triage engine.
Reads live rows with sqlite3, then carves DELETED message rows from b-tree
freeblocks with a hand-rolled page parser (the expedition-10 technique,
applied to the real `message` table layout). Emits a triage report.
"""
import sqlite3, struct, sys, os, csv, datetime

def varint(buf, pos):
    v = s = 0
    for i in range(9):
        b = buf[pos]; pos += 1
        if i == 8:
            v = (v << 8) | b; break
        v |= (b & 0x7F) << s
        if not b & 0x80: break
        s += 7
    return v, pos

def serial_size(st):
    if st == 0: return 0
    if st <= 6: return st if st < 5 else (6 if st == 5 else 8)
    if st == 7: return 8
    if st in (8, 9): return 0
    return (st - 12) // 2 if st % 2 == 0 else (st - 13) // 2

def parse_with_serials(serials, data):
    """Parse record body given explicit serial-type list -> values."""
    vals, q = [], 0
    for st in serials:
        n = serial_size(st)
        raw = data[q:q+n]; q += n
        if len(raw) < n:
            raise ValueError("short record body")
        if st == 0: vals.append(None)
        elif 1 <= st <= 6: vals.append(int.from_bytes(raw, 'big', signed=True))
        elif st == 7: vals.append(struct.unpack('>d', raw)[0])
        elif st == 8: vals.append(0)
        elif st == 9: vals.append(1)
        elif st >= 12 and st % 2 == 0: vals.append(raw)
        else:
            try: vals.append(raw.decode('utf-8'))
            except UnicodeDecodeError: vals.append(raw)
    return vals, q

def parse_record(payload):
    """payload -> list of python values (int/float/bytes/str/None)."""
    hlen, p = varint(payload, 0)
    sts, q = [], p
    while q < hlen:
        st, q = varint(payload, q); sts.append(st)
    vals, _ = parse_with_serials(sts, payload[q:])
    return vals

class FreeblockCarver:
    """Carve deleted rows of one table from its b-tree pages' freeblocks."""
    def __init__(self, path, table):
        self.raw = open(path, 'rb').read()
        self.psz = struct.unpack('>H', self.raw[16:18])[0] or 4096
        db = sqlite3.connect(path)
        self.cols = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
        self.root = db.execute(
            "SELECT rootpage FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
        db.close()

    def pages(self, pgno, out):
        off = (pgno - 1) * self.psz
        pg = self.raw[off:off+self.psz]
        ptype = pg[0]
        if ptype == 5:  # interior: 12-byte header, cell ptrs at 12
            ncells = struct.unpack('>H', pg[3:5])[0]
            for i in range(ncells):
                cptr = struct.unpack('>H', pg[12+2*i:14+2*i])[0]
                child = struct.unpack('>I', pg[cptr:cptr+4])[0]
                self.pages(child, out)
            right = struct.unpack('>I', pg[8:12])[0]
            self.pages(right, out)
        elif ptype == 13:  # leaf
            out.append(pg)
        return out

    def freeblocks(self, pg):
        blocks = []
        nxt = struct.unpack('>H', pg[1:3])[0]
        while nxt:
            size = struct.unpack('>H', pg[nxt+2:nxt+4])[0]
            blocks.append(pg[nxt+4:nxt+size])
            nxt = struct.unpack('>H', pg[nxt:nxt+2])[0]
        return blocks

    def _parse_intact(self, blk, off):
        """Parse a complete cell: varint(plen) + varint(rowid) + record."""
        plen, p = varint(blk, off)
        rowid, p = varint(blk, p)
        rec = parse_record(blk[p:p+plen])
        return (rowid, rec), p + plen

    def _parse_recon(self, blk, off):
        """Parse a cell whose first 4 bytes were clobbered by a freeblock
        header (payload-len varint, rowid varint, record-hdr-size, serial[0]).
        serial[0] is the _id column = rowid alias -> always NULL (serial 0)."""
        ncols = len(self.cols)
        serials = [0]; pos = off
        for _ in range(ncols - 1):
            st, pos = varint(blk, pos)
            serials.append(st)
        vals, used = parse_with_serials(serials, blk[pos:])
        return (None, vals), pos + used

    def carve(self, validate):
        found = []
        for pg in self.pages(self.root, []):
            for blk in self.freeblocks(pg):
                # First cell: the LIVE freeblock header always clobbers 4 bytes.
                try:
                    (rowid, vals), off = self._parse_recon(blk, 0)
                except Exception:
                    continue
                if validate(rowid, vals):
                    found.append((rowid, vals))
                while off < len(blk):
                    done = False
                    # Case A: later cell never had its own header -> intact.
                    try:
                        (r2, v2), off2 = self._parse_intact(blk, off)
                        if validate(r2, v2):
                            found.append((r2, v2)); off = off2; done = True
                    except Exception:
                        pass
                    # Case B: stale freeblock header (4B) + clobbered cell.
                    # The stale size field must equal the consumed cell size.
                    if not done and off + 4 < len(blk):
                        try:
                            size = struct.unpack('>H', blk[off+2:off+4])[0]
                            (r2, v2), off2 = self._parse_recon(blk, off + 4)
                            if validate(r2, v2) and off2 - off == size:
                                found.append((r2, v2)); off = off2; done = True
                        except Exception:
                            pass
                    if not done:
                        break
        return found

TS_MIN, TS_MAX = 1577836800000, 1893456000000  # 2020-01-01 .. 2030-01-01 (ms)
MTYPE_NAMES = {0: "text", 1: "image", 2: "video", 3: "voice", 9: "document"}

def validate_message(rowid, rec):
    # message cols: _id,chat_row_id,from_me,key_id,sender_jid_row_id,message_type,
    #               text_data,timestamp,status,sort_id,starred
    # NOTE: rowid is None for carved rows (destroyed by the freeblock header).
    if len(rec) != 11 or (rowid is not None and rowid <= 0):
        return False
    _, chat, frm, key_id, _, mtype, text, ts, _, _, _ = rec
    if frm not in (0, 1): return False
    if not isinstance(mtype, int) or mtype > 40: return False
    if not isinstance(ts, int) or not (TS_MIN <= ts <= TS_MAX): return False
    if not isinstance(chat, int) or chat <= 0: return False
    if text is not None and not isinstance(text, (str, bytes)): return False
    if key_id is not None and not isinstance(key_id, (str, bytes)): return False
    return True

def fmt_ts(ms):
    try:
        return datetime.datetime.fromtimestamp(ms/1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ms)

def triage(db_path, out_dir="/tmp/wa_triage_out"):
    os.makedirs(out_dir, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    rep = []
    rep.append(f"# WhatsApp msgstore triage — {db_path}")
    tables = [r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY 1")]
    rep.append(f"tables/views: {', '.join(tables)}")
    has = lambda t: t in tables

    # ---- chats ----
    rep.append("\n## Chats")
    chats = list(db.execute("""SELECT c._id, j.raw_string, c.subject,
        (SELECT COUNT(*) FROM message m WHERE m.chat_row_id=c._id) AS n,
        (SELECT MIN(m.timestamp) FROM message m WHERE m.chat_row_id=c._id) AS first,
        (SELECT MAX(m.timestamp) FROM message m WHERE m.chat_row_id=c._id) AS last
        FROM chat c JOIN jid j ON j._id=c.jid_row_id ORDER BY c._id"""))
    for ch in chats:
        kind = "group" if ch["raw_string"].endswith("@g.us") else "1-1"
        rep.append(f"- chat {ch['_id']} [{kind}] {ch['subject'] or ch['raw_string']}: "
                   f"{ch['n']} msgs, {fmt_ts(ch['first'])} -> {fmt_ts(ch['last'])}")
        if kind == "group" and has("group_participants"):
            parts = db.execute("""SELECT j.raw_string, gp.rank FROM group_participants gp
                                  JOIN jid j ON j._id=gp.jid_row_id
                                  WHERE gp.gjid_row_id=(SELECT jid_row_id FROM chat WHERE _id=?)""",
                               (ch["_id"],)).fetchall()
            rep.append("  participants: " + ", ".join(
                f"{p['raw_string'].split('@')[0]}{' (admin)' if p['rank']==1 else ''}" for p in parts))

    # ---- per-chat composition ----
    rep.append("\n## Message composition (live rows)")
    for ch in chats:
        rows = db.execute("""SELECT message_type, from_me, COUNT(*),
                             SUM(CASE WHEN text_data IS NULL THEN 1 ELSE 0 END)
                             FROM message WHERE chat_row_id=? GROUP BY 1,2""",
                          (ch["_id"],)).fetchall()
        comp = "; ".join(f"{MTYPE_NAMES.get(r[0], r[0])} {'out' if r[1] else 'in'}:{r[2]}"
                         + (f"({r[3]} no-text)" if r[3] else "") for r in rows)
        media = db.execute("""SELECT COUNT(*) FROM message_media mm JOIN message m
                              ON m._id=mm.message_row_id WHERE m.chat_row_id=?""",
                           (ch["_id"],)).fetchone()[0]
        rep.append(f"- chat {ch['_id']}: {comp} | media rows: {media}")

    # ---- edits & reactions ----
    if has("message_add_on"):
        rep.append("\n## Edits & reactions (message_add_on)")
        for r in db.execute("""SELECT a.add_on_type, a.text_data, m.text_data AS orig,
                               a.timestamp, j.raw_string FROM message_add_on a
                               LEFT JOIN message m ON m._id=a.message_row_id
                               LEFT JOIN jid j ON j._id=a.sender_jid_row_id
                               ORDER BY a.timestamp"""):
            who = (r["raw_string"] or "?").split("@")[0]
            if r["add_on_type"] == 2:
                rep.append(f"- EDIT by {who} @ {fmt_ts(r['timestamp'])}: {r['orig']!r} -> {r['text_data']!r}")
            elif r["add_on_type"] == 1:
                rep.append(f"- REACTION {r['text_data']} by {who} @ {fmt_ts(r['timestamp'])}")
            else:
                rep.append(f"- add_on type={r['add_on_type']} by {who}: {r['text_data']!r}")
        orphans = db.execute("""SELECT COUNT(*) FROM message_add_on a
                                LEFT JOIN message m ON m._id=a.message_row_id
                                WHERE m._id IS NULL""").fetchone()[0]
        if orphans:
            rep.append(f"  !! {orphans} add-ons point at MISSING (deleted) messages")

    # ---- calls ----
    if has("call_log"):
        rep.append("\n## Calls")
        res = {0: "missed", 1: "answered", 2: "rejected"}
        for r in db.execute("""SELECT j.raw_string, cl.from_me, cl.timestamp, cl.duration,
                               cl.call_result FROM call_log cl JOIN jid j ON j._id=cl.jid_row_id
                               ORDER BY cl.timestamp"""):
            rep.append(f"- {'out' if r['from_me'] else 'in'} {r['raw_string'].split('@')[0]} "
                       f"@ {fmt_ts(r['timestamp'])}: {r['duration']}s ({res.get(r['call_result'], '?')})")

    # ---- anomalies ----
    rep.append("\n## Anomaly flags")
    flags = []
    n_textless = db.execute("""SELECT COUNT(*) FROM message m LEFT JOIN message_media mm
                               ON mm.message_row_id=m._id
                               WHERE m.text_data IS NULL AND m.message_type=0
                               AND mm.message_row_id IS NULL""").fetchone()[0]
    if n_textless: flags.append(f"{n_textless} text-type messages with no text and no media row")
    ooo = db.execute("""SELECT chat_row_id, COUNT(*) FROM
        (SELECT chat_row_id, timestamp,
                LAG(timestamp) OVER (PARTITION BY chat_row_id ORDER BY sort_id) AS prev
         FROM message) WHERE prev IS NOT NULL AND timestamp < prev - 60000
        GROUP BY 1""").fetchall()
    for chat_id, n in ooo:
        flags.append(f"chat {chat_id}: {n} messages out of chronological order (timeline surgery?)")
    dupes = db.execute("""SELECT chat_row_id, from_me, key_id, COUNT(*) FROM message
                          GROUP BY 1,2,3 HAVING COUNT(*)>1""").fetchall()
    for d in dupes:
        flags.append(f"chat {d[0]}: duplicate message key {d[2]!r} x{d[3]}")
    rep.append("\n".join(f"- {f}" for f in flags) if flags else "- none")

    # ---- deleted-message carving ----
    rep.append("\n## Deleted-message recovery (freeblock carving)")
    carved = FreeblockCarver(db_path, "message").carve(validate_message)
    # dedupe: carved rows lost their rowids, so fingerprint by content and
    # drop anything already present among live rows
    live_sig = {(r[0], r[1], r[2], r[3]) for r in db.execute(
        "SELECT chat_row_id, from_me, timestamp, text_data FROM message")}
    def sig(rec):
        t = rec[6]
        if isinstance(t, bytes):
            t = t.decode('utf-8', 'replace')
        return (rec[1], rec[2], rec[7], t)
    uniq, seen = [], set()
    for _, rec in carved:
        s = sig(rec)
        if s not in live_sig and s not in seen:
            seen.add(s); uniq.append(rec)
    rep.append(f"recovered {len(uniq)} deleted message rows from freeblocks")
    for rec in sorted(uniq, key=lambda r: r[7]):
        _, chat, frm, key_id, _, mtype, text, ts, _, _, _ = rec
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'replace')
        rep.append(f"- [deleted] chat {chat} {'out' if frm else 'in'} "
                   f"{MTYPE_NAMES.get(mtype, mtype)} @ {fmt_ts(ts)}: {text!r}")
    db.close()

    # ---- timeline CSV ----
    with open(f"{out_dir}/timeline.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "chat", "dir", "type", "text", "deleted"])
        db = sqlite3.connect(db_path)
        for r in db.execute("""SELECT m.timestamp, c.subject, m.from_me, m.message_type,
                               m.text_data FROM message m JOIN chat c ON c._id=m.chat_row_id
                               ORDER BY m.timestamp"""):
            w.writerow([fmt_ts(r[0]), r[1], "out" if r[2] else "in",
                        MTYPE_NAMES.get(r[3], r[3]), r[4], 0])
        for rec in sorted(uniq, key=lambda r: r[7]):
            _, chat, frm, _, _, mtype, text, ts, _, _, _ = rec
            subj = db.execute("SELECT subject FROM chat WHERE _id=?", (chat,)).fetchone()
            w.writerow([fmt_ts(ts), subj[0] if subj else chat, "out" if frm else "in",
                        MTYPE_NAMES.get(mtype, mtype),
                        text.decode('utf-8', 'replace') if isinstance(text, bytes) else text, 1])
        db.close()

    report = "\n".join(rep)
    open(f"{out_dir}/triage.txt", "w").write(report)
    return report, len(uniq)

if __name__ == "__main__":
    path = sys.argv[1]
    report, n = triage(path)
    print(report)
    print(f"\n[wrote /tmp/wa_triage_out/triage.txt + timeline.csv; carved={n}]")
