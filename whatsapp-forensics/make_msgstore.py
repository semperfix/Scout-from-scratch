"""Build a synthetic WhatsApp msgstore.db (modern post-2021 schema) for testing.
ALL people/numbers are fictional (555-0xxx range). No real user data.
Includes: 1-1 chat, group chat, media, edits, reactions, calls, receipts,
and DELETED messages (rows deleted without VACUUM -> recoverable freeblocks).
"""
import sqlite3, os, random, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "msgstore.db"
random.seed(20261008)
if os.path.exists(OUT):
    os.remove(OUT)

db = sqlite3.connect(OUT)
c = db.cursor()

c.executescript("""
CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT, type INTEGER);
CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT,
                   created_timestamp INTEGER, archived INTEGER DEFAULT 0);
CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER,
    key_id TEXT, sender_jid_row_id INTEGER, message_type INTEGER, text_data TEXT,
    timestamp INTEGER, status INTEGER DEFAULT 0, sort_id INTEGER, starred INTEGER DEFAULT 0);
CREATE TABLE message_media (message_row_id INTEGER PRIMARY KEY, file_path TEXT,
    mime_type TEXT, file_size INTEGER, media_key BLOB, file_hash BLOB);
CREATE TABLE message_add_on (_id INTEGER PRIMARY KEY, chat_row_id INTEGER,
    message_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER,
    add_on_type INTEGER, timestamp INTEGER, text_data TEXT);
CREATE TABLE group_participants (_id INTEGER PRIMARY KEY, gjid_row_id INTEGER,
    jid_row_id INTEGER, rank INTEGER);
CREATE TABLE call_log (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, from_me INTEGER,
    timestamp INTEGER, duration INTEGER, call_result INTEGER);
CREATE TABLE receipts (message_row_id INTEGER, receipt_device_timestamp INTEGER,
    read_device_timestamp INTEGER);
CREATE TABLE props (key TEXT PRIMARY KEY, value TEXT);
CREATE VIEW chat_list AS
  SELECT ch._id AS _id, ch.jid_row_id, j.raw_string AS raw_string_jid,
         (SELECT MAX(m.timestamp) FROM message m WHERE m.chat_row_id = ch._id) AS sort_timestamp,
         (SELECT COUNT(*) FROM message m WHERE m.chat_row_id = ch._id) AS message_count
  FROM chat ch JOIN jid j ON j._id = ch.jid_row_id;
""")

# ---- identities (fictional) ----
ME = "15550000001@s.whatsapp.net"
PEOPLE = {
    "maya":  "15550001111@s.whatsapp.net",
    "devon": "15550002222@s.whatsapp.net",
    "priya": "15550003333@s.whatsapp.net",
}
GROUP = "15550009999-1728000000@g.us"
jid = {}
def add_jid(raw, typ):
    c.execute("INSERT INTO jid(raw_string,type) VALUES(?,?)", (raw, typ))
    jid[raw] = c.lastrowid
    return jid[raw]
add_jid(ME, 1)
for p in PEOPLE.values(): add_jid(p, 1)
add_jid(GROUP, 2)

def add_chat(raw, subject, created):
    c.execute("INSERT INTO chat(jid_row_id,subject,created_timestamp) VALUES(?,?,?)",
              (jid[raw], subject, created))
    return c.lastrowid

BASE = 1758326400000  # 2025-09-20 00:00 UTC in ms
DAY = 86400000
maya_chat = add_chat(PEOPLE["maya"], "Maya Chen", BASE)
group_chat = add_chat(GROUP, "Tree Crew", BASE + DAY)
devon_chat = add_chat(PEOPLE["devon"], "Devon Park", BASE + 2*DAY)

mid = 0
def add_msg(chat, frm, text, ts, mtype=0, sender=None, status=5):
    global mid
    mid += 1
    key_id = f"{ts:X}{mid:04d}"
    sender = sender or (ME if frm else None)
    srow = jid[sender] if sender else None
    c.execute("""INSERT INTO message(chat_row_id,from_me,key_id,sender_jid_row_id,
                 message_type,text_data,timestamp,status,sort_id)
                 VALUES(?,?,?,?,?,?,?,?,?)""",
              (chat, frm, key_id, srow, mtype, text, ts, status, mid))
    return c.lastrowid

def add_media(mrow, path, mime, size):
    c.execute("INSERT INTO message_media VALUES(?,?,?,?,?,?)",
              (mrow, path, mime, size, os.urandom(32), os.urandom(32)))

# ---- Chat 1: Maya, 45 messages, mixed directions ----
maya_texts_in = ["hey are you coming saturday", "bring the climbing rope",
    "did the chipper get fixed", "lol no way", "call me when you're free",
    "sending the invoice now", "check the oak on elm st", "running late, 10 min",
    "that storm took down the maple", "good work today"]
maya_texts_out = ["on my way", "rope's in the truck", "chipper's good",
    "haha yeah right", "will do", "got it thanks", "which oak", "no worries",
    "saw that, big one", "you too"]
t = BASE
msg_rows_maya = []
for i in range(45):
    t += random.randint(30*60000, 20*3600000)
    frm = i % 2
    txt = (maya_texts_out if frm else maya_texts_in)[i % 10]
    r = add_msg(maya_chat, frm, txt, t)
    msg_rows_maya.append(r)
# media messages
for i, (mime, path, mtype) in enumerate([
        ("image/jpeg", "WhatsApp Images/IMG-20250921-WA0001.jpg", 1),
        ("image/jpeg", "WhatsApp Images/IMG-20250925-WA0007.jpg", 1),
        ("audio/ogg", "WhatsApp Voice Notes/PTT-20251001.opus", 3)]):
    t += 3600000
    r = add_msg(maya_chat, i % 2, None if mtype != 1 else "the oak", t, mtype)
    add_media(r, path, mime, random.randint(50000, 900000))
    msg_rows_maya.append(r)
# one EDITED message: original + add_on type 2 carrying the new text
t += 3600000
orig = add_msg(maya_chat, 1, "meeting at 3pm", t)
c.execute("""INSERT INTO message_add_on(chat_row_id,message_row_id,from_me,key_id,
             sender_jid_row_id,add_on_type,timestamp,text_data)
             VALUES(?,?,?,?,?,?,?,?)""",
          (maya_chat, orig, 1, "edit1", jid[ME], 2, t + 60000, "meeting at 4pm"))
msg_rows_maya.append(orig)
# two reactions (add_on type 1)
for target in msg_rows_maya[5], msg_rows_maya[12]:
    t += 60000
    c.execute("""INSERT INTO message_add_on(chat_row_id,message_row_id,from_me,key_id,
                 sender_jid_row_id,add_on_type,timestamp,text_data)
                 VALUES(?,?,?,?,?,?,?,?)""",
              (maya_chat, target, 0, f"react{target}", jid[PEOPLE["maya"]], 1, t, "\u2764\ufe0f"))
# receipts for first 20
for r in msg_rows_maya[:20]:
    c.execute("INSERT INTO receipts VALUES(?,?,?)", (r, t, t + 120000))

# ---- Chat 2: Tree Crew group ----
c.execute("INSERT INTO group_participants(gjid_row_id,jid_row_id,rank) VALUES(?,?,?)",
          (jid[GROUP], jid[PEOPLE["maya"]], 1))
c.execute("INSERT INTO group_participants(gjid_row_id,jid_row_id,rank) VALUES(?,?,?)",
          (jid[GROUP], jid[PEOPLE["devon"]], 0))
c.execute("INSERT INTO group_participants(gjid_row_id,jid_row_id,rank) VALUES(?,?,?)",
          (jid[GROUP], jid[ME], 0))
t = BASE + DAY
senders = [PEOPLE["maya"], PEOPLE["devon"], ME]
gtexts = ["job's at 8am tomorrow", "who's got the 200ft rope", "i do",
          "elm st oak, bring the big saw", "on it", "lunch after?",
          "sure, tacos", "pics from today", "nice work crew", "storm cleanup friday"]
for i in range(30):
    t += random.randint(10*60000, 8*3600000)
    s = senders[i % 3]
    r = add_msg(group_chat, 1 if s == ME else 0, gtexts[i % 10], t, sender=s)
    if i == 7:
        add_media(r, "WhatsApp Video/VID-20250922-WA0002.mp4", "video/mp4", 4200000)
        c.execute("UPDATE message SET message_type=2 WHERE _id=?", (r,))

# ---- Chat 3: Devon, short ----
t = BASE + 2*DAY
for i, txt in enumerate(["yo", "yo", "tuesday still good?", "yep", "bring cash",
                         "how much", "60", "k"]):
    t += random.randint(60000, 3600000)
    add_msg(devon_chat, i % 2, txt, t)

# ---- calls ----
for i, (frm, dur, res) in enumerate([(0, 312, 1), (1, 45, 1), (0, 0, 0), (1, 900, 1)]):
    c.execute("INSERT INTO call_log(jid_row_id,from_me,timestamp,duration,call_result) VALUES(?,?,?,?,?)",
              (jid[PEOPLE["maya"]], frm, BASE + i*3*DAY, dur, res))

c.execute("INSERT INTO props VALUES('fts_ready','1')")
c.execute("INSERT INTO props VALUES('backup_changes','0')")
db.commit()

# ---- DELETIONS (no vacuum: freeblocks keep the rows) ----
# NOTE: Python's SQLite defaults to secure_delete=ON (zeroes freed cells).
# Real-world WhatsApp msgstore.db deletions ARE carvable per forensic
# write-ups, so we switch it OFF here to model the recoverable case.
db.execute("PRAGMA secure_delete=OFF")
# delete 6 scattered Maya messages + 2 group messages
victims = [msg_rows_maya[i] for i in (3, 11, 19, 27, 33, 41)]
c.execute("SELECT _id FROM message WHERE chat_row_id=? ORDER BY _id LIMIT 2 OFFSET 5", (group_chat,))
victims += [r[0] for r in c.fetchall()]
print("deleting message rows:", victims)
c.execute(f"DELETE FROM message WHERE _id IN ({','.join('?'*len(victims))})", victims)
db.commit()
db.execute("PRAGMA journal_mode=DELETE")
db.commit(); db.close()
print("wrote", OUT)
