"""End-to-end validation: build -> encrypt -> decrypt -> triage, all asserted."""
import os, sys, sqlite3, time
sys.path.insert(0, os.path.dirname(__file__))
from crypt_wa import make_key_file, load_backup_key, encrypt_crypt14, decrypt_crypt14
from wa_triage import triage

D = os.path.dirname(os.path.abspath(__file__))
DB = f"{D}/e2e_msgstore.db"
KEYF = f"{D}/e2e_key"
C14 = f"{D}/e2e_msgstore.db.crypt14"

# 1. build synthetic db (subprocess to keep randomness/seed behavior identical)
os.system(f"cd {D} && python3 make_msgstore.py e2e_msgstore.db > /dev/null")
orig = open(DB, "rb").read()
print(f"1. fixture db built: {len(orig)} bytes")

# 2. encrypt to crypt14 with a fresh key file
key = make_key_file(KEYF)
t0 = time.time()
encrypt_crypt14(DB, C14, key)
print(f"2. encrypted to crypt14: {os.path.getsize(C14)} bytes ({time.time()-t0:.1f}s)")

# 3. decrypt with hand-rolled stack; must be byte-identical
t0 = time.time()
pt, meta = decrypt_crypt14(C14, load_backup_key(KEYF))
dt = time.time() - t0
assert pt == orig, "decrypted db differs from original!"
print(f"3. decrypted byte-identical ({dt:.1f}s); header via {meta['nonce_source']}")
open(f"{D}/e2e_decrypted.db", "wb").write(pt)
assert sqlite3.connect(f"{D}/e2e_decrypted.db").execute(
    "pragma integrity_check").fetchone()[0] == "ok"
print("   sqlite integrity_check: ok")

# 4. triage the decrypted db
report, carved = triage(f"{D}/e2e_decrypted.db", out_dir=f"{D}/e2e_out")
db = sqlite3.connect(f"{D}/e2e_decrypted.db")
n_live = db.execute("select count(*) from message").fetchone()[0]
assert n_live == 79, f"expected 79 live messages, got {n_live}"
assert carved == 8, f"expected 8 carved deleted rows, got {carved}"
assert "Tree Crew" in report and "Maya Chen" in report
assert "EDIT by" in report and "REACTION" in report
assert "missed" in report  # call log
print(f"4. triage ok: {n_live} live + {carved} carved deleted; edits/reactions/calls found")

# 5. timeline csv has live + deleted rows
import csv
rows = list(csv.DictReader(open(f"{D}/e2e_out/timeline.csv")))
assert len(rows) == 87, f"timeline rows: {len(rows)}"
assert sum(1 for r in rows if r["deleted"] == "1") == 8
print(f"5. timeline.csv: {len(rows)} rows (79 live + 8 deleted)")

print("\nEND-TO-END PIPELINE: ALL CHECKS PASS")
