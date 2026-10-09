#!/usr/bin/env python3
"""test_sqlite.py -- validate sqliteparse.py against real SQLite databases.

Builds fixture DBs with the stdlib sqlite3 module (fixture generation only --
the parser under test never touches sqlite3), then checks:
  1. header parse (magic, page size, encoding)
  2. --dump rows match sqlite3's own query results, including a multi-KB blob
     that forces overflow pages (validates the overflow local-size solver)
  3. deleted rows are carved back: recently-deleted rows from unallocated
     space (full cells, rowid intact), a middle-deleted row from its freeblock
     (heuristic first-bytes reconstruction)
  4. WAL: header + per-frame checksums verify against a real -wal file, and
     un-checkpointed pages are detected.
"""
import os
import shutil
import sqlite3
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sqliteparse
from sqliteparse import Database

FIX = "/tmp/sqlite_forensics_fixture.db"
WFIX = "/tmp/sqlite_forensics_wal.db"
CLI = os.path.join(HERE, "sqliteforensics.py")

checks = []


def check(name, cond, detail=""):
    checks.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (" -- " + detail if detail and not cond else ""))


def build_main():
    if os.path.exists(FIX):
        os.remove(FIX)
    con = sqlite3.connect(FIX)
    # This container's sqlite3 defaults secure_delete=ON (zeroes freed cells);
    # real-world targets (browsers, chat apps) don't -- turn it off so the
    # fixture actually exercises the carver.
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE notes(id INTEGER, title TEXT, body TEXT)")
    for i in range(1, 11):
        con.execute("INSERT INTO notes VALUES (?,?,?)",
                    (i, "note-%s" % ["one", "two", "three", "four", "five",
                                     "six", "seven", "eight", "nine", "ten"][i - 1],
                     "body of note number %d" % i))
    con.execute("CREATE TABLE big(id INTEGER, payload BLOB)")
    blobs = {1: os.urandom(100), 2: os.urandom(5000), 3: os.urandom(20000)}
    for i, b in blobs.items():
        con.execute("INSERT INTO big VALUES (?,?)", (i, b))
    con.commit()
    # delete: id 4 sits mid-page -> freeblock; ids 9,10 are the newest cells ->
    # likely unallocated space. Carver handles both; we assert on content.
    con.execute("DELETE FROM notes WHERE id IN (4, 9, 10)")
    con.commit()
    live = con.execute("SELECT id, title, body FROM notes ORDER BY id").fetchall()
    con.close()
    return live, blobs


def build_wal():
    for p in (WFIX, WFIX + "-wal", WFIX + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    con = sqlite3.connect(WFIX)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    con.executemany("INSERT INTO t VALUES (?,?)", [(i, "walval-%d" % i) for i in range(50)])
    con.commit()
    # snapshot BOTH files while the connection is open: closing checkpoints
    # the WAL into the main db, which would erase the un-checkpointed diff
    shutil.copy(WFIX + "-wal", "/tmp/sqlite_forensics_wal_copy.wal")
    shutil.copy(WFIX, "/tmp/sqlite_forensics_wal_copy.db")
    con.close()
    return "/tmp/sqlite_forensics_wal_copy.wal", "/tmp/sqlite_forensics_wal_copy.db"


def main():
    live, blobs = build_main()
    db = Database(FIX)

    check("header magic", db.data[:16] == sqliteparse.MAGIC)
    check("page size sane", db.page_size in (1024, 2048, 4096, 8192, 16384, 65536),
          str(db.page_size))
    check("encoding utf-8", db.encoding == 1)

    schema = sqliteparse.read_schema(db)
    tnames = sorted(e["tbl_name"] for e in schema if e["type"] == "table"
                    and not e["name"].startswith("sqlite_"))
    check("schema tables", tnames == ["big", "notes"], str(tnames))

    cols, rows = sqliteparse.dump_table(db, "notes")
    check("dump column names", cols == ["id", "title", "body"], str(cols))
    got = sorted((r["id"], r["title"], r["body"]) for r in rows)
    check("dump rows match sqlite3", got == sorted(live),
          "got %d rows, sqlite3 has %d" % (len(got), len(live)))
    check("deleted ids absent from dump",
          {r["id"] for r in rows} == {1, 2, 3, 5, 6, 7, 8})

    _, bigrows = sqliteparse.dump_table(db, "big")
    biggot = {r["id"]: r["payload"] for r in bigrows}
    ok = all(biggot[i] == blobs[i] for i in blobs)
    check("overflow blobs round-trip (100/5000/20000 bytes)", ok,
          "lengths: " + str(sorted((k, len(v)) for k, v in biggot.items())))

    recs = sqliteparse.carve_db(db)
    texts = " ".join(repr(r["values"]) for r in recs)
    for marker, name in [("note-four", "deleted id 4 (freeblock)"),
                         ("note-nine", "deleted id 9"),
                         ("note-ten", "deleted id 10")]:
        check("carved " + name, marker in texts, texts[:200])
    check("carve count >= 3", len(recs) >= 3, str(len(recs)))
    intact = [r for r in recs if not r["heuristic"] and r["rowid"] is not None]
    check("some intact cells with rowids", len(intact) >= 1, str(len(intact)))

    # WAL
    wal_copy, wal_db_copy = build_wal()
    wdb = Database(wal_db_copy)
    wal = sqliteparse.parse_wal(wal_copy, wdb.page_size)
    check("wal magic/version", wal["version"] == sqliteparse.WAL_VERSION,
          str(wal["version"]))
    check("wal header checksum verifies", wal["checksum_ok"],
          str(wal["computed_checksum"]))
    check("wal has frames", len(wal["frames"]) >= 2, str(len(wal["frames"])))
    bad_frames = [f for f in wal["frames"] if not (f["checksum_ok"] and f["salt_ok"])]
    check("all wal frame checksums+salt verify", not bad_frames,
          str([(f["frame"], f["checksum_ok"], f["salt_ok"]) for f in bad_frames]))
    diff = sqliteparse.wal_uncheckpointed(wdb, wal)
    check("un-checkpointed pages detected", len(diff) >= 1, str(diff))

    # CLI smoke
    for argv in (["--schema"], ["--dump", "notes"], ["--carve"]):
        p = subprocess.run([sys.executable, CLI, FIX] + argv,
                           capture_output=True, text=True)
        check("cli %s exits 0" % " ".join(argv), p.returncode == 0, p.stderr[:200])
    # CLI --wal smoke: fresh WAL db, connection held open so the -wal exists
    w2 = "/tmp/sqlite_forensics_wal2.db"
    for suf in ("", "-wal", "-shm"):
        if os.path.exists(w2 + suf):
            os.remove(w2 + suf)
    con = sqlite3.connect(w2)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t(x TEXT)")
    con.execute("INSERT INTO t VALUES ('hello')")
    con.commit()
    p = subprocess.run([sys.executable, CLI, w2, "--wal"],
                       capture_output=True, text=True)
    check("cli --wal exits 0 and verifies", p.returncode == 0 and "checksum OK" in p.stdout,
          p.stdout[:300] + p.stderr[:200])
    con.close()

    p = subprocess.run([sys.executable, CLI, "--help"], capture_output=True, text=True)
    check("cli --help", p.returncode == 0 and "usage" in p.stdout.lower())

    failed = [n for n, ok, _ in checks if not ok]
    print("\n%d/%d checks passed" % (len(checks) - len(failed), len(checks)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
