#!/usr/bin/env python3
"""sqliteforensics.py -- CLI triage for SQLite database files.

Parses the file format from scratch (see sqliteparse.py): no sqlite3 module
needed for analysis (it is only used by test_sqlite.py to build fixtures).

Exit 0 always; machine-readable lines start with SCHEMA:/ROW:/CARVED:/WAL:.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sqliteparse
from sqliteparse import Database, CorruptError


def fmt_value(v):
    if v is None:
        return "NULL"
    if isinstance(v, bytes):
        try:
            t = v.decode("utf-8")
            if all(32 <= ord(c) < 127 or c in "\n\t" for c in t):
                return repr(t)
        except UnicodeDecodeError:
            pass
        h = v.hex()
        return "blob<%d bytes %s%s>" % (len(v), h[:32], "..." if len(h) > 32 else "")
    if isinstance(v, float):
        return repr(v)
    return str(v)


def cmd_schema(db):
    schema = sqliteparse.read_schema(db)
    tables = [e for e in schema if e["type"] == "table"]
    print("database: %s" % db.path)
    print("page_size=%d encoding=%d pages=%d freelist_pages=%d" % (
        db.header["page_size"], db.header["text_encoding"],
        db.npages(), db.header["freelist_pages"]))
    for e in tables:
        tname, cols = sqliteparse.parse_create_table(e["sql"] or "")
        colstr = ", ".join("%s %s" % (n, d) for n, d, _ in cols)
        print("SCHEMA: table=%s rootpage=%d columns=(%s)" % (
            e["tbl_name"], e["rootpage"], colstr))
        if e["sql"]:
            print("        %s" % " ".join(e["sql"].split()))
    idx = [e for e in schema if e["type"] == "index" and e["sql"]]
    for e in idx:
        print("SCHEMA: index=%s on %s rootpage=%d" % (
            e["name"], e["tbl_name"], e["rootpage"]))


def cmd_dump(db, table):
    colnames, rows = sqliteparse.dump_table(db, table)
    print("DUMP: table=%s rows=%d" % (table, len(rows)))
    for r in rows:
        rid = r.get("__rowid__", "?")
        parts = ["%s=%s" % (c, fmt_value(r.get(c))) for c in colnames]
        print("ROW: %s" % " | ".join(parts))


def cmd_carve(db):
    recs = sqliteparse.carve_db(db)
    print("CARVE: %d deleted-record candidate(s)" % len(recs))
    for rec in recs:
        cols = rec.get("columns") or []
        vals = rec["values"]
        if cols and len(cols) == len(vals):
            parts = ["%s=%s" % (c, fmt_value(v)) for c, v in zip(cols, vals)]
        else:
            parts = [fmt_value(v) for v in vals]
        tag = "HEURISTIC" if rec["heuristic"] else "INTACT"
        print("CARVED: [%s] table=%s rowid=%s :: %s" % (
            tag, rec["table"], rec["rowid"], " | ".join(parts)))
        print("        (%s)" % rec["note"])


def cmd_wal(db):
    wal_path = db.path + "-wal"
    if not os.path.exists(wal_path):
        print("WAL: no %s found (database not in WAL mode or fully checkpointed)"
              % wal_path)
        return
    wal = sqliteparse.parse_wal(wal_path, db.page_size)
    print("WAL: file=%s magic=0x%08x version=%d page_size=%d checkpoint_seq=%d" % (
        wal_path, wal["magic"], wal["version"], wal["page_size"],
        wal["checkpoint_seq"]))
    print("WAL: header checksum %s (stored=%08x%08x computed=%08x%08x)" % (
        "OK" if wal["checksum_ok"] else "MISMATCH",
        wal["stored_checksum"][0], wal["stored_checksum"][1],
        wal["computed_checksum"][0], wal["computed_checksum"][1]))
    bad = [f for f in wal["frames"] if not (f["checksum_ok"] and f["salt_ok"])]
    for f in wal["frames"]:
        print("WAL: frame=%d page=%d db_size=%d checksum=%s salt=%s" % (
            f["frame"], f["page"], f["db_size"],
            "OK" if f["checksum_ok"] else "MISMATCH",
            "OK" if f["salt_ok"] else "MISMATCH"))
    diff = sqliteparse.wal_uncheckpointed(db, wal)
    print("WAL: %d frame(s), %d with bad checksum/salt, "
          "%d page(s) differ from main db (un-checkpointed): %s" % (
              len(wal["frames"]), len(bad), len(diff), diff))


def cmd_page(db, pgno):
    pg = sqliteparse.Page(db, pgno)
    ptypes = {0x02: "interior-index", 0x05: "interior-table",
              0x0A: "leaf-index", 0x0D: "leaf-table"}
    print("page %d: type=%s ncells=%d freeblocks=%d frag=%d" % (
        pgno, ptypes.get(pg.ptype, "0x%02x" % pg.ptype), pg.ncells,
        len(list(pg.freeblocks())), pg.nfrag))
    start, end = pg.unallocated_span()
    print("        unallocated: 0x%x..0x%x (%d bytes)" % (start, end, end - start))
    for fo, fs in pg.freeblocks():
        print("        freeblock @0x%x size=%d" % (fo, fs))


def main():
    ap = argparse.ArgumentParser(
        description="Hand-rolled SQLite forensics: parse b-trees, dump rows, "
                    "carve deleted records, inspect WAL frames. Stdlib only.")
    ap.add_argument("db", help="SQLite database file")
    ap.add_argument("--schema", action="store_true", help="list tables/indexes")
    ap.add_argument("--dump", metavar="TABLE", help="dump all live rows")
    ap.add_argument("--carve", action="store_true",
                    help="recover deleted records from freeblocks/unallocated/freelist")
    ap.add_argument("--wal", action="store_true",
                    help="parse the -wal file: verify checksums, list frames")
    ap.add_argument("--page", type=int, metavar="N",
                    help="inspect raw page N (type, cells, freeblocks)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit("no such file: %s" % args.db)
    try:
        db = Database(args.db)
    except CorruptError as e:
        sys.exit("not a SQLite db: %s" % e)

    if not any([args.schema, args.dump, args.carve, args.wal, args.page]):
        args.schema = True
    if args.schema:
        cmd_schema(db)
    if args.dump:
        try:
            cmd_dump(db, args.dump)
        except CorruptError as e:
            sys.exit(str(e))
    if args.carve:
        cmd_carve(db)
    if args.wal:
        cmd_wal(db)
    if args.page:
        cmd_page(db, args.page)


if __name__ == "__main__":
    main()
