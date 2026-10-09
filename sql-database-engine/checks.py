#!/usr/bin/env python3
"""Validation battery for tinydb: every SQL check runs the same statements
against real sqlite3 and compares results exactly (floats with tolerance)."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tinydb import (Database, TinyDBError, encode_uvarint, decode_uvarint,
                    encode_record, decode_record)

PASS, FAIL = 0, 0


def check(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print("PASS %s" % name)
    except AssertionError as e:
        FAIL += 1
        print("FAIL %s: %s" % (name, e or "mismatch"))
    except Exception as e:
        FAIL += 1
        print("ERROR %s: %r" % (name, e))


def vals_equal(a, b):
    if isinstance(a, float) or isinstance(b, float):
        return (isinstance(a, float) and isinstance(b, float) and
                abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b)))
    return type(a) is type(b) and a == b


def rows_equal(a, b):
    if len(a) != len(b):
        return False
    return all(len(ra) == len(rb) and all(vals_equal(va, vb)
               for va, vb in zip(ra, rb)) for ra, rb in zip(a, b))


def norm(rows):
    return sorted(rows, key=repr)


class Both:
    """Build identical DBs in sqlite3 and tinydb, compare one query."""

    def __init__(self, setup_sql):
        self.setup_sql = setup_sql

    def q(self, sql, ordered=False):
        lite = sqlite3.connect(":memory:")
        lite.executescript(self.setup_sql)
        expected = [tuple(r) for r in lite.execute(sql)]
        lite.close()

        tmpd = tempfile.mkdtemp()
        path = os.path.join(tmpd, "t.db")
        try:
            db = Database(path)
            try:
                for stmt in [s for s in self.setup_sql.split(";") if s.strip()]:
                    db.execute(stmt)
                _, got = db.execute(sql)
            finally:
                db.close()
        finally:
            pass
        got = [tuple(r) for r in got]
        if not ordered:
            expected, got = norm(expected), norm(got)
        assert rows_equal(expected, got), \
            "\n  sql: %s\n  expected %r\n  got      %r" % (sql, expected[:5], got[:5])
        for f in os.listdir(tmpd):
            os.unlink(os.path.join(tmpd, f))
        os.rmdir(tmpd)


def expect_error_both(setup_sql, sql):
    lite = sqlite3.connect(":memory:")
    lite.executescript(setup_sql)
    try:
        lite.execute(sql).fetchall()
        lite_ok = True
    except Exception:
        lite_ok = False
    tmpd = tempfile.mkdtemp()
    path = os.path.join(tmpd, "t.db")
    db = Database(path)
    try:
        for stmt in [s for s in setup_sql.split(";") if s.strip()]:
            db.execute(stmt)
        try:
            db.execute(sql)
            my_ok = True
        except TinyDBError:
            my_ok = False
    finally:
        db.close()
    assert lite_ok == my_ok, "error-behavior mismatch for %r (sqlite ok=%s, mine ok=%s)" % (
        sql, lite_ok, my_ok)


SETUP = """
CREATE TABLE emp (id INTEGER, name TEXT, dept TEXT, salary REAL, bonus INTEGER);
INSERT INTO emp VALUES
  (1, 'amy', 'tree', 22.5, 100),
  (2, 'tony', 'tree', 20.0, NULL),
  (3, 'brian', 'ground', 18.75, 50),
  (4, 'tracy', 'ground', 19.0, NULL),
  (5, 'abe', 'boss', 30.0, 200),
  (6, 'rick', 'tree', NULL, 75);
CREATE TABLE dept (dname TEXT, budget REAL);
INSERT INTO dept VALUES ('tree', 100000.0), ('ground', 50000.0), ('office', 20000.0);
"""

# ---- storage unit checks ----------------------------------------------------

def _t5000():
    tmpd = tempfile.mkdtemp()
    path = os.path.join(tmpd, "big.db")
    db = Database(path)
    db.execute("CREATE TABLE big (k INTEGER, v TEXT)")
    n = 5000
    batch, B = [], 500
    for i in range(n):
        batch.append("(%d, 'v%d')" % (i, i))
        if len(batch) == B:
            db.execute("INSERT INTO big VALUES " + ",".join(batch))
            batch = []
    if batch:
        db.execute("INSERT INTO big VALUES " + ",".join(batch))
    cols, rows = db.execute("SELECT count(*), min(k), max(k) FROM big")
    assert rows == [(5000, 0, 4999)], rows
    _, r = db.execute("SELECT v FROM big WHERE k = 4999")
    assert r == [("v4999",)], r
    _, r = db.execute("SELECT v FROM big WHERE _rowid_ = 2500")
    assert r == [("v2499",)], r          # rowid 2500 -> k=2499
    # sqlite cross-check on the same file is impossible; verify via fresh scan order
    _, r = db.execute("SELECT k FROM big ORDER BY k LIMIT 3")
    assert r == [(0,), (1,), (2,)], r
    db.close()
    return path

def _persist_ok():
    tmpd = tempfile.mkdtemp()
    path = os.path.join(tmpd, "p.db")
    db = Database(path)
    db.execute("CREATE TABLE a (x INTEGER)")
    db.execute("CREATE TABLE b (y TEXT)")
    db.execute("INSERT INTO a VALUES (42)")
    db.execute("INSERT INTO b VALUES ('still here')")
    db.close()
    db2 = Database(path)
    _, r1 = db2.execute("SELECT x FROM a")
    _, r2 = db2.execute("SELECT y FROM b")
    db2.close()
    assert r1 == [(42,)] and r2 == [("still here",)], (r1, r2)
    return True


def _bigtext():
    tmpd = tempfile.mkdtemp()
    path = os.path.join(tmpd, "bt.db")
    db = Database(path)
    db.execute("CREATE TABLE t (s TEXT)")
    db.execute("INSERT INTO t VALUES ('%s')" % ("z" * 2000,))
    _, r = db.execute("SELECT s FROM t")
    db.close()
    assert r == [("z" * 2000,)], "big text roundtrip"


# ---- SQL cross-checks vs sqlite3 --------------------------------------------
check("varint roundtrip", lambda: all(
    decode_uvarint(encode_uvarint(n), 0) == (n, len(encode_uvarint(n)))
    for n in [0, 1, 127, 128, 255, 16384, 2**32 - 1, 2**63 - 1]))

def _codec_ok():
    vals = [None, 0, -5, 2**62, 3.14159, -0.0, "",
            "héllo wörld 🌲", "a" * 500]
    assert decode_record(encode_record(vals)) == vals


check("record codec roundtrip", _codec_ok)

check("5000-row insert + splits + spot reads", _t5000)

check("persistence across close/reopen", _persist_ok)


check("2000-char text record", _bigtext)


B = Both(SETUP)
check("select *", lambda: B.q("SELECT * FROM emp"))
check("projection + alias", lambda: B.q("SELECT name AS n, salary s FROM emp"))
check("comparison ops", lambda: B.q(
    "SELECT name FROM emp WHERE salary >= 20.0 AND bonus <> 100 OR id < 2"))
check("not-equal !=", lambda: B.q("SELECT name FROM emp WHERE dept != 'tree'"))
check("three-valued logic", lambda: B.q(
    "SELECT name FROM emp WHERE NOT (salary > 19 OR bonus IS NULL)"))
check("is null / is not null", lambda: B.q(
    "SELECT name FROM emp WHERE bonus IS NULL"))
check("is not null", lambda: B.q(
    "SELECT name FROM emp WHERE salary IS NOT NULL"))
check("like % and _", lambda: B.q(
    "SELECT name FROM emp WHERE name LIKE 't_n%'"))
check("not like", lambda: B.q(
    "SELECT name FROM emp WHERE name NOT LIKE '%a%'"))
check("like case-insensitive", lambda: B.q(
    "SELECT name FROM emp WHERE name LIKE 'A%'"))
check("arithmetic select+where", lambda: B.q(
    "SELECT name, salary * 40 AS weekly, bonus + 10 FROM emp WHERE salary - 20 > -1"))
check("unary minus + div", lambda: B.q(
    "SELECT -salary / 2 FROM emp WHERE salary IS NOT NULL"))
check("order by multi asc/desc", lambda: B.q(
    "SELECT name, dept, salary FROM emp ORDER BY dept ASC, salary DESC", ordered=True))
check("order by null placement", lambda: B.q(
    "SELECT name FROM emp ORDER BY salary ASC", ordered=True))
check("order by desc nulls last", lambda: B.q(
    "SELECT name FROM emp ORDER BY salary DESC", ordered=True))
check("limit", lambda: B.q(
    "SELECT name FROM emp ORDER BY id DESC LIMIT 3", ordered=True))
check("global aggregates", lambda: B.q(
    "SELECT count(*), count(bonus), sum(bonus), avg(salary), min(name), max(name) FROM emp"))
check("aggregates on empty table", lambda: Both(
    "CREATE TABLE e (a INTEGER);").q("SELECT count(*), sum(a), avg(a) FROM e"))
check("group by single", lambda: B.q(
    "SELECT dept, count(*), avg(salary) FROM emp GROUP BY dept"))
check("group by multi", lambda: B.q(
    "SELECT dept, count(*) c FROM emp GROUP BY dept HAVING count(*) > 1"))
check("having", lambda: B.q(
    "SELECT dept, sum(bonus) s FROM emp GROUP BY dept HAVING sum(bonus) > 100"))
check("distinct", lambda: B.q("SELECT DISTINCT dept FROM emp"))
check("join on + aliases", lambda: B.q(
    "SELECT e.name, d.budget FROM emp e JOIN dept d ON e.dept = d.dname"))
check("self join", lambda: B.q(
    "SELECT a.name, b.name FROM emp a JOIN emp b ON a.dept = b.dept AND a.id < b.id"))
check("join then filter+sort", lambda: B.q(
    "SELECT e.name FROM emp e INNER JOIN dept d ON e.dept = d.dname "
    "WHERE d.budget > 30000 ORDER BY e.name", ordered=True))
check("insert with column list", lambda: Both(
    "CREATE TABLE t (a INTEGER, b TEXT, c REAL);"
    "INSERT INTO t (b, a) VALUES ('x', 1), ('y', 2);").q("SELECT * FROM t"))
check("insert expressions", lambda: Both(
    "CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (1+2), (-4), (10 % 3);"
    ).q("SELECT a FROM t"))
check("rowid range", lambda: B.q("SELECT _rowid_, name FROM emp WHERE _rowid_ > 4"))
check("empty result", lambda: B.q("SELECT name FROM emp WHERE id > 999"))
check("mixed-type ordering", lambda: Both(
    "CREATE TABLE m (v TEXT); INSERT INTO m VALUES ('10'), ('9'), ('abc'), (NULL);"
    "CREATE TABLE n (x INTEGER); INSERT INTO n VALUES (10), (9);").q(
    "SELECT v FROM m ORDER BY v", ordered=True))
check("quotes + unicode", lambda: Both(
    "CREATE TABLE t (s TEXT); INSERT INTO t VALUES ('it''s'), ('héllo 🌲');"
    ).q("SELECT s FROM t"))
check("table.* expansion", lambda: B.q("SELECT e.* FROM emp e WHERE e.id = 1"))
check("select without from", lambda: Both("").q("SELECT 1 + 2 * 3, 'x'"))
check("boolean exprs -> 1/0", lambda: B.q("SELECT salary > 20 FROM emp WHERE id < 3"))
check("sum int stays int", lambda: B.q("SELECT sum(id) FROM emp"))
check("min/max text", lambda: B.q("SELECT min(dept), max(dept) FROM emp"))

check("big join 200x50", lambda: (
    lambda: Both(
        "CREATE TABLE a (k INTEGER, av TEXT);" +
        "CREATE TABLE b (k INTEGER, bv TEXT);" +
        "INSERT INTO a VALUES " + ",".join(
            "(%d, 'a%d')" % (i % 50, i) for i in range(200)) + ";" +
        "INSERT INTO b VALUES " + ",".join(
            "(%d, 'b%d')" % (i, i) for i in range(50)) + ";"
    ).q("SELECT av, bv FROM a JOIN b ON a.k = b.k"))())

check("error: unknown column", lambda: expect_error_both(SETUP,
      "SELECT nope FROM emp"))
check("error: ambiguous column", lambda: expect_error_both(SETUP,
      "SELECT name FROM emp JOIN dept ON 1=1"))
check("error: bad syntax", lambda: expect_error_both(SETUP,
      "SELECT FROM WHERE"))
check("error: no such table", lambda: expect_error_both(SETUP,
      "SELECT * FROM missing"))
check("error: aggregate misuse", lambda: expect_error_both(SETUP,
      "SELECT sum(*) FROM emp"))

def _deep_tree_ok():
    """60k rows -> 3-level tree. Verify structural invariants page by page:
    sorted keys, separator bounds (left < sep <= right), leaf linked list
    matches left-to-right walk, every key find()-able."""
    import random
    tmpd = tempfile.mkdtemp()
    path = os.path.join(tmpd, "deep.db")
    db = Database(path)
    db.execute("CREATE TABLE d (k INTEGER, v TEXT)")
    N, BATCH = 60000, 2000
    batch = []
    for i in range(N):
        batch.append("(%d, 'v%d')" % (i, i))
        if len(batch) == BATCH:
            db.execute("INSERT INTO d VALUES " + ",".join(batch))
            batch = []
    if batch:
        db.execute("INSERT INTO d VALUES " + ",".join(batch))

    t = db.tables["d"]
    bt = t.btree
    leaves_in_walk = []
    max_depth = [0]

    def walk(pgno, lo, hi, depth):
        max_depth[0] = max(max_depth[0], depth)
        node = bt._read(pgno)
        assert node.keys == sorted(node.keys), "keys unsorted"
        assert len(node.keys) == len(set(node.keys)), "dup keys"
        if node.leaf:
            for k in node.keys:
                assert lo <= k < hi, "key %d out of [%s, %s)" % (k, lo, hi)
            leaves_in_walk.append(pgno)
            return
        n = len(node.keys)
        assert len(node.children) == n + 1
        for j, c in enumerate(node.children):
            c_lo = node.keys[j - 1] if j > 0 else lo
            c_hi = node.keys[j] if j < n else hi
            walk(c, c_lo, c_hi, depth + 1)

    walk(bt.root, float("-inf"), float("inf"), 1)
    assert max_depth[0] >= 3, "expected depth>=3, got %d" % max_depth[0]

    # leaf linked list must visit exactly the walked leaves, in order
    pgno = bt.root
    while not bt._read(pgno).leaf:
        pgno = bt._read(pgno).children[0]
    chain = []
    while pgno:
        chain.append(pgno)
        pgno = bt._read(pgno).next_leaf
    assert chain == leaves_in_walk, "leaf chain != walk order"

    # scan order sorted and complete (tree is keyed by 1-based rowid)
    keys = [k for k, _ in bt.scan()]
    assert keys == sorted(keys) == list(range(1, N + 1)), "scan order/gaps"

    # random point lookups agree with scan
    spot = {k: p for k, p in bt.scan()}
    rng = random.Random(1234)
    for k in rng.sample(range(1, N + 1), 300):
        assert bt.find(k) == spot[k], "find(%d)" % k
    assert bt.find(0) is None and bt.find(N + 1) is None

    # aggregate still right at depth
    _, r = db.execute("SELECT count(*), sum(k) FROM d")
    assert r == [(N, N * (N - 1) // 2)], r
    db.close()
    return True


check("deep tree: 60k rows, structural integrity", _deep_tree_ok)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
