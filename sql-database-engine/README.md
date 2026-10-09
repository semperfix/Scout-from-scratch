# SQL Database Engine (from scratch)

A working relational database in ~1100 lines with zero dependencies. Implements
the full stack: a 4 KiB pager with write-through page cache, a B+tree keyed by
auto-assigned int64 rowid (top-down splits, leaf sibling linked list), a record
codec (LEB128 varints + type-tagged NULL/INT/REAL/TEXT values), and a SQL
front end — tokenizer plus recursive-descent parser.

Supported SQL: `CREATE TABLE`, `INSERT INTO ... VALUES` (multi-row, column
lists, expressions), `SELECT` with `*` / `t.*`, aliases, `JOIN ... ON`, `WHERE`
(Kleene 3-valued logic), `GROUP BY`, `HAVING`, `ORDER BY` (multi-key, ASC/DESC),
`LIMIT`, `DISTINCT`, aggregates (`COUNT/SUM/AVG/MIN/MAX`), `LIKE` (`%`/`_`,
case-insensitive like SQLite), `IS [NOT] NULL`, and the `_rowid_` system column.
Comparison semantics mirror SQLite: `NULL < numbers < text`, numeric `=` across
int/float, boolean results surface as `1`/`0`.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no pip packages required. (`checks.py` uses the stdlib
  `sqlite3` module to cross-validate results against real SQLite.)

## How to run

**Run a query against a database file** (entry point `tinydb.py`):

```bash
python3 tinydb.py abe_ledger.db "SELECT memo, amount FROM ledger WHERE paid = 0"
```

**Run the demo:**

```bash
python3 demo.py      # Abe wages ledger: $450 - $30 rail = $420 owed
```

**Run the full validation battery:**

```bash
python3 checks.py    # 48 checks, every query cross-validated against real sqlite3
```

## Example

```bash
$ python3 tinydb.py abe_ledger.db "SELECT memo, amount FROM ledger WHERE paid = 0"
memo	amount
tree work wages owed	450.0
top rail piece (deduct)	-30.0
cashapp payment received	0.0
```

```python
# or from Python
import tinydb
db = tinydb.Database("mydb.db")   # see demo.py for the full usage pattern
```

## Key learnings

- **A database is three separable problems**: page management, ordered key
  storage (the B+tree is just "keep leaves sorted, copy a key up when a page
  fills"), and query semantics. SQLite's NULL ordering and 3-valued logic are
  the fiddly part, not the tree.
- **The split algorithm is ~40 lines once the separator convention is fixed.**
  Copy-up from leaves, move-up from interiors — the trick that looks hard on
  paper is a bookkeeping convention.
- **The thing that actually bit was the ORDER BY namespace.** Output aliases
  must shadow input columns; that fell out of keying the evaluation
  environment by `(table, column)` pairs.
- **Cross-validation against a real implementation is the ground truth.**
  Every check runs identical statements against real sqlite3 and compares
  results exactly (floats with tolerance) — including a 60,000-row insert
  forcing a 3-level tree with a page-by-page structural audit.

## Files

| File | What it does |
|---|---|
| `tinydb.py` | **Entry point** (~1100 lines): pager, B+tree, record codec, SQL tokenizer/parser/executor — `tinydb.py <dbfile> "<sql>"` |
| `demo.py` | Wages-ledger demo against the included fixture |
| `checks.py` | **Validation**: 48/48 checks, all cross-validated against real sqlite3 |
| `abe_ledger.db` | Small sample database fixture used by `demo.py` |

## Stated non-goals

UPDATE/DELETE/DROP, secondary indexes, transactions/WAL, overflow pages (one
record must fit in a page), subqueries, UNION, scalar functions, foreign keys.
