# SQLite Forensics From Scratch

Hand-rolled binary parser for the SQLite file format: b-tree walking,
deleted-record recovery from freeblocks, and WAL file forensics. Parses
database files with zero libraries, recovers deleted rows, and verifies
un-checkpointed WAL frames. Directly useful since browsers, phones, and chat
apps all store data in SQLite.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages. (`test_sqlite.py` uses the stdlib
  `sqlite3` module, but only to *generate* fixture databases; the parser under
  test never touches it.)

## How to run

**Triage a database** (entry point `sqliteforensics.py`):

```bash
python3 sqliteforensics.py suspect.db --schema     # list tables, root pages, columns
python3 sqliteforensics.py suspect.db --dump notes # dump all live rows of a table
python3 sqliteforensics.py suspect.db --carve      # recover deleted records
python3 sqliteforensics.py suspect.db --wal        # verify WAL checksums, list frames
python3 sqliteforensics.py suspect.db --page 2     # inspect raw page 2
```

Machine-readable lines start with `SCHEMA:`, `ROW:`, `CARVED:`, or `WAL:`.
Exit 0 always (errors go to stderr with a non-zero exit).

**Use as a library:**

```python
from sqliteparse import Database, read_schema, dump_table, carve_db, parse_wal

db = Database("suspect.db")
print(read_schema(db))            # sqlite_master entries
cols, rows = dump_table(db, "messages")
for rec in carve_db(db):          # deleted-record candidates
    print(rec["table"], rec["rowid"], rec["values"], rec["note"])
wal = parse_wal("suspect.db-wal", db.page_size)
```

**Run the validation battery:**

```bash
python3 test_sqlite.py    # 23 checks: header, schema, dump-vs-sqlite3,
                          # overflow blobs, carving, WAL checksums, CLI smoke
```

## Example

```bash
$ python3 sqliteforensics.py notes.db --carve
CARVE: 3 deleted-record candidate(s)
CARVED: [HEURISTIC] table=notes rowid=None :: id=4 | title=note-four | body=body of note number 4
        (table notes page 2 freeblock: freeblock: first serial type reconstructed as 1)
CARVED: [INTACT] table=notes rowid=10 :: id=10 | title=note-ten | body=body of note number 10
        (table notes page 2: intact cell in unallocated space)
CARVED: [HEURISTIC] table=notes rowid=None :: id=9 | title=note-nine | body=body of note number 9
        (table notes page 2 unlinked freeblock: freeblock: first serial type reconstructed as 1)
```

```bash
$ python3 sqliteforensics.py wal.db --wal
WAL: file=wal.db-wal magic=0x377f0682 version=3007000 page_size=4096 checkpoint_seq=0
WAL: header checksum OK (stored=… computed=…)
WAL: frame=0 page=1 db_size=0 checksum=OK salt=OK
WAL: frame=1 page=2 db_size=2 checksum=OK salt=OK
WAL: 3 frame(s), 0 with bad checksum/salt, 2 page(s) differ from main db (un-checkpointed): [1, 2]
```

## Key learnings

- **The overflow formula in my memory was wrong; the spec settled it.**
  I first guessed `K = M - ((M - X) % (U-4))` with `M = U-4` and it failed on
  real data. Probing actual cells (reassembling payloads and comparing against
  `sqlite3`'s own output for blobs of 100–20000 bytes) showed e.g. P=5005 →
  K=913, P=20006 → K=3638, P=4066 → K=489. The file-format doc gives the real
  rule: `X = U-35`, `M = ((U-12)*32/255)-23`, `K = M + ((P-M) % (U-4))`; local
  bytes are `K` if `K <= X`, else `M`. It fits every probe byte-for-byte.
- **SQLite zeroes nothing on delete — unless `secure_delete` is on.** This
  container's Python ships `PRAGMA secure_delete=1` by default, which wipes
  freed cells and makes carving vacuous. The fixture sets it OFF, matching
  real-world targets (browsers, phones) that don't opt into it.
- **Deleting the newest row unlinks — but doesn't wipe — the freeblock.**
  When the cell-content area grows over a freeblock (delete the newest row),
  SQLite drops it from the freeblock chain while its `(next, size)` header
  survives in unallocated space. The carver detects these *orphan* freeblock
  headers by a plausible header whose `next` is 0 or points at a chained
  freeblock — this recovered a row the chain-walk alone missed.
- **Freeblock carving is a constraint puzzle, not a parse.** The freed cell's
  first 4 bytes are destroyed (payload-len varint, rowid varint, header-len
  varint, first serial-type varint). Recovery brute-forces the record header
  length `H` and solves `R - H - B_suffix = size(first field)` using the
  freeblock's own size field as ground truth for `R`, disambiguating the
  destroyed first serial type via the table schema's column affinity. Rowid is
  genuinely unrecoverable and reported as `None`.
- **WAL checksum byte order is backwards from the obvious guess.** Magic
  `0x377f0682` means the checksum integers are *little*-endian (and
  `0x377f0683` big-endian), while the header/frame fields stay big-endian and
  the stored checksum words are always big-endian. Frame checksums are
  cumulative: header[0:24] + for each frame, header[0:8] (salts excluded) +
  page image. All verified against real `-wal` files.

## Files

| File | What it does |
|---|---|
| `sqliteforensics.py` | **Entry point**: argparse CLI — `--schema`, `--dump TABLE`, `--carve`, `--wal`, `--page N` |
| `sqliteparse.py` | Hand-rolled format parser: varint codec, header, b-tree walk, records, overflow chains, freeblock/freelist walk, carver, WAL parser |
| `test_sqlite.py` | 23-check battery: builds fixtures with stdlib `sqlite3`, validates dump/carve/WAL/CLI against ground truth |

## Limitations

- Index b-trees (0x02/0x0A) are structurally parsed but not walked for row
  output; `--dump` covers table b-trees only.
- `WITHOUT ROWID` tables are not supported.
- `--dump` column names come from a naive `CREATE TABLE` parser — exotic DDL
  (quoted weirdness, complex constraints) may mis-parse; documented, not
  silent.
- The carver is heuristic by nature: freeblock bodies recover field *values*
  but never the rowid, and ambiguous first-byte reconstructions are
  disambiguated by schema affinity, which can be wrong on typeless columns.
- WAL parsing covers the common single-writer case; it does not parse the
  `-shm` wal-index (transient shared memory, not needed for recovery).
