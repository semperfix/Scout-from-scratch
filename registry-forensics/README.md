# Windows Registry Forensics (Skill 20)

Hand-rolled REGF hive parser, hive *writer*, deleted-record recovery, and a forensic triage engine — zero dependencies. Validated by round-tripping a synthetic hive whose every byte was placed deliberately, then cross-checked against the real `python-registry` library (identical key sets, byte-identical values).

## Dependencies

Stdlib only (`struct`, …). No pip packages.

## Run

Entry point: `regtriage.py`.

```bash
cd registry-forensics
python3 reghive_gen.py fakehive.dat   # build the synthetic fixture hive
python3 regtriage.py fakehive.dat     # integrity checks, timeline.csv, verdict
python3 regtriage.py <any .dat hive>  # triage a real hive file
python3 test_reg.py                   # 37-check validation battery
```

## Usage example

```bash
$ python3 regtriage.py fakehive.dat
hive: fakehive.dat  keys=22 deleted_records=3
verdict: MALICIOUS (score 170)

[PERSISTENCE +10] autorun: ROOT\Software\Microsoft\Windows\CurrentVersion\Run -> Updater = C:\Users\kyle\AppData\Roaming\updater.exe
[SUSPICIOUS  +25] autorun points at temp/appdata/net path: ...
[ARTIFACT    + 0] recent doc: budget_2026.xlsx
```

## Key learnings

- **The sign bit is the allocator.** A cell's 4-byte size is signed: negative = allocated, positive = free. Deletion flips the sign and coalesces adjacent free cells — one free cell can hold *several* remnant records (same phenomenon as SQLite freeblocks in Skill 17, different format).
- **Deleted keys keep pointing at their parents.** The freed NK's parent-offset still referenced the live Run key, so the recovered key reports its full original path (`...\Run\EvilPersistence`) — attribution survives deletion.
- **Inline values hide in the pointer field.** When the MSB of the data-size is set, the 4-byte "data offset" field *is* the data (≤4 bytes). A parser that always chases the offset reads garbage.
- **Cross-validation caught what round-tripping couldn't.** Writer and parser agreed with each other — and were both wrong (missing volatile-subkeys field, wrong lf entry order). The independent `python-registry` library crashed on my hive and led me to the real field table: self-consistent fixtures only prove internal consistency.

## Files

- `regtriage.py` — entry point: integrity checks, timeline.csv, autorun/service/USB/UserAssist/RecentDocs detectors, deleted-key re-linking, scored verdict
- `regparse.py` — the parser: header validation, bin/cell walk, NK/VK/lf/lh/li/ri, inline + data-cell + big-data values, deleted-record remnant scan
- `reghive_gen.py` — synthetic hive writer (base block, bins, cells, deletion simulation via sign-flip + coalescing)
- `test_reg.py` — 37-check validation battery
- `fakehive.dat` — generated fixture (regenerable: `python3 reghive_gen.py fakehive.dat`); contains Run/RunOnce autoruns, UserAssist ROT13, USBSTOR, an EvilSvc service, a 20 KB big-data value, and 3 planted deleted records
