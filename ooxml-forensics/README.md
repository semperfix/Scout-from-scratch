# Office OOXML Document Forensics

Hand-rolled ZIP parser plus a full forensic analyzer for Word/Excel
documents. Detects macro payloads (vbaProject.bin with OLE header validation),
external relationships (remote images/tracking pixels, hyperlink targets),
hidden text (w:vanish runs, white-on-white, micro-fonts), tracked
insertions/deletions with authors and timestamps, comments, metadata
inconsistencies, embedded OLE objects, veryHidden spreadsheet sheets, and
hyperlink display-text vs. target mismatches — the classic document-phishing
tell. Renders CLEAN / WORTH-A-LOOK / SUSPICIOUS / MALICIOUS triage verdicts.
Directly useful for vetting sketchy email attachments.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — `zlib` is used for raw-deflate inflation inside the
  hand-rolled ZIP reader (the container format is still parsed byte-by-byte;
  `zipfile` is used only by `make_fixtures.py` to *generate* test files,
  never by the analyzer).

## How to run

**Triage a suspicious document** (entry point `ooxmlcheck.py`):

```bash
python3 ooxmlcheck.py suspect.docx
python3 ooxmlcheck.py suspect.xlsx --json
python3 ooxmlcheck.py suspect.docx --list    # list ZIP entries, sizes, methods
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `SUSPICIOUS` / `MALICIOUS`).

**Rebuild the fixtures:**

```bash
python3 make_fixtures.py    # builds fixtures/clean.docx, evil-ext.docx, macro.docx
```

## Example

```bash
$ python3 ooxmlcheck.py fixtures/evil-ext.docx
file: fixtures/evil-ext.docx
zip entries: 5
metadata: creator='Scout' lastModifiedBy='Scout' ...
findings:
  [!] external relationship in word/document.xml: [image] -> http://tracker.evil.example/pixel.gif
  [.] external relationship in word/document.xml: [hyperlink] -> http://phish.evil.example/steal
  [!] hidden text (w:vanish, white-on-white): 'supersecret exfil note'
  [.] tracked ins by mallory at 2026-10-08T12:00:00Z: 'added later'
  [!!] hyperlink display/target mismatch: shows 'https://your-bank.example/login' -> 'http://phish.evil.example/steal'
VERDICT: SUSPICIOUS -- macro payload or phishing tell

$ python3 ooxmlcheck.py fixtures/macro.docx
findings:
  [!!] vbaProject.bin present: word/vbaProject.bin (macro payload)
  [i]   vbaProject.bin has a valid OLE header
VERDICT: SUSPICIOUS -- macro payload or phishing tell
```

## What it does

- **Hand-rolled ZIP reader** (`HandZip`) — EOCD located by scanning backward
  from EOF, central-directory walk, per-entry local-header parse; stored
  entries read raw, deflated entries inflated with `zlib.decompress(raw, -15)`;
  CRC32 verified against the central directory for every entry read.
- **Macro detection** — any `vbaProject.bin` entry, plus OLE magic
  (`D0 CF 11 E0…`) validation so renamed fakes get flagged, and
  `macroEnabled` content-type overrides in `[Content_Types].xml`.
- **External relationships** — every part's `.rels` walked;
  `TargetMode="External"` targets (tracking pixels, remote templates,
  hyperlink URLs) reported with type.
- **Hidden text** — `w:vanish` runs, `w:color` white (`FFFFFF`), and micro
  fonts (`w:sz` < 8 half-points) in `word/document.xml`.
- **Tracked changes** — `w:ins`/`w:del` with `w:author` and `w:date`.
- **Phish tell** — `w:hyperlink` display text compared against its
  relationship target; mismatch is a high-severity finding.
- **Excel** — `xl/workbook.xml` sheets with `state="veryHidden"`/`"hidden"`.
- **Metadata** — `docProps/core.xml` creator/lastModifiedBy/created/modified;
  creator ≠ lastModifiedBy noted.

## Key learnings

- **The EOCD is 22 bytes, not 24.** Off-by-one in the struct format silently
  shifts every field; the parser now asserts on buffer bounds and fails loud.
- **Local file headers have 10 fields after the magic**, central-directory
  entries have 17 — unpacking with the wrong count is the #1 ZIP-parser bug
  and it fails *silently* (wrong sizes, not exceptions) if you don't CRC-check.
- **`zipfile` writes local headers with real sizes** (no data descriptor) when
  the size is known up front, which is why fixtures parse — but real-world
  streaming writers set bit 3, so the parser detects and honestly skips those
  instead of misreading them.
- **A macro alone is SUSPICIOUS, not MALICIOUS.** Plenty of legitimate docs
  carry VBA; the verdict ladder only escalates to MALICIOUS when the macro
  rides along with external relationships or other high-severity tells.

## Files

| File | What it does |
|---|---|
| `ooxmlcheck.py` | **Entry point**: triage CLI — ZIP parse, all forensic checks, verdict |
| `make_fixtures.py` | Builds the 3 fixture `.docx` files with stdlib `zipfile` (generation only) |
| `fixtures/clean.docx` | Benign one-pager → CLEAN |
| `fixtures/evil-ext.docx` | External tracking pixel + white hidden text + hyperlink mismatch + tracked insert → SUSPICIOUS |
| `fixtures/macro.docx` | `vbaProject.bin` stub with valid OLE header → SUSPICIOUS |

## Limitations

- Entries using the **data-descriptor flag** (bit 3) are detected and skipped —
  sizes are needed up front for the local-header read.
- **ZIP64**, multi-disk archives, and encrypted entries are detected, not parsed.
- Hidden-text analysis covers Word; Excel cell-level hiding is limited to
  veryHidden/hidden sheet detection.
- `w:sz` is in half-points; the < 8 threshold is a heuristic for "too small
  to be legit body text".
- Verdicts are heuristics. Verify before acting.

## Source material

See `SKILLS.md` (skill #13) in the repo root for the full expedition notes.
