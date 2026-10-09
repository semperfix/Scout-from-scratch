# PDF Document Forensics

A hand-rolled PDF parser that detects hidden JavaScript, embedded files,
metadata inconsistencies, and incremental edits made after apparent signing.
Can pull text from every revision of a document, including ones the viewer
doesn't show you. Zero PDF libraries — every byte is parsed by hand.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages.

## How to run

**Triage a suspicious PDF** (entry point `pdfcheck.py`):

```bash
python3 pdfcheck.py suspect.pdf
python3 pdfcheck.py suspect.pdf --text    # also dump visible text per revision
python3 pdfcheck.py suspect.pdf --json    # machine-readable JSON
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `SUSPICIOUS` / `MALICIOUS`).

**Rebuild the fixtures:**

```bash
python3 make_fixtures.py    # hand-writes fixtures/clean.pdf, js.pdf, incremental.pdf
```

## Example

```bash
$ python3 pdfcheck.py fixtures/js.pdf
file: fixtures/js.pdf  (970 bytes)
revisions: 1  startxref -> [735]
objects: 7 (latest revision)
findings:
  [!!] /OpenAction runs JavaScript on open
  [!!] /Names /JavaScript: 1 embedded script(s)
  [i]   script "embedded": 'this.getField("x").value=1;'
VERDICT: MALICIOUS -- multiple malicious indicators

$ python3 pdfcheck.py fixtures/incremental.pdf --text
file: fixtures/incremental.pdf  (1002 bytes)
revisions: 2  startxref -> [549, 873]
findings:
  [i] 2 revisions (incremental updates) found
  [!] rev 2: redefined objects after earlier revision: [4]
--- revision 1 text ---
Original text before signing.
--- revision 2 text ---
Modified text after signing.
VERDICT: WORTH-A-LOOK -- medium-severity indicators
```

## What it does

- **Revision discovery** — scans for every `startxref`, giving a revision
  count straight from the file structure, no trust in the trailer.
- **Hand-rolled object parser** — dicts `<< >>`, arrays `[]`, literal strings
  with nested parens and `\(` `\)` `\\` octal escapes, hex strings `<…>`,
  `/Names` with `#xx` escapes, numbers, indirect refs, and `stream…endstream`
  capture.
- **xref tables + /Prev chains** — cumulative object maps per revision, so
  redefined objects in later incremental updates are reported by number.
- **Catalog checks** — `/OpenAction` (with `/S` action classification:
  JavaScript/Launch), `/AA` additional actions, `/Names /JavaScript` (script
  bodies printed), `/Names /EmbeddedFiles`, `/AcroForm /XFA`, and
  annotation-level `/Launch` actions on pages.
- **Metadata checks** — `/Info` Creator vs Producer mismatch, impossible
  `ModDate < CreationDate`, non-`D:` date formats.
- **Per-revision text** — walks the page tree with each revision's object map
  and extracts `Tj`/`TJ` strings from content streams.

## Key learnings

- **The xref table is the revision history.** Every incremental update appends
  body + xref + trailer + startxref; counting `startxref` occurrences is the
  honest revision count, and diffing cumulative object maps shows exactly which
  objects a later "signature" silently rewrote.
- **PDF strings nest.** A naive regex for `\(…\)` breaks on escaped parens in
  JavaScript payloads like `(app.alert\("x"\);)` — the parser tracks paren
  depth and escape sequences instead.
- **`stream` EOL handling matters.** The EOL after the `stream` keyword is not
  part of the data; forgetting to skip it shifts every content-stream parse.
- **Resolve-then-lose-the-ref is a classic bug.** `/Contents` must keep the
  indirect refs to fetch stream bytes; resolving the dict first throws away
  the only path to the raw stream. Caught by asserting extracted text, not
  just object counts.

## Files

| File | What it does |
|---|---|
| `pdfcheck.py` | **Entry point**: triage CLI — revisions, flags, metadata, per-revision text, verdict |
| `make_fixtures.py` | Hand-writes the 3 fixture PDFs (raw bytes, computed xref offsets, no PDF lib) |
| `fixtures/clean.pdf` | Benign single-revision one-pager |
| `fixtures/js.pdf` | `/OpenAction` JavaScript + `/Names /JavaScript` |
| `fixtures/incremental.pdf` | 2 revisions; rev 2 redefines the page content (text changed "after signing") |

## Limitations

- **xref streams** (`/Type /XRef`) and **object streams** (`/Type /ObjStm`)
  are detected and reported, not parsed — classic xref tables only.
- **Encrypted PDFs** (`/Encrypt`) are flagged and skipped; no decryption.
- Content streams with `/Filter` (e.g. FlateDecode) are skipped for text
  extraction — we only extract from unfiltered streams.
- Text decodes as Latin-1; custom font encodings and ToUnicode CMaps are not
  applied, so exotic fonts may come out garbled.
- Verdicts are heuristics. Verify before acting.

## Source material

See `SKILLS.md` (skill #5) in the repo root for the full expedition notes.
