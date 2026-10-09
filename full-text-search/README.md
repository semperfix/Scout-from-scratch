# Full-Text Search Engine (BM25)

A complete information-retrieval stack built from scratch with zero search
libraries: tokenizer → positional inverted index (custom on-disk binary format)
→ BM25 ranker → boolean/phrase/proximity query engine → KWIC snippet highlighter.
Point it at any local corpus (logs, exports, notes) for fast, private, offline
retrieval with explainable ranking.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no pip packages required.

## How to run

**Build an index over a directory of Markdown files** (entry point `build.py`):

```bash
python3 build.py <corpus_dir> <out.idx>
# prints e.g. docs=24 unique_terms=2849 index_bytes=9983
```

**Search it** (entry point `search_cli.py`):

```bash
python3 search_cli.py <index.idx> "<query>" [--top N]
```

Supported query syntax: `AND` / `OR` / `NOT`, `"quoted phrases"`, `NEAR/n`
proximity, parentheses.

**Run the validation battery:**

```bash
python3 test_search.py    # 22 known-answer retrieval checks + stemmer/varint checks
```

## Example

```bash
$ mkdir -p corpus && echo "qr forensics quishing triage tool" > corpus/qr.md
$ echo "full text search engine with bm25 ranking" > corpus/search.md
$ python3 build.py corpus demo.idx
docs=2 unique_terms=14 index_bytes=1234
$ python3 search_cli.py demo.idx "quishing"
[3.50] qr.md
   ... qr forensics **quishing** triage tool ...
```

## Key learnings

- **Stopwords break phrases unless positions count them.** `"lost my voice"`
  fails with naive consecutive-position matching because `my` occupies a
  position. The fix is the position-increment trick: drop stopwords from the
  term list but keep them on the ruler — phrase offsets become relative gaps.
- **Stemming is not a canonical form.** `bonus`→`bonu` but `bonuses`→`bonus` —
  query and document can miss each other *because of* stemming. Same behavior as
  Lucene's PorterStemFilter; it's a known recall hole, not a bug.
- **BM25's two behaviors that matter:** tf saturates (mentioning a word 100× ≈
  mentioning it 10× — kills keyword stuffing) and length normalization (a match
  in a 20-word note outranks the same match in a 2000-word dump). Together they
  explain why naive "count the hits" ranking feels wrong.
- **Self-built fixtures prove consistency, not correctness.** The 22-query
  ground-truth battery against a real corpus is what caught the empty-AND bug,
  the stopword-phrase failure, and the hyphen-compound problem.

## Files

| File | What it does |
|---|---|
| `search_cli.py` | **Entry point**: `search_cli.py <index> "<query>" [--top N]` → ranked hits with `**highlight**` snippets |
| `build.py` | **Entry point**: `build.py <corpus_dir> <out.idx>` — indexes every `.md` file under the corpus dir |
| `tokenizer.py` | Unicode tokenization, case folding, accent stripping, possessive handling, hyphen-compound splitting, stopwords, hand-implemented Porter stemmer (76/76 canonical pairs) |
| `index.py` | Positional inverted index; hand-written on-disk format (`SCOUTIDX` magic, LEB128 varints, delta-encoded doc ids and positions) |
| `rank.py` | BM25 (k1=1.2, b=0.75, Lucene-style non-negative IDF) |
| `query.py` | Recursive-descent parser: AND/OR/NOT, `"quoted phrases"`, `NEAR/n` proximity; positional phrase/NEAR evaluation |
| `snippets.py` | Densest-window KWIC snippets with `**highlight**` |
| `test_search.py` | 22 known-answer retrieval checks against a real corpus |

## Limitations

- No typo tolerance (no edit-distance / n-gram fallback).
- Single-term-per-position model: no synonyms, no embeddings.
- Boolean NOT is set-complement (scores 0) — fine for filtering, useless for ranking.
- Index is static: rebuild on corpus change (no incremental updates / deletions).

## Note

A `memory.idx` demo index previously shipped with this code was dropped from the
repo — it contained personal notes. Run `build.py` over your own corpus instead.
