# Polite Web Crawler From Scratch

A polite web crawler built from hand-rolled parts: URL canonicalization,
an RFC 9309 robots.txt parser, a politeness-aware BFS frontier, and a
hand-rolled HTML tokenizer for link/title/text extraction. The novel parts
of this skill are the frontier, robots handling, canonicalization, and
extraction — actual HTTP fetching goes through `urllib`; the from-scratch
raw-socket HTTP client lives in the `http-raw-sockets` skill, and `crawl.py`
documents that seam.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — `urllib`, `re`, `collections`, `socket` (tests).

## How to run

**Crawl a site** (entry point `crawl.py`):

```bash
python3 crawl.py --seed https://example.com/ --max-pages 50 --delay 1.0
python3 crawl.py --seed https://example.com/ --max-pages 20 --user-agent "MyBot/1.0"
python3 crawl.py --seed https://example.com/ --no-stay-host   # follow off-host links
```

Exit 0 always. Machine-readable lines start with `FETCHED:`, `SKIPPED:`,
`ROBOTS:`, `PAGE:`.

**Use as a library:**

```python
from urlnorm import canonicalize
from robots import Robots
from frontier import Frontier
import htmltok

canonicalize("HTTP://Example.COM:80/a/../b?c=2&b=1#x")
# 'http://example.com/b?b=1&c=2'

r = Robots(open("robots.txt").read(), "MyBot/1.0")
r.allowed("https://example.com/private/")   # False (longest-match wins)
r.crawl_delay()                             # 2.0

f = Frontier(delay=1.0)
f.add("https://example.com/a")
url, wait = f.next()                        # (url, 0.0) or (None, seconds)

info = htmltok.extract(html, base_url)      # title, links, visible text
```

**Run the validation battery:**

```bash
python3 test_crawl.py    # 32 checks: canonicalization vectors, robots
                         # longest-match/ties/UA-specificity, tokenizer,
                         # frontier dedup+politeness, and a live crawl of a
                         # local http.server (robots honored, dedup works)
```

## Example

```bash
$ python3 crawl.py --seed http://127.0.0.1:8899/ --max-pages 10 --delay 0.2
FETCHED: http://127.0.0.1:8899/ [title: Demo Home] (2 links)
FETCHED: http://127.0.0.1:8899/page2.html [title: Page Two] (1 links)
SKIPPED: http://127.0.0.1:8899/private/secret.html (robots disallow)
ROBOTS: crawl complete: fetched=2 skipped_robots=1 errors=0
PAGE: http://127.0.0.1:8899/ :: Demo Home
PAGE: http://127.0.0.1:8899/page2.html :: Demo Home
```

## Key learnings

- **Canonicalize before you dedupe, or the seen-set is theater.**
  `?b=1&c=2` vs `?c=2&b=1`, `:80`, `%7e` vs `~`, `/a/../b` — every one of
  these is a duplicate fetch without normalization. The frontier
  canonicalizes on `add()` so equivalent URLs collapse to one queue entry.
- **RFC 9309 group matching is most-specific-wins, and groups don't merge.**
  A crawler-specific group *replaces* the `*` group for that crawler — my
  first test wrongly expected them to combine, and the fix was in the test,
  not the parser. Ties between Allow/Disallow go to Allow.
- **Robots.txt lives at host:port.** Building the robots URL from `hostname`
  instead of `netloc` silently fetched the wrong (nonexistent) robots.txt
  and the crawl treated everything as allowed. The integration test caught
  it because it asserts on a disallowed URL, not just on parser output.
- **`<script>` is raw text, not markup.** The tokenizer consumes script/style
  bodies without tag-scanning inside them, so `var a = "<b>"` neither
  produces a phantom link nor leaks code into the extracted text.
- **Transport is a seam, not the skill.** `urllib` does the fetching here;
  everything interesting — frontier, robots, canonicalization, extraction —
  is transport-agnostic and would work unchanged over the raw-socket client.

## Files

| File | What it does |
|---|---|
| `crawl.py` | **Entry point**: argparse CLI — `--seed`, `--max-pages`, `--delay`, `--user-agent`; BFS crawl with robots + politeness |
| `urlnorm.py` | URL canonicalization: case, default ports, percent-encoding, dot-segments, query sorting, fragment strip |
| `robots.py` | RFC 9309 parser: UA groups, Allow/Disallow longest-match, `*`/`$` rules, crawl-delay, sitemaps |
| `htmltok.py` | Hand-rolled HTML tokenizer (tags/attrs/text/comments, raw-text elements, entities) + link/title/text extraction |
| `frontier.py` | Per-host FIFO queues, politeness delay (config + robots crawl-delay), canonical-URL seen-set, BFS round-robin |
| `test_crawl.py` | 32-check battery, all deterministic, incl. a live local-server crawl |

## Limitations

- Fetching is `urllib`, not the raw-socket client (see `http-raw-sockets`).
  Timeouts/redirects/errors are handled, but there is no retry budget, no
  conditional-GET, and no content-size cap beyond a 2 MB read limit.
- `urlnorm` drops userinfo and does not punycode-encode IDNs.
- `robots.py` honors `Disallow`/`Allow`/`Crawl-delay`/sitemaps; it does not
  implement crawl-budget or visit-time directives.
- `htmltok` is a tokenizer, not a spec parser: no tree construction, no
  foster parenting — fine for link/text extraction, not for DOM fidelity.
- The crawler is single-threaded and in-memory: the seen-set and queues do
  not persist across runs.
