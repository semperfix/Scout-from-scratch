"""Known-answer retrieval tests: expected doc must rank in top-3."""
import sys
from index import Index
from query import search

ix = Index("memory.idx")

# (query, [acceptable top-3 doc substrings])
CASES = [
    ("stephanie new phone number", ["stephanie-burnside", "MEMORY"]),
    ("dryer f70 error code", ["MEMORY", "2026-10-0"]),
    ("textnow password account access", ["MEMORY", "alignment"]),
    ("abe cash app wages owed", ["boss-man-abe", "MEMORY"]),
    ("912-648-2048", ["stephanie-burnside", "MEMORY"]),
    ("scout proton mail email", ["MEMORY"]),
    ("kimberly ramirez mother", ["kimberly-ramirez", "MEMORY"]),
    ("hunter tilley osint", ["MEMORY"]),
    # NOTE: "bonus" stems to "bonu" but "bonuses" stems to "bonus" (Porter
    # asymmetry — same behavior as Lucene). So "bonus" only matches docs with
    # the literal word "bonus"; use "bonuses" or drop it for the MEMORY.md hit.
    ("bettywins casino", ["MEMORY"]),
    ("ttadertot gmail", ["MEMORY"]),
    ("life360", ["MEMORY"]),
    ("voice note paused uploads", ["MEMORY", "alignment"]),
    ("amanda lives with tony", ["amanda", "the-household", "tony"]),
    ('"lost my voice"', ["MEMORY"]),
    ("robin aunt stephanie", ["robin", "MEMORY"]),
    ("contact alerts within the hour", ["MEMORY", "alignment"]),
    ("maytag bravo dryer", ["MEMORY"]),
    ("tartaria simulation theory", ["MEMORY"]),
    ("stephanie NEAR/10 voice", ["MEMORY"]),  # min distance in corpus is 8
    ("dryer AND NOT bitcoin", ["MEMORY", "2026-10-0"]),
    ("cash app OR venmo", ["boss-man-abe", "MEMORY"]),
    ("textnow number scout 403-4906", ["MEMORY", "alignment"]),
]

passed = failed = 0
for q, ok in CASES:
    try:
        res = search(ix, q, top_k=3)
    except Exception as e:
        print(f"ERROR {q!r}: {e}")
        failed += 1
        continue
    tops = [ix.docs[d]["title"] for d, _ in res]
    good = any(any(s in t for t in tops) for s in ok)
    if good:
        passed += 1
    else:
        failed += 1
        print(f"FAIL {q!r}\n  top3={tops}\n  want one of {ok}")
print(f"\n{passed}/{passed + failed} retrieval checks pass")
