"""KWIC snippet engine: pick the densest query-term window, highlight hits."""
from tokenizer import tokenize, analyze


def make_snippet(text, query, window=44, max_snippets=2):
    qterms = set(analyze(query))
    if not qterms:
        return text[:200]
    toks = tokenize(text)
    # map token index -> stemmed term for hit detection
    from tokenizer import stem, _STOPWORDS
    hit = [stem(t) in qterms and t not in _STOPWORDS for t in toks]
    n = len(toks)
    if n <= window:
        spans = [(0, n)]
    else:
        # best non-overlapping windows by hit count
        scored = []
        for start in range(0, n - window + 1, window // 3):
            c = sum(hit[start:start + window])
            scored.append((c, start))
        scored.sort(reverse=True)
        spans, used = [], []
        for c, s in scored:
            if c == 0:
                break
            if all(abs(s - u) >= window for u in used):
                spans.append((s, s + window))
                used.append(s)
            if len(spans) == max_snippets:
                break
        if not spans:
            spans = [(0, window)]
    parts = []
    for s, e in sorted(spans):
        frag = []
        for i in range(s, min(e, n)):
            frag.append(f"**{toks[i]}**" if hit[i] else toks[i])
        parts.append(("... " if s > 0 else "") + " ".join(frag) +
                     (" ..." if e < n else ""))
    return " ... ".join(parts)
