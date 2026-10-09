"""Query parser + executor: boolean (AND/OR/NOT), quoted phrases,
and NEAR/n proximity — all evaluated on positional postings.

Grammar:
    expr    := or_expr
    or_expr := and_expr (OR and_expr)*
    and_expr:= not_expr ((AND | implicit) not_expr)*
    not_expr:= NOT not_expr | primary
    primary := "phrase" | term (NEAR/n term)?
"""
import re
from tokenizer import analyze, analyze_phrase
from rank import score_docs

_TOKEN_RE = re.compile(r'"[^"]*"|\(|\)|\bNEAR/\d+\b|\bAND\b|\bOR\b|\bNOT\b|\S+', re.IGNORECASE)


class Node:
    pass


class Term(Node):
    def __init__(self, term):
        self.term = term


class Phrase(Node):
    def __init__(self, term_offsets):
        self.term_offsets = term_offsets  # [(term, raw_offset)]


class Near(Node):
    def __init__(self, left, right, n):
        self.left, self.right, self.n = left, right, n


class And(Node):
    def __init__(self, children):
        self.children = children


class Or(Node):
    def __init__(self, children):
        self.children = children


class Not(Node):
    def __init__(self, child):
        self.child = child


def parse(q):
    toks = _TOKEN_RE.findall(q)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def next_():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def primary():
        t = next_()
        if t == "(":
            e = or_expr()
            assert next_() == ")", "unbalanced parens"
            return e
        if t.startswith('"'):
            # Stopword-aware offsets: 'lost my voice' -> [(lost,0),(voic,2)].
            return Phrase(analyze_phrase(t.strip('"')))
        terms = analyze(t)
        if not terms:
            return None  # stopword-only token: contributes nothing
        node = Term(terms[0])
        while peek() and peek().upper().startswith("NEAR/"):
            n = int(next_().upper().split("/")[1])
            rterms = analyze(next_())
            if rterms:
                node = Near(node, Term(rterms[0]), n)
        return node

    def not_expr():
        if peek() and peek().upper() == "NOT":
            next_()
            return Not(not_expr())
        return primary()

    def and_expr():
        kids = [k for k in [not_expr()] if k is not None]
        while peek() and peek().upper() not in ("OR", ")", None):
            if peek().upper() == "AND":
                next_()
            k = not_expr()
            if k is not None:
                kids.append(k)
        if not kids:
            return Term("")  # query was only stopwords: match nothing
        return kids[0] if len(kids) == 1 else And(kids)

    def or_expr():
        kids = [k for k in [and_expr()] if k is not None]
        while peek() and peek().upper() == "OR":
            next_()
            k = and_expr()
            if k is not None:
                kids.append(k)
        if not kids:
            return Term("")
        return kids[0] if len(kids) == 1 else Or(kids)

    tree = or_expr()
    assert pos[0] == len(toks), f"trailing tokens: {toks[pos[0]:]}"
    return tree


def _postings_of(index, term):
    return index.postings(term)[1]


def _phrase_docs(index, term_offsets):
    """Docs where the terms occur at the same relative offsets as in the
    query (stopwords counted in the ruler, so 'lost my voice' matches
    positions 3 and 5)."""
    if not term_offsets:
        return {}
    terms = [t for t, _ in term_offsets]
    base = term_offsets[0][1]
    rel = [o - base for _, o in term_offsets]  # rel[0] == 0
    plists = [_postings_of(index, t) for t in terms]
    if any(not p for p in plists):
        return {}
    by_doc = {}
    for i, pl in enumerate(plists):
        for doc_id, poss in pl:
            by_doc.setdefault(doc_id, [None] * len(terms))[i] = set(poss)
    out = {}
    for doc_id, pos_sets in by_doc.items():
        if any(s is None for s in pos_sets):
            continue
        for p in pos_sets[0]:
            if all((p + rel[i]) in pos_sets[i] for i in range(1, len(rel))):
                out.setdefault(doc_id, []).append(p)
    return out


def _near_docs(index, left_terms, right_terms, n):
    """Docs where any left-term position is within n of any right-term position."""
    lp = {}
    for t in left_terms:
        for doc_id, poss in _postings_of(index, t):
            lp.setdefault(doc_id, []).extend(poss)
    rp = {}
    for t in right_terms:
        for doc_id, poss in _postings_of(index, t):
            rp.setdefault(doc_id, []).extend(poss)
    out = {}
    for doc_id in lp:
        if doc_id not in rp:
            continue
        a, b = sorted(lp[doc_id]), sorted(rp[doc_id])
        i = j = 0
        while i < len(a) and j < len(b):
            if abs(a[i] - b[j]) <= n:
                out.setdefault(doc_id, []).append(a[i])
                i += 1
            elif a[i] < b[j]:
                i += 1
            else:
                j += 1
    return out


def _term_list(node):
    """Flatten node to plain terms for scoring."""
    if isinstance(node, Term):
        return [node.term] if node.term else []
    if isinstance(node, Phrase):
        return [t for t, _ in node.term_offsets]
    if isinstance(node, Near):
        return _term_list(node.left) + _term_list(node.right)
    if isinstance(node, (And, Or)):
        out = []
        for c in node.children:
            out += _term_list(c)
        return out
    if isinstance(node, Not):
        return []
    return []


def execute(index, node):
    """Returns {doc_id: score}."""
    if isinstance(node, Term):
        plist = _postings_of(index, node.term)
        return score_docs(index, [(node.term, plist)]) if node.term else {}
    if isinstance(node, Phrase):
        terms = [t for t, _ in node.term_offsets]
        docs = _phrase_docs(index, node.term_offsets)
        base = score_docs(index, [(t, _postings_of(index, t)) for t in terms])
        # phrase match gets 1.5x on the matched docs (proximity is evidence)
        return {d: base.get(d, 0.0) * 1.5 for d in docs}
    if isinstance(node, Near):
        lt, rt = _term_list(node.left), _term_list(node.right)
        docs = _near_docs(index, lt, rt, node.n)
        base = score_docs(index, [(t, _postings_of(index, t)) for t in lt + rt])
        return {d: base.get(d, 0.0) * 1.25 for d in docs}
    if isinstance(node, And):
        kids = [execute(index, c) for c in node.children]
        if not kids:
            return {}
        common = set(kids[0])
        for k in kids[1:]:
            common &= set(k)
        # AND score = sum of children scores (BM25 is additive)
        return {d: sum(k[d] for k in kids) for d in common}
    if isinstance(node, Or):
        out = {}
        for k in (execute(index, c) for c in node.children):
            for d, s in k.items():
                out[d] = out.get(d, 0.0) + s
        return out
    if isinstance(node, Not):
        banned = set(execute(index, node.child))
        return {d: 0.0 for d in range(index.N) if d not in banned}
    raise ValueError(f"unknown node {node!r}")


def search(index, q, top_k=10):
    tree = parse(q)
    scores = execute(index, tree)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return [(doc_id, s) for doc_id, s in ranked[:top_k] if s > 0]
