"""BM25 ranking over the positional index. Zero dependencies."""
import math

K1 = 1.2
B = 0.75


def idf(N, df):
    """Lucene-style IDF: non-negative, no singularities at df=0 or df=N."""
    return math.log(1 + (N - df + 0.5) / (df + 0.5))


def bm25_term(tf, doc_len, avgdl, idf_val, k1=K1, b=B):
    # tf saturation: doubling tf past ~k1 barely moves the score
    return idf_val * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * doc_len / avgdl))


def score_docs(index, term_postings, boost=1.0):
    """term_postings: list of (term, [(doc_id, [positions])]).
    Returns {doc_id: score}."""
    scores = {}
    for term, plist in term_postings:
        _, _ = index.postings(term)
        df = len(plist)
        if df == 0:
            continue
        w = idf(index.N, df)
        for doc_id, poss in plist:
            dl = index.docs[doc_id]["n_terms"]
            s = bm25_term(len(poss), dl, index.avgdl, w)
            scores[doc_id] = scores.get(doc_id, 0.0) + s * boost
    return scores
