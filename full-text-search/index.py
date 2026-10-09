"""Positional inverted index with a hand-written on-disk format.

File layout (all integers LEB128 varints):
  magic 8 bytes: b'SCOUTIDX'
  version: 1
  doc_count
  per doc: doc_id, path_len, path_bytes, n_terms, n_unique_terms, title_len, title_bytes
  term_count
  per term: term_len, term_bytes, df, then postings:
      doc_id_delta, tf, then position_deltas (tf of them)
"""
import os
from tokenizer import analyze_positions

MAGIC = b"SCOUTIDX"
VERSION = 1


def encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class _Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def varint(self):
        shift, val = 0, 0
        while True:
            b = self.d[self.p]
            self.p += 1
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                return val
            shift += 7

    def raw(self, n):
        b = self.d[self.p:self.p + n]
        self.p += n
        return b


class IndexBuilder:
    def __init__(self):
        self.docs = []          # list of dicts: path, title, n_terms, n_unique
        self.postings = {}      # term -> {doc_id: [positions]}

    def add_document(self, path, text, title=None):
        doc_id = len(self.docs)
        seen = set()
        for term, pos in analyze_positions(text):
            self.postings.setdefault(term, {}).setdefault(doc_id, []).append(pos)
            seen.add(term)
        n_terms = sum(len(v) for d in self.postings.values()
                      for k, v in [(doc_id, d.get(doc_id))] if v)
        self.docs.append({"path": path, "title": title or os.path.basename(path),
                          "n_terms": n_terms, "n_unique": len(seen)})
        return doc_id

    def save(self, path):
        out = bytearray(MAGIC)
        out += encode_varint(VERSION)
        out += encode_varint(len(self.docs))
        for i, doc in enumerate(self.docs):
            pb = doc["path"].encode("utf-8")
            tb = doc["title"].encode("utf-8")
            out += encode_varint(i) + encode_varint(len(pb)) + pb
            out += encode_varint(doc["n_terms"]) + encode_varint(doc["n_unique"])
            out += encode_varint(len(tb)) + tb
        terms = sorted(self.postings)
        out += encode_varint(len(terms))
        for term in terms:
            tb = term.encode("utf-8")
            plist = self.postings[term]
            out += encode_varint(len(tb)) + tb + encode_varint(len(plist))
            prev_doc = 0
            for doc_id in sorted(plist):
                poss = plist[doc_id]
                out += encode_varint(doc_id - prev_doc)
                prev_doc = doc_id
                out += encode_varint(len(poss))
                prev_pos = 0
                for p in poss:
                    out += encode_varint(p - prev_pos)
                    prev_pos = p
        with open(path, "wb") as f:
            f.write(bytes(out))
        return len(out)


class Index:
    """Read-only index loaded from disk."""

    def __init__(self, path):
        with open(path, "rb") as f:
            data = f.read()
        r = _Reader(data)
        assert r.raw(8) == MAGIC, "bad magic"
        assert r.varint() == VERSION, "bad version"
        self.docs = []
        n_docs = r.varint()
        for _ in range(n_docs):
            doc_id = r.varint()
            plen = r.varint()
            pth = r.raw(plen).decode("utf-8")
            n_terms = r.varint()
            n_unique = r.varint()
            tlen = r.varint()
            title = r.raw(tlen).decode("utf-8")
            self.docs.append({"id": doc_id, "path": pth, "title": title,
                              "n_terms": n_terms, "n_unique": n_unique})
        self.terms = {}   # term -> (df, [(doc_id, [positions])])
        n_terms = r.varint()
        for _ in range(n_terms):
            tlen = r.varint()
            term = r.raw(tlen).decode("utf-8")
            df = r.varint()
            plist = []
            prev_doc = 0
            for _ in range(df):
                doc_id = prev_doc + r.varint()
                prev_doc = doc_id
                tf = r.varint()
                poss, prev_pos = [], 0
                for _ in range(tf):
                    prev_pos += r.varint()
                    poss.append(prev_pos)
                plist.append((doc_id, poss))
            self.terms[term] = (df, plist)
        self.N = n_docs
        self.avgdl = sum(d["n_terms"] for d in self.docs) / max(n_docs, 1)

    def postings(self, term):
        """Return (df, [(doc_id, [positions])]) or (0, [])."""
        return self.terms.get(term, (0, []))

    def doc_freq(self, term):
        return self.terms.get(term, (0, []))[0]
