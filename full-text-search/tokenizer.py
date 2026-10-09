"""Tokenizer for the from-scratch search engine: Unicode word segmentation,
case folding, stopwords, and a hand-implemented Porter stemmer.

Zero dependencies.
"""
import re
import unicodedata

# Unicode-aware word pattern: letters + digits, internal apostrophes/hyphens/
# colons kept: "doesn't", "well-known", "912-648-2048", "2:40am"
_WORD_RE = re.compile(r"[^\W_]+(?:['\u2019\-:][^\W_]+)*", re.UNICODE)

_STOPWORDS = frozenset("""
a an and are as at be been but by for from had has have he her his
i in is it its of on or she that the their them they this to was were
will with would you your
me my we our us do does did so if not no themself himself herself
""".split())


def normalize(text):
    """NFC normalize + casefold + strip diacritics where it helps matching."""
    text = unicodedata.normalize("NFC", text)
    # Strip combining marks (café -> cafe) to collapse accents
    text = "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )
    return text.casefold()


def tokenize(text):
    """Yield raw tokens (position order preserved)."""
    out = []
    for t in _WORD_RE.findall(normalize(text)):
        # Possessives collapse: "bravo's" -> "bravo", "stephanie'" -> "stephanie".
        # Internal contraction apostrophes ("doesn't") are kept — both index
        # and query go through this, so matching stays consistent.
        t = re.sub(r"['\u2019]s$", "", t).strip("'\u2019")
        if t:
            out.append(t)
    return out


# ----------------------------------------------------------------------------
# Porter stemmer, implemented by hand from the algorithm's rules.
# ----------------------------------------------------------------------------

def _cons(word, i):
    c = word[i]
    if c in "aeiou":
        return False
    if c == "y":
        return i == 0 or not _cons(word, i - 1)
    return True


def _measure(word):
    """Count of VC sequences: m."""
    m, i, n = 0, 0, len(word)
    while i < n and _cons(word, i):
        i += 1
    while i < n:
        while i < n and not _cons(word, i):
            i += 1
        if i >= n:
            break
        m += 1
        while i < n and _cons(word, i):
            i += 1
    return m


def _has_vowel(word):
    return any(not _cons(word, i) for i in range(len(word)))


def _double_cons(word):
    return len(word) >= 2 and _cons(word, -1) and _cons(word, -2) and word[-1] == word[-2]


def _cvc(word):
    if len(word) < 3 or not _cons(word, -1) or _cons(word, -2) or not _cons(word, -3):
        return False
    return word[-1] not in "wxy"


def _strip_suffix(word, suffix):
    return word[:-len(suffix)] if word.endswith(suffix) else None


def stem(word):
    """Porter stem of one lowercase word."""
    w = word
    if len(w) <= 2:
        return w

    # Step 1a
    for sfx in ("sses", "ies", "ss", "s"):
        stem_ = _strip_suffix(w, sfx)
        if stem_ is not None:
            w = {"sses": stem_ + "ss", "ies": stem_ + "i",
                 "ss": w, "s": stem_}[sfx]
            break

    # Step 1b
    done_1b = False
    for sfx in ("eed", "ed", "ing"):
        stem_ = _strip_suffix(w, sfx)
        if stem_ is not None:
            if sfx == "eed":
                if _measure(stem_) > 0:
                    w = stem_ + "ee"
            elif _has_vowel(stem_):
                w = stem_
                done_1b = True
            break
    if done_1b:
        if w.endswith(("at", "bl", "iz")):
            w += "e"
        elif _double_cons(w) and w[-1] not in "lsz":
            w = w[:-1]
        elif _measure(w) == 1 and _cvc(w):
            w += "e"

    # Step 1c
    if _strip_suffix(w, "y") is not None and _has_vowel(w[:-1]):
        w = w[:-1] + "i"

    # Step 2
    for sfx, repl in (("ational", "ate"), ("tional", "tion"), ("enci", "ence"),
                      ("anci", "ance"), ("izer", "ize"), ("abli", "able"),
                      ("alli", "al"), ("entli", "ent"), ("eli", "e"),
                      ("ousli", "ous"), ("ization", "ize"), ("ation", "ate"),
                      ("ator", "ate"), ("alism", "al"), ("iveness", "ive"),
                      ("fulness", "ful"), ("ousness", "ous"), ("aliti", "al"),
                      ("iviti", "ive"), ("biliti", "ble")):
        stem_ = _strip_suffix(w, sfx)
        if stem_ is not None and _measure(stem_) > 0:
            w = stem_ + repl
            break

    # Step 3
    for sfx, repl in (("icate", "ic"), ("ative", ""), ("alize", "al"),
                      ("iciti", "ic"), ("ical", "ic"), ("ful", ""),
                      ("ness", "")):
        stem_ = _strip_suffix(w, sfx)
        if stem_ is not None and _measure(stem_) > 0:
            w = stem_ + repl
            break

    # Step 4
    for sfx in ("al", "ance", "ence", "er", "ic", "able", "ible", "ant",
                "ement", "ment", "ent", "ou", "ism", "ate", "iti", "ous",
                "ive", "ize"):
        stem_ = _strip_suffix(w, sfx)
        if stem_ is not None and _measure(stem_) > 1:
            w = stem_
            break
    if (stem_ := _strip_suffix(w, "ion")) is not None and _measure(stem_) > 1 \
            and stem_[-1] in "st":
        w = stem_

    # Step 5a
    if (stem_ := _strip_suffix(w, "e")) is not None:
        if _measure(stem_) > 1 or (_measure(stem_) == 1 and not _cvc(stem_)):
            w = stem_
    # Step 5b
    if _measure(w) > 1 and _double_cons(w) and w.endswith("l"):
        w = w[:-1]
    return w


def _parts(text):
    """Raw tokens, with hyphenated compounds split into parts.

    'within-the-hour' -> within, the, hour (each gets its own position).
    This is word-delimiter behavior: it lets queries match inside compounds
    ('hour' finds 'within-the-hour') and makes phrases span them correctly.
    Colons are NOT split, so '2:40am' and URLs stay whole.
    """
    for tok in tokenize(text):
        sub = [p for p in tok.split("-") if p]
        yield from sub if len(sub) > 1 else (tok,)


def analyze(text, stem_words=True, drop_stops=True):
    """Full pipeline: tokenize -> split compounds -> (stopwords) -> (stem)."""
    out = []
    for tok in _parts(text):
        if drop_stops and tok in _STOPWORDS:
            continue
        out.append(stem(tok) if stem_words else tok)
    return out


def analyze_positions(text, stem_words=True, drop_stops=True):
    """Like analyze() but returns (term, position) pairs.

    Positions are sequential over split parts, so 'within-the-hour' occupies
    three consecutive positions.
    """
    out = []
    pos = 0
    for tok in _parts(text):
        if not (drop_stops and tok in _STOPWORDS):
            out.append((stem(tok) if stem_words else tok, pos))
        pos += 1
    return out


def analyze_phrase(text):
    """(term, raw_offset) pairs for phrase queries.

    Offsets count EVERY token including stopwords, so a phrase like
    'lost my voice' -> [(lost, 0), (voic, 2)] and matches indexed positions
    (3, 5) because the relative gaps agree. This is the position-increment
    trick: stopwords are removed from the term list but not from the ruler.
    """
    out = []
    pos = 0
    for tok in _parts(text):
        if tok not in _STOPWORDS:
            out.append((stem(tok), pos))
        pos += 1
    return out
