#!/usr/bin/env python3
"""htmltok.py -- hand-rolled HTML tokenizer + link/text extractor (stdlib only).

Single-pass scanner emitting tokens:
  ("start", name, attrs)   attrs = [(name, value)] with lowercased names
  ("end", name)
  ("text", data)
  ("comment", data)

<script>/<style> contents are consumed as raw text until the matching end
tag (no tag parsing inside). A small entity decoder handles the five
predefined XML entities plus numeric character references. extract() builds
on top: page title, resolved hyperlinks, and visible text with script/style
stripped.

This is a tokenizer, not a spec-compliant parser: no tree construction, no
foster parenting, no error-recovery rules beyond "skip the bad markup".
"""
import re
from urllib.parse import urljoin

ENTITY_RE = re.compile(r"&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);")
_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}


def decode_entities(s):
    def sub(m):
        e = m.group(1)
        if e in _ENTITIES:
            return _ENTITIES[e]
        try:
            if e.startswith("#x"):
                return chr(int(e[2:], 16))
            return chr(int(e[1:]))
        except (ValueError, OverflowError):
            return m.group(0)
    return ENTITY_RE.sub(sub, s)


def tokenize(html):
    """Yield tokens. Tag/attribute names are lowercased."""
    i, n = 0, len(html)
    while i < n:
        if html[i] == "<":
            if html.startswith("<!--", i):
                j = html.find("-->", i + 4)
                j = n if j < 0 else j + 3
                yield ("comment", html[i + 4:j - 3 if j < n else n])
                i = j
                continue
            if html.startswith("<!DOCTYPE", i) or html.startswith("<!doctype", i):
                j = html.find(">", i)
                i = n if j < 0 else j + 1
                continue
            m = re.match(r"</?\s*([a-zA-Z][a-zA-Z0-9]*)", html[i:])
            if not m:
                # not a tag -- literal '<'
                yield ("text", "<")
                i += 1
                continue
            name = m.group(1).lower()
            closing = html[i + 1] == "/"
            j = i + m.end()
            attrs = []
            if not closing:
                while j < n and html[j] not in (">", "/"):
                    am = re.match(r"""\s*([a-zA-Z_:][a-zA-Z0-9_:.\-]*)""",
                                  html[j:])
                    if not am:
                        j += 1
                        continue
                    aname = am.group(1).lower()
                    j += am.end()
                    aval = ""
                    jm = re.match(r"""\s*=\s*""", html[j:])
                    if jm:
                        j += jm.end()
                        if j < n and html[j] in "\"'":
                            q = html[j]
                            k = html.find(q, j + 1)
                            k = n if k < 0 else k
                            aval = decode_entities(html[j + 1:k])
                            j = k + 1
                        else:
                            km = re.match(r"[^\s>]+", html[j:])
                            if km:
                                aval = decode_entities(km.group(0))
                                j += km.end()
                    attrs.append((aname, aval))
                # skip "/>" or ">"
                if html.startswith("/>", j):
                    j += 2
                elif j < n and html[j] == ">":
                    j += 1
            else:
                k = html.find(">", j)
                j = n if k < 0 else k + 1
            if closing:
                yield ("end", name)
            else:
                yield ("start", name, attrs)
                if name in ("script", "style"):
                    # raw-text element: consume until matching end tag
                    k = re.search(r"</\s*%s\s*>" % name, html[j:], re.I)
                    if k:
                        j += k.end()
                    else:
                        j = n
                    yield ("end", name)
            i = j
        else:
            j = html.find("<", i)
            j = n if j < 0 else j
            text = decode_entities(html[i:j])
            if text:
                yield ("text", text)
            i = j


def extract(html, base_url):
    """Returns {"title": str, "links": [absolute urls], "text": str}."""
    title, links, chunks = "", [], []
    in_title = False
    base = base_url
    for tok in tokenize(html):
        if tok[0] == "start":
            _, name, attrs = tok
            ad = dict(attrs)
            if name == "title":
                in_title = True
            elif name == "base" and "href" in ad:
                base = urljoin(base_url, ad["href"])
            elif name == "a" and "href" in ad:
                href = ad["href"].strip()
                if href and not href.lower().startswith(
                        ("javascript:", "mailto:", "#")):
                    links.append(urljoin(base, href))
        elif tok[0] == "end" and tok[1] == "title":
            in_title = False
        elif tok[0] == "text":
            if in_title:
                title += tok[1]
            else:
                chunks.append(tok[1])
    text = re.sub(r"\s+", " ", "".join(chunks)).strip()
    # dedupe links, keep order
    seen, uniq = set(), []
    for l in links:
        if l not in seen:
            seen.add(l)
            uniq.append(l)
    return {"title": title.strip(), "links": uniq, "text": text}
