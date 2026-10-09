#!/usr/bin/env python3
"""urlnorm.py -- URL canonicalization for crawler dedup (stdlib only).

Two URLs that fetch the same resource must map to one string, or the
frontier's seen-set is useless. canonicalize() applies, in order:

  1. strip whitespace; lowercase scheme and host
  2. drop default ports (:80 http, :443 https)
  3. percent-encoding normalization: decode %XX for unreserved chars
     (A-Za-z0-9-._~), uppercase the hex of the rest
  4. dot-segment removal (RFC 3986 section 5.2.4)
  5. empty path -> "/"
  6. query params sorted by (name, value); blank values kept
  7. fragment stripped

Userinfo is dropped (crawlers don't log in per-URL). Internationalized
domain names are NOT punycode-encoded here (documented limitation).
"""
from urllib.parse import urlsplit, urlunsplit, quote, parse_qsl, urlencode

UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


def normalize_percent_encoding(s):
    """Decode %XX of unreserved chars; uppercase remaining hex escapes."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s):
            hexpart = s[i + 1:i + 3]
            try:
                ch = chr(int(hexpart, 16))
            except ValueError:
                out.append(s[i])
                i += 1
                continue
            if ch in UNRESERVED:
                out.append(ch)
            else:
                out.append("%" + hexpart.upper())
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def remove_dot_segments(path):
    """RFC 3986 5.2.4."""
    inp = path
    out = []
    while inp:
        if inp.startswith("../"):
            inp = inp[3:]
        elif inp.startswith("./"):
            inp = inp[2:]
        elif inp.startswith("/./"):
            inp = "/" + inp[3:]
        elif inp == "/.":
            inp = "/"
        elif inp.startswith("/../"):
            inp = "/" + inp[4:]
            if out:
                out.pop()
        elif inp == "/..":
            inp = "/"
            if out:
                out.pop()
        elif inp in (".", ".."):
            inp = ""
        else:
            # move first segment (including leading "/") to output
            if inp.startswith("/"):
                nxt = inp.find("/", 1)
            else:
                nxt = inp.find("/")
            if nxt == -1:
                out.append(inp)
                inp = ""
            else:
                out.append(inp[:nxt])
                inp = inp[nxt:]
    return "".join(out)


def canonicalize(url):
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if not scheme or not parts.hostname:
        raise ValueError("not an absolute http(s) URL: %r" % url)
    host = parts.hostname.lower()
    port = parts.port
    if port and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = host if port is None else "%s:%d" % (host, port)

    path = normalize_percent_encoding(parts.path or "/")
    path = remove_dot_segments(path)
    if not path.startswith("/"):
        path = "/" + path
    # encode stray unsafe chars; '%' is safe so valid escapes pass through
    path = quote(path, safe="/:@!$&'()*+,;=%")

    query = ""
    if parts.query:
        qsl = parse_qsl(parts.query, keep_blank_values=True)
        qsl.sort(key=lambda kv: (kv[0], kv[1]))
        query = urlencode(qsl)

    return urlunsplit((scheme, netloc, path, query, ""))


def same_host(a, b):
    return urlsplit(a).hostname == urlsplit(b).hostname
