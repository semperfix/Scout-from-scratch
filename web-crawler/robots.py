#!/usr/bin/env python3
"""robots.py -- RFC 9309 robots.txt parser (stdlib only).

Handles: user-agent groups (case-insensitive, longest prefix token wins;
tied groups merge), Allow/Disallow with longest-match-wins (Allow wins
ties), crawl-delay, sitemap collection. Path matching is done on the
percent-decoded path; rules support the RFC's '*' wildcard and '$'
end-anchor (translated to a regex).

Honest subsets: UTF-8 BOM is stripped; lines over 2083 chars are still
parsed (no truncation); the deprecated `Crawl-delay` is honored as the
de-facto standard extension.
"""
import re
from urllib.parse import urlsplit, unquote


def _rule_to_regex(rule):
    """Translate a robots path rule ('*' wildcard, trailing '$') to regex."""
    out = []
    i = 0
    while i < len(rule):
        c = rule[i]
        if c == "*":
            out.append(".*")
        elif c == "$" and i == len(rule) - 1:
            out.append("$")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class Group(object):
    def __init__(self):
        self.agents = []     # lowercased tokens, in file order
        self.rules = []      # [(is_allow, path, compiled_regex)]
        self.crawl_delay = None


def parse(text):
    """Parse robots.txt text. Returns (groups, sitemaps)."""
    if text.startswith("\ufeff"):
        text = text[1:]
    groups = []
    sitemaps = []
    cur = None
    seen_rule = False        # once a rule is seen, new UA lines start a group

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        # strip inline comments
        if "#" in value and field in ("user-agent", "allow", "disallow",
                                      "crawl-delay", "sitemap"):
            value = value.split("#", 1)[0].strip()

        if field == "user-agent":
            token = value.lower()
            if cur is None or seen_rule:
                cur = Group()
                groups.append(cur)
                seen_rule = False
            cur.agents.append(token)
        elif field in ("allow", "disallow"):
            if cur is None:
                continue
            seen_rule = True
            path = unquote(value)
            if field == "disallow" and path == "":
                continue            # empty Disallow = allow all
            rx = re.compile(_rule_to_regex(path))
            cur.rules.append((field == "allow", path, rx))
        elif field == "crawl-delay":
            if cur is None:
                continue
            seen_rule = True
            try:
                cur.crawl_delay = float(value)
            except ValueError:
                pass
        elif field == "sitemap":
            sitemaps.append(value)
    return groups, sitemaps


class Robots(object):
    def __init__(self, text, user_agent="*"):
        self.groups, self.sitemaps = parse(text)
        self.ua = user_agent.lower()

    def _matching_groups(self):
        best, bestlen = [], -1
        for g in self.groups:
            for token in g.agents:
                if token == "*" or self.ua.startswith(token):
                    if len(token) > bestlen:
                        best, bestlen = [g], len(token)
                    elif len(token) == bestlen and g not in best:
                        best.append(g)
        if not best:
            # fall back to the '*' group only
            best = [g for g in self.groups if "*" in g.agents]
        return best

    def allowed(self, url):
        """Longest-match wins; Allow beats Disallow on ties."""
        path = unquote(urlsplit(url).path or "/")
        q = urlsplit(url).query
        target = path + ("?" + q if q else "")
        best_allow, best_len = True, -1
        for g in self._matching_groups():
            for is_allow, rule_path, rx in g.rules:
                m = rx.match(target)
                if m and len(rule_path) > best_len:
                    best_allow, best_len = is_allow, len(rule_path)
                elif m and len(rule_path) == best_len and is_allow:
                    best_allow = True
        return best_allow

    def crawl_delay(self):
        delays = [g.crawl_delay for g in self._matching_groups()
                  if g.crawl_delay is not None]
        return max(delays) if delays else None
