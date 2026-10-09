#!/usr/bin/env python3
"""crawl.py -- polite web crawler CLI (stdlib only).

The novel parts of this skill are the frontier (politeness-aware,
canonicalizing, BFS), the RFC 9309 robots.txt parser, URL canonicalization,
and the hand-rolled HTML tokenizer. Actual HTTP fetching is done with
urllib -- the from-scratch raw-socket HTTP client lives in the
http-raw-sockets skill; crawl.py documents the seam and keeps the transport
swappable.

Exit 0 always. Machine-readable lines start with FETCHED:/SKIPPED:/ROBOTS:.
"""
import argparse
import os
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import urlnorm
import robots as robotsmod
import htmltok
from frontier import Frontier


def fetch(url, user_agent, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ctype = r.headers.get("Content-Type", "")
            final = r.geturl()
            if "text/html" not in ctype and "text/" not in ctype:
                return final, None, "non-html (%s)" % ctype
            raw = r.read(2 * 1024 * 1024)
            charset = r.headers.get_content_charset() or "utf-8"
            try:
                html = raw.decode(charset, errors="replace")
            except (LookupError, UnicodeError):
                html = raw.decode("utf-8", errors="replace")
            return final, html, None
    except urllib.error.HTTPError as e:
        return None, None, "http %d" % e.code
    except Exception as e:
        return None, None, "%s: %s" % (type(e).__name__, e)


def get_robots(netloc, scheme, user_agent, cache):
    """Fetch + parse robots.txt for a host:port (cached). Never fatal."""
    key = (scheme, netloc)
    if key in cache:
        return cache[key]
    url = "%s://%s/robots.txt" % (scheme, netloc)
    final, body, err = fetch(url, user_agent)
    if err or body is None:
        r = robotsmod.Robots("", user_agent)   # no robots.txt -> allow all
    else:
        r = robotsmod.Robots(body, user_agent)
    cache[key] = r
    return r


def crawl(seed, max_pages=20, delay=1.0, user_agent="ScoutCrawler/1.0",
          stay_host=True, verbose=True):
    canon_seed = urlnorm.canonicalize(seed)
    seed_host = urlsplit(canon_seed).hostname
    frontier = Frontier(delay=delay)
    frontier.add(canon_seed)
    robots_cache = {}
    fetched, skipped_robots, errors = 0, 0, 0
    pages = []

    while fetched + errors < max_pages:
        url, wait = frontier.next()
        if url is None:
            if wait > 0:
                time.sleep(min(wait, 5))
                continue
            break                       # frontier empty
        parts = urlsplit(url)
        host = parts.hostname or ""
        if stay_host and host != seed_host:
            continue
        r = get_robots(parts.netloc, parts.scheme, user_agent, robots_cache)
        cd = r.crawl_delay()
        if cd:
            frontier.set_host_delay(host, cd)
        if not r.allowed(url):
            skipped_robots += 1
            if verbose:
                print("SKIPPED: %s (robots disallow)" % url)
            continue
        final, html, err = fetch(url, user_agent)
        if err:
            errors += 1
            if verbose:
                print("SKIPPED: %s (%s)" % (url, err))
            continue
        fetched += 1
        info = htmltok.extract(html, final or url)
        pages.append({"url": final or url, "title": info["title"],
                      "links": info["links"],
                      "text": info["text"][:500]})
        if verbose:
            print("FETCHED: %s [title: %s] (%d links)" %
                  (final or url, info["title"][:60], len(info["links"])))
        for link in info["links"]:
            if link.startswith(("http://", "https://")):
                frontier.add(link)

    return {
        "seed": canon_seed,
        "fetched": fetched,
        "skipped_robots": skipped_robots,
        "errors": errors,
        "pages": pages,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Polite web crawler: canonicalizing frontier, RFC 9309 "
                    "robots, hand-rolled HTML extraction. Fetching via "
                    "urllib (raw-socket client lives in http-raw-sockets).")
    ap.add_argument("--seed", required=True, help="starting URL")
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument("--delay", type=float, default=1.0,
                    help="politeness delay between hits to the same host")
    ap.add_argument("--user-agent", default="ScoutCrawler/1.0")
    ap.add_argument("--no-stay-host", action="store_true",
                    help="follow off-host links (default: seed host only)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    res = crawl(args.seed, max_pages=args.max_pages, delay=args.delay,
                user_agent=args.user_agent,
                stay_host=not args.no_stay_host, verbose=not args.quiet)
    print("ROBOTS: crawl complete: fetched=%d skipped_robots=%d errors=%d" %
          (res["fetched"], res["skipped_robots"], res["errors"]))
    for p in res["pages"]:
        print("PAGE: %s :: %s" % (p["url"], p["title"][:80]))


if __name__ == "__main__":
    main()
