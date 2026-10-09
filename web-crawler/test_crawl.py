#!/usr/bin/env python3
"""test_crawl.py -- validate the web-crawler stack.

Unit: urlnorm canonicalization vectors, robots.txt longest-match/tie/UA
rules, htmltok link+title+text extraction, frontier dedup + politeness.
Integration: local http.server with robots.txt (Disallow: /private/) + 3
pages; crawl it and verify robots honored, dedup works, titles extracted.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import urlnorm
import robots as robotsmod
import htmltok
from frontier import Frontier
from crawl import crawl

checks = []


def check(name, cond, detail=""):
    checks.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name +
          (" -- " + str(detail) if detail and not cond else ""))


def unit_urlnorm():
    cases = [
        ("HTTP://Example.COM:80/a/../b?c=2&b=1#frag",
         "http://example.com/b?b=1&c=2"),
        ("http://example.com/%7euser", "http://example.com/~user"),
        ("http://example.com/%2f", "http://example.com/%2F"),
        ("https://example.com:443/", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("http://example.com/a/./b/../../c", "http://example.com/c"),
        ("http://example.com/x?b=&a=1", "http://example.com/x?a=1&b="),
    ]
    for raw, want in cases:
        try:
            got = urlnorm.canonicalize(raw)
        except Exception as e:
            check("urlnorm %r" % raw, False, repr(e))
            continue
        check("urlnorm %r" % raw, got == want, "got %r" % got)


def unit_robots():
    txt = """\
User-agent: *
Disallow: /private/
Allow: /private/public.html
Crawl-delay: 2

User-agent: ScoutCrawler
Disallow: /tmp/
"""
    # UA matching only the "*" group: disallow + crawl-delay apply
    r = robotsmod.Robots(txt, "OtherBot/1.0")
    check("robots disallow", not r.allowed("http://h/private/secret.html"))
    check("robots allow-longest-match",
          r.allowed("http://h/private/public.html"))
    check("robots default allow", r.allowed("http://h/about.html"))
    check("robots crawl-delay", r.crawl_delay() == 2.0, r.crawl_delay())
    # RFC 9309: most-specific UA group wins, groups do NOT merge --
    # ScoutCrawler's own group has no /private/ rule, so it is allowed,
    # but its /tmp/ rule applies.
    r = robotsmod.Robots(txt, "ScoutCrawler/1.0")
    check("robots UA-specific group wins",
          r.allowed("http://h/private/secret.html"))
    check("robots UA-specific disallow",
          not r.allowed("http://h/tmp/x"))
    check("robots UA-specific no crawl-delay", r.crawl_delay() is None)
    # tie: Allow wins
    r2 = robotsmod.Robots("User-agent: *\nDisallow: /a\nAllow: /a\n",
                          "x")
    check("robots tie -> allow", r2.allowed("http://h/a"))
    # wildcard + end anchor
    r3 = robotsmod.Robots("User-agent: *\nDisallow: /*.pdf$\n", "x")
    check("robots wildcard", not r3.allowed("http://h/doc.pdf"))
    check("robots wildcard no-match", r3.allowed("http://h/doc.pdfx"))


def unit_htmltok():
    html = """<html><head><title>Hi &amp; Bye</title>
<script>var a = "<b>not a tag</b>";</script></head>
<body><p>Hello <a href="/p2">two</a> <a href="/p2">two dup</a>
<a href="http://other/x">ext</a></p></body></html>"""
    info = htmltok.extract(html, "http://h/")
    check("title entity", info["title"] == "Hi & Bye", repr(info["title"]))
    check("links resolved+deduped",
          info["links"] == ["http://h/p2", "http://other/x"], info["links"])
    check("script text excluded", "not a tag" not in info["text"],
          repr(info["text"][:60]))
    check("visible text kept", "Hello" in info["text"])


def unit_frontier():
    f = Frontier(delay=10.0)
    check("frontier add new", f.add("HTTP://H/a?b=1&c=2"))
    check("frontier dedup canonical", not f.add("http://h/a?c=2&b=1"))
    check("frontier bad url rejected", not f.add("not a url"))
    f.add("http://h/b")
    u1, w1 = f.next(now=1000.0)
    check("frontier serves first", u1 == "http://h/a?b=1&c=2", u1)
    u2, w2 = f.next(now=1000.0)
    check("frontier politeness blocks",
          u2 is None and w2 > 0, (u2, w2))
    u3, w3 = f.next(now=1011.0)
    check("frontier serves after delay", u3 == "http://h/b", (u3, w3))


SITE = {
    "robots.txt": "User-agent: *\nDisallow: /private/\nCrawl-delay: 1\n",
    "index.html": ('<html><head><title>Home</title></head><body>'
                   '<a href="/page2.html">p2</a>'
                   '<a href="/page2.html">p2 dup</a>'
                   '<a href="/private/secret.html">secret</a>'
                   '</body></html>'),
    "page2.html": ('<html><head><title>Page Two</title></head><body>'
                   '<a href="/page3.html">p3</a><a href="/">home</a>'
                   '</body></html>'),
    "page3.html": ('<html><head><title>Page Three</title></head><body>end'
                   '</body></html>'),
    "private/secret.html": ('<html><head><title>Secret</title></head><body>shh'
                            '</body></html>'),
}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def integration():
    tmp = tempfile.mkdtemp(prefix="crawltest")
    os.makedirs(os.path.join(tmp, "private"))
    for name, body in SITE.items():
        with open(os.path.join(tmp, name), "w") as fh:
            fh.write(body)
    port = free_port()
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(port)],
                           cwd=tmp, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    try:
        base = "http://127.0.0.1:%d/" % port
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "robots.txt", timeout=2).read()
                break
            except Exception:
                time.sleep(0.1)
        res = crawl(base, max_pages=10, delay=0.1,
                    user_agent="ScoutCrawler/1.0", stay_host=True,
                    verbose=False)
        urls = sorted(p["url"] for p in res["pages"])
        check("crawled 3 pages", res["fetched"] == 3,
              "%d: %s" % (res["fetched"], urls))
        check("robots honored (secret skipped)",
              res["skipped_robots"] >= 1 and
              not any("secret" in u for u in urls),
              "skipped=%d urls=%s" % (res["skipped_robots"], urls))
        check("dedup (home once)", sum(u.rstrip("/") == base.rstrip("/")
                                        for u in urls) == 1, urls)
        titles = {p["url"]: p["title"] for p in res["pages"]}
        check("titles extracted",
              titles.get(base + "page2.html") == "Page Two", titles)
    finally:
        srv.terminate()
        srv.wait()


def main():
    unit_urlnorm()
    unit_robots()
    unit_htmltok()
    unit_frontier()
    integration()
    # CLI smoke
    p = subprocess.run([sys.executable, os.path.join(HERE, "crawl.py"),
                        "--help"], capture_output=True, text=True)
    check("cli --help", p.returncode == 0 and "usage" in p.stdout.lower())
    failed = [n for n, ok in checks if not ok]
    print("\n%d/%d checks passed" % (len(checks) - len(failed), len(checks)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
