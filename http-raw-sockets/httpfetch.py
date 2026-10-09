#!/usr/bin/env python3
"""httpfetch: entry-point CLI for the http-raw-sockets skill.

Fetch a URL with the hand-built HTTP/1.1 client and print status, headers,
and body info. Examples:

  python3 httpfetch.py http://127.0.0.1:18333/chunked
  python3 httpfetch.py http://127.0.0.1:18333/redirect   # follows to /chunked
  python3 httpfetch.py https://example.com/ --head
  python3 httpfetch.py http://example.com/ --proxy http://127.0.0.1:8080
  python3 httpfetch.py http://127.0.0.1:18333/length --output body.bin
"""
import argparse
import hashlib
import sys

from http_raw import Session, HttpError


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="httpfetch",
        description="Fetch a URL with a from-scratch HTTP/1.1 client on raw "
                    "sockets (chunked, redirects, keep-alive, proxy).")
    ap.add_argument("url", help="URL to fetch")
    ap.add_argument("--head", action="store_true", help="HEAD instead of GET")
    ap.add_argument("--proxy", default=None, help="http:// forward proxy")
    ap.add_argument("--max-redirects", type=int, default=5)
    ap.add_argument("--no-keepalive", action="store_true",
                    help="close the connection after the request")
    ap.add_argument("--output", "-o", default=None, help="save body to file")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args(argv)

    s = Session(proxy=args.proxy, timeout=args.timeout,
                max_redirects=args.max_redirects)
    try:
        try:
            resp = s.head(args.url) if args.head else s.get(args.url)
        except HttpError as e:
            sys.exit(f"error: {e}")
        except OSError as e:
            sys.exit(f"connection error: {e}")
    finally:
        if args.no_keepalive:
            s.close()

    print(f"URL: {resp.url}")
    if resp.redirects:
        print(f"redirects ({len(resp.redirects)}):")
        for u in resp.redirects:
            print(f"  -> {u}")
    print(f"status: {resp.status} {resp.reason}")
    print("headers:")
    for k, vals in resp.headers.items():
        for v in vals:
            print(f"  {k}: {v}")
    if resp.trailers:
        print("trailers:")
        for k, vals in resp.trailers.items():
            for v in vals:
                print(f"  {k}: {v}")
    print(f"body: {len(resp.body)} bytes  sha256={hashlib.sha256(resp.body).hexdigest()}")
    preview = resp.body[:200]
    print(f"preview: {preview!r}")
    if args.output:
        with open(args.output, "wb") as f:
            f.write(resp.body)
        print(f"saved to {args.output}")
    return 0 if resp.status < 400 else 1


if __name__ == "__main__":
    sys.exit(main())
