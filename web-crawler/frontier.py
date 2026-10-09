#!/usr/bin/env python3
"""frontier.py -- politeness-aware crawl frontier (stdlib only).

  * URLs are canonicalized (urlnorm) before anything else; the seen-set
    holds canonical forms, so http://h/a?b=1&c=2 and http://h/a?c=2&b=1
    are fetched once.
  * Per-host FIFO queues with a politeness delay: a host is only served
    when now - last_fetch[host] >= delay (max of the configured delay and
    the host's robots crawl-delay).
  * BFS ordering across hosts: next() round-robins over hosts that have a
    ready URL, so one slow host never starves the others.

next(now) -> (url, 0.0) when a URL is ready, or (None, wait_seconds) with
how long until the earliest host becomes ready (0.0 wait + None URL means
the frontier is empty).
"""
import time
from collections import deque
from urllib.parse import urlsplit

import urlnorm


class Frontier(object):
    def __init__(self, delay=1.0):
        self.delay = delay
        self.seen = set()
        self.queues = {}        # host -> deque([url])
        self.host_order = []    # round-robin order
        self.last_fetch = {}    # host -> timestamp of last fetch
        self.host_delay = {}    # host -> robots crawl-delay override
        self._cursor = 0

    def _host(self, url):
        return urlsplit(url).hostname or ""

    def add(self, url):
        """Canonicalize + dedupe + enqueue. Returns True if new."""
        try:
            canon = urlnorm.canonicalize(url)
        except ValueError:
            return False
        if canon in self.seen:
            return False
        self.seen.add(canon)
        host = self._host(canon)
        if host not in self.queues:
            self.queues[host] = deque()
            self.host_order.append(host)
        self.queues[host].append(canon)
        return True

    def set_host_delay(self, host, delay):
        if delay is not None:
            self.host_delay[host] = max(self.host_delay.get(host, 0), delay)

    def _ready_at(self, host, now):
        d = max(self.delay, self.host_delay.get(host, 0))
        return self.last_fetch.get(host, 0) + d <= now

    def pending(self):
        return sum(len(q) for q in self.queues.values())

    def next(self, now=None):
        now = time.time() if now is None else now
        if not self.queues:
            return None, 0.0
        n = len(self.host_order)
        earliest = None
        for k in range(n):
            host = self.host_order[(self._cursor + k) % n]
            q = self.queues[host]
            if not q:
                continue
            if self._ready_at(host, now):
                self._cursor = (self._cursor + k + 1) % n
                self.last_fetch[host] = now
                return q.popleft(), 0.0
            d = max(self.delay, self.host_delay.get(host, 0))
            ready = self.last_fetch.get(host, 0) + d
            if earliest is None or ready < earliest:
                earliest = ready
        if earliest is None:
            return None, 0.0
        return None, max(0.0, earliest - now)
