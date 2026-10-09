"""A minimal Nostr relay (NIP-01 + NIP-20 OK messages), from scratch.

Speaks the relay protocol over the hand-rolled WebSocket in ws.py:
  C->R ["EVENT", event]            publish (id+signature verified first)
  C->R ["REQ", sub_id, filter...]  subscribe
  C->R ["CLOSE", sub_id]            unsubscribe
  R->C ["EVENT", sub_id, event]     matching stored/live events
  R->C ["EOSE", sub_id]            end of stored events
  R->C ["OK", event_id, bool, msg]  publish acknowledgement (NIP-20)
  R->C ["NOTICE", msg]             human-readable errors

Filter keys: ids, authors, kinds, since, until, limit, "#e", "#p".
Replaceable events (kinds 0, 3, 10000-19999, 30000-39999): newest
created_at per (author, kind[, d-tag]) wins, older ones are dropped.
"""

import json
import socket
import threading
import time

from ws import server_accept
from event import verify_event

REPLACEABLE = {0, 3}  # + 10000-19999 and 30000-39999 ranges


def is_replaceable(kind: int) -> bool:
    return kind in REPLACEABLE or 10000 <= kind < 20000 or 30000 <= kind < 40000


def d_tag(tags):
    for t in tags:
        if t and t[0] == "d" and len(t) > 1:
            return t[1]
    return ""


def filter_match(ev: dict, f: dict) -> bool:
    if "ids" in f and ev["id"] not in f["ids"]:
        return False
    if "authors" in f and ev["pubkey"] not in f["authors"]:
        return False
    if "kinds" in f and ev["kind"] not in f["kinds"]:
        return False
    if "since" in f and ev["created_at"] < f["since"]:
        return False
    if "until" in f and ev["created_at"] > f["until"]:
        return False
    for key, want in f.items():
        if key.startswith("#") and len(key) == 2:
            tag_vals = {t[1] for t in ev["tags"] if t and t[0] == key[1] and len(t) > 1}
            if not tag_vals.intersection(want):
                return False
    return True


class Relay:
    def __init__(self):
        self.events = {}          # id -> event
        self.lock = threading.Lock()
        self.subs = {}            # ws-conn -> {sub_id: [filters]}

    # -- storage ---------------------------------------------------------
    def _replace_key(self, ev):
        return (ev["pubkey"], ev["kind"], d_tag(ev["tags"]))

    def store(self, ev: dict) -> tuple:
        """Returns (accepted: bool, message: str)."""
        ok, reason = verify_event(ev)
        if not ok:
            return False, f"invalid: {reason}"
        with self.lock:
            if ev["id"] in self.events:
                return True, "duplicate"
            if is_replaceable(ev["kind"]):
                key = self._replace_key(ev)
                for eid, old in list(self.events.items()):
                    if self._replace_key(old) == key:
                        if old["created_at"] >= ev["created_at"]:
                            return True, "duplicate"
                        del self.events[eid]
            self.events[ev["id"]] = ev
        return True, ""

    def query(self, filters) -> list:
        out = []
        with self.lock:
            evs = list(self.events.values())
        for ev in evs:
            if any(filter_match(ev, f) for f in filters):
                out.append(ev)
        out.sort(key=lambda e: e["created_at"], reverse=True)
        limit = None
        for f in filters:
            if "limit" in f:
                limit = f["limit"] if limit is None else min(limit, f["limit"])
        return out[:limit] if limit else out

    # -- protocol --------------------------------------------------------
    def handle_conn(self, conn):
        subs = {}
        self.subs[conn] = subs
        try:
            conn.send_text(json.dumps(["NOTICE", "scout-relay: NIP-01 from scratch"]))
            while True:
                try:
                    raw = conn.recv_text()
                except ConnectionError:
                    break
                try:
                    msg = json.loads(raw)
                except Exception:
                    conn.send_text(json.dumps(["NOTICE", "invalid JSON"]))
                    continue
                if not isinstance(msg, list) or not msg:
                    conn.send_text(json.dumps(["NOTICE", "message must be a JSON array"]))
                    continue
                typ = msg[0]
                if typ == "EVENT":
                    ev = msg[1] if len(msg) > 1 else None
                    if not isinstance(ev, dict):
                        conn.send_text(json.dumps(["NOTICE", "EVENT needs an event object"]))
                        continue
                    ok, why = self.store(ev)
                    conn.send_text(json.dumps(["OK", ev.get("id", ""), ok, why]))
                    if ok:
                        self._broadcast(ev, exclude=conn)
                elif typ == "REQ":
                    if len(msg) < 3 or not isinstance(msg[1], str):
                        conn.send_text(json.dumps(["NOTICE", "REQ needs sub_id + filter"]))
                        continue
                    sub_id, filters = msg[1], msg[2:]
                    subs[sub_id] = filters
                    for ev in self.query(filters):
                        conn.send_text(json.dumps(["EVENT", sub_id, ev]))
                    conn.send_text(json.dumps(["EOSE", sub_id]))
                elif typ == "CLOSE":
                    if len(msg) > 1:
                        subs.pop(msg[1], None)
                else:
                    conn.send_text(json.dumps(["NOTICE", f"unknown type {typ}"]))
        finally:
            self.subs.pop(conn, None)
            conn.close()

    def _broadcast(self, ev, exclude=None):
        dead = []
        for conn, subs in list(self.subs.items()):
            if conn is exclude:
                continue
            try:
                for sub_id, filters in subs.items():
                    if any(filter_match(ev, f) for f in filters):
                        conn.send_text(json.dumps(["EVENT", sub_id, ev]))
            except OSError:
                dead.append(conn)
        for c in dead:
            self.subs.pop(c, None)

    def serve(self, host="127.0.0.1", port=7777):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(50)
        print(f"relay listening on {host}:{port}", flush=True)
        while True:
            c, _ = srv.accept()
            try:
                conn = server_accept(c)
            except Exception:
                c.close()
                continue
            threading.Thread(target=self.handle_conn, args=(conn,),
                             daemon=True).start()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777
    Relay().serve(port=port)
