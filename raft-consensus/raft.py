#!/usr/bin/env python3
"""
raft.py -- a from-scratch Raft consensus implementation (In Search of an
Understandable Consensus Algorithm, Ongaro & Ousterhout).

Stdlib only. One Node = one OS process. RPCs are synchronous JSON-over-TCP
with a 4-byte length prefix. Client writes BLOCK until the entry is committed
(so an ack means "durable on a majority"), or fail with a leader hint.

Persistent state (survives kill -9): current_term, voted_for, log,
commit_index, last_applied, state machine, leadership events.

Deliberately NOT implemented (said out loud, not silently missing):
  - Pre-vote (leaders can be briefly disrupted by a rejoining node; harmless here)
  - Log compaction / snapshots (logs are tiny in the demo)
  - Linearizable reads (reads may be stale; documented in LEARNINGS.md)
  - Membership changes (fixed 3-node cluster)

Usage:
  python3 raft.py --id 1 --port 5001 \
      --peers "2:127.0.0.1:5002,3:127.0.0.1:5003" --data /tmp/raft-n1
"""
import argparse, json, os, random, socket, struct, threading, time

# ---------------------------------------------------------------- framing

def send_msg(sock, obj):
    body = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)

def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("closed")
        hdr += chunk
    (n,) = struct.unpack(">I", hdr)
    body = b""
    while len(body) < n:
        chunk = sock.recv(n - len(body))
        if not chunk:
            raise ConnectionError("closed")
        body += chunk
    return json.loads(body.decode())

def rpc(host, port, obj, timeout=2.0):
    """One-shot RPC: connect, send, read reply, close."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        send_msg(s, obj)
        return recv_msg(s)
    finally:
        s.close()

# ---------------------------------------------------------------- node

class Node:
    def __init__(self, node_id, peers, port, data_dir,
                 election_min=0.45, election_max=0.90, heartbeat=0.12):
        self.id = node_id
        self.peers = peers            # {id: (host, port)}
        self.port = port
        self.data_dir = data_dir
        self.e_min, self.e_max, self.hb = election_min, election_max, heartbeat
        self.mu = threading.RLock()
        self.cv = threading.Condition(self.mu)
        self.running = True

        # persistent state
        self.term = 0
        self.voted_for = None
        self.log = []                 # [{term, index, op}]
        self.commit = 0
        self.applied = 0
        self.machine = {}             # the replicated state machine: a KV store
        self.events = []              # ('leader', term, id, wallclock)
        self._load()

        # volatile state
        self.state = "follower"
        self.leader_id = None
        self.deadline = self._new_deadline()
        self.next_hb = 0.0
        self.next_index = {}          # leader only
        self.match_index = {}         # leader only
        self.drops = set()            # test hook: peer ids to blackhole (partition sim)

    # ------------------------------------------------------------ persistence
    def _path(self):
        return os.path.join(self.data_dir, "state.json")

    def _save(self):
        os.makedirs(self.data_dir, exist_ok=True)
        tmp = self._path() + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"term": self.term, "voted_for": self.voted_for,
                       "log": self.log, "commit": self.commit,
                       "applied": self.applied, "machine": self.machine,
                       "events": self.events}, f)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, self._path())

    def _load(self):
        try:
            with open(self._path()) as f:
                d = json.load(f)
            self.term = d["term"]; self.voted_for = d["voted_for"]
            self.log = d["log"]; self.commit = d["commit"]
            self.applied = d["applied"]; self.machine = d["machine"]
            self.events = d.get("events", [])
        except FileNotFoundError:
            pass

    # ------------------------------------------------------------ helpers
    def _new_deadline(self):
        return time.monotonic() + random.uniform(self.e_min, self.e_max)

    def _last(self):
        if self.log:
            e = self.log[-1]
            return e["term"], e["index"]
        return 0, 0

    def _step_down(self, term):
        """Become follower on discovering a higher term. Caller holds lock."""
        if term > self.term:
            self.term = term
            self.voted_for = None
        self.state = "follower"
        self.leader_id = None
        self.deadline = self._new_deadline()
        self._save()
        self.cv.notify_all()

    def _become_leader(self):
        self.state = "leader"
        self.leader_id = self.id
        last_idx = self.log[-1]["index"] if self.log else 0
        for p in self.peers:
            self.next_index[p] = last_idx + 1
            self.match_index[p] = 0
        self.next_hb = 0.0  # send heartbeats immediately
        self.events.append(("leader", self.term, self.id, time.time()))
        self._save()

    def _apply_committed(self):
        while self.applied < self.commit:
            self.applied += 1
            op = self.log[self.applied - 1]["op"]
            self._apply_op(op)
        self._save()
        self.cv.notify_all()

    def _apply_op(self, op):
        k = op["op"]
        if k == "set":
            self.machine[op["key"]] = op["value"]
        elif k == "incr":
            self.machine[op["key"]] = self.machine.get(op["key"], 0) + op["delta"]
        elif k == "del":
            self.machine.pop(op["key"], None)

    def _machine_hash(self):
        import hashlib
        return hashlib.sha256(
            json.dumps(self.machine, sort_keys=True).encode()).hexdigest()[:16]

    # ------------------------------------------------------------ RPC handlers
    def handle(self, req):
        t = req.get("type")
        if t == "request_vote":
            return self._on_request_vote(req)
        if t == "append_entries":
            return self._on_append_entries(req)
        if t == "client_write":
            return self._on_client_write(req)
        if t == "client_read":
            return self._on_client_read(req)
        if t == "status":
            return self._on_status()
        if t == "admin_drop":
            with self.mu:
                self.drops.add(req["peer"]); return {"ok": True, "drops": sorted(self.drops)}
        if t == "admin_heal":
            with self.mu:
                self.drops.clear(); return {"ok": True}
        if t == "admin_events":
            with self.mu:
                return {"events": self.events}
        if t == "admin_shutdown":
            self.running = False
            return {"ok": True}
        return {"error": "unknown rpc"}

    def _on_request_vote(self, req):
        with self.mu:
            cand, cterm = req["candidate"], req["term"]
            granted = False
            if cterm > self.term:
                self._step_down(cterm)
            if cterm == self.term:
                last_term, last_idx = self._last()
                up_to_date = (req["last_term"] > last_term or
                              (req["last_term"] == last_term and req["last_idx"] >= last_idx))
                if (self.voted_for in (None, cand)) and up_to_date:
                    self.voted_for = cand
                    granted = True
                    self.deadline = self._new_deadline()
                    self._save()
            return {"term": self.term, "granted": granted}

    def _on_append_entries(self, req):
        with self.mu:
            term, leader = req["term"], req["leader_id"]
            if term < self.term:
                return {"term": self.term, "success": False}
            if term > self.term or self.state != "follower":
                self._step_down(term)
            self.leader_id = leader
            self.deadline = self._new_deadline()

            prev_idx, prev_term = req["prev_idx"], req["prev_term"]
            if prev_idx > 0:
                if len(self.log) < prev_idx or self.log[prev_idx - 1]["term"] != prev_term:
                    return {"term": self.term, "success": False,
                            "conflict_len": len(self.log)}
            # append any new entries, truncating conflicts
            entries = req["entries"]
            i = 0
            for e in entries:
                idx = e["index"]
                if idx <= len(self.log):
                    if self.log[idx - 1]["term"] != e["term"]:
                        self.log = self.log[:idx - 1]
                        self.log.extend(entries[i:])
                        break
                else:
                    self.log.extend(entries[i:])
                    break
                i += 1
            if entries:
                self._save()
            if req["leader_commit"] > self.commit:
                self.commit = min(req["leader_commit"], len(self.log))
                self._apply_committed()
            return {"term": self.term, "success": True}

    def _on_client_write(self, req):
        with self.mu:
            if self.state != "leader":
                return {"ok": False, "leader": self.leader_id}
            index = (self.log[-1]["index"] if self.log else 0) + 1
            self.log.append({"term": self.term, "index": index, "op": req["op"]})
            self._save()
            my_term = self.term
            # block until committed (or step down / timeout): ack == durable
            end = time.monotonic() + 5.0
            while self.applied < index and self.state == "leader" \
                    and self.term == my_term and time.monotonic() < end:
                self.cv.wait(timeout=0.05)
            if self.applied >= index:
                return {"ok": True, "committed": True, "index": index,
                        "leader": self.id}
            return {"ok": False, "leader": self.leader_id,
                    "reason": "not-committed (stepped down or no majority)"}

    def _on_client_read(self, req):
        with self.mu:
            # NOTE: deliberately stale-ok. Linearizable reads need a
            # leader lease / read-index; not implemented (see LEARNINGS.md).
            return {"ok": True, "value": self.machine.get(req["key"]),
                    "leader": self.leader_id, "state": self.state,
                    "applied": self.applied}

    def _on_status(self):
        with self.mu:
            return {"id": self.id, "state": self.state, "term": self.term,
                    "leader": self.leader_id, "log_len": len(self.log),
                    "commit": self.commit, "applied": self.applied,
                    "machine_hash": self._machine_hash(),
                    "machine_size": len(self.machine)}

    # ------------------------------------------------------------ candidate logic
    def _start_election(self):
        with self.mu:
            self.term += 1
            self.voted_for = self.id
            self.state = "candidate"
            self.leader_id = None
            self.deadline = self._new_deadline()
            term = self.term
            last_term, last_idx = self._last()
            self._save()
            votes = 1

        def ask(peer):
            nonlocal votes
            host, port = self.peers[peer]
            try:
                r = rpc(host, port, {"type": "request_vote", "src": self.id,
                                    "term": term, "candidate": self.id,
                                    "last_term": last_term, "last_idx": last_idx},
                        timeout=0.5)
            except OSError:
                return
            with self.mu:
                if r.get("term", 0) > self.term:
                    self._step_down(r["term"])
                    return
                if (self.state == "candidate" and self.term == term
                        and r.get("granted")):
                    votes += 1
                    if votes > (len(self.peers) + 1) // 2:
                        self._become_leader()

        for p in self.peers:
            threading.Thread(target=ask, args=(p,), daemon=True).start()

    # ------------------------------------------------------------ leader logic
    def _replicate(self):
        with self.mu:
            if self.state != "leader":
                return
            term, commit = self.term, self.commit
            work = {}
            for p, (host, port) in self.peers.items():
                if p in self.drops:
                    continue
                ni = self.next_index[p]
                prev_idx = ni - 1
                prev_term = self.log[prev_idx - 1]["term"] if prev_idx > 0 else 0
                work[p] = (host, port, prev_idx, prev_term,
                           [e for e in self.log if e["index"] >= ni])

        def send(p, host, port, prev_idx, prev_term, entries):
            try:
                r = rpc(host, port, {"type": "append_entries", "src": self.id,
                                    "term": term, "leader_id": self.id,
                                    "prev_idx": prev_idx, "prev_term": prev_term,
                                    "entries": entries, "leader_commit": commit},
                        timeout=0.5)
            except OSError:
                return
            with self.mu:
                if r.get("term", 0) > self.term:
                    self._step_down(r["term"])
                    return
                if self.state != "leader" or self.term != term:
                    return
                if r.get("success"):
                    new_match = prev_idx + len(entries)
                    if new_match > self.match_index.get(p, 0):
                        self.match_index[p] = new_match
                    self.next_index[p] = new_match + 1
                    self._advance_commit()
                else:
                    self.next_index[p] = max(1, self.next_index[p] - 1)

        for p, args in work.items():
            threading.Thread(target=send, args=(p, *args), daemon=True).start()

    def _advance_commit(self):
        # Only entries from THIS term can advance the commit index directly
        # (committing an old-term entry by counting would be unsafe).
        n_nodes = len(self.peers) + 1
        for n in range(len(self.log), self.commit, -1):
            if self.log[n - 1]["term"] != self.term:
                continue
            replicas = 1 + sum(1 for m in self.match_index.values() if m >= n)
            if replicas > n_nodes // 2:
                self.commit = n
                self._apply_committed()
                break

    # ------------------------------------------------------------ main loops
    def _serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(64)
        srv.settimeout(0.2)
        while self.running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle_conn, args=(conn,),
                             daemon=True).start()
        srv.close()

    def _handle_conn(self, conn):
        try:
            conn.settimeout(2.0)
            req = recv_msg(conn)
            if req.get("src") in self.drops:
                return  # partitioned: blackhole
            send_msg(conn, self.handle(req))
        except (OSError, ValueError, KeyError):
            pass
        finally:
            conn.close()

    def _tick(self):
        while self.running:
            with self.mu:
                now = time.monotonic()
                if self.state != "leader" and now >= self.deadline:
                    do_elect = True
                else:
                    do_elect = False
                do_hb = self.state == "leader" and now >= self.next_hb
                if do_hb:
                    self.next_hb = now + self.hb
            if do_elect:
                self._start_election()
            if do_hb:
                self._replicate()
            time.sleep(0.01)

    def run(self):
        threading.Thread(target=self._serve, daemon=True).start()
        self._tick()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", type=int, required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--peers", required=True,
                    help='"2:127.0.0.1:5002,3:127.0.0.1:5003"')
    ap.add_argument("--data", required=True)
    a = ap.parse_args()
    peers = {}
    for part in a.peers.split(","):
        pid, host, port = part.split(":")
        peers[int(pid)] = (host, int(port))
    Node(a.id, peers, a.port, a.data).run()


if __name__ == "__main__":
    main()
