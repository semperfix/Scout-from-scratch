#!/usr/bin/env python3
"""
demo.py -- fault-injection scenario for the from-scratch Raft cluster.

  1. boot 3 nodes, elect exactly one leader
  2. 20 committed writes, all nodes converge
  3. kill -9 the leader mid-stream -> new leader, zero acked writes lost
  4. restart the dead node -> it catches up
  5. network partition: minority leader can't commit, majority keeps going
  6. heal -> one leader, full convergence, leadership audit (<=1 leader/term)

Every CHECK is asserted. An acked write means committed on a majority.
"""
import json, os, shutil, signal, socket, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PORTS = {1: 5001, 2: 5002, 3: 5003}
PEERS = {1: "2:127.0.0.1:5002,3:127.0.0.1:5003",
         2: "1:127.0.0.1:5001,3:127.0.0.1:5003",
         3: "1:127.0.0.1:5001,2:127.0.0.1:5002"}
DATA = os.path.join(HERE, "data")
procs = {}

def send_msg(s, o):
    b = json.dumps(o).encode(); s.sendall(struct.pack(">I", len(b)) + b)

def recv_msg(s):
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c: raise ConnectionError("closed")
        h += c
    (n,) = struct.unpack(">I", h)
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise ConnectionError("closed")
        b += c
    return json.loads(b.decode())

def rpc(node_id, obj, timeout=9.0):
    s = socket.create_connection(("127.0.0.1", PORTS[node_id]), timeout=timeout)
    try:
        s.settimeout(timeout); send_msg(s, obj); return recv_msg(s)
    finally:
        s.close()

def check(n, name, cond, extra=""):
    print(f"  CHECK {n:2d} {'PASS' if cond else 'FAIL'}  {name} {extra}")
    if not cond:
        raise SystemExit(f"CHECK {n} FAILED: {name}")

def start_node(i):
    d = os.path.join(DATA, f"n{i}")
    os.makedirs(d, exist_ok=True)
    procs[i] = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "raft.py"),
         "--id", str(i), "--port", str(PORTS[i]),
         "--peers", PEERS[i], "--data", d],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def statuses():
    out = {}
    for i in PORTS:
        try: out[i] = rpc(i, {"type": "status"}, timeout=1.0)
        except OSError: out[i] = None
    return out

def wait_leader(exclude=(), old_term=0, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        sts = statuses()
        leaders = [i for i, s in sts.items()
                   if s and s["state"] == "leader" and i not in exclude
                   and s["term"] > old_term]
        if len(leaders) == 1:
            return leaders[0], sts[leaders[0]]["term"]
        time.sleep(0.15)
    raise SystemExit("no single leader emerged: " + str(statuses()))

def write_via_leader(key, value, timeout=9.0):
    """Write, following redirects until acked. Returns leader id used."""
    end = time.monotonic() + 25
    last_err = None
    while time.monotonic() < end:
        sts = statuses()
        cands = [i for i, s in sts.items() if s and s["state"] == "leader"]
        if not cands:
            time.sleep(0.2); continue
        for i in cands:
            try:
                r = rpc(i, {"type": "client_write",
                            "op": {"op": "set", "key": key, "value": value}},
                        timeout=timeout)
            except OSError as e:
                last_err = e; continue
            if r.get("ok") and r.get("committed"):
                return i
            last_err = r
        time.sleep(0.2)
    raise SystemExit(f"write {key} never acked (last: {last_err})")

def wait_converged(timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        sts = statuses()
        live = [s for s in sts.values() if s]
        if len(live) == 3 and len({s["machine_hash"] for s in live}) == 1:
            return live[0]["machine_hash"]
        time.sleep(0.2)
    raise SystemExit("nodes did not converge: " + str(statuses()))

def read_key(i, key):
    return rpc(i, {"type": "client_read", "key": key})["value"]

def main():
    shutil.rmtree(DATA, ignore_errors=True)
    print("== booting 3-node cluster ==")
    for i in (1, 2, 3): start_node(i)

    print("== phase 1: election ==")
    lid, term = wait_leader()
    sts = statuses()
    n_leaders = sum(1 for s in sts.values() if s and s["state"] == "leader")
    check(1, "exactly one leader elected", n_leaders == 1, f"(node {lid}, term {term})")

    print("== phase 2: 20 committed writes, all replicas converge ==")
    acked = {}
    for n in range(20):
        k, v = f"k{n}", f"v{n}"
        write_via_leader(k, v); acked[k] = v
    h = wait_converged()
    check(2, "all 20 writes acked (== committed on majority)", len(acked) == 20)
    check(3, "all 3 nodes converged to identical state", True, f"(hash {h})")

    print(f"== phase 3: kill -9 leader (node {lid}) mid-stream ==")
    import threading
    results, errors = {}, []
    def writer():
        for n in range(20, 40):
            k, v = f"k{n}", f"v{n}"
            try:
                write_via_leader(k, v); results[k] = v
            except SystemExit as e:
                errors.append(str(e)); return
    t = threading.Thread(target=writer); t.start()
    time.sleep(0.6)                      # let some writes land, then murder it
    procs[lid].send_signal(signal.SIGKILL); procs[lid].wait()
    del procs[lid]
    print(f"   node {lid} is dead. electing replacement...")
    lid2, term2 = wait_leader(exclude=(lid,), old_term=term)
    check(4, "new leader elected after kill -9", lid2 != lid,
          f"(node {lid2}, term {term2})")
    t.join()
    check(5, "write stream survived the murder (no errors)", not errors, str(errors[:1]))
    acked.update(results)
    missing = [k for k, v in acked.items() if read_key(lid2, k) != v]
    check(6, f"all {len(acked)} acked writes present on new leader", not missing,
          str(missing[:3]))

    print("== phase 4: restart dead node 1, it must catch up ==")
    start_node(lid)
    h = wait_converged()
    sts = statuses()
    check(7, "restarted node rejoined and converged", sts[lid]["machine_hash"] == h)
    check(8, "still exactly one leader", sum(1 for s in statuses().values()
                                            if s["state"] == "leader") == 1)

    print(f"== phase 5: partition old leader {lid2} away from majority ==")
    others = [i for i in PORTS if i != lid2]
    for o in others: rpc(o, {"type": "admin_drop", "peer": lid2})
    for o in others: rpc(lid2, {"type": "admin_drop", "peer": o})
    time.sleep(0.3)
    new_lid, new_term = wait_leader(exclude=(lid2,), old_term=term2, timeout=15)
    check(9, "majority side elected a new leader", new_lid in others,
          f"(node {new_lid}, term {new_term})")
    st = rpc(lid2, {"type": "status"})
    check(10, "partitioned minority leader still thinks it's leader (correct Raft)",
          st["state"] == "leader" and st["term"] == term2)
    # minority leader must NOT be able to commit
    try:
        r = rpc(lid2, {"type": "client_write",
                       "op": {"op": "set", "key": "evil", "value": "x"}}, timeout=8)
        minority_committed = bool(r.get("ok"))
    except OSError:
        minority_committed = False
    check(11, "minority-side write did NOT commit (no majority)", not minority_committed)
    # majority side keeps working
    write_via_leader("maj", "yes")
    acked["maj"] = "yes"
    check(12, "majority side committed during partition", read_key(new_lid, "maj") == "yes")

    print("== phase 6: heal partition, cluster reconverges ==")
    for i in PORTS: rpc(i, {"type": "admin_heal"})
    h = wait_converged(timeout=20)
    sts = statuses()
    check(13, "exactly one leader after heal",
          sum(1 for s in sts.values() if s["state"] == "leader") == 1)
    lid3 = next(i for i, s in sts.items() if s["state"] == "leader")
    missing = [k for k, v in acked.items() if read_key(lid3, k) != v]
    check(14, "no committed write lost across partition+heal", not missing)
    check(15, "uncommitted minority write correctly discarded",
          read_key(lid3, "evil") is None)

    print("== phase 7: leadership audit (<= 1 leader per term) ==")
    events = []
    for i in PORTS: events += rpc(i, {"type": "admin_events"})["events"]
    by_term = {}
    for _, term_, nid, _ in events: by_term.setdefault(term_, set()).add(nid)
    bad = {t: n for t, n in by_term.items() if len(n) > 1}
    check(16, "election safety: at most one leader per term", not bad, str(bad))
    terms = sorted(by_term)
    check(17, "terms advanced contiguously from 1 (no gaps/jumps)",
          terms == list(range(1, max(terms) + 1)), f"terms seen: {terms}")

    print("== bonus: replicated crew board ==")
    write_via_leader("job:oak-removal", "Bloomingdale, crew: Kyle+Abe, $1200")
    write_via_leader("job:stump-grind", "Guyton, crew: Kyle, $350")
    h = wait_converged()
    boards = [read_key(i, "job:oak-removal") for i in PORTS] + \
             [read_key(i, "job:stump-grind") for i in PORTS]
    for i in PORTS:
        s = rpc(i, {"type": "status"})
        print(f"   node {i}: leader={s['leader']} applied={s['applied']} "
              f"hash={s['machine_hash']}")
    check(18, "crew board reads identically from every node",
          boards[0] == boards[1] == boards[2] and boards[3] == boards[4] == boards[5],
          str(boards))

    print("\nALL CHECKS PASSED")
    for i in PORTS:
        try: rpc(i, {"type": "admin_shutdown"}, timeout=1)
        except OSError: pass
    for p in procs.values():
        p.wait(timeout=5)

if __name__ == "__main__":
    main()
