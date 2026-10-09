# Raft Consensus — Running 3-Node Cluster from Scratch

A real, running Raft cluster (Ongaro & Ousterhout) in ~470 lines of stdlib-only
Python: 3 OS processes, JSON-over-TCP RPCs with a 4-byte length prefix, leader
election with randomized timeouts, log replication, kill -9 failover, and
simulated network partitions. The replicated state machine is a KV store, and
client writes block until the entry is committed — so **ack == durable on a
majority**, provably, not hopefully.

`demo.py` runs the full fault-injection scenario end-to-end: election, 20
committed writes, kill -9 the leader mid-write-stream, replacement election,
node restart + catch-up, network partition (minority can't commit, majority
keeps going), heal + reconvergence, and a leadership audit (≤1 leader per
term). **18/18 checks pass** (~19 s wall clock).

## Dependencies

Stdlib only. No pip packages.

## How to run

Start three nodes (separate terminals or background processes):

```
python3 raft.py --id 1 --port 5001 --data data/n1 --peers "2:127.0.0.1:5002,3:127.0.0.1:5003"
python3 raft.py --id 2 --port 5002 --data data/n2 --peers "1:127.0.0.1:5001,3:127.0.0.1:5003"
python3 raft.py --id 3 --port 5003 --data data/n3 --peers "1:127.0.0.1:5001,2:127.0.0.1:5002"
```

Run the fault-injection demo (do **not** run this with live nodes on the same
ports — it spawns and kills its own):

```
python3 demo.py     # 18/18 checks: election, kill -9 failover, partition, heal, audit
```

## Usage example

Talk to the cluster over TCP (JSON + 4-byte BE length prefix):

```python
import json, socket, struct

def rpc(port, obj):
    s = socket.create_connection(("127.0.0.1", port))
    b = json.dumps(obj).encode()
    s.sendall(struct.pack(">I", len(b)) + b)
    n = struct.unpack(">I", s.recv(4))[0]
    return json.loads(s.recv(n))

# writes block until committed on a majority; ok:false on the minority side
# of a partition, with a leader hint to retry elsewhere
print(rpc(5001, {"op": "set", "key": "crew", "value": "kyle+tony"}))
print(rpc(5001, {"op": "get", "key": "crew"}))
```

Reads are served from the node's applied state — **stale reads are the honest
default** (no read-index/lease; linearizable reads are a deliberate gap, see
`raft.py` header).

## Key learnings

- **Randomized election timeouts are the entire liveness story.** Deterministic
  timeouts split votes, time out together, split again — forever. The jitter
  (450–900 ms here) breaks the symmetry; liveness in Raft is a coin flip that
  eventually lands.
- **The election restriction is the cleverest three lines in the paper.** A
  voter grants its vote only if the candidate's log is at least as up-to-date
  (last term, then last index) — buying *Leader Completeness* without shipping
  a single log entry during elections.
- **A partitioned leader that still thinks it's leader is correct behavior.**
  Safety doesn't come from the old leader *knowing* it's deposed — it comes
  from it being *unable to commit* without a majority. The demo asserts this:
  minority-side write → `ok:false`, and the entry is truncated on heal.
- **Persist before the RPC reply, not after.** `term`, `voted_for`, and the log
  hit disk (fsync + atomic rename) before any vote is granted — otherwise a
  kill -9 between reply and flush lets a restarted node double-vote or forget
  an acked write.

## Files

- `raft.py` — the node: election, replication, persistence, RPC server
- `demo.py` — fault-injection scenario + all 18 checks
- `LEARNINGS.md` — the full expedition writeup
