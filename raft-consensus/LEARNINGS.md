# Raft Consensus From Scratch — Learnings

## What it is
A real, running Raft cluster (Ongaro & Ousterhout) in ~470 lines of stdlib-only
Python: 3 OS processes, JSON-over-TCP RPCs, leader election, log replication,
kill -9 failover, and simulated network partitions. The replicated state machine
is a KV store; client writes block until committed, so **ack == durable on a
majority**.

## Earned insights (the kind you only get by building it)

1. **Randomized election timeouts are the entire liveness story.** With
   deterministic timeouts, two candidates split the vote, time out together,
   split it again — forever. The jitter (450–900 ms here) isn't a tuning
   detail, it's what breaks the symmetry. Liveness in Raft is a coin flip
   that eventually lands.
2. **The election restriction is the cleverest three lines in the paper.**
   A voter grants its vote only if the candidate's log is at least as
   up-to-date (compare last term, then last index). That's what buys *Leader
   Completeness* — every committed entry ends up on every future leader —
   without shipping a single log entry during elections. Voters enforce it
   with metadata, not data.
3. **The commit rule has a trap (Figure 8).** A leader may only advance its
   commit index by counting replicas for entries from its *current* term.
   Counting an old-term entry to a majority and calling it committed can
   elect a leader that doesn't have it — safety gone. My `_advance_commit`
   skips non-current-term entries outright.
4. **"Ack" must mean committed-on-majority or your guarantees are fiction.**
   A write that merely reached the leader means nothing if the leader dies
   a millisecond later. Blocking client writes until the entry is applied
   makes "zero acked writes lost" a provable property instead of a hope.
5. **A partitioned leader that still thinks it's leader is correct behavior,**
   not a bug. Safety doesn't come from the old leader *knowing* it's deposed —
   it comes from the old leader being *unable to commit* without a majority.
   The demo asserts this: minority-side write → `ok:false`; the entry is later
   truncated and discarded on heal. Knowledge is unnecessary; arithmetic suffices.
6. **Log matching is one check that does all the work.** `prevLogIndex /
   prevLogTerm` either matches or it doesn't; on mismatch the leader decrements
   `nextIndex` and retries. Slow (O(n) worst case), obviously correct, and for
   small logs the simplicity wins over conflict-term fast-backup optimization.
7. **Persistence must happen before the RPC reply, not after.** `term`,
   `voted_for`, and the log hit disk (fsync + atomic rename) before any vote
   is granted or any entry acknowledged — otherwise a kill -9 between reply
   and flush lets a restarted node double-vote or forget an acked write.
8. **Stale reads are the honest default.** I serve reads from any node's
   applied state without a lease or read-index. That's a documented gap, not
   an oversight — linearizable reads need the leader to prove it's still
   leader (heartbeat round-trip), and pretending otherwise is how you get
   phantom reads.
9. **Condition variables, not sleep-polling, for commit waits.** The blocked
   client write waits on a CV, which *releases the node's lock* while waiting —
   that's what lets replication threads make progress and eventually notify
   it. Holding the lock across the wait would stall heartbeats and the commit
   it's waiting for. Concurrency correctness lived in that one line.
10. **One RLock per node, never held across network I/O.** Every RPC handler
    takes only its own node's lock; all socket work happens outside it. No
    lock ordering to get wrong because there's only ever one lock in play.

## Validation
`demo.py` runs the full fault-injection scenario end-to-end: election,
20 committed writes, kill -9 of the leader mid-write-stream, replacement
election, node restart + catch-up, network partition (minority can't commit,
majority keeps going), heal + reconvergence, and a leadership audit
(≤1 leader per term, contiguous terms). **18/18 checks pass, 3 consecutive
runs**, different winners each election (jitter doing its job). Full scenario
runs in ~19 s wall clock.

## Deliberately not built
Pre-vote, log compaction/snapshots, membership changes, linearizable reads.
Each is named in `raft.py`'s header so the gaps are visible, not hidden.

## Files
- `raft.py` — the node (run 3 of these)
- `demo.py` — fault-injection scenario + all 18 checks
- `data/` — per-node persistent state (regenerated per run)

## Why it matters
This is the algorithm underneath etcd, Consul, CockroachDB, and every
"it just stays consistent" system. Now "quorum", "leader election", and
"split-brain" aren't vocabulary — they're mechanisms I've watched survive
a `kill -9` and a partition. The demo's crew board (replicated job list)
is the shape of anything Kyle would ever want to survive a dead machine.
