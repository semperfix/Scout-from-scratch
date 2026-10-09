#!/usr/bin/env python3
"""
fuzzer.py -- a coverage-guided fuzzer built from scratch (stdlib only).

Architecture (AFL's design, reimplemented):
  * Edge coverage via sys.monitoring BRANCH events (Python 3.12+).
    An "edge" is (filename, function, src_offset, dst_offset), hashed to 64 bits.
  * Fork-server-lite runner: each input runs in a forked child with a SIGALRM
    timeout. The child pickles back (status, new edge hashes, traceback info).
    Parent classifies: ok / expected-rejection / crash / hang.
  * Queue with AFL-style power schedule: entries that discovered new coverage
    get more energy; fast small inputs get a bonus.
  * Two mutation stages: deterministic (bitflip walk) then havoc
    (bit/byte flips, arithmetic, interesting values, chunk delete/clone,
    dictionary insert, splice crossover).
  * Crash triage: dedupe by (exception type, target-file traceback frames),
    then ddmin-lite minimization preserving the crash signature.

Usage: import Fuzzer, give it a target callable + seed corpus, call run().
"""

import os
import sys
import time
import pickle
import random
import signal
import select
import hashlib
import traceback
from collections import Counter

TOOL_ID = 5  # sys.monitoring tool id (valid range is 0-5); private to this process tree


# --------------------------------------------------------------------------
# child side: coverage tracking + target execution
# --------------------------------------------------------------------------

class _ChildCov:
    """Installed in the forked child only. Collects (edge, hit-bucket) hashes.

    Hit counts are bucketed by bit_length (1, 2-3, 4-7, ...) exactly like
    AFL: this turns loop-trip-count and recursion-depth changes into new
    coverage, giving the fuzzer a gradient where pure edge coverage is blind.
    """

    def __init__(self, allowed_prefixes):
        self.allowed = tuple(allowed_prefixes)
        self.counts = Counter()

    def _cb(self, code, src, dst):
        fn = code.co_filename
        # fast path: only track target files
        for p in self.allowed:
            if fn.startswith(p):
                key = (fn.rsplit("/", 1)[-1], code.co_name, src, dst)
                h = hashlib.blake2b(repr(key).encode(),
                                    digest_size=8).digest()
                self.counts[h] += 1
                return
        return

    def edge_hashes(self):
        out = []
        for h, c in self.counts.items():
            bucket = c.bit_length()  # 1->1, 2-3->2, 4-7->3, ...
            out.append(hashlib.blake2b(h + bytes([bucket]),
                                       digest_size=8).digest())
        return out

    def install(self):
        sys.monitoring.use_tool_id(TOOL_ID, "minifuzz")
        sys.monitoring.register_callback(
            TOOL_ID, sys.monitoring.events.BRANCH, self._cb)
        sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.BRANCH)

    def uninstall(self):
        sys.monitoring.set_events(TOOL_ID, 0)


def _child_main(target_fn, data, wfd, timeout, allowed_prefixes,
                expected_exc):
    """Runs in the forked child. Never returns (os._exit)."""
    os.close(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    # keep wfd open; close the read end if inherited (parent passes only wfd)
    cov = _ChildCov(allowed_prefixes)
    cov.install()
    # wall-clock watchdog; default SIGALRM disposition kills the process
    signal.alarm(timeout)

    status = "ok"
    tb_info = None
    t0 = time.perf_counter()
    try:
        target_fn(data)
    except expected_exc as e:
        status = "expected"
        tb_info = f"{type(e).__name__}: {e}"
    except BaseException as e:
        status = "crash"
        # keep only frames inside the allowed (target) files for dedupe
        frames = []
        tb = e.__traceback__
        while tb is not None:
            f = tb.tb_frame
            fn = f.f_code.co_filename
            if any(fn.startswith(p) for p in allowed_prefixes):
                frames.append((fn.rsplit("/", 1)[-1],
                               f.f_code.co_name, tb.tb_lineno))
            tb = tb.tb_next
        tb_info = (type(e).__name__, str(e)[:200], tuple(frames[-6:]))
    finally:
        us = int((time.perf_counter() - t0) * 1e6)
        cov.uninstall()
        signal.alarm(0)
    msg = (status, cov.edge_hashes(), tb_info, us)
    try:
        blob = pickle.dumps(msg, protocol=4)
        os.write(wfd, len(blob).to_bytes(4, "little"))
        os.write(wfd, blob)
    except OSError:
        pass
    finally:
        os.close(wfd)
        os._exit(0)


def run_one(target_fn, data, timeout, allowed_prefixes, expected_exc):
    """Parent side: fork, run, classify. Returns dict."""
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rfd)
        _child_main(target_fn, data, wfd, timeout, allowed_prefixes,
                    expected_exc)
        # unreachable
    os.close(wfd)
    result = {"status": "hang", "edges": [], "tb": None, "us": 0}
    try:
        ready, _, _ = select.select([rfd], [], [], timeout + 2)
        if ready:
            hdr = b""
            while len(hdr) < 4:
                chunk = os.read(rfd, 4 - len(hdr))
                if not chunk:
                    break
                hdr += chunk
            if len(hdr) == 4:
                n = int.from_bytes(hdr, "little")
                blob = b""
                while len(blob) < n:
                    chunk = os.read(rfd, n - len(blob))
                    if not chunk:
                        break
                    blob += chunk
                if len(blob) == n:
                    status, edges, tb_info, us = pickle.loads(blob)
                    result.update(status=status, edges=edges,
                                  tb=tb_info, us=us)
        else:
            # timeout with no data: kill the child
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        os.close(rfd)
        _, wstatus = os.waitpid(pid, 0)
        if result["status"] == "hang":
            result["wsig"] = wstatus
        elif os.WIFSIGNALED(wstatus):
            # died by signal (e.g. SIGALRM raced the pickle): treat as hang
            result["status"] = "hang"
            result["wsig"] = wstatus
    return result


# --------------------------------------------------------------------------
# mutation engine
# --------------------------------------------------------------------------

INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
INTERESTING_16 = [0, 1, 16, 127, 128, 255, 256, 512, 1000, 1024, 4096,
                  32767, 32768, 65535]
INTERESTING_32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647,
                  4294967295]


class Mutator:
    def __init__(self, rng, dictionary=()):
        self.rng = rng
        self.dictionary = list(dictionary)

    # -- primitives ------------------------------------------------------
    def _flip_bit(self, data):
        if not data:
            return data
        b = bytearray(data)
        i = self.rng.randrange(len(b) * 8)
        b[i // 8] ^= 1 << (i % 8)
        return bytes(b)

    def _flip_byte(self, data, n=1):
        if not data:
            return data
        b = bytearray(data)
        for _ in range(n):
            b[self.rng.randrange(len(b))] ^= 1 << self.rng.randrange(8)
        return bytes(b)

    def _set_byte(self, data):
        if not data:
            return data
        b = bytearray(data)
        b[self.rng.randrange(len(b))] = self.rng.randrange(256)
        return bytes(b)

    def _arith(self, data):
        """Add/subtract small delta to a random 1/2/4-byte LE/BE int."""
        if len(data) < 1:
            return data
        b = bytearray(data)
        width = self.rng.choice([1, 2, 4])
        if len(b) < width:
            return bytes(b)
        i = self.rng.randrange(len(b) - width + 1)
        endian = self.rng.choice(["little", "big"])
        delta = self.rng.choice([1, 2, 5, 16, 35, 100, 255])
        if self.rng.random() < 0.5:
            delta = -delta
        v = int.from_bytes(b[i:i + width], endian)
        v = (v + delta) % (1 << (8 * width))
        b[i:i + width] = v.to_bytes(width, endian)
        return bytes(b)

    def _interesting(self, data):
        if not data:
            return data
        b = bytearray(data)
        width = self.rng.choice([1, 2, 4])
        table = {1: INTERESTING_8, 2: INTERESTING_16, 4: INTERESTING_32}[width]
        if len(b) < width:
            return bytes(b)
        i = self.rng.randrange(len(b) - width + 1)
        endian = self.rng.choice(["little", "big"])
        v = self.rng.choice(table) % (1 << (8 * width))
        b[i:i + width] = v.to_bytes(width, endian)
        return bytes(b)

    def _del_chunk(self, data, max_frac=0.25):
        if len(data) < 2:
            return data
        n = self.rng.randrange(1, max(2, int(len(data) * max_frac)))
        i = self.rng.randrange(len(data) - n + 1)
        return data[:i] + data[i + n:]

    def _clone_chunk(self, data, max_len=64):
        if not data:
            return data
        n = self.rng.randrange(1, min(max_len, len(data)) + 1)
        i = self.rng.randrange(len(data) - n + 1)
        j = self.rng.randrange(len(data) + 1)
        chunk = data[i:i + n]
        return data[:j] + chunk + data[j:]

    def _dict_insert(self, data):
        if not self.dictionary:
            return data
        tok = self.rng.choice(self.dictionary)
        j = self.rng.randrange(len(data) + 1)
        return data[:j] + tok + data[j:]

    def _dict_overwrite(self, data):
        if not self.dictionary or not data:
            return data
        tok = self.rng.choice(self.dictionary)
        j = self.rng.randrange(len(data))
        return data[:j] + tok + data[j + len(tok):]

    # -- composed ----------------------------------------------------------
    def havoc(self, data, other=None, stack=4):
        """Stack several random mutations (AFL's havoc stage)."""
        out = data
        for _ in range(self.rng.randrange(1, stack + 1)):
            op = self.rng.randrange(12 if (other and self.dictionary)
                                    else 10)
            if op == 0:
                out = self._flip_bit(out)
            elif op == 1:
                out = self._flip_byte(out)
            elif op == 2:
                out = self._set_byte(out)
            elif op == 3:
                out = self._arith(out)
            elif op == 4:
                out = self._interesting(out)
            elif op == 5:
                out = self._del_chunk(out)
            elif op == 6:
                out = self._clone_chunk(out)
            elif op == 7:
                out = self._dict_insert(out)
            elif op == 8:
                out = self._dict_overwrite(out)
            elif op == 9 and other:
                out = self._splice(out, other)
            else:
                out = self._flip_byte(out, n=self.rng.randrange(1, 8))
            if len(out) > 65536:  # cap runaway growth
                out = out[:65536]
        return out

    def _splice(self, data, other):
        """Crossover: cut both at random points, join halves."""
        if not data or not other:
            return data
        i = self.rng.randrange(len(data))
        j = self.rng.randrange(len(other))
        return data[:i] + other[j:]

    def det_arith_walk(self, data):
        """Deterministic stage lite: +/-1 and +/-35 on 1/2/4-byte words
        (AFL's arith stage, sampled). Catches off-by-N boundary logic."""
        n = len(data)
        for i in range(n):
            for width in (1, 2, 4):
                if i + width > n:
                    continue
                for endian in ("little", "big"):
                    if width == 1 and endian == "big":
                        continue
                    for delta in (1, 35):
                        for sign in (1, -1):
                            b = bytearray(data)
                            v = int.from_bytes(b[i:i + width], endian)
                            v = (v + sign * delta) % (1 << (8 * width))
                            b[i:i + width] = v.to_bytes(width, endian)
                            yield bytes(b)

    def det_bitflip_walk(self, data):
        """Deterministic stage: yield every single-bit flip."""
        for i in range(len(data) * 8):
            b = bytearray(data)
            b[i // 8] ^= 1 << (i % 8)
            yield bytes(b)


# --------------------------------------------------------------------------
# queue, power schedule, main loop
# --------------------------------------------------------------------------

class QueueEntry:
    __slots__ = ("data", "n_fuzz", "n_new", "exec_us", "depth",
                 "favored", "det_done")

    def __init__(self, data, depth=0):
        self.data = data
        self.n_fuzz = 0      # times selected for fuzzing
        self.n_new = 0       # times it discovered new coverage
        self.exec_us = 0     # calibrated exec time
        self.depth = depth   # generation depth
        self.favored = True  # recently found new coverage
        self.det_done = False


class Fuzzer:
    def __init__(self, target_fn, seeds, allowed_prefixes,
                 expected_exc=(Exception,), dictionary=(),
                 timeout=5, seed=0xF027):
        self.target_fn = target_fn
        self.allowed = list(allowed_prefixes)
        self.expected_exc = tuple(expected_exc)
        self.timeout = timeout
        self.rng = random.Random(seed)
        self.mut = Mutator(self.rng, dictionary)
        self.queue = [QueueEntry(bytes(s)) for s in seeds]
        self.global_edges = set()
        self.crashes = {}   # sig -> dict(data, tb, count)
        self.hangs = []
        self.execs = 0
        self.t0 = None
        self._seen_inputs = set(bytes(s) for s in seeds)

    # -- single execution --------------------------------------------------
    def _exec(self, data):
        r = run_one(self.target_fn, data, self.timeout, self.allowed,
                    self.expected_exc)
        self.execs += 1
        return r

    def _note_coverage(self, entry, edges):
        new = [e for e in edges if e not in self.global_edges]
        if new:
            for e in new:
                self.global_edges.add(e)
            entry.n_new += 1
            entry.favored = True
            return True
        return False

    def _handle_result(self, data, r, depth):
        is_new_cov = self._note_coverage_input(data, r["edges"])
        if r["status"] == "crash":
            sig = self._sig(r["tb"])
            c = self.crashes.get(sig)
            if c is None:
                self.crashes[sig] = {"data": data, "tb": r["tb"],
                                     "count": 1}
            else:
                c["count"] += 1
                if len(data) < len(c["data"]):
                    c["data"] = data
        elif r["status"] == "hang":
            self.hangs.append(data)
        # NOTE: every executed input is already in _seen_inputs (added by the
        # caller before exec), so queue admission is keyed on new coverage
        # alone. (An earlier draft checked `data not in self._seen_inputs`
        # here, which silently disabled queue growth entirely.)
        if is_new_cov:
            e = QueueEntry(data, depth=depth + 1)
            e.exec_us = r["us"]
            self.queue.append(e)
        return is_new_cov

    def _note_coverage_input(self, data, edges):
        new = [e for e in edges if e not in self.global_edges]
        for e in new:
            self.global_edges.add(e)
        return bool(new)

    @staticmethod
    def _sig(tb):
        exc, msg, frames = tb
        return (exc, tuple(frames))

    # -- power schedule ------------------------------------------------------
    def _energy(self, e):
        base = 4
        if e.favored:
            base *= 4
        # fast inputs get more: AFL rewards low exec time
        if e.exec_us and e.exec_us < 2000:
            base *= 2
        # small inputs get a nudge
        if len(e.data) < 256:
            base *= 2
        # handicap: rarely-fuzzed entries get a boost (avoid starvation)
        if e.n_fuzz == 0:
            base *= 2
        return max(1, min(base, 128))

    def _pick(self):
        # weighted choice over favored first, then all
        favored = [e for e in self.queue if e.favored]
        pool = favored or self.queue
        weights = [self._energy(e) for e in pool]
        return self.rng.choices(pool, weights=weights, k=1)[0]

    # -- deterministic stage ---------------------------------------------------
    def _deterministic(self, entry):
        if entry.det_done or len(entry.data) > 4096:
            return 0
        found = 0

        def feed(gen, cap):
            nonlocal found
            n = 0
            for mutant in gen:
                if n >= cap or self._budget_exceeded():
                    break
                n += 1
                if mutant in self._seen_inputs:
                    continue
                self._seen_inputs.add(mutant)
                r = self._exec(mutant)
                if self._handle_result(mutant, r, entry.depth):
                    found += 1

        # bitflip walk (full for small inputs; budget-enforced, so a huge
        # walk can never starve the campaign), then the arithmetic walk
        # (small inputs only: the arith walk is ~14n mutants)
        def full_bitflip():
            for pos in range(len(entry.data) * 8):
                b = bytearray(entry.data)
                b[pos // 8] ^= 1 << (pos % 8)
                yield bytes(b)

        feed(full_bitflip(), 10**9)
        if len(entry.data) <= 1024:
            feed(self.mut.det_arith_walk(entry.data), 3000)
        entry.det_done = True
        return found

    # -- trimming ---------------------------------------------------------------
    def _trim(self, entry):
        """Greedy chunk removal preserving the entry's edge set."""
        r0 = self._exec(entry.data)
        keep = set(e for e in r0["edges"] if e in self.global_edges)
        data = entry.data
        size = max(1, len(data) // 2)
        while size >= 1 and len(data) > 1 and not self._budget_exceeded():
            i = 0
            changed = False
            while i < len(data):
                cand = data[:i] + data[i + size:]
                if cand and cand != data:
                    r = self._exec(cand)
                    cov = set(r["edges"])
                    if keep.issubset(cov) and r["status"] != "crash":
                        data = cand
                        changed = True
                        continue
                i += size
            if not changed:
                size //= 2
        if len(data) < len(entry.data):
            entry.data = data
        return len(data)

    # -- crash minimization (ddmin-lite) -----------------------------------------
    def minimize(self, data, sig):
        """Shrink a crashing input while it still crashes with same sig."""
        def still_crashes(d):
            if not d:
                return False
            r = self._exec(d)
            return (r["status"] == "crash" and
                    self._sig(r["tb"]) == sig)

        data = bytes(data)
        n = 2
        while len(data) > 1:
            chunk = max(1, len(data) // n)
            reduced = False
            i = 0
            while i < len(data):
                cand = data[:i] + data[i + chunk:]
                if cand != data and still_crashes(cand):
                    data = cand
                    reduced = True
                    n = max(2, n - 1)
                    i = 0
                else:
                    i += chunk
            if not reduced:
                if chunk == 1:
                    break
                n *= 2
        # single-byte removal pass
        i = 0
        while i < len(data):
            cand = data[:i] + data[i + 1:]
            if still_crashes(cand):
                data = cand
            else:
                i += 1
        return data

    # -- main loop ---------------------------------------------------------------
    def _budget_exceeded(self):
        return (self.execs >= getattr(self, "_max_execs", 10**18) or
                (self.t0 is not None and
                 time.time() - self.t0 >= getattr(self, "_max_secs", 10**18)))

    def run(self, max_execs=20000, max_secs=600, log_every=2000):
        self.t0 = time.time()
        self._max_execs = max_execs
        self._max_secs = max_secs
        # calibrate + trim seeds (trim keeps the seed's coverage, and makes
        # the deterministic stage affordable)
        for e in list(self.queue):
            r = self._exec(e.data)
            e.exec_us = r["us"]
            self._note_coverage_input(e.data, r["edges"])
            if len(e.data) > 512:
                self._trim(e)
            if r["status"] == "crash":
                sig = self._sig(r["tb"])
                self.crashes.setdefault(sig, {"data": e.data,
                                              "tb": r["tb"], "count": 1})
        while not self._budget_exceeded():
            entry = self._pick()
            # deterministic stage once per favored seed
            if entry.favored and not entry.det_done:
                self._deterministic(entry)
                entry.favored = False
            energy = self._energy(entry)
            other = self.rng.choice(self.queue).data
            for _ in range(energy):
                mutant = self.mut.havoc(entry.data,
                                        other if other != entry.data else None)
                if mutant in self._seen_inputs:
                    continue
                self._seen_inputs.add(mutant)
                r = self._exec(mutant)
                self._handle_result(mutant, r, entry.depth)
                if self._budget_exceeded():
                    break
            entry.n_fuzz += 1
            entry.favored = False
            if self.execs and self.execs % log_every < energy:
                self._log()
        self._log(final=True)
        return self

    def _log(self, final=False):
        dt = time.time() - self.t0
        eps = self.execs / dt if dt > 0 else 0
        tag = "done" if final else "stat"
        print(f"[{tag}] execs={self.execs} edges={len(self.global_edges)} "
              f"queue={len(self.queue)} crashes={len(self.crashes)} "
              f"hangs={len(self.hangs)} {eps:.0f} exec/s", flush=True)

    def report(self):
        lines = [f"execs={self.execs} edges={len(self.global_edges)} "
                 f"queue={len(self.queue)}",
                 f"unique crashes={len(self.crashes)} "
                 f"hangs={len(self.hangs)}"]
        for sig, c in self.crashes.items():
            exc, frames = sig
            lines.append(f"  CRASH {exc} x{c['count']} "
                         f"len={len(c['data'])}")
            for fn, name, ln in frames[-3:]:
                lines.append(f"    {fn}:{name}:{ln}")
        return "\n".join(lines)
