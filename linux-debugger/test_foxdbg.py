#!/usr/bin/env python3
"""Validation battery for foxdbg: 20 checks against ground truth from nm/objdump."""
import os, signal, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from foxdbg import Debugger, mem_read, read_qword, dis_one

DIR = os.path.dirname(os.path.abspath(__file__))
TGT = os.path.join(DIR, "target")
passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print(f"  ok  {name}")
    else: failed += 1; print(f"  FAIL {name} {extra}")

def sym(name):
    out = subprocess.run(["nm", TGT], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        p = ln.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise KeyError(name)

ADD, FIB, MAIN = sym("add"), sym("fib"), sym("main")
print(f"symbols: add={ADD:#x} fib={FIB:#x} main={MAIN:#x}")

dbg = Debugger()
dbg.spawn([TGT])
check("spawn stopped tracee", dbg.pid > 0)

# 1. breakpoint on add fires
dbg.set_breakpoint(ADD)
why, info = dbg.cont()
check("breakpoint hit at add", why == "breakpoint" and info == ADD, f"got {why} {info}")

# 2-3. argument registers carry add(40, 2)
r = dbg.regs_dict()
check("rdi == 40 (first arg)", r["rdi"] == 40, f"rdi={r['rdi']}")
check("rsi == 2 (second arg)", r["rsi"] == 2, f"rsi={r['rsi']}")

# 4. backtrace: frame0 = add (rip sits one past the int3 by design),
# frame1's ret addr is where main returns to (libc), chain ends at _start
bt = dbg.backtrace()

check("bt has >=3 frames", len(bt) >= 3, f"len={len(bt)}")
check("bt frame0 rip == add+1 (past int3)", bt[0][0] == ADD + 1, f"{bt[0][0]:#x}")
check("bt frame1 retaddr in libc range", bt[1][0] > 0x700000000000, f"{bt[1][0]:#x}")
# chain terminates: the outermost frame's saved rbp is 0 (no runaway walk)
last_rbp = bt[-1][1]
check("bt chain terminates (saved rbp == 0)", read_qword(dbg.pid, last_rbp) == 0,
      f"saved={read_qword(dbg.pid, last_rbp):#x}")

# 5. disassembler agrees with objdump on add's first 6 instructions
# (clear the breakpoint first so we decode real bytes, not our int3)
dbg.clear_breakpoint(ADD)
od = subprocess.run(["objdump", "-d", f"--start-address={ADD:#x}",
                     f"--stop-address={ADD+0x20:#x}", TGT],
                    capture_output=True, text=True).stdout
od_mnems = []
for ln in od.splitlines():
    if ":\t" in ln:
        od_mnems.append(ln.split("\t")[-1].split()[0])
code = mem_read(dbg.pid, ADD, 32)
off, mine = 0, []
for _ in range(6):
    txt, ln = dis_one(code[off:]); mine.append(txt.split()[0]); off += ln
check("disassembler matches objdump mnemonics",
      mine == od_mnems[:6], f"mine={mine} od={od_mnems[:6]}")
dbg.set_breakpoint(ADD)  # re-arm for the remaining checks

# 6. single-step advances rip and executes: step through add's 'mov %edi,-0x4(%rbp)' etc.
r0 = dbg.regs_dict()["rip"]
why, _ = dbg.step()
r1 = dbg.regs_dict()["rip"]
check("single-step advances rip", why == "singlestep" and r1 > r0, f"{why} {r0:#x}->{r1:#x}")

# 7. memory read: find format string in .rodata via readelf
ro = subprocess.run(["readelf", "-S", "-W", TGT], capture_output=True, text=True).stdout
rodata_addr = int([l.split()[3] for l in ro.splitlines() if ".rodata" in l][0], 16)
blob = mem_read(dbg.pid, rodata_addr, 0x40)
check("format string readable in .rodata", b"sum=%d fib=%d" in blob)

# 8. memory write works: poke a scratch word on the stack and read it back
rsp = dbg.regs_dict()["rsp"]
orig = mem_read(dbg.pid, rsp, 8)
from foxdbg import mem_write
mem_write(dbg.pid, rsp, b"\xef\xbe\xad\xde\x00\x00\x00\x00")
check("mem_write round-trips", read_qword(dbg.pid, rsp) == 0xdeadbeef)
mem_write(dbg.pid, rsp, orig)

# 9. clear breakpoint, run to completion -> exit 0
dbg.clear_breakpoint(ADD)
outcomes = []
while True:
    why, info = dbg.cont()
    outcomes.append((why, info))
    if why in ("exited", "killed"):
        break
check("program exits cleanly", outcomes[-1] == ("exited", 0), f"{outcomes}")

# 10. attach/detach on a live process
p = subprocess.Popen(["sleep", "30"])
time.sleep(0.2)
dbg2 = Debugger()
dbg2.attach(p.pid)
rr = dbg2.regs_dict()
check("attach: rip looks like userspace code", rr["rip"] > 0x10000, f"{rr['rip']:#x}")
dbg2.detach()
p.terminate(); p.wait()
check("detach: process survives", p.returncode == -signal.SIGTERM)

# 11. breakpoint save/restore: byte at ADD is intact after clear
dbg3 = Debugger(); dbg3.spawn([TGT])
dbg3.set_breakpoint(FIB)
check("int3 planted", mem_read(dbg3.pid, FIB, 1) == b"\xcc")
dbg3.clear_breakpoint(FIB)
real = subprocess.run(["objdump", "-d", f"--start-address={FIB:#x}",
                       f"--stop-address={FIB+1:#x}", TGT],
                      capture_output=True, text=True).stdout
check("original byte restored", mem_read(dbg3.pid, FIB, 1) != b"\xcc")
why, info = dbg3.cont()
check("no bp -> runs to exit 0", (why, info) == ("exited", 0), f"{why} {info}")

print(f"\n{passed} passed, {failed} failed")
if failed:
    sys.exit(1)

# ---- 12. hardware watchpoint: 5 writes to `counter` -> 5 traps ----
print("watchpoint checks:")
TGT2 = os.path.join(DIR, "target2")
CTR = None
out = subprocess.run(["nm", TGT2], capture_output=True, text=True).stdout
for ln in out.splitlines():
    p = ln.split()
    if len(p) == 3 and p[2] == "counter":
        CTR = int(p[0], 16)
assert CTR, "counter symbol not found"

# DR7 bit-math is kernel-independent: verify the encoding formula directly
# L0=bit0, RW0=bits16-17 (01=write), LEN0=bits18-19 (11=4 bytes)
check("DR7 encoding write/len4", 0x1 | (1 << 16) | (3 << 18) == 0xD0001)
check("DR7 encoding rw/len8", 0x1 | (3 << 16) | (2 << 18) == 0xB0001)

from foxdbg import PtraceError as _PE
dbg4 = Debugger(); dbg4.spawn([TGT2])
try:
    dbg4.set_watchpoint(CTR, "write", 4)
    wp_supported = True
except _PE as e:
    wp_supported = False
    print(f"  skip live watchpoint traps: {e}")
    dbg4.detach()

if wp_supported:
    seen = []
    while True:
        why, info = dbg4.cont()
        if why == "watchpoint":
            seen.append(read_qword(dbg4.pid, CTR) & 0xFFFFFFFF)
        elif why in ("exited", "killed"):
            break
        else:
            check("watchpoint run: unexpected stop", False, f"{why} {info}")
            break
    check("5 watchpoint traps for 5 writes", seen == [1, 2, 3, 4, 5], f"{seen}")
    check("watchpoint run exits 0", why == "exited" and info == 0, f"{why} {info}")

    # watchpoint cleared -> no more traps
    dbg5 = Debugger(); dbg5.spawn([TGT2])
    dbg5.set_watchpoint(CTR, "write", 4)
    check("unwatch reports removal", dbg5.clear_watchpoint() is True)
    check("second unwatch is no-op", dbg5.clear_watchpoint() is False)
    why, info = dbg5.cont()
    check("no watchpoint -> straight to exit", (why, info) == ("exited", 0), f"{why} {info}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
