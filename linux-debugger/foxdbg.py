#!/usr/bin/env python3
"""foxdbg - a from-scratch Linux x86-64 debugger built on ptrace.

Zero dependencies beyond the stdlib. Features:
  * spawn a process under PTRACE_TRACEME, or attach to a live pid
  * software breakpoints (int3 patching with original-byte save/restore)
  * single-stepping, continue-to-breakpoint
  * full register dump (user_regs_struct), targeted register set
  * arbitrary memory read/write via PEEK/POKE
  * backtrace by walking the rbp frame-pointer chain
  * tiny x86-64 disassembler for a readable `step` display
  * scripted REPL commands: break/b, continue/c, step/s, regs, x, bt, dis, quit
"""
import ctypes, ctypes.util, os, signal, struct, sys

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

# ptrace request numbers (x86-64 Linux)
PTRACE_TRACEME    = 0
PTRACE_PEEKTEXT   = 2
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 4
PTRACE_PEEKUSER   = 4
PTRACE_POKEUSER   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17

# offsetof(struct user, u_debugreg[0]) on x86-64 (measured with a C probe)
U_DEBUGREG0 = 848

def poke_user(pid, offset, value):
    _ptrace(PTRACE_POKEUSER, pid, offset, value & 0xFFFFFFFFFFFFFFFF)

def peek_user(pid, offset):
    return _ptrace(PTRACE_PEEKUSER, pid, offset) & 0xFFFFFFFFFFFFFFFF

WORD = ctypes.sizeof(ctypes.c_ulong)  # 8

class UserRegs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15","r14","r13","r12","rbp","rbx","r11","r10",
        "r9","r8","rax","rcx","rdx","rsi","rdi","orig_rax",
        "rip","cs","eflags","rsp","ss","fs_base","gs_base",
        "ds","es","fs","gs")]

REGS = [n for n, _ in UserRegs._fields_]

class PtraceError(RuntimeError):
    pass

def _ptrace(req, pid, addr=0, data=0):
    ctypes.set_errno(0)
    addr_p = ctypes.c_void_p(addr) if isinstance(addr, int) else addr
    data_p = ctypes.c_void_p(data) if isinstance(data, int) else data
    r = libc.ptrace(req, pid, addr_p, data_p)
    err = ctypes.get_errno()
    if r == -1 and err != 0:
        raise PtraceError(f"ptrace({req}) failed: {os.strerror(err)}")
    return r

# ---------------------------------------------------------------- memory ----
def mem_read(pid, addr, n):
    out = bytearray()
    # align down; read whole words and slice
    start = addr - (addr % WORD)
    words = _ptrace(PTRACE_PEEKDATA, pid, start)  # prime errno check
    chunks = []
    a = start
    while a < addr + n:
        chunks.append(struct.pack("<Q", _ptrace(PTRACE_PEEKDATA, pid, a) & 0xFFFFFFFFFFFFFFFF))
        a += WORD
    buf = b"".join(chunks)
    return bytes(buf[addr - start : addr - start + n])

def mem_write(pid, addr, data):
    start = addr - (addr % WORD)
    buf = bytearray(mem_read(pid, start, ((addr + len(data) - start + WORD - 1) // WORD) * WORD))
    buf[addr - start : addr - start + len(data)] = data
    for i in range(0, len(buf), WORD):
        _ptrace(PTRACE_POKEDATA, pid, start + i,
                struct.unpack("<Q", bytes(buf[i:i+WORD]))[0])

def read_qword(pid, addr):
    return struct.unpack("<Q", mem_read(pid, addr, 8))[0]

# --------------------------------------------------------------- process ----
class Debugger:
    def __init__(self):
        self.pid = None
        self.breakpoints = {}   # addr -> saved original byte
        self.watch_addr = None

    # -- lifecycle --
    def spawn(self, argv):
        pid = os.fork()
        if pid == 0:
            _ptrace(PTRACE_TRACEME, 0)
            os.execvp(argv[0], argv)
        self.pid = pid
        self._wait_initial()
        return pid

    def attach(self, pid):
        _ptrace(PTRACE_ATTACH, pid)
        self.pid = pid
        self._wait_initial()
        return pid

    def detach(self):
        for addr in list(self.breakpoints):
            self.clear_breakpoint(addr)
        self.clear_watchpoint()
        _ptrace(PTRACE_DETACH, self.pid, 0, 0)
        self.pid = None

    def _wait_initial(self):
        _, status = os.waitpid(self.pid, 0)
        assert os.WIFSTOPPED(status), f"unexpected status {status:#x}"
        return status

    def wait_stop(self):
        """Wait for the tracee to stop. Returns (why, info)."""
        pid, status = os.waitpid(self.pid, 0)
        if os.WIFEXITED(status):
            return ("exited", os.WEXITSTATUS(status))
        if os.WIFSIGNALED(status):
            return ("killed", os.WTERMSIG(status))
        assert os.WIFSTOPPED(status)
        sig = os.WSTOPSIG(status)
        if sig == signal.SIGTRAP:
            if self.watch_addr is not None and self.watch_fired():
                return ("watchpoint", self.watch_addr)
            regs = self.get_regs()
            hit = regs.rip - 1
            if hit in self.breakpoints:
                return ("breakpoint", hit)
            return ("singlestep", regs.rip)
        return ("signal", sig)

    # -- registers --
    def get_regs(self):
        regs = UserRegs()
        _ptrace(PTRACE_GETREGS, self.pid, 0, ctypes.byref(regs))
        return regs

    def set_regs(self, regs):
        _ptrace(PTRACE_SETREGS, self.pid, 0, ctypes.byref(regs))

    def regs_dict(self):
        r = self.get_regs()
        return {n: getattr(r, n) for n in REGS}

    # -- breakpoints --
    def set_breakpoint(self, addr):
        if addr in self.breakpoints:
            return
        orig = mem_read(self.pid, addr, 1)
        mem_write(self.pid, addr, b"\xcc")
        self.breakpoints[addr] = orig

    def clear_breakpoint(self, addr):
        orig = self.breakpoints.pop(addr, None)
        if orig is None:
            return False
        # only restore if the int3 is still ours
        if mem_read(self.pid, addr, 1) == b"\xcc":
            mem_write(self.pid, addr, orig)
        return True

    def _step_past_breakpoint(self, addr):
        """Resume cleanly when stopped on our own int3: restore byte,
        back rip up by one, single-step over it, re-arm."""
        self.clear_breakpoint(addr)
        regs = self.get_regs()
        regs.rip = addr
        self.set_regs(regs)
        _ptrace(PTRACE_SINGLESTEP, self.pid, 0, 0)
        why, _ = self.wait_stop()
        assert why == "singlestep", f"expected singlestep, got {why}"
        self.set_breakpoint(addr)

    # -- hardware watchpoints (DR0 slot) --
    # NOTE: PTRACE_PEEKUSER/POKEUSER are blocked (EIO) in some sandboxed
    # kernels. set_watchpoint probes once and raises a clear error there;
    # wait_stop never touches debug registers unless armed.
    def set_watchpoint(self, addr, kind="write", length=8):
        rw = {"exec": 0, "write": 1, "rw": 3}[kind]
        ln = {1: 0, 2: 1, 4: 3, 8: 2}[length]
        try:
            poke_user(self.pid, U_DEBUGREG0, addr)            # DR0 = address
            poke_user(self.pid, U_DEBUGREG0 + 6*8, 0)         # DR6 = clear status
            poke_user(self.pid, U_DEBUGREG0 + 7*8,
                      0x1 | (rw << 16) | (ln << 18))          # DR7 = L0|RW0|LEN0
        except PtraceError as e:
            raise PtraceError(f"hardware watchpoints unavailable here "
                              f"(PTRACE_POKEUSER blocked): {e}")
        self.watch_addr = addr

    def clear_watchpoint(self):
        if self.watch_addr is None:
            return False
        poke_user(self.pid, U_DEBUGREG0 + 7*8, 0)
        poke_user(self.pid, U_DEBUGREG0, 0)
        self.watch_addr = None
        return True

    def watch_fired(self):
        dr6 = peek_user(self.pid, U_DEBUGREG0 + 6*8)
        if dr6 & 0x1:                                     # B0: DR0 fired
            poke_user(self.pid, U_DEBUGREG0 + 6*8, 0)     # clear sticky status
            return True
        return False

    # -- execution control --
    def cont(self):
        regs = self.get_regs()
        hit = regs.rip - 1
        if hit in self.breakpoints:
            self._step_past_breakpoint(hit)
        _ptrace(PTRACE_CONT, self.pid, 0, 0)
        return self.wait_stop()

    def step(self):
        regs = self.get_regs()
        hit = regs.rip - 1
        if hit in self.breakpoints:
            # don't re-arm: we want to step *off* the breakpoint
            self.clear_breakpoint(hit)
            regs.rip = hit
            self.set_regs(regs)
        _ptrace(PTRACE_SINGLESTEP, self.pid, 0, 0)
        return self.wait_stop()

    # -- inspection --
    def backtrace(self, max_frames=32):
        """Walk the rbp chain. Each frame: saved rbp at [rbp], return addr at [rbp+8]."""
        regs = self.get_regs()
        frames = [(regs.rip, regs.rbp)]
        rbp = regs.rbp
        try:
            for _ in range(max_frames - 1):
                if rbp == 0:
                    break
                saved_rbp = read_qword(self.pid, rbp)
                ret_addr  = read_qword(self.pid, rbp + 8)
                if ret_addr == 0:
                    break
                frames.append((ret_addr, rbp))
                if saved_rbp <= rbp:   # not a sane upward chain; stop
                    break
                rbp = saved_rbp
        except PtraceError:
            pass
        return frames

# ------------------------------------------------- tiny x86-64 disassembler --
# Just enough to make single-stepping readable: common prologue/epilogue,
# mov/push/pop/call/ret/leave/sub/add/xor/test/cmp/jumps.
REG64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
         "r8","r9","r10","r11","r12","r13","r14","r15"]
REG32 = ["eax","ecx","edx","ebx","esp","ebp","esi","edi",
         "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"]

def _modrm(b):
    return (b >> 6) & 3, (b >> 3) & 7, b & 7

def dis_one(code):
    """Decode one instruction from bytes. Returns (text, length)."""
    i = 0
    rex_w = False
    prefixes = []
    while i < len(code) and code[i] in (0x66, 0x67, 0xF0, 0xF2, 0xF3):
        prefixes.append(code[i]); i += 1
    rex = 0
    if i < len(code) and 0x40 <= code[i] <= 0x4F:
        rex = code[i]; rex_w = bool(rex & 8); i += 1
    def regname(r, w64):
        # callers pre-apply REX.R/REX.B into the high bit; just index
        return (REG64 if w64 else REG32)[r & 15]
    def operand(mod, rm, w64):
        if mod == 3:
            return regname(rm | (((rex >> 0) & 1) << 3), w64)
        base = REG64[(rm | (((rex >> 0) & 1) << 3)) & 15]
        return f"[{base}]"
    if i >= len(code):
        return ("db ?", 1)
    op = code[i]; i += 1

    if op == 0xCC: return ("int3", i)
    if op == 0xC3: return ("ret", i)
    if op == 0xC9: return ("leave", i)
    if op == 0x90: return ("nop", i)
    if op == 0x0F:
        # two-byte opcodes; CET markers: F3 0F 1E FA = endbr64, FB = endbr32
        # (the F3 was already consumed as a prefix above)
        if i + 1 < len(code) and code[i] == 0x1E and code[i+1] in (0xFA, 0xFB):
            return ("endbr64" if code[i+1] == 0xFA else "endbr32", i + 2)
        return ("db 0x0f", i)
    if 0x50 <= op <= 0x57:
        return (f"push {REG64[(op-0x50)|(((rex>>0)&1)<<3)]}", i)
    if 0x58 <= op <= 0x5F:
        return (f"pop {REG64[(op-0x58)|(((rex>>0)&1)<<3)]}", i)
    if op == 0xE8:
        if i + 4 > len(code): return ("call ?", i)
        rel = struct.unpack("<i", code[i:i+4])[0]; i += 4
        return (f"call {rel:+#x}", i)
    if op == 0xE9:
        rel = struct.unpack("<i", code[i:i+4])[0]; i += 4
        return (f"jmp {rel:+#x}", i)
    if op == 0xEB:
        if i >= len(code): return ("jmp ?", i)
        rel = struct.unpack("<b", code[i:i+1])[0]; i += 1
        return (f"jmp {rel:+#x}", i)
    if 0x70 <= op <= 0x7F:
        if i >= len(code): return ("jcc ?", i)
        cc = ["o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"][op-0x70]
        rel = struct.unpack("<b", code[i:i+1])[0]; i += 1
        return (f"j{cc} {rel:+#x}", i)
    if op in (0x89, 0x8B, 0x01, 0x03, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B, 0x85):
        if i >= len(code): return ("?", i)
        mod, reg, rm = _modrm(code[i]); i += 1
        disp = ""
        if mod == 1:
            disp = f"{struct.unpack('<b', code[i:i+1])[0]:+#x}"; i += 1
        elif mod == 2 or (mod == 0 and rm == 5):
            disp = f"{struct.unpack('<i', code[i:i+4])[0]:+#x}"; i += 4
        if mod == 0 and rm == 5:
            mem = f"[rip{disp}]"
        elif mod == 3:
            # register-direct: operand width is 64-bit iff REX.W, else 32-bit
            r1 = regname(reg | (((rex >> 2) & 1) << 3), rex_w)
            r2 = regname(rm | (((rex >> 0) & 1) << 3), rex_w)
            names = {0x89:"mov",0x8B:"mov",0x01:"add",0x03:"add",0x29:"sub",
                     0x2B:"sub",0x31:"xor",0x33:"xor",0x39:"cmp",0x3B:"cmp",0x85:"test"}
            n = names[op]
            dst, src = (r2, r1) if op in (0x89,0x01,0x29,0x31,0x39) else (r1, r2)
            if op == 0x85: dst, src = r2, r1
            return (f"{n} {dst},{src}", i)
        else:
            base = REG64[(rm | (((rex >> 0) & 1) << 3)) & 15]
            mem = f"[{base}{disp}]"
        r = regname(reg | (((rex >> 2) & 1) << 3), rex_w)
        names = {0x89:"mov",0x8B:"mov",0x01:"add",0x03:"add",0x29:"sub",
                 0x2B:"sub",0x31:"xor",0x33:"xor",0x39:"cmp",0x3B:"cmp",0x85:"test"}
        n = names[op]
        dst, src = (mem, r) if op in (0x89,0x01,0x29,0x31,0x39) else (r, mem)
        if op == 0x85: dst, src = r, mem
        return (f"{n} {dst},{src}", i)
    if op in (0x83, 0x81):
        if i >= len(code): return ("?", i)
        mod, reg, rm = _modrm(code[i]); i += 1
        names = ["add","or","adc","sbb","and","sub","xor","cmp"]
        n = names[reg]
        disp = ""
        if mod == 1:
            disp = f"{struct.unpack('<b', code[i:i+1])[0]:+#x}"; i += 1
        elif mod == 2 or (mod == 0 and rm == 5):
            disp = f"{struct.unpack('<i', code[i:i+4])[0]:+#x}"; i += 4
        if mod == 3:
            dst = regname(rm | (((rex >> 0) & 1) << 3), rex_w)
        elif mod == 0 and rm == 5:
            dst = f"[rip{disp}]"
        else:
            base = REG64[(rm | (((rex >> 0) & 1) << 3)) & 15]
            dst = f"[{base}{disp}]"
        if op == 0x83:
            imm = struct.unpack("<b", code[i:i+1])[0]; i += 1
        else:
            imm = struct.unpack("<i", code[i:i+4])[0]; i += 4
        return (f"{n} {dst},{imm:#x}", i)
    if op in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
        r = regname(op - 0xB8, rex_w)
        imm = struct.unpack("<i", code[i:i+4])[0]; i += 4
        return (f"mov {r},{imm:#x}", i)
    if op == 0x8D:
        if i >= len(code): return ("?", i)
        mod, reg, rm = _modrm(code[i]); i += 1
        r = regname(reg | (((rex >> 2) & 1) << 3), rex_w)
        if mod == 0 and rm == 5:
            disp = struct.unpack("<i", code[i:i+4])[0]; i += 4
            return (f"lea {r},[rip{disp:+#x}]", i)
        return (f"lea {r},?", i)
    if op == 0xC7:
        if i >= len(code): return ("?", i)
        mod, reg, rm = _modrm(code[i]); i += 1
        if mod == 1:
            disp = struct.unpack("<b", code[i:i+1])[0]; i += 1
            imm = struct.unpack("<i", code[i:i+4])[0]; i += 4
            base = REG64[(rm | (((rex >> 0) & 1) << 3)) & 15]
            return (f"mov DWORD PTR [{base}{disp:+#x}],{imm:#x}", i)
        return ("mov ?,?", i)
    return (f"db {op:#04x}", i)

def fmt_regs(d):
    lines = []
    for grp in (("rax","rbx","rcx","rdx"), ("rsi","rdi","rbp","rsp"),
                ("r8","r9","r10","r11"), ("r12","r13","r14","r15"),
                ("rip","eflags","cs","ss")):
        lines.append("  ".join(f"{n:>6} {d[n]:#018x}" for n in grp))
    return "\n".join(lines)

# ------------------------------------------------------------------ REPL ----
HELP = """commands:
  break <addr>   set breakpoint (hex, e.g. 0x401136, or symbol via nm)
  clear <addr>   remove breakpoint
  watch <addr> [w|r|rw] [len]  hardware watchpoint (DR0) on data access
  unwatch        remove hardware watchpoint
  continue       run until breakpoint/exit
  step           single-step one instruction
  regs           dump registers
  x <addr> [n]   hexdump n bytes at addr
  bt             backtrace
  dis [n]        disassemble n instructions at rip
  sym <file>     load nm symbols for bt/dis display
  quit           detach and quit"""

def main(argv):
    if len(argv) < 2:
        print("usage: foxdbg.py <program> [args...]  |  foxdbg.py -p <pid>")
        sys.exit(1)
    dbg = Debugger()
    symbols = {}
    sym_addrs = []  # sorted [(addr, name)] for nearest-symbol lookup
    def nearest(addr):
        import bisect
        i = bisect.bisect_right(sym_addrs, (addr, chr(0x10FFFF))) - 1
        if i >= 0:
            base, name = sym_addrs[i]
            if base == addr:
                return name
            return f"{name}+{addr-base:#x}" if addr - base < 0x100000 else "??"
        return ""
    if argv[1] == "-p":
        dbg.attach(int(argv[2]))
        print(f"[+] attached to pid {argv[2]}")
    else:
        pid = dbg.spawn(argv[1:])
        print(f"[+] spawned pid {pid}: {' '.join(argv[1:])}")
    print("type 'help' for commands")
    while True:
        try:
            line = input("(foxdbg) ").strip().split()
        except EOFError:
            line = ["quit"]
        if not line:
            continue
        cmd, args = line[0], line[1:]
        try:
            if cmd == "help":
                print(HELP)
            elif cmd in ("break", "b") and args:
                a = int(args[0], 16)
                dbg.set_breakpoint(a)
                print(f"[+] breakpoint at {a:#x} {symbols.get(a,'')}")
            elif cmd == "clear" and args:
                print("[-] cleared" if dbg.clear_breakpoint(int(args[0], 16)) else "[-] none there")
            elif cmd == "watch" and args:
                kind = {"w": "write", "r": "rw", "rw": "rw"}.get(args[1] if len(args) > 1 else "w", "write")
                ln = int(args[2]) if len(args) > 2 else 8
                dbg.set_watchpoint(int(args[0], 16), kind, ln)
                print(f"[+] watchpoint {kind} len={ln} at {int(args[0],16):#x}")
            elif cmd == "unwatch":
                print("[-] watch removed" if dbg.clear_watchpoint() else "[-] none set")
            elif cmd in ("continue", "c"):
                why, info = dbg.cont()
                print(f"[*] stopped: {why} {info if not isinstance(info,int) or why!='breakpoint' else hex(info)}")
                if why in ("exited", "killed"):
                    break
            elif cmd in ("step", "s"):
                why, info = dbg.step()
                r = dbg.regs_dict()
                code = mem_read(dbg.pid, r["rip"], 15)
                txt, _ = dis_one(code)
                print(f"{r['rip']:#x}: {txt}")
            elif cmd == "regs":
                print(fmt_regs(dbg.regs_dict()))
            elif cmd == "x" and args:
                a = int(args[0], 16); n = int(args[1]) if len(args) > 1 else 64
                data = mem_read(dbg.pid, a, n)
                for off in range(0, n, 16):
                    chunk = data[off:off+16]
                    hexs = " ".join(f"{b:02x}" for b in chunk)
                    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    print(f"{a+off:#x}: {hexs:<48} {asc}")
            elif cmd == "bt":
                for i, (ra, rbp) in enumerate(dbg.backtrace()):
                    print(f"#{i} {ra:#x} {nearest(ra)}  (rbp={rbp:#x})")
            elif cmd == "dis":
                n = int(args[0]) if args else 8
                r = dbg.regs_dict(); pc = r["rip"]
                code = mem_read(dbg.pid, pc, 15 * n)
                off = 0
                for _ in range(n):
                    txt, ln = dis_one(code[off:])
                    mark = "=>" if off == 0 else "  "
                    print(f"{mark} {pc+off:#x}: {txt}")
                    off += ln
            elif cmd == "sym" and args:
                import subprocess
                out = subprocess.run(["nm", "-n", args[0]], capture_output=True, text=True).stdout
                for ln in out.splitlines():
                    p = ln.split()
                    if len(p) == 3:
                        symbols[int(p[0], 16)] = p[2]
                sym_addrs = sorted((a, n) for a, n in symbols.items())
                print(f"[+] {len(symbols)} symbols")
            elif cmd in ("quit", "q"):
                dbg.detach()
                print("[*] detached")
                break
            else:
                print("? unknown command")
        except PtraceError as e:
            print(f"[!] {e}")
        except BrokenPipeError:
            break

if __name__ == "__main__":
    main(sys.argv)
