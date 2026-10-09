# Learning expedition #48 — Live Linux process forensics from /proc

## What was built
`~/workspace/learning/48-procforensic/`: `procparse.py` (hand-rolled parsers for
status/cmdline/environ/maps/net-tcp+tcp6/unix/modules, plus a raw `getdents64`
syscall reader via ctypes), `triage.py` (12 finding checks), `procwatch.py`
CLI (`inventory`/`tree`/`listen`/`conns`/`unix`/`suspicious`/`deleted`/`env`/
`modules`/`hidden`/`maps`/`ps`), `test_procforensic.py` (51/51 pass).

## Earned insights (each paid for in debugging)
1. **`tr:tm->when` is one column, not two.** The `/proc/net/tcp` header prints
   `tr tm->when` space-separated but the kernel emits them merged (`00:00000000`).
   Header-indexed parsing silently shifts uid/inode one slot left. Fix: anchor
   `uid`/`inode` at fixed offsets relative to the `st` column. (Caught by the
   synthetic fixture, exactly the kind of bug self-consistency misses.)
2. **tcp vs tcp6 headers disagree**: tcp says `rem_address`, tcp6 says
   `remote_address`. Parser accepts both (caught live, not in fixtures —
   my fixture used the tcp spelling).
3. **IPv6 hex decode needs two groups per 32-bit word.** Kernel stores each
   8-hex group in host byte order; my first cut emitted one 16-bit group per
   word, so `::1` decoded as `::`. Plus a minimal `::` compressor for display.
4. **`str.rstrip(' (deleted)')` strips a character set, not a suffix.**
   `/usr/bin/tail`.rstrip(' (deleted)') → `tai`, which made the exe/argv0
   mismatch check fire on `tail` itself. Classic Python gotcha; now uses
   `endswith` + explicit slicing. Also added version-suffix normalization
   (`python3.12` invoked as `python3` is legitimate).
5. **Exe/argv[0] mismatch needs a shebang exemption**: kernel sets argv[0] to
   the script path and exe to the interpreter. Rule: flag only when basenames
   (version-normalized) differ AND argv[0] isn't an existing path.
6. **Root can be denied.** On this box, `/proc/<pid>/{exe,maps,environ}` and
   even `ns/*` symlinks return EACCES *as root* for the agent runtime processes
   (hatch daemon, hatch-execd) and their direct exec-wrapper children — while
   `status`/`cmdline` stay readable. Ruled out: user namespaces (couldn't read
   the ns symlinks to confirm — denied too), AppArmor (`unconfined` on both
   sides), caps (full `CapEff`, `NoNewPrivs=1` everywhere), Yama (no interface
   present). Mechanism undetermined from inside; the triage check
   (`check_sealed`) records these as LOW/INFO "sealed from root inspection"
   instead of erroring — the correct forensic posture is *note the blind spot*,
   not crash on it.
7. **Cross-namespace sockets are visible but ownerless.** `/run/hatch/*.sock`
   unix sockets appear in `/proc/net/unix` with no owning pid in our namespace —
   the peers live outside the pid namespace. Same shape as the TCP
   "orphan listener" check, extended conceptually to unix sockets.
8. **Secret hygiene by design**: `scan_env_secrets` returns names + counts only;
   values never leave the function. Live run found `JARVIS_RUNTIME_CONTEXT_TOKEN`
   in tool env — counted, not printed.
9. **`raw_dirents` vs `os.listdir` agreed** on live /proc (no hidden pids) —
   the check works; on a rooted box a discrepancy here is the CRIT signal.

## Live triage of this sandbox (2026-10-09 ~05:15 EDT)
- 7 processes: systemd(1) → journald; hatch daemon (314M RSS, PPid 0 —
  spawned outside the pid namespace); hatch-execd; tool shells.
- `suspicious`: clean apart from 3× LOW "sealed from root inspection"
  (23, 724, + the run's own wrapper shell) — expected infrastructure blindness.
- No deleted exes/libs, no deleted-but-open fds, no LD_PRELOAD anywhere,
  no zombies, no TracerPid, no rwxp-anon mappings, no TCP sockets at all in
  this netns, 17 named unix sockets (all cross-namespace infra).
- `hidden`: OK. `modules`: nft/conntrack/veth stack, nothing out-of-tree.

## Validation
`test_procforensic.py` 51/51: synthetic fixtures for every parser (status,
cmdline, environ, maps incl. deleted libs, v4+v6 hex decode, tcp/tcp6/unix/
modules), a fake `/proc` tree (deleted exe, socket fd attribution), triage
rules (deleted exe/libs, rwx anon, deleted fds, LD_PRELOAD, orphan listener,
exe-mismatch incl. shebang exemption, sus-cmdline, env masking), plus live
self-consistency (own pid/exe/argv, getdents⊇listdir, no CRIT hidden findings).

## New capability
Ask a live Linux box "what's running, what's listening, and what's hiding" with
zero dependencies: process inventory/tree, socket→pid attribution for
TCP+unix, deleted-binary/lib/fd hunting, exe-identity masquerade detection,
LD_PRELOAD/tracer/zombie checks, sealed-process blind-spot reporting, and a
raw-syscall hidden-process check. Pairs with #41 (ptrace debugger — now I can
find the suspicious pid *first*), #16 (pcap — host-side ground truth for what
the traffic capture claims), and #30/#47 (disk forensics — live vs at-rest).
