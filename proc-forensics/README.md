# Live Linux Process Forensics From /proc

A zero-dependency live host interrogation toolkit in stdlib-only Python:
ask a running Linux box "what's running, what's listening, and what's
hiding" using nothing but the `/proc` filesystem.

- `procparse.py` — hand-rolled parsers: `status`, `cmdline`, `environ`,
  `maps`, `/proc/net/{tcp,tcp6,unix}`, kernel modules, plus a raw
  `getdents64` syscall reader via ctypes (for the hidden-process check)
- `triage.py` — 16 finding checks: deleted exes/libs/open fds, exe/argv0
  identity masquerade (with shebang exemption), RWX anonymous mappings,
  `/tmp` execution, tracer/zombie detection, `LD_PRELOAD`, orphan
  listeners, sealed-from-root blind-spot reporting, env secret counting
  (names only — values never leave the function), kernel socket owners
- `procwatch.py` — CLI: `inventory`, `tree`, `listen`, `conns`, `unix`,
  `suspicious` (full triage battery), `deleted`, `env`, `modules`,
  `hidden` (raw-syscall vs `listdir` discrepancy check), `maps PID`,
  `ps PID`

**51/51 tests pass** (`test_procforensic.py`): synthetic fixtures for
every parser (status, cmdline, environ, maps incl. deleted libs, v4+v6
hex decode, tcp/tcp6/unix/modules), a fake `/proc` tree (deleted exe,
socket fd attribution), all triage rules, plus live self-consistency
checks on the machine it runs on (own pid/exe/argv, getdents⊇listdir, no
CRIT hidden findings).

## Dependencies

Stdlib only (`ctypes` for the raw `getdents64` check). No pip packages.
Linux only — everything reads `/proc`.

## How to run

```
python3 test_procforensic.py        # 51/51 (safe anywhere; live checks are self-consistent)
python3 procwatch.py --help        # command list
python3 procwatch.py inventory      # process table (pid, ppid, state, RSS, cmd)
python3 procwatch.py suspicious     # full triage battery
python3 procwatch.py hidden         # hidden-process check (raw getdents64 vs listdir)
```

## Usage example

```
python3 procwatch.py tree      # process tree from ppid links
python3 procwatch.py listen    # listening sockets attributed to owning processes
python3 procwatch.py deleted   # deleted exes / libs / open-but-deleted files
python3 procwatch.py env       # secret-looking env var counts (values never printed)
python3 procwatch.py ps 1      # full dossier on one pid
```

As a library:

```python
import procparse, triage

procs = procparse.snapshot_all()           # parse every /proc/<pid>
net = procparse.parse_net_tcp('/proc/net/tcp')
findings = triage.run_all(procs, net)      # CRIT/HIGH/LOW/INFO findings
for sev, f in findings:
    print(f'== {sev} ==', f.title, f.detail)
```

## Key learnings

- **The `/proc/net/tcp` header lies about columns.** `tr tm->when` is one
  space-separated-looking column, but the kernel emits them merged —
  header-indexed parsing silently shifts `uid`/`inode` one slot left.
  Anchor `uid`/`inode` at fixed offsets relative to the `st` column.
- **`tr:tm->when`'s sibling gotcha:** tcp says `rem_address`, tcp6 says
  `remote_address`; the parser accepts both. IPv6 hex needs two 16-bit
  groups per 32-bit word or `::1` decodes as `::`.
- **`str.rstrip(' (deleted)')` strips a character set, not a suffix.**
  It turned `/usr/bin/tail` into `tai` and false-fired the exe-mismatch
  check on `tail` itself. Use `endswith` + explicit slicing.
- **Root can be denied.** Even as root, some processes' `exe`/`maps`/
  `environ` return EACCES — the correct forensic posture is *note the
  blind spot* (`check_sealed` → LOW/INFO), not crash on it.
- **Secret hygiene by design:** `scan_env_secrets` returns names +
  counts only; values never leave the function.

## Limitations

- **Linux-only** — `/proc` is the entire data source.
- **Sealed processes are blind spots**, not verdicts: EACCES on a
  process's internals gets reported as LOW/INFO ("sealed from root
  inspection"), with mechanism undetermined from inside.
- **The hidden-process check detects discrepancy**, not rootkits —
  `getdents64` vs `listdir` disagreement is the CRIT signal, but a
  sufficiently deep rootkit can hide from both.
- **Cross-namespace sockets are visible but ownerless** — unix sockets
  whose peers live outside your pid namespace show up with no owning pid.
- Like all /proc forensics: point-in-time snapshot only, no history.

## Files

- `procparse.py` — hand-rolled /proc parsers (status/cmdline/environ/maps/net-tcp+tcp6/unix/modules, raw getdents64)
- `procwatch.py` — CLI: inventory/tree/listen/conns/unix/suspicious/deleted/env/modules/hidden/maps/ps
- `triage.py` — 16 finding checks + `run_all()` battery (library; used by `procwatch suspicious`)
- `test_procforensic.py` — 51/51: synthetic fixtures for every parser + all triage rules + live self-consistency
- `LEARNINGS.md` — the full expedition writeup
