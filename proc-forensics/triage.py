"""triage.py — forensic finding checks over a process snapshot.

Each check returns findings as (severity, pid, title, detail) tuples.
Severities: CRIT > HIGH > MED > LOW > INFO.
"""
import os
import re
import procparse

SEV_ORDER = {'CRIT': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3, 'INFO': 4}

SECRET_HINTS = ('KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PASSWD', 'AWS_',
                'PRIVATE', 'CREDENTIAL', 'AUTH')

SUSPICIOUS_CMDLINE = (
    ('/dev/tcp/', 'bash TCP backconnect idiom'),
    ('nc -e', 'netcat -e (bind/connect shell)'),
    ('ncat -e', 'ncat -e (bind/connect shell)'),
    ('curl', 'curl in cmdline'),
    ('wget', 'wget in cmdline'),
    ('base64 -d', 'base64 decode pipeline'),
    ('base64 --decode', 'base64 decode pipeline'),
    ('| sh', 'pipe-to-shell pattern'),
    ('| bash', 'pipe-to-shell pattern'),
    ('-c powershell', 'powershell -c'),
    ('mimikatz', 'mimikatz string'),
    ('LD_PRELOAD', 'LD_PRELOAD in cmdline'),
    ('ptrace', 'ptrace string in cmdline'),
    ('/tmp/', 'executes from /tmp'),
    ('/dev/shm', 'executes from /dev/shm'),
    ('chmod +x', 'chmod +x in cmdline'),
    ('nohup', 'nohup (persist past shell)'),
)

def is_kernel_thread(p):
    # kernel threads: empty cmdline AND no maps AND ppid==2 (kthreadd),
    # or the classic [kworker/...] bracketed name with no argv
    if p.argv:
        return False
    if p.status.get('_ppid') == 2:
        return True
    return (p.name or '').startswith('[')

def check_deleted_exe(procs):
    out = []
    for pid, p in procs.items():
        if p.exe and p.exe.endswith(' (deleted)'):
            out.append(('HIGH', pid, 'deleted executable still running',
                        'exe=%s cmdline=%s' % (p.exe, ' '.join(p.argv[:3]))))
    return out

def check_exe_mismatch(procs):
    """exe basename differs from argv[0] basename and argv[0] isn't an
    existing script path (shebang launches legitimately differ)."""
    out = []
    for pid, p in procs.items():
        if not p.exe or p.exe.endswith(' (deleted)') or not p.argv:
            continue
        argv0 = p.argv[0]
        exe_base = os.path.basename(p.exe)
        a0_base = os.path.basename(argv0)
        if exe_base == a0_base:
            continue
        # version-suffixed binaries are legit: python3.12 invoked as python3
        norm = lambda s: re.sub(r'[0-9.]+$', '', s)
        if norm(exe_base) == norm(a0_base) and norm(exe_base):
            continue
        if argv0.startswith('/') and os.path.exists(argv0):
            continue  # shebang script: kernel argv0=script, exe=interpreter
        out.append(('MED', pid, 'exe/argv[0] identity mismatch',
                    'exe=%s argv0=%s' % (p.exe, argv0)))
    return out

def check_deleted_libs(procs):
    out = []
    for pid, p in procs.items():
        hits = sorted({m['path'].replace(' (deleted)', '')
                       for m in p.maps if m['path'].endswith(' (deleted)')})
        if hits:
            out.append(('MED', pid, 'deleted libraries still mapped',
                        '%d: %s' % (len(hits), ', '.join(hits[:5]))))
    return out

def check_rwx_anon(procs):
    out = []
    for pid, p in procs.items():
        n = sum(1 for m in p.maps
                if m['perms'] == 'rwxp' and not m['path'])
        if n:
            out.append(('LOW', pid, 'writable+executable anonymous mappings',
                        '%d rwxp anon regions (shellcode/JIT shape)' % n))
    return out

def check_tmp_exec(procs):
    out = []
    for pid, p in procs.items():
        hits = sorted({m['path'] for m in p.maps
                       if 'x' in m['perms'] and m['path'] and
                       m['path'].startswith(('/tmp/', '/var/tmp/',
                                             '/dev/shm/'))})
        if hits:
            out.append(('MED', pid, 'executable mapping from tmpfs/tmp',
                        ', '.join(hits[:5])))
    return out

def check_sealed(procs):
    """Processes whose status is visible but whose exe/maps are sealed from
    root (EACCES): lives in a more-privileged security context — different
    user namespace or LSM policy. In a container that means host-side."""
    out = []
    for pid, p in procs.items():
        if (p.exe is None and p.exe_err and 'Permission denied' in p.exe_err
                and not p.maps):
            out.append(('LOW', pid, 'process sealed from root inspection',
                        'exe/maps EACCES as root (cross-userns or LSM); '
                        'cmd=%s' % ' '.join(p.argv[:3])))
    return out

def check_tracer(procs):
    out = []
    for pid, p in procs.items():
        tp = p.status.get('_tracerpid')
        if tp:
            out.append(('MED', pid, 'process is being ptraced',
                        'TracerPid=%d' % tp))
    return out

def check_zombies(procs):
    out = []
    zoms = [(pid, p) for pid, p in procs.items()
            if p.status.get('_state') == 'Z']
    if len(zoms) >= 10:
        out.append(('MED', 0, 'zombie storm',
                    '%d zombies' % len(zoms)))
    for pid, p in zoms:
        out.append(('LOW', pid, 'zombie process',
                    'ppid=%s cmd=%s' % (p.status.get('_ppid'),
                                        ' '.join(p.argv[:2]) or p.name)))
    return out

def check_suspicious_cmdline(procs, self_pid=None):
    out = []
    for pid, p in procs.items():
        if pid == self_pid or not p.argv:
            continue
        cmd = ' '.join(p.argv)
        for needle, why in SUSPICIOUS_CMDLINE:
            if needle in cmd:
                out.append(('LOW', pid, 'suspicious cmdline pattern: %s' % why,
                            cmd[:160]))
                break
    return out

def check_deleted_fds(procs):
    out = []
    for pid, p in procs.items():
        hits = ['fd%s->%s' % (fd, tgt) for fd, tgt in p.fds.items()
                if tgt and '(deleted)' in tgt]
        if hits:
            out.append(('MED', pid, 'open file handles to deleted files',
                        '%d: %s' % (len(hits), '; '.join(hits[:4]))))
    return out

def check_ld_preload(procs, proc_root='/proc'):
    out = []
    try:
        with open('/etc/ld.so.preload') as fh:
            content = fh.read().strip()
        if content:
            out.append(('HIGH', 0, '/etc/ld.so.preload is set',
                        content[:200]))
    except OSError:
        pass
    for pid, p in procs.items():
        if 'LD_PRELOAD' in p.env:
            out.append(('HIGH', pid, 'LD_PRELOAD in environment',
                        p.env['LD_PRELOAD'][:200]))
    return out

def check_hidden_processes(proc_root='/proc'):
    """os.listdir (/proc via getdents already, same syscall family) vs the
    RAW getdents64 syscall through libc. A discrepancy means something is
    filtering directory reads between us and the kernel — classic
    rootkit behavior. (Both paths use getdents64 here; the point is the
    libc readdir layer some rootkits hook is bypassed.)"""
    try:
        listed = {e for e in os.listdir(proc_root) if e.isdigit()}
        raw = {e for e in procparse.raw_dirents(proc_root) if e.isdigit()}
    except OSError as e:
        return [('LOW', 0, 'hidden-process check unavailable', str(e))]
    only_listed = listed - raw
    only_raw = raw - listed
    out = []
    if only_raw:
        out.append(('CRIT', 0, 'processes visible only to raw syscall',
                    'possible hidden pids: %s' % sorted(only_raw)[:10]))
    if only_listed:
        out.append(('MED', 0, 'pids in listdir missing from raw syscall',
                    '%s (usually races: pids exited between reads)' %
                    sorted(only_listed)[:10]))
    return out

def check_orphan_listeners(net_rows, owners):
    out = []
    for r in net_rows:
        if r['state'] != 'LISTEN':
            continue
        pids = owners.get(r['inode'], set())
        if not pids:
            ip, port = r['local']
            out.append(('HIGH', 0, 'listening socket with no owning process',
                        '%s:%d inode=%d (hidden process? kernel socket?)'
                        % (ip, port, r['inode'])))
    return out

def check_kernel_sock_owners(net_rows, owners, proc_root='/proc'):
    # informational: count listeners owned per pid
    return []

def scan_env_secrets(procs):
    """Count secret-looking env vars. Values are NEVER returned — counts
    and variable names only, values stay masked."""
    hits = {}
    for pid, p in procs.items():
        for k in p.env:
            ku = k.upper()
            if any(h in ku for h in SECRET_HINTS):
                hits.setdefault(k, []).append(pid)
    return hits

def run_all(procs, net_rows, proc_root='/proc', self_pid=None):
    owners = procparse.socket_owners(procs)
    findings = []
    findings += check_deleted_exe(procs)
    findings += check_exe_mismatch(procs)
    findings += check_deleted_libs(procs)
    findings += check_rwx_anon(procs)
    findings += check_tmp_exec(procs)
    findings += check_tracer(procs)
    findings += check_sealed(procs)
    findings += check_zombies(procs)
    findings += check_suspicious_cmdline(procs, self_pid)
    findings += check_deleted_fds(procs)
    findings += check_ld_preload(procs, proc_root)
    findings += check_hidden_processes(proc_root)
    findings += check_orphan_listeners(net_rows, owners)
    findings.sort(key=lambda f: (SEV_ORDER[f[0]], f[1]))
    return findings, owners
