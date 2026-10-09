#!/usr/bin/env python3
"""procwatch — live Linux process/host forensics from /proc.

Subcommands:
  inventory   table of all processes (pid, ppid, user-ish, state, rss, cmd)
  tree        process tree from ppid links
  listen      listening sockets attributed to owning processes
  conns       all TCP connections with owner attribution
  unix        named unix-domain sockets with owner attribution
  suspicious  run the full triage battery
  deleted     deleted exes / libs / open deleted files
  env         secret-looking env var counts (values never printed)
  modules     kernel module list with out-of-tree flags
  hidden      raw-getdents64 vs listdir hidden-process check
  maps PID    memory-map summary for one pid
  ps PID      full dossier on one pid
"""
import os
import sys
import pwd

import procparse
import triage

def _user_of(p):
    # no uid in status; use exe ownership as approximation
    try:
        st = os.stat('/proc/%d/exe' % p.pid)
        return pwd.getpwuid(st.st_uid).pw_name
    except (OSError, KeyError):
        return '?'

def _short_cmd(p, n=70):
    if p.argv:
        s = ' '.join(p.argv)
    else:
        s = '[%s]' % (p.name or '?')
    return s[:n]

def cmd_inventory(procs):
    print('%-7s %-7s %-4s %-10s %-8s %s' % ('PID', 'PPID', 'ST', 'USER', 'RSS', 'CMD'))
    for pid in sorted(procs):
        p = procs[pid]
        rss = p.status.get('_vmrss_kb')
        print('%-7d %-7s %-4s %-10s %-8s %s' % (
            pid, p.status.get('_ppid', '?'), p.status.get('_state', '?'),
            _user_of(p), ('%dM' % (rss // 1024)) if rss else '-',
            _short_cmd(p)))

def cmd_tree(procs):
    kids = {}
    for pid, p in procs.items():
        ppid = p.status.get('_ppid')
        kids.setdefault(ppid, []).append(pid)
    def walk(pid, depth):
        p = procs.get(pid)
        label = _short_cmd(p, 60) if p else '?'
        print('  ' * depth + '%d %s' % (pid, label))
        for c in sorted(kids.get(pid, [])):
            if c != pid:
                walk(c, depth + 1)
    roots = sorted(k for k in kids if k not in procs or k in (0, None))
    seen = set()
    for r in roots:
        for c in sorted(kids.get(r, [])):
            if c not in seen:
                seen.add(c)
                walk(c, 0)
    # orphans whose ppid vanished mid-scan
    for pid in sorted(procs):
        if pid not in seen and all(pid not in kids.get(r, []) for r in roots):
            pass

def _net_rows():
    rows = []
    for name in ('tcp', 'tcp6'):
        t = procparse._read('/proc/net/' + name)
        if t:
            rows += procparse.parse_net_tcp(t)
    return rows

def cmd_unix(procs, owners):
    t = procparse._read('/proc/net/unix')
    if not t:
        print('no /proc/net/unix')
        return
    rows = procparse.parse_net_unix(t)
    print('%-42s %-6s %s' % ('UNIX SOCKET', 'PID', 'PROCESS'))
    shown = 0
    for r in rows:
        if not r['path']:
            continue  # unnamed; skip for brevity
        pids = sorted(owners.get(r['inode'], ()))
        who = ', '.join('%d(%s)' % (q, _short_cmd(procs[q], 30))
                        for q in pids if q in procs) or '?? no owner'
        print('%-42s %-6s %s' % (r['path'][:42],
                                 ','.join(map(str, pids)) or '-', who))
        shown += 1
    print('(%d named unix sockets)' % shown)

def cmd_listen(procs, owners):
    rows = [r for r in _net_rows() if r['state'] == 'LISTEN']
    print('%-22s %-6s %s' % ('LISTENING', 'PID', 'PROCESS'))
    for r in rows:
        ip, port = r['local']
        pids = sorted(owners.get(r['inode'], ()))
        who = ', '.join('%d(%s)' % (q, _short_cmd(procs[q], 40))
                        for q in pids if q in procs) or '?? no owner'
        print('%-22s %-6s %s' % ('%s:%d' % (ip, port),
                                 ','.join(map(str, pids)) or '-', who))

def cmd_conns(procs, owners):
    rows = _net_rows()
    print('%-8s %-22s %-22s %-10s %s' % ('STATE', 'LOCAL', 'REMOTE', 'PID', 'PROCESS'))
    for r in rows:
        lip, lport = r['local']
        rip, rport = r['remote']
        pids = sorted(owners.get(r['inode'], ()))
        who = _short_cmd(procs[pids[0]], 40) if pids and pids[0] in procs else '-'
        print('%-8s %-22s %-22s %-10s %s' % (
            r['state'], '%s:%d' % (lip, lport), '%s:%d' % (rip, rport),
            ','.join(map(str, pids)) or '-', who))

def cmd_suspicious(procs, proc_root):
    net_rows = _net_rows()
    findings, _ = triage.run_all(procs, net_rows, proc_root,
                                 self_pid=os.getpid())
    if not findings:
        print('clean: no findings')
        return
    cur = None
    for sev, pid, title, detail in findings:
        if sev != cur:
            cur = sev
            print('== %s ==' % sev)
        print('  pid %-7d %-42s %s' % (pid, title, detail))

def cmd_deleted(procs):
    for fn, label in ((triage.check_deleted_exe, 'deleted exe'),
                      (triage.check_deleted_libs, 'deleted libs'),
                      (triage.check_deleted_fds, 'deleted open fds')):
        fs = fn(procs)
        print('== %s: %d ==' % (label, len(fs)))
        for sev, pid, title, detail in fs:
            print('  pid %-7d %s: %s' % (pid, title, detail))

def cmd_env(procs):
    hits = triage.scan_env_secrets(procs)
    print('secret-looking env vars (names only, values masked): %d distinct' %
          len(hits))
    for name in sorted(hits):
        pids = hits[name]
        print('  %-28s %d procs  e.g. pid %d' % (name, len(pids), pids[0]))

def cmd_modules():
    t = procparse._read('/proc/modules')
    if not t:
        print('/proc/modules unreadable (containers often hide it)')
        return
    mods = procparse.parse_modules(t)
    print('%-24s %-8s %s' % ('MODULE', 'SIZE', 'STATE/SRC'))
    for m in mods:
        print('%-24s %-8d %s/%s' % (m['name'], m['size'], m['state'], m['src']))

def cmd_hidden():
    for sev, pid, title, detail in triage.check_hidden_processes():
        print('[%s] %s: %s' % (sev, title, detail))
    if not triage.check_hidden_processes():
        print('OK: listdir and raw getdents64 agree on /proc pids')

def cmd_maps(procs, pid):
    p = procs.get(pid)
    if not p:
        print('no such pid in snapshot')
        return
    print('maps for pid %d (%s): %d regions' % (pid, _short_cmd(p, 50),
                                                len(p.maps)))
    by_perm = {}
    for m in p.maps:
        by_perm[m['perms']] = by_perm.get(m['perms'], 0) + 1
    print('perm histogram:', dict(sorted(by_perm.items())))
    print('%-36s %-6s %s' % ('RANGE', 'PERMS', 'PATH'))
    for m in p.maps[:40]:
        print('%08x-%08x  %-6s %s' % (m['start'], m['end'], m['perms'],
                                      m['path'] or '[anon]'))

def cmd_ps(procs, pid):
    p = procs.get(pid)
    if not p:
        print('no such pid in snapshot')
        return
    print('pid %d  name=%s  state=%s  ppid=%s  threads=%s  tracer=%s' % (
        pid, p.name, p.status.get('_state'), p.status.get('_ppid'),
        p.status.get('_threads'), p.status.get('_tracerpid')))
    print('exe: %s' % p.exe)
    print('cmdline: %s' % ' '.join(p.argv))
    print('rss: %s kB  vmsize: %s kB' % (p.status.get('_vmrss_kb'),
                                         p.status.get('_vmsize_kb')))
    print('env vars: %d  fds: %d  map regions: %d' % (len(p.env),
                                                       len(p.fds),
                                                       len(p.maps)))
    for fd, tgt in sorted(p.fds.items(), key=lambda kv: int(kv[0])):
        print('  fd %s -> %s' % (fd, tgt))

def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    sub = argv[1]
    if sub in ('modules', 'hidden'):
        {'modules': cmd_modules, 'hidden': cmd_hidden}[sub]()
        return 0
    print('scanning /proc ...', file=sys.stderr)
    procs = procparse.snapshot_all()
    print('%d processes snapshotted' % len(procs), file=sys.stderr)
    owners = procparse.socket_owners(procs)
    if sub == 'inventory':
        cmd_inventory(procs)
    elif sub == 'tree':
        cmd_tree(procs)
    elif sub == 'listen':
        cmd_listen(procs, owners)
    elif sub == 'conns':
        cmd_conns(procs, owners)
    elif sub == 'unix':
        cmd_unix(procs, owners)
    elif sub == 'suspicious':
        cmd_suspicious(procs, '/proc')
    elif sub == 'deleted':
        cmd_deleted(procs)
    elif sub == 'env':
        cmd_env(procs)
    elif sub == 'maps':
        cmd_maps(procs, int(argv[2]))
    elif sub == 'ps':
        cmd_ps(procs, int(argv[2]))
    else:
        print('unknown subcommand: %s' % sub)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
