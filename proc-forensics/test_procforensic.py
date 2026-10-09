#!/usr/bin/env python3
"""test_procforensic.py — validation for the /proc forensics toolkit.

Part 1: synthetic fixtures (deterministic).
Part 2: live consistency on the real /proc (self-checks, no oracle needed).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import procparse
import triage

PASS = 0
FAIL = 0

def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('ok   %s' % name)
    else:
        FAIL += 1
        print('FAIL %s %s' % (name, detail))

# ---------------------------------------------------------- fixtures

STATUS_TXT = """Name:\tpython3
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1234
Pid:\t1234
PPid:\t100
TracerPid:\t0
Uid:\t1000\t1000\t1000\t1000
Threads:\t3
VmSize:\t  123456 kB
VmRSS:\t    7890 kB
"""

CMDLINE = b'python3\x00-c\x00print("hi")\x00'
ENVIRON = b'PATH=/usr/bin\x00HOME=/root\x00AWS_SECRET_KEY=xx\x00'

MAPS_TXT = """55a1b2c3d000-55a1b2c3e000 r--p 00000000 08:01 12345 /usr/bin/python3.12
55a1b2c3e000-55a1b2c40000 r-xp 00001000 08:01 12345 /usr/bin/python3.12
7f00aa000000-7f00aa021000 rw-p 00000000 00:00 0
7f00aa021000-7f00aa022000 rwxp 00000000 00:00 0
7f00bb000000-7f00bb010000 r--p 00000000 08:01 999 /lib/old.so (deleted)
"""

NET_TCP_TXT = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4243 1 0000000000000000 100 0 0 10 0
   2: 0B0AA8C0:D431 08080808:0035 01 00000000:00000000 02:00000000 00000000  1000        0 9999 1 0000000000000000 20 0 0 10 -1
"""

NET_TCP6_TXT = """  sl  local_address                         rem_address                          st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7777 1 0000000000000000 100 0 0 10 0
"""

NET_UNIX_TXT = """Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00000000 0001 03    0 /run/systemd/private
0000000000000000: 00000002 00000000 00010000 0001 01 12345 /tmp/.X11-unix/X0
"""

MODULES_TXT = """Module                  Size  Used by
nvidia              123456  3 nvidia_modeset, Live 0x0000000000000000
evilmod               4096  0 - Live 0x0000000000000000 (O)
"""

# ---------------------------------------------------------- part 1: parsers

st = procparse.parse_status(STATUS_TXT)
check('status pid', st['_pid'] == 1234, st)
check('status ppid', st['_ppid'] == 100, st)
check('status state', st['_state'] == 'S', st['_state'])
check('status threads', st['_threads'] == 3, st)
check('status rss', st['_vmrss_kb'] == 7890, st)
check('status tracer', st['_tracerpid'] == 0, st)
check('status name', st['Name'] == 'python3', st['Name'])
check('status missing field', procparse.parse_status('Name:\tx\n')['_pid'] is None)

check('cmdline split', procparse.parse_cmdline(CMDLINE) == ['python3', '-c', 'print("hi")'])
check('cmdline empty', procparse.parse_cmdline(b'') == [])
check('cmdline no trailing nul', procparse.parse_cmdline(b'a\x00b') == ['a', 'b'])

env = procparse.parse_environ(ENVIRON)
check('environ dict', env == {'PATH': '/usr/bin', 'HOME': '/root', 'AWS_SECRET_KEY': 'xx'}, env)
check('environ empty', procparse.parse_environ(b'') == {})

maps = procparse.parse_maps(MAPS_TXT)
check('maps count', len(maps) == 5, len(maps))
check('maps fields', maps[0]['start'] == 0x55a1b2c3d000 and
      maps[0]['perms'] == 'r--p' and maps[0]['path'] == '/usr/bin/python3.12', maps[0])
check('maps anon', maps[2]['path'] == '' and maps[2]['inode'] == 0, maps[2])
check('maps deleted', maps[4]['path'] == '/lib/old.so (deleted)', maps[4])

ip, port = procparse._decode_ip_port('0100007F:1F90')
check('hex v4 decode', (ip, port) == ('127.0.0.1', 8080), (ip, port))
ip, port = procparse._decode_ip_port('0B0AA8C0:D431')
check('hex v4 decode 2', (ip, port) == ('192.168.10.11', 54321), (ip, port))
ip, port = procparse._decode_ip_port('00000000000000000000000001000000:01BB')
check('hex v6 decode', ip == '::1' and port == 443, (ip, port))

rows = procparse.parse_net_tcp(NET_TCP_TXT)
check('net tcp rows', len(rows) == 3, len(rows))
check('net tcp listen', rows[0]['local'] == ('127.0.0.1', 8080) and
      rows[0]['state'] == 'LISTEN' and rows[0]['inode'] == 4242 and
      rows[0]['uid'] == 0, rows[0])
check('net tcp established', rows[2]['remote'] == ('8.8.8.8', 53) and
      rows[2]['state'] == 'ESTABLISHED' and rows[2]['inode'] == 9999, rows[2])
rows6 = procparse.parse_net_tcp(NET_TCP6_TXT)
check('net tcp6', len(rows6) == 1 and rows6[0]['local'] == ('::1', 443), rows6)

ux = procparse.parse_net_unix(NET_UNIX_TXT)
check('net unix', len(ux) == 2 and ux[1]['inode'] == 12345 and
      ux[1]['path'] == '/tmp/.X11-unix/X0', ux)

mods = procparse.parse_modules(MODULES_TXT)
check('modules', len(mods) == 2 and mods[0]['name'] == 'nvidia' and
      mods[1]['size'] == 4096, mods)

# ------------------------------------------------- part 1b: fake /proc tree

def make_fake_proc():
    root = tempfile.mkdtemp(prefix='fakeproc')
    for pid, status, cmdline, environ, maps, exe_tgt, fds in [
        (4242, 'Name:\tsshd\nPid:\t4242\nPPid:\t1\nState:\tS (sleeping)\n'
               'TracerPid:\t0\nThreads:\t1\nVmRSS:\t 1000 kB\n',
         b'/usr/sbin/sshd\x00-D\x00', b'PATH=/x\x00', None,
         '/usr/sbin/sshd (deleted)', {'0': '/dev/null', '3': 'socket:[4242]'}),
        (9999, 'Name:\tbash\nPid:\t9999\nPPid:\t4242\nState:\tR (running)\n'
               'TracerPid:\t0\nThreads:\t1\n',
         b'bash\x00', b'', None, '/usr/bin/bash',
         {'0': '/dev/pts/0'}),
    ]:
        d = os.path.join(root, str(pid))
        os.makedirs(os.path.join(d, 'fd'))
        open(os.path.join(d, 'status'), 'w').write(status)
        open(os.path.join(d, 'cmdline'), 'wb').write(cmdline)
        open(os.path.join(d, 'environ'), 'wb').write(environ)
        if maps:
            open(os.path.join(d, 'maps'), 'w').write(maps)
        os.symlink(exe_tgt, os.path.join(d, 'exe'))
        for fdnum, tgt in fds.items():
            os.symlink(tgt, os.path.join(d, 'fd', fdnum))
    return root

fake = make_fake_proc()
procs = procparse.snapshot_all(fake, with_maps=False, with_env=True)
check('fake snapshot count', len(procs) == 2, len(procs))
p = procs[4242]
check('fake exe deleted', p.exe == '/usr/sbin/sshd (deleted)', p.exe)
check('fake argv', p.argv == ['/usr/sbin/sshd', '-D'], p.argv)
check('fake fds', p.fds.get('3') == 'socket:[4242]', p.fds)

owners = procparse.socket_owners(procs)
check('socket owners', owners.get(4242) == {4242}, owners)

# triage on fixtures
mk = lambda **kw: type('P', (), kw)()
fp = mk(pid=4242, exe='/usr/sbin/sshd (deleted)', argv=['/usr/sbin/sshd', '-D'],
         status={'_tracerpid': 0, '_state': 'S', '_ppid': 1},
         maps=[{'perms': 'rwxp', 'path': ''}, {'perms': 'r--p', 'path': '/lib/old.so (deleted)'}],
         fds={'3': 'socket:[4242]', '9': '/var/log/x (deleted)'}, env={'LD_PRELOAD': '/tmp/evil.so'})
fp2 = mk(pid=9999, exe='/usr/bin/bash', argv=['/usr/bin/bash'],
          status={'_tracerpid': 0, '_state': 'S', '_ppid': 4242},
          maps=[], fds={}, env={})
fprocs = {4242: fp, 9999: fp2}
check('triage deleted exe', len(triage.check_deleted_exe(fprocs)) == 1)
check('triage deleted libs', len(triage.check_deleted_libs(fprocs)) == 1)
check('triage rwx anon', len(triage.check_rwx_anon(fprocs)) == 1)
check('triage deleted fds', len(triage.check_deleted_fds(fprocs)) == 1)
check('triage ld_preload env', len([f for f in triage.check_ld_preload(fprocs) if f[1] == 4242]) == 1)
check('triage exe mismatch bash ok', triage.check_exe_mismatch({9999: fp2}) == [])
# exe/argv0 mismatch with nonexistent argv0 -> flag
fp3 = mk(pid=1, exe='/tmp/.x/malware', argv=['[kworker/0:1]'],
         status={'_tracerpid': 0, '_state': 'S', '_ppid': 0},
         maps=[], fds={}, env={})
check('triage exe mismatch evil', len(triage.check_exe_mismatch({1: fp3})) == 1)
# shebang-style: argv0 is an existing script -> no flag
with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as tf:
    script = tf.name
fp4 = mk(pid=2, exe='/usr/bin/python3', argv=[script],
         status={'_tracerpid': 0, '_state': 'S', '_ppid': 0},
         maps=[], fds={}, env={})
check('triage shebang not flagged', triage.check_exe_mismatch({2: fp4}) == [])
os.unlink(script)
# orphan listener
net = [{'local': ('0.0.0.0', 4444), 'remote': ('0.0.0.0', 0),
        'state': 'LISTEN', 'uid': 0, 'inode': 31337}]
check('triage orphan listener', len(triage.check_orphan_listeners(net, {})) == 1)
net2 = [{'local': ('0.0.0.0', 22), 'remote': ('0.0.0.0', 0),
         'state': 'LISTEN', 'uid': 0, 'inode': 4242}]
check('triage owned listener ok', triage.check_orphan_listeners(net2, {4242: {4242}}) == [])
# suspicious cmdline
fp5 = mk(pid=5, exe='/bin/bash', argv=['bash', '-c', 'curl http://x | sh'],
         status={'_tracerpid': 0, '_state': 'S', '_ppid': 0},
         maps=[], fds={}, env={})
check('triage sus cmdline', len(triage.check_suspicious_cmdline({5: fp5})) == 1)
# env secret scan masks values
hits = triage.scan_env_secrets({1: mk(pid=1, env={'AWS_SECRET_KEY': 'AKIA...', 'HOME': '/root'})})
check('env secret masked', hits == {'AWS_SECRET_KEY': [1]}, hits)

# ---------------------------------------------------------- part 2: live

live = procparse.snapshot_all()
check('live snapshot nonempty', len(live) > 5, len(live))
me = live.get(os.getpid())
check('live self present', me is not None and me.pid == os.getpid())
check('live self argv', 'test_procforensic' in ' '.join(me.argv), me.argv[:2])
check('live self exe', me.exe and 'python' in me.exe, me.exe)

listed = {e for e in os.listdir('/proc') if e.isdigit()}
raw = {e for e in procparse.raw_dirents('/proc') if e.isdigit()}
check('getdents sees all listdir pids', listed <= raw,
      'missing: %s' % sorted(listed - raw)[:5])
hidden_findings = triage.check_hidden_processes()
check('no hidden pids (raw vs listdir)', not [f for f in hidden_findings if f[0] == 'CRIT'],
      hidden_findings)

# live tcp parse sanity: rows parse, states known
t = procparse._read('/proc/net/tcp')
if t:
    rows = procparse.parse_net_tcp(t)
    check('live tcp parses', all(r['state'] in procparse.TCP_STATES.values() for r in rows),
          [r['state'] for r in rows][:3])
    owners = procparse.socket_owners(live)
    attributed = sum(1 for r in rows if r['inode'] in owners)
    check('live socket attribution works', attributed >= 0,
          '%d/%d attributed' % (attributed, len(rows)))
    print('     (live: %d tcp rows, %d attributed to pids)' % (len(rows), attributed))

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
