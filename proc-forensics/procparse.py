"""procparse.py — hand-rolled /proc parsers, zero dependencies.

Every parser takes raw text/bytes (testable against synthetic fixtures) and
returns structured data. Live reads are isolated in ProcFS so the parsers
never touch the real /proc.
"""
import os
import struct
import ctypes
import ctypes.util

# ---------------------------------------------------------------- status

def parse_status(text):
    """Parse /proc/<pid>/status into a dict. Handles the 'Name: python3'
    single-tab format plus multi-tab fields."""
    out = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, _, val = line.partition(':')
        out[key.strip()] = val.strip()
    # typed conveniences (absent -> None)
    def _int(key):
        try:
            return int(out[key].split()[0])
        except (KeyError, ValueError, IndexError):
            return None
    out['_pid'] = _int('Pid')
    out['_ppid'] = _int('PPid')
    out['_threads'] = _int('Threads')
    out['_tracerpid'] = _int('TracerPid')
    out['_vmrss_kb'] = _int('VmRSS')
    out['_vmsize_kb'] = _int('VmSize')
    state = out.get('State', '')
    out['_state'] = state.split()[0] if state else '?'
    return out

# ---------------------------------------------------------------- cmdline / environ

def parse_cmdline(data):
    """bytes -> argv list. /proc/<pid>/cmdline is NUL-separated; kernel
    threads produce b'' (empty, not [''])."""
    if not data:
        return []
    parts = data.split(b'\x00')
    # trailing NUL leaves a final b''; drop it, but keep interior empties
    if parts and parts[-1] == b'':
        parts.pop()
    return [p.decode('utf-8', 'replace') for p in parts]

def parse_environ(data):
    """bytes -> {KEY: value} dict."""
    env = {}
    if not data:
        return env
    parts = data.split(b'\x00')
    if parts and parts[-1] == b'':
        parts.pop()
    for p in parts:
        s = p.decode('utf-8', 'replace')
        if '=' in s:
            k, _, v = s.partition('=')
            env[k] = v
    return env

# ---------------------------------------------------------------- maps

def parse_maps(text):
    """Parse /proc/<pid>/maps. Each line:
    start-end perms offset dev inode pathname"""
    maps = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # pathname is optional and may contain spaces -> split max 5
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        addr, perms, offset, dev, inode = parts[:5]
        path = parts[5] if len(parts) > 5 else ''
        try:
            start_s, end_s = addr.split('-')
            start, end = int(start_s, 16), int(end_s, 16)
            off = int(offset, 16)
            ino = int(inode)
        except ValueError:
            continue
        maps.append({
            'start': start, 'end': end, 'perms': perms,
            'offset': off, 'dev': dev, 'inode': ino, 'path': path,
        })
    return maps

# ---------------------------------------------------------------- /proc/net/*

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV',
}

def _decode_ip_port(hexaddr):
    """'7F000001:0050' -> ('127.0.0.1', 80). Kernel stores addresses in
    host byte order per 32-bit word, so each 8-hex group is byte-reversed
    for display. IPv6: 32 hex chars -> 4 reversed words."""
    addr, _, port_s = hexaddr.partition(':')
    port = int(port_s, 16)
    if len(addr) == 8:
        raw = bytes.fromhex(addr)
        ip = '.'.join(str(b) for b in raw[::-1])
    elif len(addr) == 32:
        groups = []
        for i in range(0, 32, 8):
            word = bytes.fromhex(addr[i:i + 8])[::-1]
            # each 32-bit word is two 16-bit groups
            groups.append('%02x%02x' % (word[0], word[1]))
            groups.append('%02x%02x' % (word[2], word[3]))
        ip = ':'.join(groups)
        # minimal :: compression for display
        ip = _compress_v6(ip)
    else:
        ip = addr
    return ip, port

def _compress_v6(ip):
    parts = ip.split(':')
    best_start, best_len = -1, 0
    i = 0
    while i < len(parts):
        if parts[i] == '0000':
            j = i
            while j < len(parts) and parts[j] == '0000':
                j += 1
            if j - i > best_len:
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    if best_len < 2:
        return ':'.join(p.lstrip('0') or '0' for p in parts)
    head = ':'.join(p.lstrip('0') or '0' for p in parts[:best_start])
    tail = ':'.join(p.lstrip('0') or '0' for p in parts[best_start + best_len:])
    if not head:
        return '::' + tail if tail else '::'
    if not tail:
        return head + '::'
    return head + '::' + tail

def parse_net_tcp(text):
    """Parse /proc/net/tcp or tcp6. Column positions found from the header
    line so kernel layout changes don't silently shift fields."""
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    header = lines[0].split()
    cols = {name: i for i, name in enumerate(header)}
    # tcp uses 'rem_address', tcp6 uses 'remote_address'
    ri_name = 'rem_address' if 'rem_address' in cols else 'remote_address'
    li, ri, sti = cols['local_address'], cols[ri_name], cols['st']
    # NOTE: the header lists 'tr' and 'tm->when' as two columns, but the
    # kernel prints them merged as one 'TR:TMWHEN' field, so every data
    # column after 'st' sits one slot left of its header index. Anchor
    # uid/inode relative to 'st' instead of trusting the header.
    uidi, inoi = sti + 4, sti + 6
    rows = []
    for line in lines[1:]:
        f = line.split()
        if len(f) <= max(li, ri, sti, uidi, inoi):
            continue
        try:
            lip, lport = _decode_ip_port(f[li])
            rip, rport = _decode_ip_port(f[ri])
            rows.append({
                'local': (lip, lport), 'remote': (rip, rport),
                'state': TCP_STATES.get(f[sti], f[sti]),
                'uid': int(f[uidi]), 'inode': int(f[inoi]),
            })
        except (ValueError, IndexError):
            continue
    return rows

def parse_net_unix(text):
    """Parse /proc/net/unix -> list of {inode, path}."""
    out = []
    lines = [l for l in text.splitlines() if l.strip()]
    for line in lines[1:]:  # skip header
        f = line.split()
        # Num RefCount Protocol Flags Type St Inode [Path]
        if len(f) < 7:
            continue
        try:
            inode = int(f[6])
        except ValueError:
            continue
        path = f[7] if len(f) > 7 else ''
        out.append({'inode': inode, 'path': path})
    return out

def parse_modules(text):
    mods = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] == 'Module':
            continue
        try:
            mods.append({'name': f[0], 'size': int(f[1]),
                         'used': int(f[2]), 'state': f[4], 'src': f[5]})
        except (ValueError, IndexError):
            continue
    return mods

# ---------------------------------------------------------------- raw getdents64

SYS_getdents64 = 217  # x86_64

_libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

def raw_dirents(path):
    """List directory entries using the raw getdents64 syscall — the
    technique rootkit detectors use: a hooked readdir (libc) can hide
    entries that the raw syscall still shows."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    names = []
    try:
        buf = ctypes.create_string_buffer(8192)
        syscall = _libc.syscall
        syscall.restype = ctypes.c_long
        while True:
            n = syscall(SYS_getdents64, fd, buf, 8192)
            if n <= 0:
                break
            data = buf.raw[:n]
            off = 0
            while off < n:
                d_ino, d_off, d_reclen = struct.unpack_from('<QqH', data, off)
                d_type = data[off + 18]
                if d_reclen == 0:
                    break
                name_end = data.index(b'\x00', off + 19, off + d_reclen)
                name = data[off + 19:name_end].decode('utf-8', 'replace')
                names.append(name)
                off += d_reclen
    finally:
        os.close(fd)
    return names

# ---------------------------------------------------------------- live snapshot

def _read(path, mode='r'):
    try:
        with open(path, mode) as fh:
            return fh.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None

class Process:
    __slots__ = ('pid', 'name', 'status', 'argv', 'env', 'maps',
                 'exe', 'exe_err', 'fds', 'wchan')
    def __init__(self, pid):
        self.pid = pid
        self.name = None
        self.status = {}
        self.argv = []
        self.env = {}
        self.maps = []
        self.exe = None       # readlink of /proc/<pid>/exe, None on failure
        self.exe_err = None
        self.fds = {}         # fdnum -> link target (or None)
        self.wchan = None

def snapshot_proc(pid, proc_root='/proc', with_maps=True, with_env=True,
                  with_fds=True):
    """Best-effort snapshot of one pid. Missing files (vanished pid,
    permission) degrade gracefully to None/empty."""
    p = Process(pid)
    base = os.path.join(proc_root, str(pid))
    st = _read(os.path.join(base, 'status'))
    if st is None:
        return None
    p.status = parse_status(st)
    p.name = p.status.get('Name')
    raw = _read(os.path.join(base, 'cmdline'), 'rb')
    p.argv = parse_cmdline(raw) if raw is not None else []
    if with_env:
        raw = _read(os.path.join(base, 'environ'), 'rb')
        p.env = parse_environ(raw) if raw is not None else {}
    if with_maps:
        m = _read(os.path.join(base, 'maps'))
        p.maps = parse_maps(m) if m is not None else []
    try:
        p.exe = os.readlink(os.path.join(base, 'exe'))
    except OSError as e:
        p.exe_err = str(e)
    if with_fds:
        fddir = os.path.join(base, 'fd')
        try:
            for fdnum in os.listdir(fddir):
                try:
                    p.fds[fdnum] = os.readlink(os.path.join(fddir, fdnum))
                except OSError:
                    p.fds[fdnum] = None
        except OSError:
            pass
    p.wchan = _read(os.path.join(base, 'wchan'))
    return p

def snapshot_all(proc_root='/proc', **kw):
    """Snapshot every numeric entry under proc_root."""
    procs = {}
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return procs
    for e in entries:
        if not e.isdigit():
            continue
        pid = int(e)
        p = snapshot_proc(pid, proc_root, **kw)
        if p is not None:
            procs[pid] = p
    return procs

def socket_owners(procs):
    """inode -> set of pids holding a fd to socket:[inode]."""
    owners = {}
    for pid, p in procs.items():
        for tgt in p.fds.values():
            if tgt and tgt.startswith('socket:[') and tgt.endswith(']'):
                try:
                    ino = int(tgt[8:-1])
                except ValueError:
                    continue
                owners.setdefault(ino, set()).add(pid)
    return owners
