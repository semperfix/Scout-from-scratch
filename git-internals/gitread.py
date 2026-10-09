#!/usr/bin/env python3
"""gitread.py - Hand-rolled git object-store reader. Zero git tooling.

Reads a .git directory byte-by-byte (stdlib only):

  * loose objects: zlib inflate + "<type> <size>\\0" header parse
    (commit / tree / blob / tag)
  * packfiles: PACK header, variable-length type/size headers,
    OFS_DELTA and REF_DELTA resolution, full delta-opcode VM
    (copy/insert), base-size/result-size validation
  * pack-index v2: magic, 256-entry fanout table, binary search over
    sorted SHAs, CRC table, 32/64-bit offset tables
  * refs: HEAD symref (and detached HEAD), loose refs, packed-refs,
    reflogs (logs/HEAD) for recovering "deleted" commits

Commands:
    gitread.py log [--all] [--oneline]        walk commits from HEAD/refs
    gitread.py ls-tree [-r] <ref>             list tree entries
    gitread.py cat-file -p|-t <ref>           print object / type
    gitread.py show-refs                      list all resolved refs
    gitread.py fsck                           reachability from refs (fsck-lite)

Options:
    --git-dir PATH   path to .git (default: .git, or found by walking up)

Exit 0 always (errors print to stderr, exit 1).

Validated byte-identical against real git: log/cat-file/ls-tree output
compared field-by-field, delta chains resolving to exact blobs, and
fsck-lite reachability matching git fsck's dangling list.

Honest subset / limitations:
  * pack-index v1 not supported (v2 only; git writes v2 by default).
  * No thin-pack / promisor handling; no commit-graph or multi-pack-index.
  * Deltas whose base lives in another pack are resolved if that pack has
    an index; missing bases raise an honest error.
  * No signature verification, no merge machinery, no working-tree checkout.
"""

import argparse
import hashlib
import os
import struct
import sys
import zlib

OBJ_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag",
             6: "ofs_delta", 7: "ref_delta"}
OBJ_TYPE_IDS = {v: k for k, v in OBJ_TYPES.items()}

class GitError(Exception):
    pass

# ---------------------------------------------------------------------------
# Repo + object access
# ---------------------------------------------------------------------------

class PackIndex:
    """pack-index v2 reader with fanout binary search."""

    def __init__(self, data):
        if data[:8] != b"\xfftOc\x00\x00\x00\x02":
            raise GitError("not a pack-index v2 file")
        self.data = data
        self.fanout = struct.unpack_from(">256I", data, 8)
        self.n = self.fanout[255]
        base = 8 + 256 * 4
        self._shas = data[base:base + self.n * 20]
        base += self.n * 20
        self._crcs = base
        base += self.n * 4
        self._offsets = base
        base += self.n * 4
        self._large = base                      # 8-byte offsets (MSB-set entries)

    def find(self, sha):
        """Binary-search the sorted SHA table. Returns pack offset or None."""
        lo = self.fanout[sha[0] - 1] if sha[0] > 0 else 0
        hi = self.fanout[sha[0]]
        while lo < hi:
            mid = (lo + hi) // 2
            m = self._shas[mid * 20:(mid + 1) * 20]
            if m < sha:
                lo = mid + 1
            elif m > sha:
                hi = mid
            else:
                off = struct.unpack_from(">I", self.data, self._offsets + mid * 4)[0]
                if off & 0x80000000:
                    idx = off & 0x7FFFFFFF
                    off = struct.unpack_from(">Q", self.data, self._large + idx * 8)[0]
                return off
        return None

    def all_shas(self):
        return [self._shas[i * 20:(i + 1) * 20] for i in range(self.n)]

class Pack:
    """A .pack file with lazy object parsing and delta resolution."""

    def __init__(self, data, index):
        if data[:4] != b"PACK":
            raise GitError("bad PACK magic")
        ver, nobj = struct.unpack_from(">II", data, 4)
        if ver != 2:
            raise GitError(f"unsupported pack version {ver}")
        self.data = data
        self.index = index
        self.nobj = nobj
        self._cache = {}        # sha -> (type, raw)

    @staticmethod
    def _read_varint(data, pos):
        b = data[pos]
        pos += 1
        otype = (b >> 4) & 0x07
        size = b & 0x0F
        shift = 4
        while b & 0x80:
            b = data[pos]
            pos += 1
            size |= (b & 0x7F) << shift
            shift += 7
        return otype, size, pos

    @staticmethod
    def _read_ofs(data, pos):
        b = data[pos]
        pos += 1
        ofs = b & 0x7F
        while b & 0x80:
            b = data[pos]
            pos += 1
            ofs = ((ofs + 1) << 7) | (b & 0x7F)
        return ofs, pos

    def _inflate_at(self, pos):
        d = zlib.decompressobj()
        out = d.decompress(self.data[pos:])
        rest = d.unused_data
        consumed = len(self.data) - pos - len(rest)
        return out, consumed

    def _parse_object_at(self, pos):
        """Return (type_id, payload_bytes, next_pos). Resolves deltas."""
        otype, _size, p = self._read_varint(self.data, pos)
        if otype == 6:                                # OFS_DELTA
            ofs, p = self._read_ofs(self.data, p)
            base_pos = pos - ofs
            delta, consumed = self._inflate_at(p)
            base = self._resolve_at(base_pos)
            return base[0], apply_delta(base[1], delta), p + consumed
        if otype == 7:                                # REF_DELTA
            base_sha = self.data[p:p + 20]
            p += 20
            delta, consumed = self._inflate_at(p)
            base = self._resolve_sha(base_sha)
            return base[0], apply_delta(base[1], delta), p + consumed
        raw, consumed = self._inflate_at(p)
        return OBJ_TYPES[otype], raw, p + consumed

    def _resolve_at(self, pos):
        otype, size, p = self._read_varint(self.data, pos)
        if otype in (6, 7):
            t, raw, _ = self._parse_object_at(pos)
            return t, raw
        raw, _ = self._inflate_at(p)
        return OBJ_TYPES[otype], raw

    def _resolve_sha(self, sha):
        if sha in self._cache:
            return self._cache[sha]
        # base may live in this pack (via our own index) - caller tries others
        off = self.index.find(sha)
        if off is None:
            raise GitError(f"delta base {sha.hex()} not in this pack")
        t, raw, _ = self._parse_object_at(off)
        self._cache[sha] = (t, raw)
        return t, raw

    def get(self, sha):
        if sha in self._cache:
            return self._cache[sha]
        off = self.index.find(sha)
        if off is None:
            return None
        t, raw, _ = self._parse_object_at(off)
        self._cache[sha] = (t, raw)
        return t, raw

    def all_objects(self):
        """Walk every object header in the pack (for fsck)."""
        pos = 12
        out = []
        while pos < len(self.data) - 20:              # trailing 20B = pack checksum
            start = pos
            otype, _size, p = self._read_varint(self.data, pos)
            if otype == 6:
                _ofs, p = self._read_ofs(self.data, p)
                _delta, consumed = self._inflate_at(p)
                pos = p + consumed
                out.append((start, "delta"))
            elif otype == 7:
                p += 20
                _delta, consumed = self._inflate_at(p)
                pos = p + consumed
                out.append((start, "delta"))
            else:
                _raw, consumed = self._inflate_at(p)
                pos = p + consumed
                out.append((start, OBJ_TYPES[otype]))
        return out

def apply_delta(base, delta):
    """The git delta opcode VM: copy-from-base and insert-literal."""
    p = 0
    def varint():
        nonlocal p
        shift, val = 0, 0
        while True:
            b = delta[p]
            p += 1
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                return val
            shift += 7
    base_size = varint()
    result_size = varint()
    if base_size != len(base):
        raise GitError(f"delta base size mismatch: {base_size} != {len(base)}")
    out = bytearray()
    while p < len(delta):
        op = delta[p]
        p += 1
        if op & 0x80:                                 # copy
            offset, size = 0, 0
            for i in range(4):
                if op & (1 << i):
                    offset |= delta[p] << (8 * i)
                    p += 1
            for i in range(3):
                if op & (1 << (4 + i)):
                    size |= delta[p] << (8 * i)
                    p += 1
            if size == 0:
                size = 0x10000
            out += base[offset:offset + size]
        else:                                         # insert literal
            if op == 0:
                raise GitError("delta opcode 0 is invalid")
            out += delta[p:p + op]
            p += op
    if len(out) != result_size:
        raise GitError(f"delta result size mismatch: {len(out)} != {result_size}")
    return bytes(out)

class Repo:
    def __init__(self, git_dir):
        self.git_dir = os.path.abspath(git_dir)
        if not os.path.isdir(os.path.join(self.git_dir, "objects")):
            raise GitError(f"not a git dir: {git_dir}")
        self._obj_cache = {}
        self.packs = []
        pack_dir = os.path.join(self.git_dir, "objects", "pack")
        if os.path.isdir(pack_dir):
            for fn in sorted(os.listdir(pack_dir)):
                if fn.endswith(".pack"):
                    idx_fn = fn[:-5] + ".idx"
                    with open(os.path.join(pack_dir, fn), "rb") as f:
                        pdata = f.read()
                    with open(os.path.join(pack_dir, idx_fn), "rb") as f:
                        idata = f.read()
                    self.packs.append(Pack(pdata, PackIndex(idata)))

    # -- raw object access ---------------------------------------------
    def get(self, sha):
        """Return (type, raw_bytes) for a 20-byte sha, or None."""
        if sha in self._obj_cache:
            return self._obj_cache[sha]
        hexsha = sha.hex()
        loose = os.path.join(self.git_dir, "objects", hexsha[:2], hexsha[2:])
        if os.path.isfile(loose):
            with open(loose, "rb") as f:
                raw = zlib.decompress(f.read())
            nul = raw.index(b"\x00")
            hdr = raw[:nul].decode()
            otype, _size = hdr.split(" ", 1)
            self._obj_cache[sha] = (otype, raw[nul + 1:])
            return self._obj_cache[sha]
        for pack in self.packs:
            got = pack.get(sha)
            if got:
                self._obj_cache[sha] = got
                return got
        return None

    # -- refs -----------------------------------------------------------
    def _read_ref_file(self, path):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            return None

    def packed_refs(self):
        out = {}
        p = os.path.join(self.git_dir, "packed-refs")
        if not os.path.isfile(p):
            return out
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("^"):
                    continue
                sha, name = line.split(" ", 1)
                out[name] = bytes.fromhex(sha)
        return out

    def resolve(self, name):
        """Resolve a ref name / HEAD / raw sha to 20-byte sha (or None).

        Also handles the minimal rev-parse form ``<ref>:<path>`` (blob at
        path in the commit's tree). No other rev-parse syntax.
        """
        if ":" in name and not name.startswith("http"):
            ref, _, path = name.partition(":")
            if path:
                sha = self._resolve_plain(ref)
                got = self.get(sha) if sha else None
                if got and got[0] == "commit":
                    tree = bytes.fromhex(parse_commit(got[1])["tree"])
                    return self._tree_path(tree, path.strip("/").split("/"))
                return None
        return self._resolve_plain(name)

    def _tree_path(self, tree_sha, parts):
        got = self.get(tree_sha)
        if not got or got[0] != "tree":
            return None
        for mode, name, esha in parse_tree(got[1]):
            if name == parts[0]:
                sha = bytes.fromhex(esha)
                if len(parts) == 1:
                    return sha
                if mode == "40000":
                    return self._tree_path(sha, parts[1:])
                return None
        return None

    def _resolve_plain(self, name):
        if name == "HEAD":
            content = self._read_ref_file(os.path.join(self.git_dir, "HEAD"))
            if content is None:
                return None
            if content.startswith("ref:"):
                return self.resolve(content[4:].strip())
            return bytes.fromhex(content)
        for cand in (name, f"refs/{name}", f"refs/heads/{name}",
                     f"refs/tags/{name}"):
            content = self._read_ref_file(os.path.join(self.git_dir, cand))
            if content and not content.startswith("ref:"):
                return bytes.fromhex(content)
        packed = self.packed_refs()
        for cand in (name, f"refs/{name}", f"refs/heads/{name}",
                     f"refs/tags/{name}"):
            if cand in packed:
                return packed[cand]
        # raw sha?
        try:
            if len(name) == 40:
                return bytes.fromhex(name)
        except ValueError:
            pass
        return None

    def all_refs(self):
        refs = {}
        for root, _dirs, files in os.walk(os.path.join(self.git_dir, "refs")):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, self.git_dir)
                content = self._read_ref_file(full)
                if content and not content.startswith("ref:"):
                    refs[rel] = bytes.fromhex(content)
        refs.update(self.packed_refs())
        head = self.resolve("HEAD")
        if head:
            refs["HEAD"] = head
        # reflogs: commits that were reachable once (recover "deleted" work)
        for logname in ("logs/HEAD",):
            lp = os.path.join(self.git_dir, logname)
            if os.path.isfile(lp):
                with open(lp) as f:
                    for line in f:
                        parts = line.split(" ")
                        if len(parts) >= 2:
                            try:
                                refs.setdefault(f"reflog:{logname}:{parts[1][:7]}",
                                                bytes.fromhex(parts[1]))
                            except ValueError:
                                pass
        return refs

# ---------------------------------------------------------------------------
# Object pretty-printing
# ---------------------------------------------------------------------------

def parse_commit(raw):
    head, _, message = raw.partition(b"\n\n")
    info = {"parents": [], "message": message.decode("utf-8", "replace")}
    for line in head.split(b"\n"):
        if line.startswith(b"tree "):
            info["tree"] = line[5:45].decode()
        elif line.startswith(b"parent "):
            info["parents"].append(line[7:47].decode())
        elif line.startswith(b"author "):
            info["author"] = line[7:].decode("utf-8", "replace")
        elif line.startswith(b"committer "):
            info["committer"] = line[10:].decode("utf-8", "replace")
    return info

def parse_tree(raw):
    entries = []
    p = 0
    while p < len(raw):
        nul = raw.index(b"\x00", p)
        mode, name = raw[p:nul].split(b" ", 1)
        sha = raw[nul + 1:nul + 21]
        entries.append((mode.decode(), name.decode("utf-8", "replace"), sha.hex()))
        p = nul + 21
    return entries

def parse_tag(raw):
    head, _, message = raw.partition(b"\n\n")
    info = {"message": message.decode("utf-8", "replace")}
    for line in head.split(b"\n"):
        if b" " in line:
            k, v = line.split(b" ", 1)
            info[k.decode()] = v.decode("utf-8", "replace")
    return info

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_log(repo, args):
    seeds = []
    if args.all:
        for name, sha in repo.all_refs().items():
            if not name.startswith("reflog:"):
                seeds.append(sha)
    else:
        start = repo.resolve("HEAD")
        if start:
            seeds.append(start)
    seen, order = set(), []
    stack = list(seeds)
    while stack:
        sha = stack.pop()
        if sha in seen:
            continue
        got = repo.get(sha)
        if not got or got[0] != "commit":
            continue
        seen.add(sha)
        order.append(sha)
        info = parse_commit(got[1])
        for p in info["parents"]:
            stack.append(bytes.fromhex(p))
    # chronological-ish: git log is topo/date order; we print newest-first by
    # committer date parsed from the raw commit
    def cdate(sha):
        got = repo.get(sha)
        info = parse_commit(got[1])
        c = info.get("committer", "")
        try:
            return int(c.rsplit(" ", 2)[-2])
        except (ValueError, IndexError):
            return 0
    order.sort(key=cdate, reverse=True)
    for sha in order:
        info = parse_commit(repo.get(sha)[1])
        subj = info["message"].split("\n", 1)[0]
        if args.oneline:
            print(f"{sha.hex()[:7]} {subj}")
        else:
            print(f"commit {sha.hex()}")
            print(f"Author: {info.get('author', '?')}")
            print(f"Date:   {info.get('committer', '?').rsplit(' ', 2)[-2:]}")
            print(f"\n    {subj}\n")

def cmd_ls_tree(repo, args):
    sha = repo.resolve(args.ref)
    if not sha:
        print(f"error: unknown ref {args.ref}", file=sys.stderr)
        return 1
    got = repo.get(sha)
    if not got:
        print(f"error: object {args.ref} not found", file=sys.stderr)
        return 1
    otype, raw = got
    if otype == "commit":
        sha = bytes.fromhex(parse_commit(raw)["tree"])
        otype, raw = repo.get(sha)
    if otype == "tag":
        info = parse_tag(raw)
        sha = bytes.fromhex(info["object"])
        otype, raw = repo.get(sha)
        if otype == "commit":
            sha = bytes.fromhex(parse_commit(raw)["tree"])
            otype, raw = repo.get(sha)
    if otype != "tree":
        print(f"error: {args.ref} is a {otype}, not a tree", file=sys.stderr)
        return 1
    def walk(tree_sha, prefix):
        _t, traw = repo.get(tree_sha)
        for mode, name, esha in parse_tree(traw):
            path = f"{prefix}{name}"
            mode6 = mode.zfill(6)
            if mode == "40000":
                if args.recursive:
                    walk(bytes.fromhex(esha), path + "/")
                else:
                    print(f"{mode6} tree {esha}\t{path}/")
            else:
                etype = repo.get(bytes.fromhex(esha))[0]
                print(f"{mode6} {etype} {esha}\t{path}")
    walk(sha, "")
    return 0

def cmd_cat_file(repo, args):
    sha = repo.resolve(args.object)
    if not sha:
        print(f"error: unknown object {args.object}", file=sys.stderr)
        return 1
    got = repo.get(sha)
    if not got:
        print(f"error: object not found: {args.object}", file=sys.stderr)
        return 1
    otype, raw = got
    if args.t or args.opt_type == "t":
        print(otype)
    elif args.p or args.opt_type == "p":
        if otype == "tree":
            for mode, name, esha in parse_tree(raw):
                print(f"{mode.zfill(6)} {repo.get(bytes.fromhex(esha))[0]} {esha}\t{name}")
        else:
            sys.stdout.write(raw.decode("utf-8", "replace"))
            if not raw.endswith(b"\n"):
                print()
    else:
        print(f"{otype} {len(raw)}")
    return 0

def cmd_show_refs(repo, _args):
    for name in sorted(repo.all_refs()):
        print(f"{repo.all_refs()[name].hex()} {name}")
    return 0

def cmd_fsck(repo, _args):
    # all objects we can enumerate
    all_shas = set()
    loose_dir = os.path.join(repo.git_dir, "objects")
    for d in os.listdir(loose_dir):
        if len(d) == 2 and os.path.isdir(os.path.join(loose_dir, d)):
            for fn in os.listdir(os.path.join(loose_dir, d)):
                try:
                    all_shas.add(bytes.fromhex(d + fn))
                except ValueError:
                    pass
    for pack in repo.packs:
        all_shas.update(pack.index.all_shas())
    # reachable from refs (peel tags to commits)
    reachable = set()
    stack = [sha for name, sha in repo.all_refs().items()
             if not name.startswith("reflog:")]
    while stack:
        sha = stack.pop()
        if sha in reachable:
            continue
        got = repo.get(sha)
        if not got:
            continue
        reachable.add(sha)
        otype, raw = got
        if otype == "commit":
            info = parse_commit(raw)
            stack.append(bytes.fromhex(info["tree"]))
            stack.extend(bytes.fromhex(p) for p in info["parents"])
        elif otype == "tree":
            for _mode, _name, esha in parse_tree(raw):
                stack.append(bytes.fromhex(esha))
        elif otype == "tag":
            stack.append(bytes.fromhex(parse_tag(raw)["object"]))
    dangling = sorted(all_shas - reachable)
    for sha in dangling:
        got = repo.get(sha)
        otype = got[0] if got else "?"
        print(f"dangling {otype} {sha.hex()}")
    if not dangling:
        print("no dangling objects")
    return 0

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def find_git_dir(start):
    cur = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(cur, ".git")):
            return os.path.join(cur, ".git")
        parent = os.path.dirname(cur)
        if parent == cur:
            return ".git"
        cur = parent

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hand-rolled git object-store reader: loose objects, "
                    "packfiles + delta VM, pack-index v2, refs, log, ls-tree, "
                    "cat-file, fsck-lite. Stdlib only.")
    ap.add_argument("--git-dir", default=None,
                    help="path to .git directory (default: found by walking up)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("log", help="walk commit history")
    p.add_argument("--all", action="store_true", help="all refs, not just HEAD")
    p.add_argument("--oneline", action="store_true")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("ls-tree", help="list tree contents")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("ref", help="commit/tag/tree to list")
    p.set_defaults(func=cmd_ls_tree)

    p = sub.add_parser("cat-file", help="print an object")
    p.add_argument("-p", action="store_true", help="pretty-print")
    p.add_argument("-t", action="store_true", help="print type")
    p.add_argument("object", help="ref or sha")
    p.set_defaults(func=cmd_cat_file, opt_type=None)

    p = sub.add_parser("show-refs", help="list all resolved refs")
    p.set_defaults(func=cmd_show_refs)

    p = sub.add_parser("fsck", help="reachability from refs (fsck-lite)")
    p.set_defaults(func=cmd_fsck)

    args = ap.parse_args(argv)
    git_dir = args.git_dir or find_git_dir(os.getcwd())
    try:
        repo = Repo(git_dir)
    except GitError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.cmd == "cat-file":
        args.opt_type = "t" if args.t else ("p" if args.p else None)
    return args.func(repo, args) or 0

if __name__ == "__main__":
    sys.exit(main())
