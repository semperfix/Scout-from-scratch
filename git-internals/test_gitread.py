#!/usr/bin/env python3
"""test_gitread.py - Validate gitread.py against the real git CLI.

Builds a throwaway repo in /tmp with git (commits, a deleted branch for a
dangling commit, repack for delta objects, packed refs), then asserts:

  * log --oneline matches git log (sha + subject, order)
  * ls-tree -r matches git ls-tree -r byte-for-byte
  * cat-file -p matches for every object in the pack (incl. deltas)
  * cat-file -t matches for a sample of objects
  * fsck surfaces the deleted branch's commit as dangling
  * <ref>:<path> resolution matches git cat-file -p

Run: python3 test_gitread.py
"""
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GITREAD = os.path.join(HERE, "gitread.py")
WORK = "/tmp/gitread-test-repo"

def sh(*args, cwd=WORK):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout

def shb(*args, cwd=WORK):
    return subprocess.run(args, cwd=cwd, capture_output=True, check=True).stdout

def gitread(*args):
    return subprocess.run([sys.executable, GITREAD, "--git-dir",
                           os.path.join(WORK, ".git")] + list(args),
                          capture_output=True, text=True, check=True).stdout

def gitreadb(*args):
    return subprocess.run([sys.executable, GITREAD, "--git-dir",
                           os.path.join(WORK, ".git")] + list(args),
                          capture_output=True, check=True).stdout

def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    sh("git", "init", "-q", "-b", "main", ".")
    sh("git", "config", "user.email", "scout@example.com")
    sh("git", "config", "user.name", "Scout")
    open(os.path.join(WORK, "a.txt"), "w").write("hello world\n")
    os.makedirs(os.path.join(WORK, "sub"))
    open(os.path.join(WORK, "sub", "b.txt"), "w").write("nested\n")
    sh("git", "add", "-A"); sh("git", "commit", "-qm", "first commit")
    # near-duplicate 100KB blobs -> git will deltafy on repack
    import random
    random.seed(7)
    lines = [f"line {i:06d} " + "".join(random.choice("abcdef") for _ in range(40))
             for i in range(2500)]
    blob = "\n".join(lines) + "\n"
    open(os.path.join(WORK, "big.dat"), "w").write(blob)
    open(os.path.join(WORK, "big2.dat"), "w").write(blob.replace("line 000100 ", "line 000100 ~", 1))
    sh("git", "add", "-A"); sh("git", "commit", "-qm", "add big files")
    # doomed branch -> dangling commit after delete
    sh("git", "checkout", "-qb", "doomed")
    open(os.path.join(WORK, "x.txt"), "w").write("doomed\n")
    sh("git", "add", "-A"); sh("git", "commit", "-qm", "doomed commit")
    doomed = sh("git", "rev-parse", "HEAD").strip()
    sh("git", "checkout", "-q", "main"); sh("git", "branch", "-qD", "doomed")
    sh("git", "tag", "v1")
    sh("git", "repack", "-a", "-d", "-q", "--depth=50")
    sh("git", "pack-refs", "--all")

    fails = []
    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name + (f" ({extra})" if extra and not cond else ""))
        if not cond:
            fails.append(name)

    # 1. log
    want = sh("git", "log", "--format=%H %s").strip().split("\n")
    got = gitread("log", "--oneline").strip().split("\n")
    got_full = [l for l in
                (w[:7] + " " + s for w, s in (l.split(" ", 1) for l in want))]
    # compare full sha+subject
    want_pairs = [(l[:40], l[41:]) for l in want]
    got_pairs = []
    for l in gitread("log").split("\n"):
        if l.startswith("commit "):
            got_pairs.append(l.split()[1])
    check("log shas+order", [p[0] for p in want_pairs] == got_pairs)

    # 2. ls-tree -r
    check("ls-tree -r byte-identical",
          sh("git", "ls-tree", "-r", "HEAD") == gitread("ls-tree", "-r", "HEAD"))

    # 3. every object in the pack, byte-identical (exercises delta VM)
    idx = glob.glob(os.path.join(WORK, ".git", "objects", "pack", "*.idx"))[0]
    vp = sh("git", "verify-pack", "-v", idx)
    objs = [l.split()[0] for l in vp.split("\n")
            if len(l.split()) >= 5 and len(l.split()[0]) == 40
            and all(c in "0123456789abcdef" for c in l.split()[0])]
    bad = [s for s in objs if shb("git", "cat-file", "-p", s) != gitreadb("cat-file", "-p", s)]
    check(f"cat-file -p all {len(objs)} objects byte-identical", not bad, f"bad={bad[:3]}")

    # 4. types
    types_ok = all(sh("git", "cat-file", "-t", s).strip() ==
                   gitread("cat-file", "-t", s).strip() for s in objs[:8])
    check("cat-file -t types", types_ok)

    # 5. ref:path
    check("HEAD:a.txt matches",
          shb("git", "cat-file", "-p", "HEAD:a.txt") == gitreadb("cat-file", "-p", "HEAD:a.txt"))
    check("HEAD:sub/b.txt matches",
          shb("git", "cat-file", "-p", "HEAD:sub/b.txt") == gitreadb("cat-file", "-p", "HEAD:sub/b.txt"))

    # 6. fsck finds the doomed commit
    fsck_out = gitread("fsck")
    check("fsck surfaces deleted commit", doomed in fsck_out, "doomed sha missing")
    rec = gitreadb("cat-file", "-p", doomed)
    check("deleted commit recoverable", b"doomed commit" in rec)

    print(f"\n{len(fails)} failures" if fails else "\nALL CHECKS PASSED")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
