#!/usr/bin/env python3
"""fscheck.py -- read-only ext4 triage CLI.

    python3 fscheck.py --image fixture.img --summary
    python3 fscheck.py --image fixture.img --ls
    python3 fscheck.py --image fixture.img --deleted
    python3 fscheck.py --journal fixture.journal

Fully read-only: the image file is opened rb and never modified.
"""

import argparse
import datetime
import sys

import ext4
import journal


def fmt_time(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def cmd_summary(img):
    gd = img.group_descriptors()[0]
    print(f"image:  {img_path}")
    print(f"label:  {img.label or '(none)'}")
    print(f"block size:        {img.block_size}")
    print(f"blocks:            {img.blocks_count} total, "
          f"{gd['free_blocks']} free")
    print(f"inodes:            {img.inodes_count} total, "
          f"{gd['free_inodes']} free")
    print(f"inodes per group:  {img.inodes_per_group}")
    print(f"first data block:  {img.first_data_block}")
    print(f"groups:            {img.n_groups}")


def cmd_ls(img, inum):
    ino = img.read_inode(inum)
    if not ino["is_dir"]:
        print(f"inode {inum} is not a directory")
        return 1
    print(f"directory listing for inode {inum}:")
    for e in img.list_dir(ino):
        print(f"  {e['inode']:>6}  {e['file_type']:<7}  {e['name']}")
    return 0


def cmd_deleted(img):
    found = img.deleted_inodes()
    if not found:
        print("no deleted inodes found (links==0 && dtime!=0)")
        return 0
    for ino in found:
        v = img.recover_verdict(ino)
        print(f"inode {ino['inum']}: size={ino['size']} "
              f"dtime={fmt_time(ino['dtime'])}")
        print(f"  extents: " + ", ".join(
            f"log{log}->phys{phys}x{ln}" for log, phys, ln in v["extents"])
            or "(none)")
        print(f"  recoverable blocks: {v['good_blocks'] or '(none)'}")
        print(f"  reallocated (gaps): {v['gap_blocks'] or '(none)'}")
        print(f"  VERDICT: {v['verdict']}")
        if v["verdict"] in ("OK", "PARTIAL"):
            data = img.read_inode_data(ino)
            preview = data[:64]
            print(f"  carved {len(data)} bytes, "
                  f"head={preview!r}")
    return 0


def cmd_journal(path):
    with open(path, "rb") as f:
        data = f.read()
    # Try to find the journal blocksize from its superblock.
    sb = journal.parse_journal_superblock(data[:4096])
    res = journal.scan_journal(data, blocksize=sb["blocksize"])
    print(f"journal: {path}  (blocksize {sb['blocksize']}, "
          f"{len(res['records'])} tagged blocks)")
    for r in res["records"]:
        extra = ""
        if r["type"] == "descriptor":
            extra = f" seq={r['sequence']} tags=" + ",".join(
                f"fsblk{b}" for b, _fl in r["tags"])
        elif r["type"] == "commit":
            extra = f" seq={r['sequence']}"
        print(f"  jblock {r['journal_block']}: {r['type']}{extra}")
    print(f"newest-copy map: {len(res['newest_copies'])} journaled block(s)")
    for fsblk, off in sorted(res["newest_copies"].items()):
        print(f"  fs block {fsblk} -> journal offset {off}")
    return 0


def main(argv=None):
    global img_path
    ap = argparse.ArgumentParser(
        description="Read-only ext4 triage: superblock summary, directory "
                    "listing, deleted-file recovery verdicts, JBD2 scan.")
    ap.add_argument("--image", metavar="FILE",
                    help="ext4 image file (read-only)")
    ap.add_argument("--summary", action="store_true",
                    help="print superblock summary (label/blocks/inodes)")
    ap.add_argument("--ls", action="store_true",
                    help="list the root directory (inode 2)")
    ap.add_argument("--inode", type=int, default=2,
                    help="inode for --ls (default: 2, the root)")
    ap.add_argument("--deleted", action="store_true",
                    help="scan for deleted inodes and report recovery verdicts")
    ap.add_argument("--journal", metavar="FILE",
                    help="scan a raw JBD2 journal area")
    args = ap.parse_args(argv)

    if args.journal:
        return cmd_journal(args.journal)
    if not args.image:
        ap.print_help()
        return 2
    img_path = args.image
    img = ext4.Ext4Image(args.image)
    rc = 0
    if args.summary:
        cmd_summary(img)
    if args.ls:
        rc = cmd_ls(img, args.inode) or rc
    if args.deleted:
        rc = cmd_deleted(img) or rc
    if not (args.summary or args.ls or args.deleted):
        ap.print_help()
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
