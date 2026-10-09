"""ext4.py -- hand-rolled read-only ext4 parser (stdlib only).

Parses: superblock (at byte offset 1024), group descriptor table, the inode
table (256-byte inodes), extent trees (leaf + index levels), linear directory
entries, and block bitmaps. Deleted-file triage: scan the inode table for
links==0 && dtime!=0, walk the (usually still intact) extent tree, and
cross-check every data block against the block bitmap.

Verdicts:
    OK      -- every data block is still marked free (recoverable as-is)
    PARTIAL -- some blocks were reallocated; recoverable blocks returned,
               reallocated ranges reported as gaps (would read as zeros)
    GONE    -- no extent tree left, or every block reallocated

Honest subset: 32-bit block/inode counts only (no 64bit feature), no
huge_file / inline_data / inline extents, linear (non-htree) directories
only, no journal replay -- the JBD2 *scanner* lives in journal.py.
Everything is read-only; the image is never modified.
"""

import struct

SB_MAGIC = 0xEF53
EXTENT_MAGIC = 0xF30A

S_IFDIR = 0o040000
S_IFREG = 0o100000

DIR_FILE_TYPES = {0: "unknown", 1: "file", 2: "dir", 5: "fifo",
                  6: "sock", 7: "symlink"}


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


class Ext4Image:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse_superblock()

    # -- superblock ------------------------------------------------------
    def _parse_superblock(self):
        sb = self.data[1024:1024 + 1024]
        if len(sb) < 1024:
            raise ValueError("image too small for a superblock")
        if _u16(sb, 56) != SB_MAGIC:
            raise ValueError("bad ext4 magic (not 0xEF53)")
        self.inodes_count = _u32(sb, 0)
        self.blocks_count = _u32(sb, 4)
        self.first_data_block = _u32(sb, 20)
        self.block_size = 1024 << _u32(sb, 24)
        self.blocks_per_group = _u32(sb, 32)
        self.inodes_per_group = _u32(sb, 40)
        self.inode_size = _u16(sb, 90)
        self.first_ino = _u16(sb, 88)
        self.label = sb[112:128].split(b"\x00")[0].decode("ascii", "replace")
        self.uuid = sb[96:112]
        desc_size = _u16(sb, 254)
        self.desc_size = desc_size if desc_size >= 32 else 32
        n_groups = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group
        self.n_groups = n_groups

    def block_offset(self, block_no):
        return block_no * self.block_size

    def read_block(self, block_no):
        off = self.block_offset(block_no)
        return self.data[off:off + self.block_size]

    # -- group descriptors ------------------------------------------------
    def group_descriptors(self):
        # GDT starts at the first block after the superblock.
        gdt_block = self.first_data_block + 1
        out = []
        for g in range(self.n_groups):
            off = self.block_offset(gdt_block) + g * self.desc_size
            d = self.data[off:off + self.desc_size]
            out.append({
                "group": g,
                "block_bitmap": _u32(d, 0),
                "inode_bitmap": _u32(d, 4),
                "inode_table": _u32(d, 8),
                "free_blocks": _u16(d, 12),
                "free_inodes": _u16(d, 14),
                "used_dirs": _u16(d, 16),
            })
        return out

    # -- inodes ------------------------------------------------------------
    def read_inode(self, inum):
        if not 1 <= inum <= self.inodes_count:
            raise ValueError(f"inode {inum} out of range")
        group = (inum - 1) // self.inodes_per_group
        idx = (inum - 1) % self.inodes_per_group
        gd = self.group_descriptors()[group]
        off = (self.block_offset(gd["inode_table"])
               + idx * self.inode_size)
        b = self.data[off:off + self.inode_size]
        mode = _u16(b, 0)
        size = _u32(b, 4) | (_u32(b, 108) << 32)
        return {
            "inum": inum,
            "mode": mode,
            "is_dir": bool(mode & S_IFDIR),
            "is_reg": bool(mode & S_IFREG),
            "size": size,
            "atime": _u32(b, 8), "ctime": _u32(b, 12),
            "mtime": _u32(b, 16), "dtime": _u32(b, 20),
            "links": _u16(b, 26),
            "blocks_512": _u32(b, 28),
            "flags": _u32(b, 32),
            "extent_raw": b[40:100],   # i_block[60]
        }

    # -- extent tree walker -------------------------------------------------
    def extent_walk(self, inode):
        """Return [(logical_block, physical_block, length_blocks)]."""
        raw = inode["extent_raw"]
        return self._walk_extent_node(raw, 0)

    def _walk_extent_node(self, node, depth_from_header):
        if _u16(node, 0) != EXTENT_MAGIC:
            return []
        entries = _u16(node, 2)
        depth = _u16(node, 6)
        out = []
        for i in range(entries):
            e = node[12 + 12 * i: 24 + 12 * i]
            if depth == 0:
                ee_block = _u32(e, 0)
                ee_len = _u16(e, 4)
                ee_start = _u32(e, 8) | (_u16(e, 6) << 32)
                out.append((ee_block, ee_start, ee_len))
            else:
                child = _u32(e, 4) | (_u16(e, 8) << 32)
                child_node = self.read_block(child)[:60]
                out.extend(self._walk_extent_node(child_node, depth - 1))
        return sorted(out)

    # -- linear directories ---------------------------------------------------
    def list_dir(self, inode):
        """Linear directory entries; zeroed (deleted) entries are skipped."""
        if isinstance(inode, int):
            inode = self.read_inode(inode)
        entries = []
        for log, phys, length in self.extent_walk(inode):
            for blk in range(phys, phys + length):
                data = self.read_block(blk)
                off = 0
                while off + 8 <= len(data):
                    ino = _u32(data, off)
                    rec_len = _u16(data, off + 4)
                    if rec_len == 0:
                        break  # corrupt; stop rather than spin
                    name_len = data[off + 6]
                    ftype = data[off + 7]
                    if ino != 0 and name_len:
                        name = data[off + 8: off + 8 + name_len].decode(
                            "utf-8", "replace")
                        entries.append({
                            "inode": ino, "name": name,
                            "file_type": DIR_FILE_TYPES.get(ftype, str(ftype)),
                        })
                    off += rec_len
        return entries

    # -- block bitmap ---------------------------------------------------------
    def block_is_used(self, block_no):
        gd = self.group_descriptors()[(block_no) // self.blocks_per_group]
        bmp = self.read_block(gd["block_bitmap"])
        rel = block_no % self.blocks_per_group
        return bool(bmp[rel // 8] & (1 << (rel % 8)))

    # -- deleted-file triage ----------------------------------------------------
    def deleted_inodes(self):
        """Inodes with links==0 && dtime!=0 -- unlinked but not yet reused."""
        out = []
        for inum in range(1, self.inodes_count + 1):
            ino = self.read_inode(inum)
            if ino["links"] == 0 and ino["dtime"] != 0:
                out.append(ino)
        return out

    def recover_verdict(self, inode):
        """Verdict + recoverable block runs for a deleted inode.

        Returns dict: verdict in {OK, PARTIAL, GONE}, extents, good_blocks,
        gap_blocks (reallocated ranges, reported not read).
        """
        if isinstance(inode, int):
            inode = self.read_inode(inode)
        extents = self.extent_walk(inode)
        good, gaps = [], []
        for log, phys, length in extents:
            for blk in range(phys, phys + length):
                (gaps if self.block_is_used(blk) else good).append(blk)
        if not extents:
            verdict = "GONE"
        elif not gaps:
            verdict = "OK"
        elif not good:
            verdict = "GONE"
        else:
            verdict = "PARTIAL"
        return {"verdict": verdict, "extents": extents,
                "good_blocks": good, "gap_blocks": gaps,
                "size": inode["size"]}

    def read_inode_data(self, inode, skip_gaps=True):
        """Carve a file's data; reallocated blocks come back as zeros.

        Only call on a deleted inode after checking recover_verdict --
        for live files every block should be allocated anyway.
        """
        if isinstance(inode, int):
            inode = self.read_inode(inode)
        v = self.recover_verdict(inode)
        buf = bytearray()
        gapset = set(v["gap_blocks"])
        for log, phys, length in v["extents"]:
            for blk in range(phys, phys + length):
                if blk in gapset:
                    buf += b"\x00" * self.block_size
                else:
                    buf += self.read_block(blk)
        return bytes(buf[:inode["size"]])
