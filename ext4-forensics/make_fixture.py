#!/usr/bin/env python3
"""make_fixture.py -- hand-craft a minimal ext4 image + JBD2 journal fixture.

Layout (block size 1024, 16 blocks, 16 inodes, 256-byte inodes):
    block  0  boot area (zeros)
    block  1  superblock            label "FORENSIC-TEST"
    block  2  group descriptor table (1 group)
    block  3  block bitmap
    block  4  inode bitmap
    blocks 5-8 inode table
    block  9  root directory (., .., hello.txt)
    block 10  hello.txt data        (inode 12, live)
    block 11  gone.txt data         (inode 13, deleted; block FREE -> OK)
    block 12  junk (reallocated)    (inode 14 partial.txt block 0 -> PARTIAL)
    block 13  partial.txt block 1   (intact, free)
    block 14  junk (reallocated)    (inode 15 wiped.txt -> GONE)
    block 15  free

Also writes fixture.journal: a 4-block JBD2 area (superblock v2, descriptor
tagging fs block 100, one data block, commit) for the journal scanner.
"""

import struct

BS = 1024
N_BLOCKS = 16
N_INODES = 16
INODE_SIZE = 256

HELLO = b"hello ext4 forensics\n"
GONE = b"deleted but recoverable\n"
PARTIAL_B1 = b"partial-file second block intact\n"
JUNK = b"REUSED!" * 64  # 448 bytes of junk for reallocated blocks


def extent_leaf(phys, length, logical=0):
    hdr = struct.pack("<HHHHI", 0xF30A, 1, 4, 0, 0)
    ext = struct.pack("<IHHI", logical, length, 0, phys)
    return (hdr + ext).ljust(60, b"\x00")


def make_inode(mode, size, links, dtime, phys, nblocks, mtime=1700000000):
    b = bytearray(INODE_SIZE)
    struct.pack_into("<H", b, 0, mode)
    struct.pack_into("<I", b, 4, size)
    struct.pack_into("<I", b, 8, mtime)    # atime
    struct.pack_into("<I", b, 12, mtime)   # ctime
    struct.pack_into("<I", b, 16, mtime)   # mtime
    struct.pack_into("<I", b, 20, dtime)   # dtime
    struct.pack_into("<H", b, 26, links)
    struct.pack_into("<I", b, 28, nblocks * 2)  # 512-byte sectors
    b[40:100] = extent_leaf(phys, nblocks)
    return bytes(b)


def dir_entry(inode, name, ftype, rec_len):
    nb = name.encode()
    e = struct.pack("<IHBB", inode, rec_len, len(nb), ftype) + nb
    return e.ljust(rec_len, b"\x00")


def build_image():
    img = bytearray(N_BLOCKS * BS)

    # --- superblock at byte 1024 ---
    sb = bytearray(BS)
    struct.pack_into("<I", sb, 0, N_INODES)     # s_inodes_count
    struct.pack_into("<I", sb, 4, N_BLOCKS)    # s_blocks_count_lo
    struct.pack_into("<I", sb, 12, 3)          # s_free_blocks_count_lo
    struct.pack_into("<I", sb, 16, 10)         # s_free_inodes_count_lo
    struct.pack_into("<I", sb, 20, 1)          # s_first_data_block
    struct.pack_into("<I", sb, 24, 0)          # s_log_block_size -> 1024
    struct.pack_into("<I", sb, 32, N_BLOCKS)   # s_blocks_per_group
    struct.pack_into("<I", sb, 40, N_INODES)   # s_inodes_per_group
    struct.pack_into("<H", sb, 56, 0xEF53)     # s_magic
    struct.pack_into("<I", sb, 76, 1)          # s_rev_level (dynamic)
    struct.pack_into("<H", sb, 88, 11)         # s_first_ino
    struct.pack_into("<H", sb, 90, INODE_SIZE) # s_inode_size
    sb[96:112] = bytes.fromhex("00112233445566778899aabbccddeeff")
    sb[112:128] = b"FORENSIC-TEST\x00\x00\x00"
    struct.pack_into("<H", sb, 254, 32)        # s_desc_size
    img[BS:2 * BS] = sb

    # --- group descriptor (block 2) ---
    gd = bytearray(BS)
    struct.pack_into("<I", gd, 0, 3)   # bg_block_bitmap_lo
    struct.pack_into("<I", gd, 4, 4)   # bg_inode_bitmap_lo
    struct.pack_into("<I", gd, 8, 5)   # bg_inode_table_lo
    struct.pack_into("<H", gd, 12, 3)  # bg_free_blocks_count_lo
    struct.pack_into("<H", gd, 14, 10) # bg_free_inodes_count_lo
    struct.pack_into("<H", gd, 16, 1)  # bg_used_dirs_count_lo
    img[2 * BS:3 * BS] = gd

    # --- block bitmap (block 3): used = 0-10, 12, 14 ---
    bmp = bytearray(BS)
    for blk in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14):
        bmp[blk // 8] |= 1 << (blk % 8)
    img[3 * BS:4 * BS] = bmp

    # --- inode bitmap (block 4): inodes 1,2,12,13,14,15 used ---
    ibmp = bytearray(BS)
    for ino in (1, 2, 12, 13, 14, 15):
        ibmp[(ino - 1) // 8] |= 1 << ((ino - 1) % 8)
    img[4 * BS:5 * BS] = ibmp

    # --- inode table (blocks 5-8) ---
    it = bytearray(4 * BS)
    def put_ino(inum, data):
        it[(inum - 1) * INODE_SIZE:(inum) * INODE_SIZE] = data
    put_ino(2, make_inode(0o040755, BS, 2, 0, 9, 1))          # root dir
    put_ino(12, make_inode(0o100644, len(HELLO), 1, 0, 10, 1))  # hello.txt
    put_ino(13, make_inode(0o100644, len(GONE), 0, 1700000000, 11, 1))   # gone.txt (OK)
    put_ino(14, make_inode(0o100644, 2048, 0, 1700000001, 12, 2))        # partial.txt (PARTIAL)
    put_ino(15, make_inode(0o100644, BS, 0, 1700000002, 14, 1))          # wiped.txt (GONE)
    img[5 * BS:9 * BS] = it

    # --- root directory (block 9) ---
    d = (dir_entry(2, ".", 2, 12) + dir_entry(2, "..", 2, 12)
         + dir_entry(12, "hello.txt", 1, BS - 24))
    img[9 * BS:10 * BS] = d

    # --- file data blocks ---
    img[10 * BS:10 * BS + len(HELLO)] = HELLO
    img[11 * BS:11 * BS + len(GONE)] = GONE
    img[12 * BS:12 * BS + len(JUNK)] = JUNK          # reallocated junk
    img[13 * BS:13 * BS + len(PARTIAL_B1)] = PARTIAL_B1
    img[14 * BS:14 * BS + len(JUNK)] = JUNK          # reallocated junk

    with open("fixture.img", "wb") as f:
        f.write(img)
    print(f"wrote fixture.img ({len(img)} bytes)")


def build_journal():
    j = bytearray(4 * BS)
    # block 0: journal superblock v2 (big-endian; header is 12 bytes)
    struct.pack_into(">I", j, 0, 0xC03B3998)
    struct.pack_into(">I", j, 4, 4)        # superblock_v2
    struct.pack_into(">I", j, 12, BS)      # s_blocksize
    struct.pack_into(">I", j, 16, 4)       # s_maxlen
    struct.pack_into(">I", j, 20, 1)       # s_first
    struct.pack_into(">I", j, 24, 7)       # s_sequence
    struct.pack_into(">I", j, 28, 1)       # s_start
    # block 1: descriptor, sequence 7, one tag (fs block 100, LAST_TAG|SAME_UUID)
    struct.pack_into(">I", j, BS + 0, 0xC03B3998)
    struct.pack_into(">I", j, BS + 4, 1)   # descriptor
    struct.pack_into(">I", j, BS + 8, 7)   # sequence
    struct.pack_into(">I", j, BS + 12, 100)
    struct.pack_into(">H", j, BS + 16, 0x0A)
    # block 2: the journaled data block
    j[2 * BS:2 * BS + 19] = b"JOURNALED-BLOCK-100"
    # block 3: commit, sequence 7
    struct.pack_into(">I", j, 3 * BS + 0, 0xC03B3998)
    struct.pack_into(">I", j, 3 * BS + 4, 2)  # commit
    struct.pack_into(">I", j, 3 * BS + 8, 7)
    with open("fixture.journal", "wb") as f:
        f.write(j)
    print(f"wrote fixture.journal ({len(j)} bytes)")


if __name__ == "__main__":
    build_image()
    build_journal()
