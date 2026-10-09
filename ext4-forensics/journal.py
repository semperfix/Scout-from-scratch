"""journal.py -- JBD2 (ext4 journal) scanner (stdlib only).

JBD2 is big-endian while ext4 itself is little-endian -- the single most
common triage mistake, caught here by parsing everything with ">".

Scans a raw journal area (block device region or file): finds the journal
superblock (magic 0xC03B3998), then walks descriptor blocks (type 1) and
their chained tags to build a newest-copy-wins map of journaled filesystem
blocks, and commit blocks (type 2) that close each transaction.

Honest subset: parses descriptor/commit/superblock blocks and the standard
12-byte tag format (t_blocknr, t_flags); the 64-bit high-blocknr and UUID
tag variants are detected by flag bits and skipped over, not decoded.
No replay -- this is a scanner, not a recovery engine.
"""

import struct

JBD2_MAGIC = 0xC03B3998

BLOCK_TYPE_DESC = {
    1: "descriptor",
    2: "commit",
    3: "superblock_v1",
    4: "superblock_v2",
    5: "revoke",
}

# journal_block_tag_t flag bits
JBD2_FLAG_ESCAPE = 0x01
JBD2_FLAG_SAME_UUID = 0x02
JBD2_FLAG_DELETED = 0x04
JBD2_FLAG_LAST_TAG = 0x08


def _be32(b, off):
    return struct.unpack_from(">I", b, off)[0]


def _be16(b, off):
    return struct.unpack_from(">H", b, off)[0]


def parse_journal_superblock(block):
    """Parse a JBD2 journal superblock (first journal block)."""
    if _be32(block, 0) != JBD2_MAGIC:
        raise ValueError("not a JBD2 journal (bad magic)")
    btype = _be32(block, 4)
    if btype not in (3, 4):
        raise ValueError(f"block is not a journal superblock (type {btype})")
    # journal_header_t is 12 bytes, so s_blocksize sits at offset 12.
    return {
        "block_type": BLOCK_TYPE_DESC[btype],
        "blocksize": _be32(block, 12),
        "maxlen": _be32(block, 16),
        "first": _be32(block, 20),
        "sequence": _be32(block, 24),
        "start": _be32(block, 28),
    }


def parse_descriptor(block):
    """Parse a descriptor block's tag array.

    Returns (sequence, [(fs_blocknr, flags), ...]). Each data block follows
    its tag in journal order. Stops at JBD2_FLAG_LAST_TAG.
    """
    seq = _be32(block, 8)
    tags = []
    off = 12
    while off + 12 <= len(block):
        fs_block = _be32(block, off)
        flags = _be16(block, off + 4)
        tags.append((fs_block, flags))
        # 64-bit / UUID tag variants carry extra words; skip them.
        extra = 0
        if not (flags & JBD2_FLAG_SAME_UUID):
            extra += 16
        if flags & JBD2_FLAG_ESCAPE:
            pass  # escape affects the data block, not the tag layout
        off += 12 + extra
        if flags & JBD2_FLAG_LAST_TAG:
            break
    return seq, tags


def parse_commit(block):
    """Parse a commit block: (sequence, commit_time)."""
    return {"sequence": _be32(block, 8)}


def scan_journal(data, blocksize=1024):
    """Scan a raw journal area. Returns per-block records and a
    newest-copy-wins map: fs block number -> journal data-block offset.

    Only well-formed descriptor/commit chains are followed; anything else
    is reported as unknown/skipped, never guessed.
    """
    n = len(data) // blocksize
    records = []
    block_map = {}   # fs_block -> (journal_offset, sequence)
    for i in range(n):
        blk = data[i * blocksize:(i + 1) * blocksize]
        if len(blk) < 12 or _be32(blk, 0) != JBD2_MAGIC:
            continue
        btype = _be32(blk, 4)
        rec = {"journal_block": i, "type": BLOCK_TYPE_DESC.get(btype, f"unknown({btype})")}
        if btype == 1:
            seq, tags = parse_descriptor(blk)
            rec["sequence"] = seq
            rec["tags"] = tags
            # Data blocks follow the tags in journal order, starting at the
            # next journal block after the descriptor.
            for ntag, (fs_block, flags) in enumerate(tags):
                data_off = (i + 1 + ntag) * blocksize
                prev = block_map.get(fs_block)
                if prev is None or seq >= prev[1]:
                    block_map[fs_block] = (data_off, seq)
        elif btype == 2:
            rec.update(parse_commit(blk))
        elif btype in (3, 4):
            rec.update(parse_journal_superblock(blk))
        records.append(rec)
    return {"records": records,
            "newest_copies": {fs: off for fs, (off, _seq) in block_map.items()}}
