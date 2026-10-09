"""WhatsApp Android backup decryption, from scratch.
Formats (from public reverse-engineering, as used by the ElDavoo/InfoForense
decryptors and the whatsapp-chat-exporter):
  key file: 158 bytes; bytes[126:158] = 32-byte backup key (crypt12/crypt14).
  crypt12: 67-byte header, IV = file[51:67] (16B), AES-256-CBC from offset 67,
           plaintext = zlib-compressed msgstore.db (strip trailing padding).
  crypt14: protobuf "database header" first, then AES-256-GCM ciphertext whose
           nonce comes from the header, then zlib-compressed msgstore.db.
           (crypt14 is NOT E2E — the device key file is the whole secret;
           crypt15 adds the E2E javaobj/HKDF layer on top.)
This module implements decrypt for both, plus ENCRYPTORS used only to build
synthetic test fixtures (so the pipeline is validated end-to-end).
"""
import os, zlib, struct, sys
sys.path.insert(0, os.path.dirname(__file__))
from crypto_aes256_gcm import aes256_encrypt_block, aes256_decrypt_block, gcm_encrypt, gcm_decrypt
from proto_min import decode as proto_decode, encode as proto_encode, find, pretty, read_varint, write_varint

def load_backup_key(key_path: str) -> bytes:
    """Extract the 32-byte backup key from a WhatsApp `key` file (158 bytes)."""
    raw = open(key_path, "rb").read()
    if len(raw) == 32:  # already a raw key
        return raw
    if len(raw) != 158:
        raise ValueError(f"key file must be 158 bytes, got {len(raw)}")
    return raw[126:158]

def make_key_file(path: str, key: bytes | None = None) -> bytes:
    """Create a synthetic 158-byte key file (fixture helper)."""
    key = key or os.urandom(32)
    blob = os.urandom(126) + key
    open(path, "wb").write(blob)
    return key

# ---------- crypt12 (AES-256-CBC, IV@51, data@67) ----------
def _cbc_decrypt(key, iv, data):
    out, prev = bytearray(), iv
    for i in range(0, len(data) - len(data) % 16, 16):
        blk = aes256_decrypt_block(key, data[i:i+16])
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[i:i+16]
    # PKCS#7 strip
    pad = out[-1]
    if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
        out = out[:-pad]
    return bytes(out)

def _cbc_encrypt(key, iv, data):
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        xored = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        blk = aes256_encrypt_block(key, xored)
        out += blk; prev = blk
    return bytes(out)

def decrypt_crypt12(crypt12_path: str, key: bytes) -> bytes:
    blob = open(crypt12_path, "rb").read()
    iv, ct = blob[51:67], blob[67:]
    if blob[:8] == b"\x00" * 8 and len(blob) < 67:
        raise ValueError("file too short for crypt12 header")
    pt = _cbc_decrypt(key, iv, ct)
    return zlib.decompress(pt)

def encrypt_crypt12(db_path: str, out_path: str, key: bytes, iv: bytes | None = None):
    """Fixture encryptor: writes a crypt12-format file."""
    iv = iv or os.urandom(16)
    comp = zlib.compress(open(db_path, "rb").read(), 9)
    header = b"\x00" * 51 + iv          # 67-byte header, IV at offset 51
    open(out_path, "wb").write(header + _cbc_encrypt(key, iv, comp))

# ---------- crypt14 (protobuf header + AES-256-GCM + zlib) ----------
# File layout used here: varint(header_len) | protobuf header | ct | 16B tag.
# The protobuf wire parsing is exact; the length-prefix framing is the
# unambiguous reconstruction (the public tools locate the header the same
# way conceptually, then fall back to IV@8 / data@122 guesses).
def parse_crypt14_header(blob: bytes):
    """Parse the leading length-prefixed protobuf header -> (fields, total_len)."""
    hlen, pos = read_varint(blob, 0)
    fields = proto_decode(blob[pos:pos+hlen])
    return fields, pos + hlen

def find_nonce(fields) -> bytes:
    """Heuristic: the nonce is a 12- or 16-byte length-delimited field."""
    for n, t, v in fields:
        if t == 2 and isinstance(v, bytes) and len(v) in (12, 16):
            return v[:12]
    # documented fallback guess: IV at offset 8 (from the decrypter's -ivo default)
    return None

def decrypt_crypt14(crypt14_path: str, key: bytes, verbose=False) -> tuple[bytes, dict]:
    blob = open(crypt14_path, "rb").read()
    try:
        fields, hlen = parse_crypt14_header(blob)
        nonce = find_nonce(fields)
        src = "protobuf-header"
    except ValueError:
        fields, hlen, nonce, src = [], 122, blob[8:20], "fallback-offset-8/122"
    meta = {"header_fields": [(n, t, (v.hex()[:32] if isinstance(v, bytes) else v))
                              for n, t, v in fields],
            "header_len": hlen, "nonce_source": src}
    if nonce is None:
        raise ValueError("no 12/16-byte nonce field in header and no fallback IV")
    ct = blob[hlen:]
    if len(ct) < 16:
        raise ValueError("ciphertext too short for GCM tag")
    ct_body, tag = ct[:-16], ct[-16:]
    comp = gcm_decrypt(key, nonce, ct_body, tag)
    if verbose:
        print(pretty(fields))
        print("header_len:", hlen, "nonce:", nonce.hex())
    return zlib.decompress(comp), meta

def encrypt_crypt14(db_path: str, out_path: str, key: bytes,
                    nonce: bytes | None = None, cipher_version: bytes = b"c14"):
    """Fixture encryptor: writes a crypt14-format file (proto header + GCM + zlib)."""
    nonce = nonce or os.urandom(12)
    comp = zlib.compress(open(db_path, "rb").read(), 9)
    header = proto_encode([(1, 2, cipher_version), (2, 2, nonce)])
    frame = write_varint(len(header)) + header
    ct, tag = gcm_encrypt(key, nonce, comp)
    open(out_path, "wb").write(frame + ct + tag)

if __name__ == "__main__":
    # roundtrip self-test on dummy payload
    os.makedirs("/tmp/wa_selftest", exist_ok=True)
    key = make_key_file("/tmp/wa_selftest/key")
    open("/tmp/wa_selftest/fake.db", "wb").write(b"FAKEDB" * 1000)
    encrypt_crypt14("/tmp/wa_selftest/fake.db", "/tmp/wa_selftest/f.crypt14", key)
    pt, meta = decrypt_crypt14("/tmp/wa_selftest/f.crypt14", load_backup_key("/tmp/wa_selftest/key"))
    assert pt == open("/tmp/wa_selftest/fake.db", "rb").read(), "crypt14 roundtrip failed"
    encrypt_crypt12("/tmp/wa_selftest/fake.db", "/tmp/wa_selftest/f.crypt12", key)
    assert decrypt_crypt12("/tmp/wa_selftest/f.crypt12", key) == open("/tmp/wa_selftest/fake.db", "rb").read(), "crypt12 roundtrip failed"
    # wrong key must fail loudly (GCM auth)
    try:
        decrypt_crypt14("/tmp/wa_selftest/f.crypt14", os.urandom(32))
        raise SystemExit("wrong key accepted!")
    except ValueError as e:
        print("wrong-key correctly rejected:", e)
    print("crypt12/crypt14 self-tests pass; header:", meta)
