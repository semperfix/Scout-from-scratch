#!/usr/bin/env python3
"""pe_gen.py -- Synthetic PE fixture builder for testing peparse.py.

Builds byte-correct minimal PE32 binaries from scratch with struct.
Fixtures: benign.exe, packed.exe, overlay.exe, evil_api.exe, exports.dll,
cert.exe, mangled.bin, truncated.bin
"""

import struct, os, random

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')


def dos_header(e_lfanew=0x40):
    h = bytearray(64)
    h[0:2] = b'MZ'
    struct.pack_into('<I', h, 0x3C, e_lfanew)
    return bytes(h)


def coff(machine, nsec, optsize, chars, timedate=0x64B00000):
    return struct.pack('<HHIIIHH', machine, nsec, timedate, 0, 0, optsize, chars)


def optional32(entrypoint, image_base=0x400000, size_image=0x4000,
               size_headers=0x200, checksum=0, subsystem=3, dll_chars=0x8140,
               directories=None):
    o = bytearray(96 + 16 * 8)  # fixed part + 16 data directories
    struct.pack_into('<HBBIIIII', o, 0, 0x10b, 14, 0, 0x200, 0x400, 0x200,
                     entrypoint, 0x1000)
    struct.pack_into('<I', o, 28, image_base)
    struct.pack_into('<IIHHHHHHIIIIHHIIIIII', o, 32,
                     0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                     size_image, size_headers, checksum, subsystem, dll_chars,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = directories or [(0, 0)] * 16
    for i, (rva, size) in enumerate(dirs):
        struct.pack_into('<II', o, 96 + i * 8, rva, size)
    return bytes(o)


def section(name, vsize, vaddr, rawsize, rawptr, chars):
    nm = name.encode('ascii')[:8].ljust(8, b'\x00')
    return nm + struct.pack('<IIIIIIHHI', vsize, vaddr, rawsize, rawptr,
                            0, 0, 0, 0, chars)


def build_import_rdata(dll_name, funcs, rva_base=0x2000):
    """Return (rdata_bytes, import_dir_rva, import_dir_size). funcs: list of names."""
    r = bytearray(0x400)
    # layout: descriptors @0, ILT @40, IAT @40+4*(n+1), hintnames, dll name
    n = len(funcs)
    desc_off, ilt_off = 0, 40
    iat_off = ilt_off + 4 * (n + 1)
    hn_off = iat_off + 4 * (n + 1)
    hn_rvas = []
    p = hn_off
    for f in funcs:
        hn_rvas.append(rva_base + p)
        struct.pack_into('<H', r, p, 0)
        p += 2
        r[p:p + len(f) + 1] = f.encode('ascii') + b'\x00'
        p += len(f) + 1
    dll_off = p
    r[p:p + len(dll_name) + 1] = dll_name.encode('ascii') + b'\x00'
    for j, hrva in enumerate(hn_rvas):
        struct.pack_into('<I', r, ilt_off + 4 * j, hrva)
        struct.pack_into('<I', r, iat_off + 4 * j, hrva)
    struct.pack_into('<IIIII', r, desc_off, rva_base + ilt_off, 0, 0,
                     rva_base + dll_off, rva_base + iat_off)
    return bytes(r), rva_base + desc_off, 40


def assemble(sections, rdata_content=None, imports=None, exports=None,
             entry_rva=0x1000, chars=0x010f, dll_chars=0x8140, subsystem=3,
             extra_dirs=None, timedate=0x64B00000):
    """sections: list of (name, vsize, vaddr, rawbytes, flags)."""
    # assign rawptrs
    nsec = len(sections)
    hdr_len = 0x40 + 4 + 20 + 96 + 40 * nsec
    size_headers = 0x200
    directories = [(0, 0)] * 16
    if imports:
        dll_name, funcs, rva_base = imports
        rdata, imp_rva, imp_size = build_import_rdata(dll_name, funcs, rva_base)
        # inject the import tables into the .rdata section blob
        for idx, (name, vsize, vaddr, rawbytes, flags) in enumerate(sections):
            if name == '.rdata':
                sections[idx] = (name, vsize, vaddr, rdata, flags)
                break
        else:
            raise ValueError('imports requested but no .rdata section')
        directories[1] = (imp_rva, imp_size)
    rawptr = size_headers
    blobs = []
    sec_headers = []
    for name, vsize, vaddr, rawbytes, flags in sections:
        rawsize = (len(rawbytes) + 0x1ff) & ~0x1ff
        blobs.append((rawptr, rawbytes, rawsize))
        sec_headers.append(section(name, vsize, vaddr, rawsize, rawptr, flags))
        rawptr += rawsize
    size_image = (sections[-1][2] + max(sections[-1][1], blobs[-1][2]) + 0xfff) & ~0xfff
    if extra_dirs:
        for idx, (rva, size) in extra_dirs.items():
            directories[idx] = (rva, size)
    opt = optional32(entry_rva, size_image=size_image, size_headers=size_headers,
                     subsystem=subsystem, dll_chars=dll_chars,
                     directories=directories)
    img = bytearray()
    img += dos_header()
    img += b'PE\x00\x00'
    img += coff(0x14c, nsec, 224, chars, timedate)  # PE32 opt header = 224 bytes
    img += opt
    for sh in sec_headers:
        img += sh
    img += b'\x00' * (size_headers - len(img))
    for off, rawbytes, rawsize in blobs:
        assert len(img) == off, (len(img), off)
        img += rawbytes + b'\x00' * (rawsize - len(rawbytes))
    return bytes(img), directories


def set_checksum(img):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from peparse import PE
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
        f.write(img)
        tmp = f.name
    pe = PE(tmp)
    cks = pe.checksum_computed()
    os.unlink(tmp)
    img = bytearray(img)
    struct.pack_into('<I', img, 0x40 + 4 + 20 + 64, cks)
    return bytes(img)


def write(name, data):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    print(f'{name}: {len(data)} bytes')


R = lambda n: bytes(random.Random(1234).randbytes(n))

# --- benign.exe ------------------------------------------------------------
text = b'\x90' * 0x100 + b'\x6a\x00\xe8\x00\x00\x00\x00\xc3' + b'\x90' * (0x200 - 0x109)
img, _ = assemble([
    ('.text', 0x200, 0x1000, text, 0x60000020),
    ('.rdata', 0x400, 0x2000, b'\x00' * 0x400, 0x40000040),
    ('.data', 0x200, 0x3000, b'\x00' * 0x200, 0xC0000040),
], imports=('KERNEL32.dll', ['ExitProcess', 'GetModuleHandleA'], 0x2000),
    entry_rva=0x1000)
write('benign.exe', set_checksum(img))

# --- packed.exe: UPX-shaped -------------------------------------------------
rnd = R(0x200)
img, _ = assemble([
    ('.upx0', 0x4000, 0x1000, rnd, 0xE0000020),  # RWX!
    ('.rdata', 0x400, 0x5000, b'\x00' * 0x400, 0x40000040),
], imports=('KERNEL32.dll', ['LoadLibraryA', 'GetProcAddress'], 0x5000),
    entry_rva=0x1000)
write('packed.exe', set_checksum(img))

# --- overlay.exe: benign + appended blob ------------------------------------
ov = b'OVERLAYBLOB' + bytes((i * 7) & 0xff for i in range(4096))
with open(os.path.join(OUT, 'benign.exe'), 'rb') as f:
    write('overlay.exe', f.read() + ov)

# --- evil_api.exe: suspicious imports ---------------------------------------
img, _ = assemble([
    ('.text', 0x200, 0x1000, text, 0x60000020),
    ('.rdata', 0x400, 0x2000, b'\x00' * 0x400, 0x40000040),
], imports=('KERNEL32.dll',
            ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
             'InternetOpenUrlA', 'SetWindowsHookExA', 'IsDebuggerPresent'],
            0x2000),
    entry_rva=0x1000)
write('evil_api.exe', set_checksum(img))

# --- exports.dll: a DLL with an export table --------------------------------
# layout inside .rdata (index == rva - 0x2000):
#   0x100: export directory (40 bytes)
#   0x128: "MyExport\0" (9 bytes)      0x131: "mydll.dll\0" (10 bytes)
#   0x13c: address table (1 dword)     0x140: name ptr table (1 dword)
#   0x144: ordinal table (1 word)
rdata = bytearray(0x400)
rdata[0x128:0x131] = b'MyExport\x00'
rdata[0x131:0x13b] = b'mydll.dll\x00'
struct.pack_into('<I', rdata, 0x13c, 0x1000)   # address table -> .text
struct.pack_into('<I', rdata, 0x140, 0x2128)   # name ptr table -> "MyExport"
struct.pack_into('<H', rdata, 0x144, 0)        # ordinal table
struct.pack_into('<IIHHIIIIIII', rdata, 0x100,
                 0, 0x64B00000, 0, 0, 0x2131, 1, 1, 1,
                 0x213c, 0x2140, 0x2144)
img, _ = assemble([
    ('.text', 0x200, 0x1000, text, 0x60000020),
    ('.rdata', 0x400, 0x2000, bytes(rdata), 0x40000040),
], entry_rva=0x1000, chars=0x2100, extra_dirs={0: (0x2100, 40)})
write('exports.dll', set_checksum(img))

# --- resource.exe: benign + hostile resources --------------------------------
# .rsrc layout (offsets relative to section start, rva_base 0x4000):
#   root dir @0 -> type 10 (RCDATA) subdir @24
#   type subdir @24 -> name 1 -> lang subdir @56 ; name 2 -> lang subdir @80
#   lang subdirs -> data entries @104, @120
#   payload1 @136: MZ stub (embedded exe) ; payload2 @0x640: mystery blob
rsrc = bytearray(0x2800)
def rdir(buf, off, entries):
    struct.pack_into('<IIHHHH', buf, off, 0, 0, 0, 0, 0, len(entries))
    for i, (nm, tgt, isdir) in enumerate(entries):
        struct.pack_into('<II', buf, off + 16 + i * 8, nm,
                         (0x80000000 | tgt) if isdir else tgt)
def rdataent(buf, off, rva, size):
    struct.pack_into('<IIII', buf, off, rva, size, 0, 0)
rdir(rsrc, 0, [(10, 24, True)])
rdir(rsrc, 24, [(1, 56, True), (2, 80, True)])
rdir(rsrc, 56, [(1033, 104, False)])
rdir(rsrc, 80, [(1033, 120, False)])
pay1 = b'MZ' + R(0x500)
pay2 = R(0x2000)
rdataent(rsrc, 104, 0x4000 + 136, len(pay1))
rdataent(rsrc, 120, 0x4000 + 0x640, len(pay2))
rsrc[136:136 + len(pay1)] = pay1
rsrc[0x640:0x640 + len(pay2)] = pay2
img, _ = assemble([
    ('.text', 0x200, 0x1000, text, 0x60000020),
    ('.rdata', 0x400, 0x2000, b'\x00' * 0x400, 0x40000040),
    ('.rsrc', 0x2800, 0x4000, bytes(rsrc), 0x40000040),
], imports=('KERNEL32.dll', ['ExitProcess'], 0x2000),
    entry_rva=0x1000, extra_dirs={2: (0x4000, 0x2800)})
write('resource.exe', set_checksum(img))

# --- cert.exe: benign with a fake Authenticode cert directory ----------------
with open(os.path.join(OUT, 'benign.exe'), 'rb') as f:
    base = f.read()
cert_off = len(base)
cert_blob = struct.pack('<IHH', 16, 0x0200, 3) + b'\x30\x82\x01\x02FAKE'
img = bytearray(base) + cert_blob
# patch SECURITY data directory (index 4) -> (file offset, size)
struct.pack_into('<II', img, 0x40 + 4 + 20 + 96 + 4 * 8, cert_off, len(cert_blob))
write('cert.exe', set_checksum(bytes(img)))

# --- malformed --------------------------------------------------------------
write('mangled.bin', b'This is definitely not a PE file, just text.')
write('truncated.bin', dos_header(0x400) + b'\x00' * 16)  # e_lfanew past EOF

print('done')
