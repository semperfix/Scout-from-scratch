#!/usr/bin/env python3
"""peparse.py -- Hand-rolled Windows PE parser. Zero deps, stdlib only.

Parses: DOS header, NT headers, COFF, Optional header (PE32 + PE32+),
section table, import table (ILT/IAT, ordinals, hint/name), export table,
debug directory (CodeView PDB paths), security directory (Authenticode cert
block), TLS, relocation summary, overlay carving, and PE checksum verification.

Everything is read with struct at explicit offsets; nothing trusted on faith.
"""

import struct, math, os

class PEError(Exception): pass

# --- characteristic flags ---------------------------------------------------
SECTION_FLAGS = {
    0x00000020: 'CODE', 0x00000040: 'INITIALIZED_DATA',
    0x00000080: 'UNINITIALIZED_DATA', 0x00000200: 'INFO',
    0x00001000: 'REMOVE', 0x00002000: 'COMDAT',
    0x01000000: 'NO_DEFER_SPEC_EXC', 0x02000000: 'GPREL',
    0x04000000: 'MEM_PURGEABLE', 0x08000000: 'MEM_16BIT',
    0x10000000: 'MEM_LOCKED', 0x20000000: 'MEM_EXECUTE',
    0x40000000: 'MEM_READ', 0x80000000: 'MEM_WRITE',
}
MACHINES = {0x014c: 'i386', 0x8664: 'x86-64', 0x01c0: 'ARM',
            0xaa64: 'ARM64', 0x014d: 'i486'}
SUBSYSTEMS = {0: 'UNKNOWN', 1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
              5: 'OS2_CUI', 7: 'POSIX_CUI', 9: 'WINDOWS_CE_GUI',
              10: 'EFI_APPLICATION', 13: 'EFI_BOOT_SERVICE_DRIVER'}
DIRECTORY_NAMES = ['EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPT', 'SECURITY',
                   'BASERELOC', 'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS',
                   'LOADCONFIG', 'BOUNDIMPORT', 'IAT', 'DELAYIMPORT',
                   'COMDESCRIPTOR', 'RESERVED']
DLL_CHARS = {0x0001: 'HIGH_ENTROPY_VA', 0x0040: 'DYNAMIC_BASE',
             0x0080: 'FORCE_INTEGRITY',
             0x0100: 'NX_COMPAT', 0x0200: 'NO_ISOLATION',
             0x0400: 'NO_SEH', 0x0800: 'NO_BIND',
             0x1000: 'APPCONTAINER', 0x2000: 'WDM_DRIVER',
             0x4000: 'GUARD_CF', 0x8000: 'TERMINAL_SERVER_AWARE'}


def flags_to_names(flags, table):
    return [n for bit, n in sorted(table.items()) if flags & bit]


RESOURCE_TYPES = {1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG',
                  6: 'STRING', 7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR',
                  10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR',
                  14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE',
                  19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON',
                  23: 'HTML', 24: 'MANIFEST'}


class PE:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self.path = path
        self._parse()

    # -- low level ------------------------------------------------------------
    def _u16(self, o): self._need(o, 2, 'u16'); return struct.unpack_from('<H', self.data, o)[0]
    def _u32(self, o): self._need(o, 4, 'u32'); return struct.unpack_from('<I', self.data, o)[0]
    def _u64(self, o): self._need(o, 8, 'u64'); return struct.unpack_from('<Q', self.data, o)[0]
    def _need(self, o, n, what):
        if o < 0 or o + n > len(self.data):
            raise PEError(f'truncated {what} at file offset {o:#x}')

    def _read(self, o, n, what='bytes'):
        self._need(o, n, what)
        return self.data[o:o+n]

    def _cstr(self, o, what='string'):
        self._need(o, 1, what)
        end = self.data.index(b'\x00', o)  # raises if none
        if end - o > 512:
            raise PEError(f'{what} at {o:#x} not terminated within 512 bytes')
        return self.data[o:end].decode('utf-8', 'replace')

    # -- main parse -----------------------------------------------------------
    def _parse(self):
        d = self.data
        if len(d) < 64:
            raise PEError('too small to be a PE (no DOS header)')
        if d[:2] != b'MZ':
            raise PEError(f'bad DOS magic: {d[:2]!r}')
        self.e_lfanew = self._u32(0x3C)
        self._need(self.e_lfanew, 6, 'NT signature')
        if d[self.e_lfanew:self.e_lfanew+4] != b'PE\x00\x00':
            raise PEError(f'bad NT signature at {self.e_lfanew:#x}')

        o = self.e_lfanew + 4
        self._need(o, 20, 'COFF header')
        (self.machine, self.nsections, self.timedate, self.ptr_sym,
         self.nsym, self.optsize, self.characteristics) = struct.unpack_from('<HHIIIHH', d, o)
        o += 20
        self.opt_off = o
        self._need(o, 2, 'optional header magic')
        magic = self._u16(o)
        if magic == 0x10b:
            self.is64 = False
        elif magic == 0x20b:
            self.is64 = True
        else:
            raise PEError(f'unknown optional header magic {magic:#x}')
        self._parse_optional(o)
        o += self.optsize

        self.sections = []
        for i in range(self.nsections):
            self._need(o, 40, f'section header {i}')
            raw = d[o:o+40]
            name = raw[:8].rstrip(b'\x00')
            (vsize, vaddr, rawsize, rawptr, relocptr, linenoptr,
             nreloc, nline, chars) = struct.unpack('<IIIIIIHHI', raw[8:])
            # sanity: rawptr/rawsize must not wildly overrun the file
            if rawptr and rawptr + rawsize > len(d) + 1:
                raise PEError(f'section {i} raw data extends past EOF')
            self.sections.append({
                'name': name.decode('ascii', 'replace'), 'vsize': vsize,
                'vaddr': vaddr, 'rawsize': rawsize, 'rawptr': rawptr,
                'chars': chars, 'flags': flags_to_names(chars, SECTION_FLAGS),
                'index': i,
            })
            o += 40

        # entry point -> section
        self.entry_section = self._section_for_rva(self.entrypoint)

        # imports / exports / debug / security / tls / reloc summary / resources
        self.imports = self._parse_imports()
        self.exports = self._parse_exports()
        self.debug = self._parse_debug()
        self.security = self._parse_security()
        self.tls = self.directories['TLS']['rva'] != 0
        self.reloc_count = self._parse_reloc_count()
        self.resources = self._parse_resources()

        # overlay: anything past the end of the last raw section
        last_end = 0
        for s in self.sections:
            if s['rawptr']:
                last_end = max(last_end, s['rawptr'] + s['rawsize'])
        # security directory (cert table) usually lives past sections too
        sec = self.directories['SECURITY']
        cert_end = sec['rva'] + sec['size'] if sec['size'] else 0
        overlay_start = max(last_end, cert_end)
        self.overlay = self.data[overlay_start:] if overlay_start < len(d) else b''

    def _parse_optional(self, o):
        is64 = self.is64
        self._need(o, 24, 'optional header')
        (magic, linker_maj, linker_min, code_size, init_size, uninit_size,
         entrypoint, base_code) = struct.unpack_from('<HBBIIIII', self.data, o)
        if not is64:
            image_base = self._u32(o + 28)
            # o+32: SectionAlign, FileAlign, OS(2H), Img(2H), Sub(2H),
            #       Win32Ver, SizeOfImage, SizeOfHeaders, CheckSum,
            #       Subsystem, DllChars, StackRes/Com, HeapRes/Com,
            #       LoaderFlags, NumberOfRvaAndSizes
            self._need(o + 32, struct.calcsize('<IIHHHHHHIIIIHHIIIIII'),
                       'optional header')
            vals = struct.unpack_from('<IIHHHHHHIIIIHHIIIIII', self.data, o + 32)
            ddo = o + 96
        else:
            image_base = self._u64(o + 24)
            self._need(o + 32, struct.calcsize('<IIHHHHHHIIIIHHQQQQII'),
                       'optional header')
            vals = struct.unpack_from('<IIHHHHHHIIIIHHQQQQII', self.data, o + 32)
            ddo = o + 112
        (sec_align, file_align, os_maj, os_min, img_maj, img_min,
         sub_maj, sub_min, win32_ver, size_image, size_headers,
         checksum, subsystem, dll_chars,
         stack_res, stack_com, heap_res, heap_com,
         loader_flags, nrva) = vals
        self.entrypoint = entrypoint
        self.image_base = image_base
        self.sec_align = sec_align
        self.file_align = file_align
        self.size_image = size_image
        self.size_headers = size_headers
        self.checksum_stored = checksum
        self.subsystem = subsystem
        self.dll_chars = dll_chars
        self.nrva = nrva
        self.directories = {}
        for i in range(min(16, nrva)):
            self._need(ddo + i*8, 8, 'data directory')
            rva, size = struct.unpack_from('<II', self.data, ddo + i*8)
            self.directories[DIRECTORY_NAMES[i]] = {'rva': rva, 'size': size}
        for name in DIRECTORY_NAMES[len(self.directories):]:
            self.directories[name] = {'rva': 0, 'size': 0}

    # -- rva mapping ----------------------------------------------------------
    def rva_to_offset(self, rva):
        if rva is None:
            return None
        for s in self.sections:
            size = max(s['vsize'], s['rawsize'])
            if s['vaddr'] <= rva < s['vaddr'] + size:
                off = s['rawptr'] + (rva - s['vaddr'])
                if off >= len(self.data):
                    return None
                return off
        # maybe in headers
        if rva < self.size_headers:
            return rva
        return None

    def _section_for_rva(self, rva):
        for s in self.sections:
            size = max(s['vsize'], s['rawsize'])
            if s['vaddr'] <= rva < s['vaddr'] + size:
                return s['name']
        return None

    # -- imports --------------------------------------------------------------
    def _parse_imports(self):
        dd = self.directories['IMPORT']
        if not dd['size']:
            return []
        off = self.rva_to_offset(dd['rva'])
        if off is None:
            raise PEError('import directory RVA outside any section')
        imports, i = [], 0
        ws = 8 if self.is64 else 4
        while True:
            self._need(off + i*20, 20, 'import descriptor')
            ilt, ts, fwd, name_rva, iat = struct.unpack_from('<IIIII', self.data, off + i*20)
            if (ilt, ts, fwd, name_rva, iat) == (0, 0, 0, 0, 0):
                break
            name_off = self.rva_to_offset(name_rva)
            dll = self._cstr(name_off, 'import DLL name') if name_off is not None else '?'
            thunk_rva = ilt or iat  # some binaries omit ILT; fall back to IAT
            thunk_off = self.rva_to_offset(thunk_rva)
            funcs = []
            if thunk_off is not None:
                j = 0
                while True:
                    self._need(thunk_off + j*ws, ws, 'thunk entry')
                    entry = (self._u64(thunk_off + j*ws) if self.is64
                             else self._u32(thunk_off + j*ws))
                    if entry == 0:
                        break
                    if entry >> (63 if self.is64 else 31):
                        funcs.append(f"ordinal:{entry & 0xffff}")
                    else:
                        hn_off = self.rva_to_offset(entry & (0x7fffffff if not self.is64 else 0x7fffffffffffffff))
                        if hn_off is None:
                            funcs.append('?')
                        else:
                            hint = self._u16(hn_off)
                            funcs.append(self._cstr(hn_off + 2, 'hint/name'))
                    j += 1
                    if j > 65536:
                        raise PEError('import thunk runaway (>64k entries)')
            imports.append({'dll': dll, 'functions': funcs})
            i += 1
            if i > 1024:
                raise PEError('too many import descriptors')
        return imports

    # -- exports --------------------------------------------------------------
    def _parse_exports(self):
        dd = self.directories['EXPORT']
        if not dd['size']:
            return []
        off = self.rva_to_offset(dd['rva'])
        if off is None:
            return []
        self._need(off, struct.calcsize('<IIHHIIIIIII'), 'export directory')
        (chars, ts, maj, minor, name_rva, base, nfuncs, nnames,
         addr_rva, names_rva, ord_rva) = struct.unpack_from('<IIHHIIIIIII', self.data, off)
        nfuncs = min(nfuncs, 100000); nnames = min(nnames, 100000)
        exports = []
        addr_off = self.rva_to_offset(addr_rva)
        names_off = self.rva_to_offset(names_rva)
        ord_off = self.rva_to_offset(ord_rva)
        for i in range(nnames):
            self._need(names_off + i*4, 4, 'export name ptr')
            fn_off = self.rva_to_offset(self._u32(names_off + i*4))
            self._need(ord_off + i*2, 2, 'export ordinal')
            oi = self._u16(ord_off + i*2)
            self._need(addr_off + oi*4, 4, 'export address')
            f_rva = self._u32(addr_off + oi*4)
            exports.append({'name': self._cstr(fn_off), 'ordinal': base + oi, 'rva': f_rva})
        return exports

    # -- debug (CodeView) -----------------------------------------------------
    def _parse_debug(self):
        dd = self.directories['DEBUG']
        if not dd['size']:
            return []
        off = self.rva_to_offset(dd['rva'])
        if off is None:
            return []
        out = []
        for i in range(dd['size'] // 28):
            self._need(off + i*28, 28, 'debug entry')
            (chars, ts, maj, minor, dtype, dsize, raddr,
             rfile) = struct.unpack_from('<IIHHIIII', self.data, off + i*28)
            entry = {'type': dtype, 'timestamp': ts}
            if dtype == 2:  # CodeView
                cv_off = rfile or self.rva_to_offset(raddr)
                if cv_off is not None and self.data[cv_off:cv_off+4] == b'RSDS':
                    self._need(cv_off + 4, 16, 'CodeView GUID')
                    (guid,) = struct.unpack_from('<16s', self.data, cv_off + 4)
                    age = self._u32(cv_off + 20)
                    entry['pdb'] = self._cstr(cv_off + 24, 'PDB path')
                    entry['guid'] = guid.hex()
                    entry['age'] = age
                elif cv_off is not None and self.data[cv_off:cv_off+4] == b'NB10':
                    entry['pdb'] = self._cstr(cv_off + 16, 'PDB path')
            out.append(entry)
        return out

    # -- security directory (Authenticode cert blob) --------------------------
    def _parse_security(self):
        dd = self.directories['SECURITY']
        if not dd['size']:
            return None
        # NOTE: SECURITY is a FILE OFFSET, not an RVA -- classic gotcha
        off, size = dd['rva'], dd['size']
        self._need(off, 8, 'certificate entry')
        length, revision, cert_type = struct.unpack_from('<IHH', self.data, off)
        return {'offset': off, 'length': length, 'revision': revision,
                'cert_type': cert_type,  # 2 = X509, 3 = PKCS#7 signedData
                'size_declared': size}

    # -- resources: 3-level tree (type -> name -> language -> data) -------------
    def _parse_resources(self):
        dd = self.directories['RESOURCE']
        if not dd['size']:
            return []
        base = self.rva_to_offset(dd['rva'])
        if base is None:
            return []
        out = []
        # entry RVAs inside the resource tree are relative to the section base
        def entry_name(off, raw_name):
            if raw_name & 0x80000000:
                so = base + (raw_name & 0x7fffffff)
                self._need(so, 2, 'resource string length')
                ln = self._u16(so)
                self._need(so + 2, ln * 2, 'resource string')
                return self.data[so+2:so+2+ln*2].decode('utf-16-le', 'replace')
            return str(raw_name & 0xffff)

        def walk(dir_off, level, path):
            self._need(dir_off, 16, 'resource directory')
            (chars, ts, maj, minor, nnamed, nid) = struct.unpack_from(
                '<IIHHHH', self.data, dir_off)
            for i in range(nnamed + nid):
                self._need(dir_off + 16 + i*8, 8, 'resource entry')
                raw_name, raw_off = struct.unpack_from('<II', self.data,
                                                      dir_off + 16 + i*8)
                name = entry_name(dir_off, raw_name)
                if raw_off & 0x80000000:  # subdirectory
                    if level < 3:
                        walk(base + (raw_off & 0x7fffffff), level + 1,
                             path + [name])
                else:  # data entry
                    de = base + (raw_off & 0x7fffffff)
                    self._need(de, 16, 'resource data entry')
                    data_rva, size, codepage, _rsv = struct.unpack_from(
                        '<IIII', self.data, de)
                    data_off = self.rva_to_offset(data_rva)
                    blob = (self.data[data_off:data_off+size]
                            if data_off is not None else b'')
                    rtype = path[0] if path else '?'
                    try:
                        tid = int(rtype)
                        tname = RESOURCE_TYPES.get(tid, f'#{tid}')
                    except ValueError:
                        tname = rtype
                    out.append({'type': tname, 'type_id': rtype,
                                'name': path[1] if len(path) > 1 else '',
                                'lang': name, 'size': size, 'data': blob})
        walk(base, 0, [])
        return out

    def resource_entropy(self, r):
        d = r['data']
        if not d:
            return 0.0
        freq = [0]*256
        for b in d:
            freq[b] += 1
        return -sum((c/len(d)) * math.log2(c/len(d)) for c in freq if c)
    def _parse_reloc_count(self):
        dd = self.directories['BASERELOC']
        if not dd['size']:
            return 0
        off = self.rva_to_offset(dd['rva'])
        if off is None:
            return 0
        total, p, end = 0, off, off + dd['size']
        while p + 8 <= end:
            page, size = struct.unpack_from('<II', self.data, p)
            if size == 0:
                break
            total += max(0, (size - 8) // 2)
            p += size
        return total

    # -- checksum -------------------------------------------------------------
    def checksum_computed(self):
        """The PE checksum algorithm: sum of all u16 words, folding carries,
        with the CheckSum field itself skipped, plus file length."""
        buf = bytearray(self.data)
        # CheckSum field sits at opt+64 in both PE32 and PE32+ layouts
        # (verified against the field maps in _parse_optional above)
        co = self.opt_off + 64
        struct.pack_into('<I', buf, co, 0)
        total = 0
        n = len(buf) & ~1
        for i in range(0, n, 2):
            total += buf[i] | (buf[i+1] << 8)
            total = (total & 0xffffffff) + (total >> 32)
        if len(buf) & 1:
            total += buf[-1]
            total = (total & 0xffffffff) + (total >> 32)
        total = (total & 0xffff) + (total >> 16)
        total = (total & 0xffff) + (total >> 16)
        total = (total & 0xffff) + (total >> 16)
        return (total + len(self.data)) & 0xffffffff

    # -- entropy ----------------------------------------------------------------
    def section_entropy(self, s):
        if not s['rawptr'] or not s['rawsize']:
            return 0.0
        raw = self.data[s['rawptr']:s['rawptr'] + s['rawsize']]
        if not raw:
            return 0.0
        freq = [0]*256
        for b in raw:
            freq[b] += 1
        ent = 0.0
        for c in freq:
            if c:
                p = c / len(raw)
                ent -= p * math.log2(p)
        return ent

    def summary(self):
        lines = []
        lines.append(f"{os.path.basename(self.path)}: {'PE32+' if self.is64 else 'PE32'} "
                     f"machine={MACHINES.get(self.machine, hex(self.machine))} "
                     f"sections={self.nsections} subsystem={SUBSYSTEMS.get(self.subsystem, self.subsystem)}")
        lines.append(f"  entrypoint RVA {self.entrypoint:#x} in section '{self.entry_section}'")
        lines.append(f"  ASLR={'DYNAMIC_BASE' in flags_to_names(self.dll_chars, DLL_CHARS)} "
                     f"NX={'NX_COMPAT' in flags_to_names(self.dll_chars, DLL_CHARS)}")
        for s in self.sections:
            e = self.section_entropy(s)
            lines.append(f"  sect {s['name']:<10} vsize={s['vsize']:#x} raw={s['rawsize']:#x} "
                         f"entropy={e:.2f} {'|'.join(s['flags'][:4])}")
        lines.append(f"  imports: {len(self.imports)} DLLs, "
                     f"{sum(len(i['functions']) for i in self.imports)} functions")
        lines.append(f"  exports: {len(self.exports)}, debug: {len(self.debug)}, "
                     f"cert: {'yes' if self.security else 'no'}, overlay: {len(self.overlay)} bytes")
        return '\n'.join(lines)


if __name__ == '__main__':
    import sys
    pe = PE(sys.argv[1])
    print(pe.summary())
