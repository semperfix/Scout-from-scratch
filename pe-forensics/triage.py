#!/usr/bin/env python3
"""triage.py -- PE malware-triage verdict engine on top of peparse.py.

Scores a PE file and renders CLEAN / SUSPICIOUS / MALICIOUS with reasons.
Heuristics (each grounded in real malware-analysis practice):

- Section entropy: packed/encrypted payloads sit at 7.0-8.0. .rsrc is
  exempted (icons/cursors compress well and PuTTY's real .rsrc hits 7.83).
- VirtualSize >> RawSize: a section that unpacks much bigger than its file
  footprint is the classic packed-binary shape.
- Entry point location: EP in a section that is writeable (unpacker stub
  writes its payload there) or not marked executable.
- Known packer section names: .upx0/.upx1, .aspack, .themida, .enigma1/2, .petite.
- Tiny import table + high entropy = dynamically resolves everything at runtime.
- Suspicious API imports, grouped by capability:
    process injection, memory execution, anti-debug, keylogging,
    networking/download, credential/crypto-abuse.
- Checksum mismatch: file was modified after linking (patching/tampering).
- Overlay: appended data (installers do this legitimately; malware hides payloads).
- No digital signature: unsigned is normal for freeware, but signed + everything
  else clean is a strong benign signal.
- Debug CodeView PDB path: leaks build-machine paths (attribution + sloppiness).
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peparse import PE, PEError, flags_to_names, DLL_CHARS

PACKER_SECTIONS = {'.upx0', '.upx1', '.upx2', '.aspack', '.adata', '.themida',
                   '.enigma1', '.enigma2', '.petite', '.mpress1', '.mpress2',
                   '.rlpack', '.vmp0', '.vmp1', '.sforce3'}
# .rsrc legitimately has high entropy (compressed icons) -- exclude from entropy flag
ENTROPY_EXEMPT = {'.rsrc'}

SUSPICIOUS_APIS = {
    'CreateRemoteThread': ('process injection', 25),
    'WriteProcessMemory': ('process injection', 25),
    'VirtualAllocEx': ('process injection', 20),
    'NtCreateThreadEx': ('process injection', 25),
    'QueueUserAPC': ('process injection', 20),
    'SetThreadContext': ('process injection', 20),
    'VirtualAlloc': ('memory execution (shellcode)', 12),
    'VirtualProtect': ('memory execution (shellcode)', 12),
    'IsDebuggerPresent': ('anti-debug', 10),
    'CheckRemoteDebuggerPresent': ('anti-debug', 10),
    'NtQueryInformationProcess': ('anti-debug', 8),
    'SetWindowsHookExA': ('keylogging/hooking', 20),
    'SetWindowsHookExW': ('keylogging/hooking', 20),
    'GetAsyncKeyState': ('keylogging', 15),
    'GetKeyState': ('keylogging', 10),
    'InternetOpenUrlA': ('network download', 15),
    'InternetOpenUrlW': ('network download', 15),
    'URLDownloadToFileA': ('network download', 20),
    'URLDownloadToFileW': ('network download', 20),
    'HttpSendRequestA': ('network C2', 12),
    'HttpSendRequestW': ('network C2', 12),
    'socket': ('raw networking', 8),
    'connect': ('raw networking', 8),
    'CryptEncrypt': ('crypto (possible ransomware)', 10),
    'CryptDecrypt': ('crypto', 5),
    'AdjustTokenPrivileges': ('privilege escalation', 12),
    'CreateServiceA': ('persistence via service', 12),
    'CreateServiceW': ('persistence via service', 12),
    'RegSetValueExA': ('persistence via registry', 8),
    'RegSetValueExW': ('persistence via registry', 8),
    'ShellExecuteA': ('execution', 5),
    'WinExec': ('execution', 8),
    'LoadLibraryA': ('dynamic API resolution (packer-ish)', 4),
    'GetProcAddress': ('dynamic API resolution (packer-ish)', 4),
}


def triage(path):
    findings = []  # (points, text)
    try:
        pe = PE(path)
    except PEError as e:
        return {'verdict': 'UNPARSEABLE', 'score': 0,
                'findings': [(0, f'not a valid PE: {e}')], 'pe': None}

    n_imports = sum(len(i['functions']) for i in pe.imports)
    max_ent, max_ent_sect = 0.0, None

    for s in pe.sections:
        e = pe.section_entropy(s)
        flags = set(s['flags'])
        # high entropy outside exempt sections
        if e > 7.0 and s['name'].lower() not in ENTROPY_EXEMPT and s['rawsize'] >= 0x200:
            findings.append((20, f"section '{s['name']}' entropy {e:.2f} -- "
                                  'packed/encrypted payload shape'))
            max_ent, max_ent_sect = e, s['name']
        # vsize >> rawsize: meaningful only for code/high-entropy sections.
        # .data legitimately has vsize > rawsize (zero-initialized statics);
        # PuTTY's real .data is 4x and entropy 2.07 -- not packed.
        if (s['rawsize'] and s['vsize'] / s['rawsize'] >= 4 and s['vsize'] >= 0x1000
                and ('MEM_EXECUTE' in flags or 'CODE' in flags or e > 6.5)):
            findings.append((15, f"section '{s['name']}' vsize {s['vsize']:#x} is "
                                  f"{s['vsize']/s['rawsize']:.0f}x raw size -- unpacks in memory"))
        # known packer names
        if s['name'].lower() in PACKER_SECTIONS:
            findings.append((25, f"section '{s['name']}' matches known packer signature"))
        # RWX section
        if {'MEM_READ', 'MEM_WRITE', 'MEM_EXECUTE'} <= flags:
            findings.append((15, f"section '{s['name']}' is RWX -- writeable+executable"))
        # entry point checks
        if s['name'] == pe.entry_section:
            if 'MEM_EXECUTE' not in flags and 'CODE' not in flags:
                findings.append((20, f"entry point in non-executable section '{s['name']}'"))
            if 'MEM_WRITE' in flags:
                findings.append((15, f"entry point in writeable section '{s['name']}' "
                                     '-- unpacker-stub shape'))

    if n_imports < 10 and max_ent and max_ent > 7.0:
        findings.append((15, f'only {n_imports} imports with high-entropy section -- '
                             'APIs likely resolved dynamically at runtime'))

    seen_caps = set()
    for imp in pe.imports:
        for fn in imp['functions']:
            if fn in SUSPICIOUS_APIS:
                cap, pts = SUSPICIOUS_APIS[fn]
                # LoadLibraryA/GetProcAddress are mundane in big import tables
                # (PuTTY imports both among 348 functions); they only smell
                # when the binary resolves nearly everything dynamically.
                if cap.startswith('dynamic API resolution') and n_imports >= 50:
                    continue
                # count each capability once per binary (avoid double-counting
                # CreateRemoteThread+WriteProcessMemory as two separate crimes)
                key = (cap, fn)
                if key not in seen_caps:
                    seen_caps.add(key)
                    findings.append((pts, f'imports {fn} ({imp["dll"]}) -- {cap}'))

    # --- resources -----------------------------------------------------------
    BENIGN_RTYPES = {'ICON', 'GROUP_ICON', 'CURSOR', 'GROUP_CURSOR', 'BITMAP',
                     'VERSION', 'MANIFEST', 'DIALOG', 'STRING', 'MENU',
                     'ACCELERATOR', 'FONT', 'FONTDIR'}
    for r in pe.resources:
        d = r['data']
        if not d:
            continue
        if d.startswith(b'MZ'):
            findings.append((20, f"resource {r['type']}/{r['name']} contains an "
                                 'embedded executable (MZ)'))
            continue
        magic_note = ''
        if d.startswith(b'ITSF'):
            magic_note = ' (CHM help file -- benign)'
        elif d.startswith(b'PK\x03\x04'):
            magic_note = ' (zip archive)'
        elif d.startswith((b'Rar!', b'7z\xbc\xaf\x27\x1c', b'\x1f\x8b')):
            magic_note = ' (compressed archive)'
        e = pe.resource_entropy(r)
        if r['type'] not in BENIGN_RTYPES and r['size'] >= 0x1000 and e > 7.0:
            if magic_note:
                findings.append((0, f"resource {r['type']}/{r['name']}: "
                                    f'{r["size"]} bytes, entropy {e:.2f}{magic_note}'))
            else:
                findings.append((15, f"resource {r['type']}/{r['name']}: "
                                      f'{r["size"]} bytes, entropy {e:.2f} -- '
                                      'unidentified high-entropy blob, possible '
                                      'embedded payload'))

    # checksum
    if pe.checksum_stored and pe.checksum_stored != pe.checksum_computed():
        findings.append((15, f'PE checksum mismatch (stored {pe.checksum_stored:#x} != '
                             f'computed {pe.checksum_computed():#x}) -- modified after linking'))
    elif pe.checksum_stored:
        findings.append((-5, 'PE checksum valid'))

    # overlay
    if pe.overlay:
        findings.append((8, f'{len(pe.overlay)} bytes of overlay data past last section '
                            '-- appended payload or installer blob'))
        if pe.overlay.startswith(b'MZ'):
            findings.append((20, 'overlay starts with MZ -- a second executable is appended'))

    # signature
    if pe.security:
        ct = {2: 'X.509', 3: 'PKCS#7 signedData (Authenticode)'}.get(
            pe.security['cert_type'], f"type {pe.security['cert_type']}")
        findings.append((-10, f"digital signature present ({ct}, "
                              f"{pe.security['length']} bytes) -- signed binaries "
                              'are rarely malware'))
    else:
        findings.append((3, 'no digital signature (normal for freeware, weak signal)'))

    # hardening
    dc = set(flags_to_names(pe.dll_chars, DLL_CHARS))
    if 'DYNAMIC_BASE' not in dc:
        findings.append((5, 'no ASLR (DYNAMIC_BASE) -- old or deliberately unhardened build'))
    if 'NX_COMPAT' not in dc:
        findings.append((5, 'no DEP/NX -- old or deliberately unhardened build'))

    # debug paths
    for dbg in pe.debug:
        if dbg.get('pdb'):
            findings.append((5, f"CodeView PDB path leaks build path: {dbg['pdb'][:80]}"))

    score = max(0, sum(p for p, _ in findings))
    verdict = 'CLEAN' if score < 20 else 'SUSPICIOUS' if score < 60 else 'MALICIOUS'
    return {'verdict': verdict, 'score': score, 'findings': findings, 'pe': pe}


def report(path):
    r = triage(path)
    print(f'{path}: {r["verdict"]} ({r["score"]} pts)')
    for pts, text in sorted(r['findings'], key=lambda x: -x[0]):
        sign = '+' if pts > 0 else ''
        print(f'  [{sign}{pts}] {text}')
    if r['pe'] is not None:
        print()
        print(r['pe'].summary())
    return r


if __name__ == '__main__':
    report(sys.argv[1])
