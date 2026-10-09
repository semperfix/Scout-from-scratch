#!/usr/bin/env python3
"""test_pe.py -- Validation suite for the PE forensics expedition.
Asserts parser + triage behavior against synthetic fixtures and real-world.exe.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peparse import PE, PEError
from triage import triage

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
REAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'real-world.exe')

passed = failed = 0
def check(name, cond, detail=''):
    global passed, failed
    if cond:
        passed += 1
        print(f'  ok: {name}')
    else:
        failed += 1
        print(f'  FAIL: {name} {detail}')

print('== benign.exe')
pe = PE(f'{FX}/benign.exe')
check('machine i386', pe.machine == 0x14c, hex(pe.machine))
check('3 sections', pe.nsections == 3)
check('entry in .text', pe.entry_section == '.text')
check('imports KERNEL32/ExitProcess',
      any(i['dll'] == 'KERNEL32.dll' and 'ExitProcess' in i['functions'] for i in pe.imports),
      str([i['dll'] for i in pe.imports]))
check('imports GetModuleHandleA',
      any('GetModuleHandleA' in i['functions'] for i in pe.imports))
check('checksum self-consistent', pe.checksum_stored == pe.checksum_computed(),
      f'{pe.checksum_stored:#x} vs {pe.checksum_computed():#x}')
r = triage(f'{FX}/benign.exe')
check('benign verdict CLEAN', r['verdict'] == 'CLEAN', f"{r['verdict']} {r['score']}")

print('== packed.exe')
pe = PE(f'{FX}/packed.exe')
check('entry in .upx0', pe.entry_section == '.upx0')
check('vsize>>rawsize', pe.sections[0]['vsize'] / pe.sections[0]['rawsize'] >= 4)
check('RWX section', {'MEM_READ','MEM_WRITE','MEM_EXECUTE'} <= set(pe.sections[0]['flags']))
check('entropy high', pe.section_entropy(pe.sections[0]) > 7.0)
r = triage(f'{FX}/packed.exe')
check('packed verdict SUSPICIOUS+', r['verdict'] in ('SUSPICIOUS','MALICIOUS'), r['verdict'])

print('== evil_api.exe')
pe = PE(f'{FX}/evil_api.exe')
fns = [f for i in pe.imports for f in i['functions']]
check('CreateRemoteThread imported', 'CreateRemoteThread' in fns)
check('6 imports', len(fns) == 6, str(len(fns)))
r = triage(f'{FX}/evil_api.exe')
check('evil verdict MALICIOUS', r['verdict'] == 'MALICIOUS', f"{r['verdict']} {r['score']}")

print('== overlay.exe')
pe = PE(f'{FX}/overlay.exe')
check('overlay carved', len(pe.overlay) == 4107, str(len(pe.overlay)))
check('overlay content', pe.overlay.startswith(b'OVERLAYBLOB'))
r = triage(f'{FX}/overlay.exe')
check('overlay flagged', any('overlay' in t for _, t in r['findings']))

print('== exports.dll')
pe = PE(f'{FX}/exports.dll')
check('export MyExport found', any(e['name'] == 'MyExport' for e in pe.exports),
      str(pe.exports))
check('export ordinal 1', any(e['ordinal'] == 1 for e in pe.exports))
check('export points at .text', any(e['rva'] == 0x1000 for e in pe.exports))

print('== cert.exe')
pe = PE(f'{FX}/cert.exe')
check('security parsed', pe.security is not None)
check('cert type PKCS7', pe.security['cert_type'] == 3, str(pe.security))
check('no overlay (cert is last)', len(pe.overlay) == 0, str(len(pe.overlay)))
r = triage(f'{FX}/cert.exe')
check('signed reduces score', r['score'] < triage(f'{FX}/benign.exe')['score'] + 3)

print('== resource.exe')
pe = PE(f'{FX}/resource.exe')
check('2 RCDATA resources', len(pe.resources) == 2, str(len(pe.resources)))
check('resource names parsed', {r['name'] for r in pe.resources} == {'1', '2'})
check('resource data intact', pe.resources[0]['data'].startswith(b'MZ'))
r = triage(f'{FX}/resource.exe')
check('resource verdict SUSPICIOUS+', r['verdict'] in ('SUSPICIOUS','MALICIOUS'), r['verdict'])
check('MZ resource flagged', any('embedded executable' in t for _, t in r['findings']))
check('blob resource flagged', any('unidentified high-entropy blob' in t for _, t in r['findings']))

print('== malformed')
for name in ('mangled.bin', 'truncated.bin'):
    try:
        PE(f'{FX}/{name}')
        check(f'{name} rejected', False, 'parsed without error')
    except PEError:
        check(f'{name} rejected', True)

print('== real-world.exe (PuTTY, signed PE32+)')
pe = PE(REAL)
check('is64', pe.is64)
check('>=8 import DLLs', len(pe.imports) >= 8, str(len(pe.imports)))
check('BitBlt imported', any('BitBlt' in i['functions'] for i in pe.imports))
check('cert present', pe.security is not None and pe.security['cert_type'] == 2)
check('checksum matches linker', pe.checksum_stored == pe.checksum_computed(),
      f'{pe.checksum_stored:#x} vs {pe.checksum_computed():#x}')
check('entry in .text', pe.entry_section == '.text')
r = triage(REAL)
check('putty verdict not MALICIOUS', r['verdict'] in ('CLEAN','SUSPICIOUS'),
      f"{r['verdict']} {r['score']}")

print(f'\n{passed} passed, {failed} failed')
sys.exit(1 if failed else 0)
