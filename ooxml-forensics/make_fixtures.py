#!/usr/bin/env python3
"""make_fixtures.py - Build 3 forensic .docx fixtures with stdlib zipfile.

NOTE: zipfile is used ONLY to *generate* fixtures. The analyzer
(ooxmlcheck.py) never touches zipfile - it parses ZIP by hand.

  fixtures/clean.docx   - benign one-pager, consistent metadata
  fixtures/evil-ext.docx - external image rel (tracking pixel) + white-on-white
                           hidden text + a hyperlink display/target mismatch
  fixtures/macro.docx   - vbaProject.bin stub with valid OLE header
"""
import os
import zipfile

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>"""

RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>"""

CORE = """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
<dc:creator>Scout</dc:creator>
<cp:lastModifiedBy>Scout</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">2026-10-09T00:00:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">2026-10-09T00:00:00Z</dcterms:modified>
</cp:coreProperties>"""

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

def doc_xml(body):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="{W}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<w:body>{body}
<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr>
</w:body></w:document>"""

def para(text, rpr=""):
    rpr_xml = f"<w:rPr>{rpr}</w:rPr>" if rpr else ""
    return f'<w:p><w:r>{rpr_xml}<w:t>{text}</w:t></w:r></w:p>'

CLEAN_BODY = para("Hello, this is a clean document.")
CLEAN_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>"""

EVIL_BODY = (
    para("Please review the attached invoice.")
    + para("supersecret exfil note", '<w:vanish/><w:color w:val="FFFFFF"/>')
    + '<w:p><w:hyperlink r:id="rId9" w:history="1"><w:r><w:t>https://your-bank.example/login</w:t></w:r></w:hyperlink></w:p>'
    + '<w:p><w:ins w:author="mallory" w:date="2026-10-08T12:00:00Z"><w:r><w:t>added later</w:t></w:r></w:ins></w:p>'
)
EVIL_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="http://tracker.evil.example/pixel.gif" TargetMode="External"/>
<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://phish.evil.example/steal" TargetMode="External"/>
</Relationships>"""

MACRO_BODY = para("This document contains a macro.")
MACRO_CT = CONTENT_TYPES.replace(
    "</Types>",
    '<Override PartName="/word/vbaProject.bin" '
    'ContentType="application/vnd.ms-office.vbaProject"/>\n</Types>')
OLE_STUB = (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 504
            + b"FakeVBA project stub for forensics testing." + b"\x00" * 64)

def write_docx(path, body, doc_rels, content_types=CONTENT_TYPES, extra=()):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", doc_xml(body))
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("docProps/core.xml", CORE)
        for name, blob in extra:
            z.writestr(name, blob)

def main():
    os.makedirs(FIX, exist_ok=True)
    write_docx(os.path.join(FIX, "clean.docx"), CLEAN_BODY, CLEAN_RELS)
    write_docx(os.path.join(FIX, "evil-ext.docx"), EVIL_BODY, EVIL_RELS)
    write_docx(os.path.join(FIX, "macro.docx"), MACRO_BODY, CLEAN_RELS,
               content_types=MACRO_CT,
               extra=[("word/vbaProject.bin", OLE_STUB)])
    print("wrote fixtures/clean.docx, evil-ext.docx, macro.docx")

if __name__ == "__main__":
    main()
