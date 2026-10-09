#!/usr/bin/env python3
"""make_fixtures.py - Hand-write 3 forensic PDF fixtures (no PDF library).

Writes raw PDF bytes with computed xref offsets:
  fixtures/clean.pdf        - single revision, benign one-pager
  fixtures/js.pdf           - /OpenAction JavaScript + /Names /JavaScript
  fixtures/incremental.pdf  - rev 1 "clean", rev 2 redefines the page
                              content (text changed after apparent signing)
"""
import os

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

CONTENT_TMPL = ("BT /F1 24 Tf 72 720 Td ({text}) Tj ET")

def build_pdf(objects, info=None, root_extra=b"", prev=None, size=None):
    """objects: list of (num, body_bytes). Returns full PDF bytes."""
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num, body in objects:
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref_pos = len(out)
    n = (size or max(offsets)) + 1
    out += b"xref\n0 %d\n" % n
    out += b"0000000000 65535 f \n"
    for i in range(1, n):
        out += b"%010d 00000 n \n" % offsets.get(i, 0)
    out += b"trailer\n<< /Size %d /Root 1 0 R" % n
    if info is not None:
        out += b" /Info %d 0 R" % info
    if prev is not None:
        out += b" /Prev %d" % prev
    out += root_extra + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref_pos
    return bytes(out), xref_pos

def clean_objects(text, creator=b"Scout", producer=b"pdfcheck-fixture"):
    return [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        (4, b"<< /Length %d >>\nstream\n" % len(CONTENT_TMPL.format(text=text).encode())
            + CONTENT_TMPL.format(text=text).encode() + b"\nendstream"),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
        (6, b"<< /Creator (%s) /Producer (%s) "
            b"/CreationDate (D:20261009000000) /ModDate (D:20261009000000) >>"
            % (creator, producer)),
    ]

def main():
    os.makedirs(FIX, exist_ok=True)

    # 1. clean
    pdf, _ = build_pdf(clean_objects("Hello, this is a clean document."), info=6)
    open(os.path.join(FIX, "clean.pdf"), "wb").write(pdf)

    # 2. javascript via /OpenAction and /Names
    objs = clean_objects("Document with JavaScript.")
    objs[0] = (1, b"<< /Type /Catalog /Pages 2 0 R "
                  b"/OpenAction << /S /JavaScript /JS (app.alert\\(\"pwned\"\\);) >> "
                  b"/Names << /JavaScript << /Names [(embedded) 7 0 R] >> >> >>")
    objs.append((7, b"<< /S /JavaScript /JS (this.getField\\(\"x\"\\).value=1;) >>"))
    pdf, _ = build_pdf(objs, info=6)
    open(os.path.join(FIX, "js.pdf"), "wb").write(pdf)

    # 3. incremental update: rev 1 clean, rev 2 redefines object 4 (new text)
    rev1, xref1 = build_pdf(clean_objects("Original text before signing."), info=6)
    new_content = CONTENT_TMPL.format(text="Modified text after signing.")
    body = (b"<< /Length %d >>\nstream\n" % len(new_content.encode())
            + new_content.encode() + b"\nendstream")
    out = bytearray(rev1)
    out += b"4 0 obj\n" + body + b"\nendobj\n"
    xref2_pos = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n4 1\n"
    out += b"%010d 00000 n \n" % (xref2_pos - (len(b"4 0 obj\n") + len(body) + len(b"\nendobj\n")))
    out += (b"trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev %d >>\n"
            b"startxref\n%d\n%%%%EOF\n" % (xref1, xref2_pos))
    open(os.path.join(FIX, "incremental.pdf"), "wb").write(bytes(out))

    for f in ("clean.pdf", "js.pdf", "incremental.pdf"):
        print("wrote", os.path.join(FIX, f))

if __name__ == "__main__":
    main()
