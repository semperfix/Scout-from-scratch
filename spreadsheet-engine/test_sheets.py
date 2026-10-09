#!/usr/bin/env python3
"""test_sheets.py — validation suite for the from-scratch spreadsheet engine.
Checks are grounded in documented Excel semantics and independently known
numeric values (e.g. the standard 30-year mortgage payment)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sheets import (Workbook, load_csv, save_csv, shift_formula, lex,
                    parse_formula, DIV0, VALUE, REF, NAME, NUM, NA, CYCLE,
                    XlError)

PASS = 0
FAIL = 0
FAILURES = []


def check(label, got, want):
    global PASS, FAIL
    ok = (got == want) if not isinstance(want, float) else \
        (isinstance(got, float) and abs(got - want) < 1e-9)
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%s: got %r want %r" % (label, got, want))


def approx(label, got, want, tol):
    global PASS, FAIL
    if isinstance(got, (int, float)) and abs(got - want) <= tol:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%s: got %r want %r±%r" % (label, got, want, tol))


def wb_of(pairs, sheet="Sheet1"):
    wb = Workbook()
    for a1, raw in pairs:
        wb.set(sheet, a1, raw)
    wb.calc()
    return wb


def ev(formula, cells=(), sheet="Sheet1"):
    wb = wb_of(list(cells) + [("Z100", formula)], sheet)
    return wb.get(sheet, "Z100")


# ---- 1. precedence & arithmetic ----
check("add/mul precedence", ev("=2+3*4"), 14.0)
check("parens", ev("=(2+3)*4"), 20.0)
check("power right-assoc", ev("=2^3^2"), 512.0)
check("excel unary-minus quirk", ev("=-2^2"), 4.0)   # Excel: 4, not -4
check("double negation", ev("=--5"), 5.0)
check("percent", ev("=50%"), 0.5)
check("percent arithmetic", ev("=50%+50%"), 1.0)
check("neg exponent", ev("=2^-2"), 0.25)
check("division", ev("=7/2"), 3.5)
check("concat precedence", ev('="a"&"b"="ab"'), True)

# ---- 2. comparisons ----
check("lt", ev("=1<2"), True)
check("neq", ev("=1<>2"), True)
check("chain is left-assoc", ev("=1<2<3"), False)  # (1<2)=TRUE; TRUE<3 -> False
check("text case-insensitive eq", ev('="A"="a"'), True)
check("number < text rank", ev("=1<\"a\""), True)
check("text < bool rank", ev('="a"<TRUE'), True)
check("number vs text eq", ev('=1="a"'), False)

# ---- 3. coercion ----
check("numeric text coerces", ev('="1"+2'), 3.0)
check("bad text -> VALUE", ev('=1+"a"'), VALUE)
check("bool coerces", ev("=TRUE+1"), 2.0)
check("blank cell is 0", ev("=A1+1"), 1.0)
check("blank = 0", ev("=A1=0"), True)
check('blank = ""', ev('=A1=""'), True)
check('"" = 0 (excel)', ev('=""=0'), True)
check("empty text not 0 in arith", ev('=""+1'), VALUE)
check("text condition -> VALUE", ev('=IF("x",1,2)'), VALUE)

# ---- 4. error values & propagation ----
check("div0", ev("=1/0"), DIV0)
check("div0 propagates", ev("=1/0+5"), DIV0)
check("div0 through compare", ev("=1/0=1"), DIV0)
check("unknown fn", ev("=NOSUCHFN(1)"), NAME)
check("bare name", ev("=BIGNAME"), NAME)
check("sqrt neg", ev("=SQRT(-1)"), NUM)
check("out of grid -> REF", ev("=ZZZ9999999"), REF)
check("range in scalar ctx", ev("=A1:A3", [("A1", "1")]), VALUE)

# ---- 5. aggregators (Excel range vs direct-arg rules) ----
cells = [("A1", "1"), ("A2", "x"), ("A3", "TRUE"), ("A4", "")]
check("SUM ignores text/bool/blank in range", ev("=SUM(A1:A4)", cells), 1.0)
check("direct bool counts", ev("=SUM(1,TRUE)"), 2.0)
check("direct text -> VALUE", ev('=SUM(1,"5")'), VALUE)
check("AVERAGE", ev("=AVERAGE(A1:A4)", cells), 1.0)
check("AVERAGE empty -> DIV0", ev("=AVERAGE(B1:B2)"), DIV0)
check("COUNT", ev("=COUNT(A1:A4)", cells), 1.0)
check("COUNTA", ev("=COUNTA(A1:A4)", cells), 3.0)
check("MIN", ev("=MIN(3,1,2)"), 1.0)
check("MAX range", ev("=MAX(A1:A4)", cells), 1.0)
check("PRODUCT", ev("=PRODUCT(2,3,4)"), 24.0)

# ---- 6. IF laziness ----
check("IF true branch only", ev("=IF(TRUE,1,1/0)"), 1.0)
check("IF false branch only", ev("=IF(FALSE,1/0,2)"), 2.0)
check("IF cond 0", ev('=IF(0,"y","n")'), "n")
check("IF 2-arg true", ev("=IF(TRUE,5)"), 5.0)
check("IF 2-arg false -> FALSE", ev("=IF(FALSE,5)"), False)
check("IFERROR lazy", ev('=IFERROR(1/0,"oops")'), "oops")
check("IFERROR passthrough", ev('=IFERROR(5,"oops")'), 5.0)

# ---- 7. logic ----
check("AND vacuous", ev("=AND()"), True)
check("OR vacuous", ev("=OR()"), False)
check("AND", ev("=AND(TRUE,1,2)"), True)
check("AND short text err", ev('=AND(TRUE,"x")'), VALUE)
check("NOT", ev("=NOT(0)"), True)

# ---- 8. rounding (half away from zero, Excel style) ----
check("ROUND half up", ev("=ROUND(2.5,0)"), 3.0)
check("ROUND neg half away", ev("=ROUND(-2.5,0)"), -3.0)
check("ROUND decimals", ev("=ROUND(2.45,1)"), 2.5)
check("ROUNDUP", ev("=ROUNDUP(2.11,1)"), 2.2)
check("ROUNDDOWN", ev("=ROUNDDOWN(2.19,1)"), 2.1)
check("MOD sign of divisor", ev("=MOD(-3,2)"), 1.0)
check("MOD neg divisor", ev("=MOD(3,-2)"), -1.0)
check("INT floor neg", ev("=INT(-2.5)"), -3.0)

# ---- 9. text functions ----
check("LEFT", ev('=LEFT("hello",2)'), "he")
check("RIGHT", ev('=RIGHT("hello",2)'), "lo")
check("MID 1-indexed", ev('=MID("hello",2,3)'), "ell")
check("UPPER", ev('=UPPER("ab")'), "AB")
check("TRIM collapses", ev('=TRIM("  a  b ")'), "a b")
check("LEN", ev('=LEN("hello")'), 5.0)
check("FIND", ev('=FIND("l","hello")'), 3.0)
check("FIND missing -> VALUE", ev('=FIND("z","hello")'), VALUE)
check("CONCAT mixed", ev('=CONCAT("a",1,TRUE)'), "a1TRUE")
check("ampersand", ev('="n="&42'), "n=42")
check("string with escaped quote", ev('="say ""hi"""'), 'say "hi"')

# ---- 10. VLOOKUP ----
vtable = [("A1", "apple"), ("B1", "1"), ("A2", "banana"), ("B2", "2"),
          ("A3", "cherry"), ("B3", "3")]
check("VLOOKUP exact", ev("=VLOOKUP(\"banana\",A1:B3,2,FALSE)", vtable), 2.0)
check("VLOOKUP case-insensitive", ev("=VLOOKUP(\"BANANA\",A1:B3,2,FALSE)", vtable), 2.0)
check("VLOOKUP missing -> N/A", ev("=VLOOKUP(\"grape\",A1:B3,2,FALSE)", vtable), NA)
check("VLOOKUP col too big -> REF", ev("=VLOOKUP(\"banana\",A1:B3,5,FALSE)", vtable), REF)
check("VLOOKUP col 0 -> VALUE", ev("=VLOOKUP(\"banana\",A1:B3,0,FALSE)", vtable), VALUE)

# ---- 11. SUMIF / COUNTIF / AVERAGEIF ----
scells = [("A1", "1"), ("A2", "6"), ("A3", "3"), ("A4", "8"), ("A5", "2")]
check("SUMIF >5", ev('=SUMIF(A1:A5,">5")', scells), 14.0)
check("COUNTIF >5", ev('=COUNTIF(A1:A5,">5")', scells), 2.0)
check("COUNTIF <>", ev('=COUNTIF(A1:A5,"<>")', scells), 5.0)
check("AVERAGEIF", ev('=AVERAGEIF(A1:A5,">5")', scells), 7.0)
tcells = [("B1", "apple"), ("B2", "apricot"), ("B3", "banana")]
check("COUNTIF wildcard", ev('=COUNTIF(B1:B3,"ap*")', tcells), 2.0)

# ---- 12. PMT: 30-yr $200k mortgage at 5% -> $1,073.64/mo (standard value) ----
approx("PMT mortgage", ev("=PMT(0.05/12,360,200000)"), -1073.64, 0.01)
check("PMT zero rate", ev("=PMT(0,12,1200)"), -100.0)

# ---- 13. cycles ----
cwb = wb_of([("A1", "=B1+1"), ("B1", "=A1+1"), ("C1", "=A1*2"), ("D1", "=D1+1"),
             ("E1", "=1+1")])
check("cycle A1", cwb.get("Sheet1", "A1"), CYCLE)
check("cycle B1", cwb.get("Sheet1", "B1"), CYCLE)
check("cycle propagates", cwb.get("Sheet1", "C1"), CYCLE)
check("self cycle", cwb.get("Sheet1", "D1"), CYCLE)
check("non-cycle still fine", cwb.get("Sheet1", "E1"), 2.0)

# ---- 14. dependency shapes ----
check("diamond", ev("=B1+C1", [("A1", "2"), ("B1", "=A1*2"), ("C1", "=A1*3")]), 10.0)
check("chain", ev("=A5", [("A1", "1"), ("A2", "=A1+1"), ("A3", "=A2+1"),
                          ("A4", "=A3+1"), ("A5", "=A4+1")]), 5.0)
check("formula over formula range", ev("=SUM(B1:B2)",
      [("A1", "5"), ("B1", "=A1*2"), ("B2", "=B1+1")]), 21.0)

# ---- 15. cross-sheet ----
wb = Workbook()
wb.set("Sheet2", "A1", "10")
wb.set("Sheet1", "A1", "=Sheet2!A1*2")
wb.calc()
check("cross-sheet ref", wb.get("Sheet1", "A1"), 20.0)
wb2 = Workbook()
wb2.set("My Sheet", "A1", "7")
wb2.set("Sheet1", "A1", "='My Sheet'!A1+1")
wb2.calc()
check("quoted sheet ref", wb2.get("Sheet1", "A1"), 8.0)

# ---- 16. drag-fill copy ----
check("shift relative", shift_formula("A1*2+$B$2", 1, 0), "A2*2+$B$2")
check("shift range", shift_formula("SUM(A1:A3)", 1, 0), "SUM(A2:A4)")
check("string literal untouched", shift_formula('"A1"&A1', 1, 0), '"A1"&A2')
check("mixed abs col", shift_formula("$A1", 2, 3), "$A3")
check("mixed abs row", shift_formula("A$1", 2, 3), "D$1")
check("off-grid -> REF", shift_formula("A1", -1, 0), "#REF!")

# ---- 17. lexer spot checks ----
toks = lex('SUM(A1:B2,$C$3,"x""y",1.5E3,2%)')
kinds = [t[0] for t in toks]
check("lexer kinds", kinds,
      ["IDENT", "OP", "CELL", "OP", "CELL", "OP", "CELL", "OP",
       "STR", "OP", "NUM", "OP", "NUM", "OP", "OP", "EOF"])

# ---- 18. CSV roundtrip ----
with tempfile.TemporaryDirectory() as td:
    p1 = os.path.join(td, "in.csv")
    with open(p1, "w", newline="") as f:
        f.write("a,b,total\n1,2,=A2+B2\n3,4,=A3+B3\n")
    wb = load_csv(p1)
    wb.calc()
    check("csv formula C2", wb.get("Sheet1", "C2"), 3.0)
    check("csv formula C3", wb.get("Sheet1", "C3"), 7.0)
    p2 = os.path.join(td, "out.csv")
    save_csv(wb, p2, values=True)
    with open(p2) as f:
        content = f.read()
    check("csv values written", "3" in content and "7" in content, True)
    p3 = os.path.join(td, "outf.csv")
    save_csv(wb, p3, values=False)
    wb3 = load_csv(p3)
    wb3.calc()
    check("csv formulas survive", wb3.get("Sheet1", "C3"), 7.0)

print("PASS %d  FAIL %d" % (PASS, FAIL))
for f in FAILURES:
    print("FAIL:", f)
sys.exit(1 if FAIL else 0)
