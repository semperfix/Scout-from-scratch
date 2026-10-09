#!/usr/bin/env python3
"""Demo: track what Boss Man Abe owes Kyle using the from-scratch engine.

Positive amounts = money owed TO Kyle; negative = deductions/payments.
(Numbers from Kyle's own account: ~$450 wages minus $30 for a top rail piece.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tinydb import Database

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "abe_ledger.db")
if os.path.exists(PATH):
    os.unlink(PATH)

db = Database(PATH)
db.execute("""CREATE TABLE ledger (
    id INTEGER, who TEXT, memo TEXT, amount REAL, paid INTEGER)""")
db.execute("""INSERT INTO ledger VALUES
    (1, 'abe', 'tree work wages owed', 450.00, 0),
    (2, 'abe', 'top rail piece (deduct)', -30.00, 0),
    (3, 'abe', 'cashapp payment received', 0.00, 0)""")

print("== ledger ==")
cols, rows = db.execute("SELECT id, memo, amount FROM ledger ORDER BY id")
print("\t".join(cols))
for r in rows:
    print("\t".join(str(v) for v in r))

print("\n== balance still owed ==")
_, [(bal,)] = db.execute(
    "SELECT sum(amount) FROM ledger WHERE who = 'abe' AND paid = 0")
print("$%.2f" % bal)

print("\n== unpaid entries ==")
cols, rows = db.execute(
    "SELECT memo, amount FROM ledger WHERE paid = 0 AND amount <> 0 "
    "ORDER BY amount DESC")
for memo, amt in rows:
    print("  %-28s $%7.2f" % (memo, amt))
db.close()
print("\nDB file: %s (query it: python3 tinydb.py abe_ledger.db \"SELECT ...\")" % PATH)
