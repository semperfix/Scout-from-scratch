#!/usr/bin/env python3
"""Fixture generator for expedition #21: mailbox forensics.

Builds:
  fixtures/inbox.mbox   - Gmail-Takeout style mbox with 8 messages, forensic scenarios
  fixtures/corrupt.mbox - mbox with an unescaped bare "From " line mid-body (corruption test)
  fixtures/maildir/     - Maildir with cur/new/tmp incl. flags, deleted message, torn tmp file
  fixtures/timeline.csv - expected ground truth (computed while generating)
All deterministic: fixed timestamps, fixed random seed.
"""
import base64, hashlib, os, random, shutil, textwrap

random.seed(21)
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
shutil.rmtree(FIX, ignore_errors=True)
for d in ("cur", "new", "tmp"):
    os.makedirs(os.path.join(FIX, "maildir", d))

ATTACH = b"PCFET0NUWVBFIGh0bWw+"  # placeholder replaced below
attach_raw = b"<html><body><h1>Invoice #4471</h1><p>Amount due: $1,299.00</p></body></html>"
attach_b64 = base64.encodebytes(attach_raw).decode()
attach_sha = hashlib.sha256(attach_raw).hexdigest()

def msg(headers, body):
    h = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return h + "\r\n" + body

BOUND = "----=_Part_21_4471.1775300000"

# 1: plain thread parent from Stephanie
M1 = msg([
    ("From", '"Stephanie Burnside" <stephanie.burnside@example.com>'),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "thinking about you"),
    ("Date", "Tue, 06 Oct 2026 15:42:11 -0400"),
    ("Message-ID", "<CA+parent21@example.com>"),
    ("X-Gmail-Labels", "Inbox,Category personal,Unread"),
], "Hey, can we talk later? -S\r\n")

# 2: Kyle's reply (multipart/alternative, thread reply)
alt = (
    f"--{BOUND}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
    "Sure. Call me after 6.\r\n"
    f"--{BOUND}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
    "<p>Sure. <b>Call me after 6.</b></p>\r\n"
    f"--{BOUND}--\r\n")
M2 = msg([
    ("From", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("To", '"Stephanie Burnside" <stephanie.burnside@example.com>'),
    ("Subject", "Re: thinking about you"),
    ("Date", "Tue, 06 Oct 2026 16:03:44 -0400"),
    ("Message-ID", "<CA+reply21@example.com>"),
    ("In-Reply-To", "<CA+parent21@example.com>"),
    ("References", "<CA+parent21@example.com>"),
    ("Content-Type", f'multipart/alternative; boundary="{BOUND}"'),
    ("X-Gmail-Labels", "Sent"),
], alt)

# 3: message whose BODY contains a ">From " escaped line (mbox correctness test)
M3 = msg([
    ("From", "Tony Smith <tony.smith@example.com>"),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "From the shop"),
    ("Date", "Wed, 07 Oct 2026 09:15:02 -0400"),
    ("Message-ID", "<tony-shop-21@example.com>"),
], "Boss said:\r\n>From the shop floor, nobody leaves early.\r\nWe leave at 5.\r\n")

# 4: SPOOFED-DATE message: Date: header claims 2024, Received chain says 2026
M4 = msg([
    ("From", '"Abe Bossman" <abe@example.com>'),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "about the money"),
    ("Date", "Mon, 14 Oct 2024 10:00:00 -0400"),
    ("Message-ID", "<abe-money-21@example.com>"),
    ("Received", "from mail.example.com by mx.takeout.example.com with ESMTPS id ABC123; Wed, 07 Oct 2026 18:22:31 -0400"),
], "I sent the payment yesterday, check your app.\r\n")

# 5: encoded-word subject + folded headers + attachment (mixed)
B2 = "----=_Part_21_9917.1775300001"
mix = (
    f"--{B2}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
    "Invoice attached. Let me know.\r\n"
    f"--{B2}\r\nContent-Type: text/html; name=\"invoice.html\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    f'Content-Disposition: attachment; filename="invoice.html"\r\n\r\n'
    + attach_b64 +
    f"--{B2}--\r\n")
long_subj = "=?UTF-8?Q?Your_invoice_=E2=80=93_October_is_ready_for_review?="
M5 = msg([
    ("From", '"Billing Dept" <billing@acme-invoices.example>'),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Cc", "amanda.bruner@example.com,\r\n tony.smith@example.com"),
    ("Subject", long_subj),
    ("Date", "Thu, 08 Oct 2026 08:05:59 -0400"),
    ("Message-ID", "<invoice-4471-21@example.com>"),
    ("Content-Type", f'multipart/mixed; boundary="{B2}"'),
    ("X-Gmail-Labels", "Inbox,Unread"),
], mix)

# 6: quoted-printable body
M6 = msg([
    ("From", "Ricky Mobley <ricky.mobley@example.com>"),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "saturday"),
    ("Date", "Thu, 08 Oct 2026 11:47:20 -0400"),
    ("Message-ID", "<ricky-sat-21@example.com>"),
    ("Content-Type", "text/plain; charset=UTF-8"),
    ("Content-Transfer-Encoding", "quoted-printable"),
], "Meet at the shop=2C bring the=20climbing gear.\r\nRope=3Ds good.\r\n")

# 7: second thread parent (standalone, unread in Maildir too)
M7 = msg([
    ("From", "Tracy Lane <tracy.lane@example.com>"),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "saw your truck"),
    ("Date", "Thu, 08 Oct 2026 13:02:55 -0400"),
    ("Message-ID", "<tracy-truck-21@example.com>"),
    ("X-Gmail-Labels", "Inbox,Unread"),
], "Saw your truck by the seventeen eighty. You working today?\r\n")

# 8: final message, no trailing newline at EOF (edge case)
M8 = msg([
    ("From", "Amanda Bruner <amanda.bruner@example.com>"),
    ("To", "Kyle Rhoton <kyle.rhoton@example.com>"),
    ("Subject", "dinner"),
    ("Date", "Thu, 08 Oct 2026 17:20:10 -0400"),
    ("Message-ID", "<amanda-dinner-21@example.com>"),
], "Dinner's at 7. Don't be late.")
M8 = M8.rstrip("\r\n")  # strip trailing newline: EOF edge case

FROM_LINES = [
    "From stephanie.burnside@example.com Tue Oct  6 15:42:11 2026",
    "From kyle.rhoton@example.com Tue Oct  6 16:03:44 2026",
    "From tony.smith@example.com Wed Oct  7 09:15:02 2026",
    "From abe@example.com Wed Oct  7 18:22:31 2026",
    "From billing@acme-invoices.example Thu Oct  8 08:05:59 2026",
    "From ricky.mobley@example.com Thu Oct  8 11:47:20 2026",
    "From tracy.lane@example.com Thu Oct  8 13:02:55 2026",
    "From amanda.bruner@example.com Thu Oct  8 17:20:10 2026",
]
MSGS = [M1, M2, M3, M4, M5, M6, M7, M8]

# Write mbox: escape bare "From " lines, blank line between messages
parts = []
for fl, m in zip(FROM_LINES, MSGS):
    body_escaped = m.replace("\r\nFrom ", "\r\n>From ")
    parts.append(fl + "\n" + body_escaped.replace("\r\n", "\n"))
with open(os.path.join(FIX, "inbox.mbox"), "w") as f:
    f.write("\n\n".join(parts) + "\n")

# corrupt.mbox: bare unescaped "From " inside a body (tests corruption detection)
CORRUPT = (
    "From legit@example.com Thu Oct  8 10:00:00 2026\n"
    "From: legit@example.com\nSubject: ok\nDate: Thu, 08 Oct 2026 10:00:00 -0400\n\n"
    "first line\n"
    "From forged@example.com Thu Oct  8 10:01:00 2026\n"   # NOT escaped -> looks like a new message
    "this pretends to be a delimiter\n"
)
with open(os.path.join(FIX, "corrupt.mbox"), "w") as f:
    f.write(CORRUPT)

# Maildir: 4 messages -> new/ (unread), 2 in cur/ with flags, 1 DELETED (simulated
# by simply never writing it, plus a UIDL-gap record), 1 torn file in tmp/
MD = os.path.join(FIX, "maildir")
def md_write(sub, name, content):
    with open(os.path.join(MD, sub, name), "wb") as f:
        f.write(content.encode())

uidl = ["UID1001", "UID1002", "UID1003", "UID1004", "UID1006"]  # UID1005 deleted -> gap
md_write("new", "1775300001.1001_0.host,U=1001:2,", M1.replace("\r\n", "\n"))
md_write("new", "1775300002.1002_0.host,U=1002:2,", M7.replace("\r\n", "\n"))
md_write("cur", "1775300003.1003_0.host,U=1003:2,FS", M2.replace("\r\n", "\n"))  # flagged+seen
md_write("cur", "1775300004.1004_0.host,U=1004:2,S", M5.replace("\r\n", "\n"))   # seen
md_write("new", "1775300006.1006_0.host,U=1006:2,", M4.replace("\r\n", "\n"))
# torn tmp file: partial delivery remnant
with open(os.path.join(MD, "tmp", "1775300007.1007_0.host"), "wb") as f:
    f.write(M6.replace("\r\n", "\n").encode()[:120])
with open(os.path.join(FIX, "maildir", "uidl.txt"), "w") as f:
    f.write("\n".join(uidl) + "\n")

# Ground truth
with open(os.path.join(FIX, "ground_truth.txt"), "w") as f:
    f.write(textwrap.dedent(f"""\
        mbox messages: 8
        mbox subjects: thinking about you | Re: thinking about you | From the shop |
          about the money | Your invoice — October is ready for review | saturday |
          saw your truck | dinner
        attachment: invoice.html sha256={attach_sha} size={len(attach_raw)}
        escaped-from body: M3 body must contain ">From the shop floor" and NOT start a new message
        spoofed date: M4 Date=2024-10-14 vs Received=2026-10-07 (skew flag)
        maildir messages: 5 (2 new, 2 cur, 0 tmp-complete); UID1005 deleted (gap in uidl.txt)
        torn tmp: 1 partial file (1775300007.1007_0.host), 120 bytes
        thread: <CA+parent21@example.com> -> <CA+reply21@example.com>
        """))
print("fixtures written to", FIX)
print("attachment sha256:", attach_sha)
