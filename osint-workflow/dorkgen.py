#!/usr/bin/env python3
"""dorkgen.py -- OSINT search-dork battery generator (stdlib only, offline).

From --name/--email/--phone/--username/--location, generates a categorized
battery of 18+ search dorks for a person-investigation: identity, social,
public records, contact pivots, breach-adjacent guidance, and image pivots.

Also prints the source-grading rubric (--rubric), the identity
disambiguation checklist (--checklist), and a full printable investigation
worksheet (--worksheet).

No live network queries are made -- this is the offline methodology plus the
dork battery. You run the dorks yourself in a search engine.
"""
import argparse
import textwrap

RUBRIC = """\
SOURCE-GRADING RUBRIC (grade every finding before it enters the worksheet)
  A  Primary / authoritative ......... the subject themselves, government
     records (court, property, voter), the platform's own profile page
  B  Reliable secondary .............. reputable journalism, employer or
     school directories, archived official pages
  C  Unverified / aggregator ......... people-search sites, data brokers,
     forums, social posts by third parties -- treat as LEADS, not facts
  D  Unreliable / likely junk ........ unsourced claims, AI-generated
     content farms, mismatched identities, stale copies of C sources
Rule: a C never promotes to B without a second independent source; a D never
enters the timeline at all. Record the grade next to every fact.
"""

CHECKLIST = """\
IDENTITY-DISAMBIGUATION CHECKLIST (same name != same person)
  [ ] DOB / age cross-match: does the candidate's age fit the timeline?
  [ ] Address history: do locations chain together plausibly over time?
  [ ] Associates: do family / friends / coworkers overlap across sources?
  [ ] Photos: does the face match across profiles (reverse-image pivot)?
  [ ] Employment / education: consistent across LinkedIn, employer, news?
  [ ] Phone/email pivots: does the same contact detail appear on two
      independent profiles?
  [ ] Negative check: search '"name" NOT <your location>' to find the OTHER
      people sharing the name -- know who they are so you don't merge them.
  [ ] Timeline sanity: no graduations before birth, no jobs overlapping
      prison stints, etc.
Two independent anchors (e.g. DOB + address, or photo + associates) are the
minimum to declare an identity match.
"""


def username_variants(username):
    v = [username]
    squashed = username.replace("_", "").replace(".", "").replace("-", "")
    if squashed != username:
        v.append(squashed)
    return v


def build_dorks(name=None, email=None, phone=None, username=None,
                location=None):
    """Returns [(category, [dork, ...])]."""
    cats = []

    if name:
        ident = ['"%s"' % name]
        if location:
            ident.append('"%s" "%s"' % (name, location))
            ident.append('"%s" "%s" age OR birthday OR "date of birth"'
                         % (name, location))
        ident.append('"%s" phone OR email OR address' % name)
        ident.append('"%s" resume OR CV OR portfolio' % name)
        ident.append('"%s" news OR newspaper' % name)
        ident.append('"%s" obituary' % name)
        cats.append(("IDENTITY -- who is this name", ident))

        social = [
            'site:linkedin.com/in "%s"' % name,
            'site:facebook.com "%s"' % name,
            'site:x.com "%s" OR site:twitter.com "%s"' % (name, name),
            'site:youtube.com "%s"' % name,
            '"%s" "about.me" OR "linktr.ee" OR "link in bio"' % name,
        ]
        if username:
            for u in username_variants(username):
                social.append('site:instagram.com "%s"' % u)
                break
            social.append('site:tiktok.com "@%s"' % username)
            social.append('site:github.com "%s"' % username)
            social.append('site:reddit.com/user/%s' % username)
        if location:
            social.append('site:facebook.com "%s" "%s"' % (name, location))
        cats.append(("SOCIAL -- profiles under this name", social))

        records = [
            '"%s" arrest OR mugshot OR "court records"' % name,
            '"%s" lawsuit OR litigation OR sued' % name,
            '"%s" "property records" OR deed OR "tax assessor"' % name,
            '"%s" business OR LLC OR "real estate"' % name,
            '"%s" married OR divorce OR "voter registration"' % name,
        ]
        if location:
            records.append('"%s" "%s" "court" OR "jail" OR "sheriff"'
                           % (name, location))
        cats.append(("RECORDS -- public-record pivots", records))

    pivots = []
    if email:
        pivots.append('"%s"' % email)
        local = email.split("@")[0]
        pivots.append('"%s" github OR linkedin OR facebook' % local)
    if phone:
        pivots.append('"%s"' % phone)
        digits = "".join(c for c in phone if c.isdigit())
        if len(digits) == 11 and digits.startswith("1"):
            alt = "%s-%s-%s" % (digits[1:4], digits[4:7], digits[7:])
            pivots.append('"%s"' % alt)
        elif len(digits) == 10:
            pivots.append('"(%s) %s-%s"'
                          % (digits[:3], digits[3:6], digits[6:]))
    if username and not email:
        for u in username_variants(username):
            pivots.append('"%s"' % u)
    if pivots:
        cats.append(("CONTACT PIVOTS -- reuse of the same handle/address",
                     pivots))

    breach = [
        "haveibeenpwned.com -- enter the email BY HAND; never script it, "
        "never paste the password anywhere",
    ]
    if email:
        breach.append('"%s" "password" OR "leak" OR "breach" OR "combo list"'
                      % email)
    cats.append(("BREACH-ADJACENT -- guidance, no live queries here", breach))

    images = [
        "Reverse-image search the best profile photo (Google Lens, TinEye, "
        "Yandex Images): same face on other profiles = identity anchor.",
    ]
    if name:
        images.append('"%s" photo OR image OR picture' % name)
        images.append('"%s" avatar OR "profile picture"' % name)
    cats.append(("IMAGES -- face pivots", images))

    return cats


def print_dorks(args):
    cats = build_dorks(args.name, args.email, args.phone, args.username,
                       args.location)
    who = args.name or args.username or args.email or args.phone or "subject"
    print("OSINT dork battery -- %s" % who)
    print("Run each dork by hand in your search engine of choice.")
    print()
    n = 0
    for cat, dorks in cats:
        print("== %s ==" % cat)
        for d in dorks:
            n += 1
            print("  [%02d] %s" % (n, d))
        print()
    print("%d dorks generated." % n)


def worksheet(args):
    who = args.name or args.username or args.email or args.phone or "SUBJECT"
    w = []
    w.append("# Investigation Worksheet -- %s" % who)
    w.append("")
    w.append("_Opened: YYYY-MM-DD. One worksheet per person. Grade every fact._")
    w.append("")
    w.append("## Known anchors (start here)")
    w.append("")
    for label, val in (("Name", args.name), ("Email", args.email),
                       ("Phone", args.phone), ("Username", args.username),
                       ("Location", args.location)):
        w.append("- %s: %s" % (label, val or "?"))
    w.append("")
    w.append("## Source-grading rubric")
    w.append("")
    w.append(textwrap.indent(RUBRIC.strip(), "  "))
    w.append("")
    w.append("## Identity-disambiguation checklist")
    w.append("")
    w.append(textwrap.indent(CHECKLIST.strip(), "  "))
    w.append("")
    w.append("## Dork battery")
    w.append("")
    for cat, dorks in build_dorks(args.name, args.email, args.phone,
                                  args.username, args.location):
        w.append("### %s" % cat)
        w.append("")
        for d in dorks:
            w.append("- [ ] `%s`" % d)
            w.append("  - result / grade:")
        w.append("")
    w.append("## Timeline (graded facts only: A or B)")
    w.append("")
    w.append("| Date | Event | Source | Grade |")
    w.append("|------|-------|--------|-------|")
    w.append("|      |       |        |       |")
    w.append("")
    w.append("## Associates graph")
    w.append("")
    w.append("- name -- relation -- anchor (how confirmed)")
    w.append("")
    w.append("## Exposure / removal notes")
    w.append("")
    w.append("- data-broker listing -> opt-out URL -> date requested")
    w.append("")
    w.append("## Open questions")
    w.append("")
    w.append("-")
    return "\n".join(w)


def main():
    ap = argparse.ArgumentParser(
        description="Offline OSINT helper: search-dork battery, source "
                    "grading rubric, disambiguation checklist, printable "
                    "investigation worksheet. No network access.")
    ap.add_argument("--name", help="full name of the subject")
    ap.add_argument("--email", help="known email address")
    ap.add_argument("--phone", help="known phone number")
    ap.add_argument("--username", help="known handle/username")
    ap.add_argument("--location", help="city/state or region")
    ap.add_argument("--rubric", action="store_true",
                    help="print the source-grading rubric")
    ap.add_argument("--checklist", action="store_true",
                    help="print the identity-disambiguation checklist")
    ap.add_argument("--worksheet", action="store_true",
                    help="print a full markdown investigation worksheet")
    args = ap.parse_args()

    if args.worksheet:
        print(worksheet(args))
        return
    if args.rubric:
        print(RUBRIC.strip())
        print()
    if args.checklist:
        print(CHECKLIST.strip())
        print()
    if any([args.name, args.email, args.phone, args.username]):
        print_dorks(args)
    elif not (args.rubric or args.checklist):
        ap.error("give at least one of --name/--email/--phone/--username")


if __name__ == "__main__":
    main()
