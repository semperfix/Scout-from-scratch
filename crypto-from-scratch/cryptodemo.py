#!/usr/bin/env python3
"""cryptodemo: entry-point CLI for the crypto-from-scratch skill.

Subcommands:
  aes-test   verify the hand-built AES-128 against the FIPS-197 test vector
  rsa-demo   run the textbook-RSA demos (malleability, e=3 cube-root, sign/verify)
  dh-demo    run a Diffie-Hellman key exchange over localhost TCP with an
             AES-CBC encrypted echo channel
"""
import argparse
import sys

import aes
import rsa
import dh_demo


def cmd_aes_test(_args):
    ok, detail = aes.self_test()
    print(detail)
    return 0 if ok else 1


def cmd_rsa_demo(args):
    results = rsa.run_demos(bits=args.bits)
    rc = 0
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        rc |= 0 if ok else 1
    return rc


def cmd_dh_demo(args):
    ok, report = dh_demo.demo(port=args.port)
    print(report)
    print("DH DEMO:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cryptodemo",
        description="Demos for hand-built AES-128, textbook RSA, and "
                    "Diffie-Hellman over TCP. Pure stdlib, no crypto libs.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("aes-test", help="verify AES-128 vs FIPS-197 Appendix B")
    p.set_defaults(func=cmd_aes_test)

    p = sub.add_parser("rsa-demo", help="textbook RSA attacks + sign/verify demos")
    p.add_argument("--bits", type=int, default=512,
                   help="RSA modulus size in bits (default 512; demo speed)")
    p.set_defaults(func=cmd_rsa_demo)

    p = sub.add_parser("dh-demo", help="DH exchange + encrypted echo over localhost TCP")
    p.add_argument("--port", type=int, default=18321, help="localhost TCP port")
    p.set_defaults(func=cmd_dh_demo)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
